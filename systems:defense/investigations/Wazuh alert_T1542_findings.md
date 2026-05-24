## Wazuh alert - T.1542

<br>

<br>

```
# Wazuh Alert Triage: AppImage Flagged as Possible Kernel-Level Rootkit

## Summary

Wazuh generated an alert for a file path under `/tmp/.mount_[appname]`, reporting:

```text
Anomaly detected in file '/tmp/.mount_[image]'.
Hidden from stat, but showing up on readdir.
Possible kernel level rootkit.

```

<br>

Initial concern was that the alert indicated hidden filesystem behavior consistent with a rootkit. This was flagged as a potential persistence mechanism aligned with MITRE ATT&CK T.1542. Could there be something in this AppImage? As usual, I need to know if this is legitimate and what I need to do for investigation. So, after consulting with MITRE ATT&CK, doing some Googling, and working with ChatGPT, I ran through a series of checks to determine what exactly was happening with this AppImage. After investigation, the path and process behavior strongly suggest this is related to typical Linux temporary mount behavior rather than confirmed rootkit activity.

<br>

AppImages commonly mount themselves under `/tmp/.mount_*` while running. This can appear unusual to rootkit or file-integrity checks because the temporary mount may exist during directory enumeration but disappear or change before stat checks complete.

<br>

## Environment / Context

The flagged application was a portable AppImage launched by double-clicking the file from a local directory.

The application and launcher were the same file:

```
/home/user/apps/[App].AppImage

```

I noted an odd timestamp when checking the physical file: the file appeared to have been created in the last 24 hours, even though it had existed on the system for much longer. This required additional review to distinguish actual content modification from metadata or inode change time.

<br>

## Initial Wazuh Alert

Relevant alert text:

```
Anomaly detected in file '/tmp/.mount_[image]'.
Hidden from stat, but showing up on readdir.
Possible kernel level rootkit.

```

<br>

## <br>

## Key Findings

### 1\. `/tmp/.mount_*` Path Matched Normal AppImage Behavior

The suspicious path was under:

```
/tmp/.mount_[AppImage]...

```

This is typical for AppImage execution. AppImages often mount themselves temporarily under `/tmp/.mount_*` using FUSE, execute from that mounted directory, and unmount when closed.

<br>

Observed process path:

```
/tmp/.mount_[AppImage]--type=gpu-process ...

```

This supported the conclusion that the alert was likely related to AppImage runtime behavior.

### <br>

### 2\. Multiple AppImage Processes Observed

`pgrep` and `ps auxf` showed approximately 10 processes related to the AppImage, which struck me as odd at first. 

<br>

Example:

```
/tmp/.mount_[AppImage] --type=gpu-process --ozone-platform=x11 ...

```

<br>

This looked normal for an Electron/Chromium-based desktop application, but I had to look that up. Electron apps commonly spawn multiple processes, including:

```
main process
renderer processes
GPU process
utility processes
crash reporter

```

This finding did not independently indicate compromise.

<br>

### <br>

### 3\. User-Created Audit Script Appeared as Failed systemd User Units

Several failed units appeared in `systemctl --user list-units`:

```
app-\x2fhome\x2fuser\x2fscripts\x2fscript.sh@...service

```

Decoded path:

```
app-/home/user/scripts/script.sh@...service

```

<br>

This initially looked strange because the script appeared as a “service” and I have never seen this before. Of course, I have to know what it is, so I look that up too. According to modern Linux desktops, applications and scripts launched from the GUI can be tracked as transient `systemd --user` app units. This particular script I had been creating and testing had a background issue and was terminated (”failed unit”), but these artifacts were leftover. I was able to clear these out with: 

```
systemctl --user reset-failed
```

<br>

## Action Steps / Commands Used

### Check AppImage Process Behavior

```
pgrep -a -f [AppImage]
ps auxf | grep -i [AppImage]

```

### <br>

### Check Temporary AppImage Mount

```
findmnt | grep -i [AppImage]
mount | grep -i [AppImage]
ls -lah /tmp | grep -i mount

```

### <br>

### Close the AppImage and Verify Cleanup

```
findmnt | grep -i [AppImage]
pgrep -a -f [AppImage]
ls -lah /tmp | grep -i [AppImage]

```

<br>

Expected benign result:

```
No [AppImage] processes remain.
No /tmp/.mount_[AppImage]* mount remains.

```

### <br>

### Inspect systemd User Units

```
systemctl --user list-units

```

### <br>

### Inspect a Suspicious User Unit

```
systemctl --user show '<unit-name>' \
  -p FragmentPath \
  -p UnitFileState \
  -p Transient \
  -p ExecStart \
  -p Result \
  -p ExecMainStatus

```

Important interpretation:

```
FragmentPath empty + Transient=yes = likely temporary user-session unit
FragmentPath pointing to ~/.config/systemd/user or /etc/systemd/system = real service file exists
UnitFileState=enabled = persistence concern

```

### <br>

### Search for Actual Service Files

```
find ~/.config/systemd/user ~/.local/share/systemd/user /etc/systemd/user /usr/lib/systemd/user /etc/systemd/system /usr/lib/systemd/system \
  -type f 2>/dev/null | grep -Ei '[AppImageName]|AppImage'

```

### <br>

### Check Runtime Transient systemd Units

```
ls -lah /run/user/$(id -u)/systemd/transient 2>/dev/null

find /run/user/$(id -u)/systemd/transient -type f 2>/dev/null | grep -Ei 'audit|[AppImageName]|AppImage'

```

<br>

### Check Kernel Messages

```
sudo dmesg -T | grep -Ei 'module|taint|segfault|audit|apparmor|bpf|kprobe|ftrace|rootkit|denied|fuse|mount' | tail -200

```

### <br>

### Check AppImage Metadata

```
stat /home/[user]/apps/[AppImage].AppImage
ls -l --full-time /home/[user]/apps/[AppImage].AppImage
sha256sum /home/[user]/apps/[AppImage].AppImage
file /home/[user]/apps/[AppImage].AppImage

```

### <br>

### Check Recent Changes to App Directory

```
find /home/[user]/apps -maxdepth 1 -type f -mtime -7 -ls
find /home/[user]/apps -maxdepth 1 -type f -ctime -7 -ls

```

### <br>

### Extract and Inspect AppImage

```
/home/[user]/apps/[AppImage].AppImage --appimage-extract

```

Then:

```
clamscan -r squashfs-root

find squashfs-root -type f -perm -4000 -o -perm -2000 -ls

find squashfs-root -type f \( -name "*.service" -o -name "*.sh" -o -name "*.desktop" -o -name "*.py" \) -ls

```

### <br>

### Check for Persistence Related to the App

```
find ~/.config/autostart ~/.config/systemd ~/.local/share/systemd ~/.local/share/applications \
  -type f 2>/dev/null | grep -Ei '[AppImageName]'

```

## <br>

## Findings

The alert wording sounded severe, but the evidence pointed toward normal AppImage behavior.

<br>

The most important correlation was:

```
Wazuh flagged /tmp/.mount_[image]
The running application was an AppImage
The process executable path was inside /tmp/.mount_[AppImage]*
AppImages commonly create temporary /tmp/.mount_* FUSE mounts

```

<br>

This suggests the alert was likely triggered by a timing or visibility mismatch during Wazuh rootcheck scanning. A temporary AppImage mount may appear during `readdir` but be unavailable or changed when Wazuh attempts `stat`.

## <br>

## Conclusion & Lessons Learned

**Current assessment:** Likely false positive / benign AppImage runtime artifact. No confirmed evidence of kernel-level rootkit activity from the observed data.

<br>

**Confidence level:** Moderate to high, assuming:

- /tmp/.mount\_\[AppImage\]\* only exists while the AppImage is running
- no persistent service file exists for the app or the audit script
- the AppImage hash/source can be validated
- no suspicious persistence or unexplained network activity is found

<br>

This investigation showed how normal Linux desktop behavior can look suspicious to security tooling. As someone forever learning the ins and outs of multiple operating systems, taking the time to break down what is happening is invaluable regardless of the benign result. I still learned many different things about App Images and their behavior, got to practice a multitude of commands, and dug into sysctl behavior.

<br>

This ended up being a useful example of alert triage: do not dismiss the alert, but do not assume the worst until the behavior is correlated with system evidence.

<br>

Key takeaways:

- AppImages commonly mount under /tmp/.mount\_\*
- Electron apps commonly spawn many processes
- Desktop-launched scripts/apps may appear as transient systemd --user app units
- Wazuh rootcheck alerts should be validated with local process, mount, and persistence evidence
