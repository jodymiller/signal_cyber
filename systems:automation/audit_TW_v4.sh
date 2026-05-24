#!/usr/bin/env bash

set -uo pipefail

AUDIT_NAME="opensuse-tumbleweed-audit"
TIMESTAMP="$(date +%Y%m%d_%H%M%S)"

if [[ -n "${SUDO_USER:-}" && "${SUDO_USER}" != "root" ]]; then
    REAL_USER="$SUDO_USER"
    REAL_HOME="$(getent passwd "$REAL_USER" | cut -d: -f6)"
else
    REAL_USER="$(whoami)"
    REAL_HOME="$HOME"
fi

OUTDIR="${REAL_HOME}/${AUDIT_NAME}_${TIMESTAMP}"


SUMMARY="${OUTDIR}/summary.txt"
DETAILS="${OUTDIR}/details.log"
FINDINGS="${OUTDIR}/findings.txt"

DAYS_MODIFIED=5
VERBOSE=0
SUDO_OK=0

RED=$'\033[31m'
YELLOW=$'\033[33m'
GREEN=$'\033[32m'
BLUE=$'\033[34m'
RESET=$'\033[0m'

usage() {
    cat <<EOF
Usage: $0 [options]

Options:
  -v, --verbose       Print more detail to terminal
  -d, --days DAYS     Check files modified in the last DAYS days. Default: 5
  -h, --help          Show this help

Output:
  Audit output is saved under:
  ${OUTDIR}

Notes:
  This script is intended to be read-only.
  It can be run as a normal user, but some checks will use sudo if available.
  For the fullest audit, run:
    sudo $0
EOF
}

have() {
    command -v "$1" >/dev/null 2>&1
}

safe_count() {
    wc -l | tr -d ' '
}

section() {
    echo
    echo "==== $1 ===="
}

finding() {
    local severity="$1"
    local msg="$2"

    case "$severity" in
        HIGH)   echo "${RED}[HIGH]${RESET} $msg" ;;
        MEDIUM) echo "${YELLOW}[MEDIUM]${RESET} $msg" ;;
        LOW)    echo "${BLUE}[LOW]${RESET} $msg" ;;
        OK)     echo "${GREEN}[OK]${RESET} $msg" ;;
        INFO)   echo "[INFO] $msg" ;;
        *)      echo "[$severity] $msg" ;;
    esac

    echo "[$severity] $msg" >> "$FINDINGS"
}

log_detail() {
    {
        echo
        echo "==== $1 ===="
        cat
    } >> "$DETAILS"
}

run_sudo() {
    if [[ "$EUID" -eq 0 ]]; then
        "$@" 2>>"$DETAILS"
    elif [[ "$SUDO_OK" -eq 1 ]]; then
        sudo "$@" 2>>"$DETAILS"
    else
        echo "Skipped privileged command because sudo is unavailable or not authorized: $*" >> "$DETAILS"
        return 1
    fi
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        -d|--days)
            if [[ $# -lt 2 || ! "${2:-}" =~ ^[0-9]+$ || "$2" -eq 0 ]]; then
                echo "Error: --days requires a positive number."
                exit 1
            fi
            DAYS_MODIFIED="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

mkdir -p "$OUTDIR"

if [[ "$EUID" -eq 0 && -n "${REAL_USER:-}" && "$REAL_USER" != "root" ]]; then
    chown "$REAL_USER:$REAL_USER" "$OUTDIR" 2>/dev/null || true
fi

touch "$SUMMARY" "$DETAILS" "$FINDINGS"

echo "====[ openSUSE Tumbleweed Security Audit ]===="
echo "This script is intended to be read-only."
echo "Output directory:"
echo "$OUTDIR"
echo

if [[ "$EUID" -eq 0 ]]; then
    SUDO_OK=1
    echo "Running as root. Full audit available."
elif have sudo; then
    echo "Checking whether sudo is available for privileged checks..."
    if sudo -v; then
        SUDO_OK=1
        echo "sudo available. Privileged checks will run as needed."
    else
        SUDO_OK=0
        echo "sudo unavailable or permission denied. Running limited audit."
    fi
else
    SUDO_OK=0
    echo "sudo command not found. Running limited audit."
fi

{
    echo "Audit started: $(date)"
    echo "Hostname: $(hostname 2>/dev/null || echo unknown)"
    echo "Kernel: $(uname -a)"
    echo "User: $(whoami)"
    echo "EUID: $EUID"
    echo "SUDO_OK: $SUDO_OK"
    echo "Output directory: $OUTDIR"
} >> "$SUMMARY"

section "Tool availability"

for tool in rpm zypper systemctl firewall-cmd ss journalctl snapper nft getcap auditctl aa-status awk grep find sed stat; do
    if have "$tool"; then
        finding OK "Tool available: $tool"
    else
        finding LOW "Tool missing: $tool"
    fi
done

section "System identity"

if have hostnamectl; then
    hostnamectl | tee -a "$SUMMARY" | log_detail "hostnamectl"
else
    uname -a | tee -a "$SUMMARY" | log_detail "uname"
fi

section "Package integrity: rpm -Va"

if have rpm; then
    RPM_RAW="${OUTDIR}/rpm_verify_raw.txt"
    RPM_FINDINGS="${OUTDIR}/rpm_verify_filtered.txt"

    run_sudo rpm -Va > "$RPM_RAW" || true

    # rpm verify flags:
    # S size, M mode, 5 digest, D device, L symlink, U user, G group, T mtime, P capabilities
    #
    # Clean unchanged lines normally begin with eight dots.
    grep -vE '^\.{8}' "$RPM_RAW" > "$RPM_FINDINGS" || true

    rpm_total=$(safe_count < "$RPM_FINDINGS")
    rpm_non_config=$(grep -v ' c ' "$RPM_FINDINGS" | safe_count || true)
    rpm_config=$(grep ' c ' "$RPM_FINDINGS" | safe_count || true)

    if [[ "$rpm_total" -eq 0 ]]; then
        finding OK "rpm -Va found no altered packaged files."
    else
        finding MEDIUM "rpm -Va found ${rpm_total} altered packaged files: ${rpm_non_config} non-config, ${rpm_config} config. Full list: $RPM_FINDINGS"

        echo "Top non-config package integrity changes:"
        grep -v ' c ' "$RPM_FINDINGS" | head -n 25 || true

        if [[ "$VERBOSE" -eq 1 ]]; then
            echo
            echo "Top config changes:"
            grep ' c ' "$RPM_FINDINGS" | head -n 25 || true
        fi
    fi
else
    finding LOW "rpm command not found."
fi

section "Tumbleweed update and repository review"

if have zypper; then
    ZYPPER_REPOS="${OUTDIR}/zypper_repos.txt"
    ZYPPER_DUP="${OUTDIR}/zypper_dup_dry_run.txt"

    zypper lr -uEP > "$ZYPPER_REPOS" 2>>"$DETAILS" || true

    repo_count=$(grep -E '^\s*[0-9]+' "$ZYPPER_REPOS" | safe_count || true)
    external_repo_count=$(
        grep -E '^\s*[0-9]+' "$ZYPPER_REPOS" \
        | grep -viE 'opensuse|download\.opensuse\.org|repo\.opensuse\.org|packman' \
        | safe_count || true
    )

    finding INFO "Enabled zypper repos: ${repo_count}. Non-openSUSE/non-Packman-looking repos: ${external_repo_count}. Details: $ZYPPER_REPOS"

    if [[ "$external_repo_count" -gt 0 ]]; then
        echo "External-looking enabled repos:"
        grep -E '^\s*[0-9]+' "$ZYPPER_REPOS" \
            | grep -viE 'opensuse|download\.opensuse\.org|repo\.opensuse\.org|packman' || true
    fi

    run_sudo zypper --non-interactive dup --dry-run > "$ZYPPER_DUP" || true

    dup_updates=$(
        grep -Ei 'The following .* package|will be upgraded|will be changed|will be installed|will be removed|will change vendor' "$ZYPPER_DUP" \
        | head -n 20 || true
    )

    if [[ -n "$dup_updates" ]]; then
        finding INFO "zypper dup dry-run has pending package actions. Details: $ZYPPER_DUP"
        echo "$dup_updates"
    else
        finding OK "zypper dup dry-run did not show obvious pending package actions."
    fi
else
    finding LOW "zypper not found."
fi

section "Failed systemd units"

if have systemctl; then
    FAILED_UNITS="${OUTDIR}/systemd_failed_units.txt"
    systemctl --failed --no-pager > "$FAILED_UNITS" 2>>"$DETAILS" || true

    failed_count=$(grep -E ' loaded failed ' "$FAILED_UNITS" | safe_count || true)

    if [[ "$failed_count" -eq 0 ]]; then
        finding OK "No failed systemd units."
    else
        finding MEDIUM "${failed_count} failed systemd unit(s). Details: $FAILED_UNITS"
        systemctl --failed --no-pager || true
    fi
else
    finding LOW "systemctl not found."
fi

section "Enabled services review"

if have systemctl; then
    ENABLED_SERVICES="${OUTDIR}/enabled_services.txt"
    systemctl list-unit-files --type=service --state=enabled --no-pager > "$ENABLED_SERVICES" 2>>"$DETAILS" || true

    finding INFO "Enabled services saved to $ENABLED_SERVICES"

    echo "Potentially interesting enabled services:"
    grep -Ei 'ssh|vnc|xrdp|samba|smb|winbind|ftp|tftp|telnet|avahi|cups|docker|podman|libvirt|rpc|nfs|cockpit|nginx|apache|httpd|mysql|mariadb|postgres|tailscale|zerotier|syncthing|tor' "$ENABLED_SERVICES" || true
fi

section "Firewall status"

if have firewall-cmd; then
    FIREWALL_STATE="${OUTDIR}/firewalld_status.txt"

    {
        echo "State:"
        firewall-cmd --state 2>/dev/null || true
        echo
        echo "Default zone:"
        firewall-cmd --get-default-zone 2>/dev/null || true
        echo
        echo "Active zones:"
        firewall-cmd --get-active-zones 2>/dev/null || true
        echo
        echo "Permanent services by zone:"
        firewall-cmd --list-all-zones 2>/dev/null || true
    } > "$FIREWALL_STATE"

    if systemctl is-active --quiet firewalld 2>/dev/null; then
        finding OK "firewalld is active. Details: $FIREWALL_STATE"
        echo "Active zones:"
        firewall-cmd --get-active-zones 2>/dev/null || true
        echo
        echo "Default zone:"
        firewall-cmd --get-default-zone 2>/dev/null || true
    else
        finding HIGH "firewalld is not active."
    fi
else
    finding MEDIUM "firewall-cmd not found. firewalld may not be installed."
fi

section "nftables ruleset"

NFT_REPORT="${OUTDIR}/nftables_ruleset.txt"

if have nft; then
    run_sudo nft -a list ruleset > "$NFT_REPORT" || true

    if [[ -s "$NFT_REPORT" ]]; then
        finding INFO "nftables ruleset saved to $NFT_REPORT"
        if [[ "$VERBOSE" -eq 1 ]]; then
            head -n 80 "$NFT_REPORT"
        fi
    else
        finding LOW "nft command ran but no ruleset output was saved."
    fi
else
    finding LOW "nft command not found."
fi

section "Open network listeners"

if have ss; then
    LISTENERS="${OUTDIR}/network_listeners.txt"
    NON_LOOPBACK="${OUTDIR}/network_listeners_non_loopback.txt"

    run_sudo ss -tulpen > "$LISTENERS" || true

    grep -vE '127\.0\.0\.1|::1|\[::1\]' "$LISTENERS" > "$NON_LOOPBACK" || true

    listener_count=$(grep -E 'LISTEN|UNCONN' "$NON_LOOPBACK" | safe_count || true)

    if [[ "$listener_count" -eq 0 ]]; then
        finding OK "No non-loopback TCP/UDP listener entries found."
    else
        finding MEDIUM "${listener_count} non-loopback listener entries found. Details: $NON_LOOPBACK"
        awk 'NR==1 || /LISTEN|UNCONN/' "$NON_LOOPBACK" | head -n 50
    fi
else
    finding LOW "ss command not found."
fi

section "SSH configuration"

SSH_REPORT="${OUTDIR}/ssh_audit.txt"

{
    echo "sshd service:"
    systemctl status sshd --no-pager 2>/dev/null || true
    echo
    echo "/etc/ssh/sshd_config active lines:"
    grep -Ei '^\s*(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication|AllowUsers|AllowGroups|PermitEmptyPasswords|X11Forwarding|Port|ListenAddress)' /etc/ssh/sshd_config 2>/dev/null || true
    echo
    echo "Root authorized_keys metadata:"
    run_sudo ls -lah /root/.ssh/authorized_keys 2>/dev/null || true
    run_sudo wc -l /root/.ssh/authorized_keys 2>/dev/null || true
    echo
    echo "Root authorized_keys key types/comments only:"
    run_sudo awk '{print "key_type=" $1, "comment=" $NF}' /root/.ssh/authorized_keys 2>/dev/null || true
} > "$SSH_REPORT"

if systemctl is-active --quiet sshd 2>/dev/null; then
    finding INFO "sshd is active. Review SSH details: $SSH_REPORT"
    grep -Ei '^\s*(PermitRootLogin|PasswordAuthentication|Port|AllowUsers|AllowGroups)' /etc/ssh/sshd_config 2>/dev/null || true
else
    finding OK "sshd is not active."
fi

section "Users, groups, and sudo access"

USER_REPORT="${OUTDIR}/users_and_sudo.txt"

{
    echo "UID >= 1000:"
    awk -F: '$3 >= 1000 && $3 < 65534 {print $1 " UID=" $3 " HOME=" $6 " SHELL=" $7}' /etc/passwd
    echo
    echo "UID 0 users:"
    awk -F: '$3 == 0 {print $1 " UID=" $3 " HOME=" $6 " SHELL=" $7}' /etc/passwd
    echo
    echo "wheel group:"
    getent group wheel || true
    echo
    echo "sudo group:"
    getent group sudo || true
    echo
    echo "sudoers active lines:"
    run_sudo grep -RHE '^[^#].*(ALL|\bNOPASSWD\b)' /etc/sudoers /etc/sudoers.d 2>/dev/null || true
} > "$USER_REPORT"

uid0_count=$(awk -F: '$3 == 0 {print $1}' /etc/passwd | safe_count)

if [[ "$uid0_count" -gt 1 ]]; then
    finding HIGH "More than one UID 0 account exists. Details: $USER_REPORT"
else
    finding OK "Only one UID 0 account found."
fi

finding INFO "User and sudo review saved to $USER_REPORT"

echo "Interactive-ish user accounts:"
awk -F: '$3 >= 1000 && $3 < 65534 {print $1 " UID=" $3 " SHELL=" $7}' /etc/passwd

section "Cron and timers"

CRON_TIMER_REPORT="${OUTDIR}/cron_and_timers.txt"

{
    echo "System cron directories:"
    run_sudo find /etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly -maxdepth 2 -type f -ls 2>/dev/null || true
    echo
    echo "Spool cron:"
    run_sudo find /var/spool/cron -type f -ls 2>/dev/null || true
    echo
    echo "Root crontab:"
    run_sudo crontab -l 2>/dev/null || true
    echo
    echo "Systemd timers:"
    systemctl list-timers --all --no-pager 2>/dev/null || true
} > "$CRON_TIMER_REPORT"

finding INFO "Cron and systemd timer details saved to $CRON_TIMER_REPORT"

echo "Enabled/active timers:"
systemctl list-timers --all --no-pager 2>/dev/null | head -n 30 || true

section "User persistence locations"

PERSISTENCE_REPORT="${OUTDIR}/user_persistence_locations.txt"

{
    echo "User systemd units:"
    find /home -path '*/.config/systemd/user/*' -type f -ls 2>/dev/null || true
    echo
    echo "Autostart desktop files:"
    find /home -path '*/.config/autostart/*.desktop' -type f -ls 2>/dev/null || true
    echo
    echo "Recently modified shell startup files:"
    find /home -maxdepth 4 \
        \( -name '.bashrc' -o -name '.profile' -o -name '.bash_profile' -o -name '.zshrc' -o -name '.config/fish/config.fish' \) \
        -mtime "-${DAYS_MODIFIED}" -ls 2>/dev/null || true
} > "$PERSISTENCE_REPORT"

finding INFO "User persistence locations saved to $PERSISTENCE_REPORT"

section "AppArmor, auditd, and security services"

SECURITY_SERVICES="${OUTDIR}/security_services.txt"

{
    echo "AppArmor:"
    systemctl status apparmor --no-pager 2>/dev/null || true
    echo
    if have aa-status; then
        run_sudo aa-status 2>/dev/null || true
    fi
    echo
    echo "auditd:"
    systemctl status auditd --no-pager 2>/dev/null || true
    echo
    echo "audit rules:"
    if have auditctl; then
        run_sudo auditctl -l 2>/dev/null || true
    fi
} > "$SECURITY_SERVICES"

if systemctl is-active --quiet apparmor 2>/dev/null; then
    finding OK "AppArmor is active."
else
    finding MEDIUM "AppArmor is not active or not installed."
fi

if systemctl is-active --quiet auditd 2>/dev/null; then
    finding OK "auditd is active."
else
    finding LOW "auditd is not active. This may be fine for a desktop, but it reduces audit visibility."
fi

section "Recently modified system files"

MODIFIED_REPORT="${OUTDIR}/recently_modified_system_files.txt"

run_sudo find /etc /usr/bin /usr/sbin /bin /sbin /lib /lib64 \
    -xdev \
    -type f \
    -mtime "-${DAYS_MODIFIED}" \
    -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' \
    2>/dev/null \
    | sort -r > "$MODIFIED_REPORT" || true

modified_count=$(safe_count < "$MODIFIED_REPORT")

if [[ "$modified_count" -eq 0 ]]; then
    finding OK "No system files modified in the last ${DAYS_MODIFIED} day(s)."
else
    finding INFO "${modified_count} system files modified in the last ${DAYS_MODIFIED} day(s). Details: $MODIFIED_REPORT"
    echo "Most recent modified system files:"
    head -n 25 "$MODIFIED_REPORT"
fi

section "SUID, SGID, and Linux capabilities"

SUID_REPORT="${OUTDIR}/suid_sgid_files.txt"
CAP_REPORT="${OUTDIR}/linux_capabilities.txt"

run_sudo find / -xdev \( -perm -4000 -o -perm -2000 \) -type f \
    -printf '%m %u:%g %p\n' 2>/dev/null \
    | sort > "$SUID_REPORT" || true

if have getcap; then
    run_sudo getcap -r / 2>/dev/null > "$CAP_REPORT" || true
else
    echo "getcap not found" > "$CAP_REPORT"
fi

finding INFO "SUID/SGID file list saved to $SUID_REPORT"
finding INFO "Linux capabilities saved to $CAP_REPORT"

echo "Interesting Linux capabilities:"
grep -Ev '/usr/bin/ping|/usr/bin/traceroute|/usr/sbin/mtr-packet' "$CAP_REPORT" | head -n 30 || true

if grep -Ei '/(python|python[0-9.]*|perl|ruby|bash|dash|zsh|sh|node|php|lua).*cap_setuid' "$CAP_REPORT" >/dev/null 2>&1; then
    finding HIGH "Interpreter binary has cap_setuid. Review immediately: $CAP_REPORT"
    grep -Ei '/(python|python[0-9.]*|perl|ruby|bash|dash|zsh|sh|node|php|lua).*cap_setuid' "$CAP_REPORT" || true
fi

if grep -Ei 'cap_sys_admin|cap_dac_read_search|cap_dac_override|cap_setuid|cap_setgid|cap_net_admin' "$CAP_REPORT" >/dev/null 2>&1; then
    finding MEDIUM "Powerful Linux capabilities found. Review: $CAP_REPORT"
fi

section "Suspicious scripts and binaries in writable locations"

SUSPICIOUS_REPORT="${OUTDIR}/suspicious_writable_locations.txt"

{
    echo "Executable files in /tmp, /var/tmp, /dev/shm:"
    run_sudo find /tmp /var/tmp /dev/shm -xdev -type f -executable \
        -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %s %p\n' 2>/dev/null | sort -r || true

    echo
    echo "Suspicious script content paths:"
    if [[ "$SUDO_OK" -eq 1 || "$EUID" -eq 0 ]]; then
        run_sudo find /home /tmp /var/tmp /dev/shm -xdev -type f -size -2M \
            \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.rb' -o -name '*.js' -o -name '*.php' -o -perm -111 \) \
            -print0 2>/dev/null \
            | xargs -0 grep -IlE 'bash -i|/dev/tcp|socket\.socket|subprocess|pty\.spawn|nc -e|ncat|socat|curl .*\|.*sh|wget .*\|.*sh|base64 -d|chmod \+x' \
            2>/dev/null || true
    else
        find /home /tmp /var/tmp /dev/shm -xdev -type f -size -2M \
            \( -name '*.sh' -o -name '*.py' -o -name '*.pl' -o -name '*.rb' -o -name '*.js' -o -name '*.php' -o -perm -111 \) \
            -print0 2>/dev/null \
            | xargs -0 grep -IlE 'bash -i|/dev/tcp|socket\.socket|subprocess|pty\.spawn|nc -e|ncat|socat|curl .*\|.*sh|wget .*\|.*sh|base64 -d|chmod \+x' \
            2>/dev/null || true
    fi

    echo
    echo "Netcat-like binaries:"
    run_sudo find / -xdev -type f \
        \( -iname 'nc' -o -iname 'netcat' -o -iname 'ncat' -o -iname 'socat' \) \
        -executable -printf '%m %u:%g %p\n' 2>/dev/null || true
} > "$SUSPICIOUS_REPORT"

suspicious_count=$(grep -vE '^\s*$|^Executable files|^Suspicious script|^Netcat-like' "$SUSPICIOUS_REPORT" | safe_count || true)

if [[ "$suspicious_count" -eq 0 ]]; then
    finding OK "No obvious suspicious executable/script hits in writable locations."
else
    finding MEDIUM "${suspicious_count} suspicious writable-location/script hits. Details: $SUSPICIOUS_REPORT"
    head -n 60 "$SUSPICIOUS_REPORT"
fi

section "Shells outside normal paths"

SHELL_REPORT="${OUTDIR}/nonstandard_shells.txt"

run_sudo find / -xdev -type f -executable \
    \( -name 'sh' -o -name 'bash' -o -name 'zsh' -o -name 'dash' -o -name '*sh' \) \
    ! -path '/bin/*' \
    ! -path '/usr/bin/*' \
    ! -path '/usr/lib/*' \
    ! -path '/snap/*' \
    -printf '%m %u:%g %p\n' 2>/dev/null \
    | sort > "$SHELL_REPORT" || true

shell_count=$(safe_count < "$SHELL_REPORT")

if [[ "$shell_count" -eq 0 ]]; then
    finding OK "No nonstandard shell executables found on root filesystem."
else
    finding LOW "${shell_count} nonstandard shell-like executable(s) found. Details: $SHELL_REPORT"
    head -n 25 "$SHELL_REPORT"
fi

section "Logs: auth, sudo, SSH, kernel warnings"

JOURNAL_REPORT="${OUTDIR}/journal_security_recent.txt"

if have journalctl; then
    {
        echo "Recent sudo/auth/ssh failures:"
        run_sudo journalctl --since "7 days ago" --no-pager 2>/dev/null \
            | grep -Ei 'failed password|authentication failure|invalid user|sudo|session opened|session closed|su:|sshd' \
            | tail -n 200 || true

        echo
        echo "Recent high-priority journal entries:"
        run_sudo journalctl -p warning..alert --since "48 hours ago" --no-pager 2>/dev/null \
            | tail -n 200 || true
    } > "$JOURNAL_REPORT"

    finding INFO "Recent security-ish journal entries saved to $JOURNAL_REPORT"

    echo "Recent failed auth/SSH snippets:"
    grep -Ei 'failed password|authentication failure|invalid user' "$JOURNAL_REPORT" | tail -n 20 || true
else
    finding LOW "journalctl not found."
fi

section "Snapper / Btrfs snapshots"

SNAPSHOT_REPORT="${OUTDIR}/snapper_snapshots.txt"

if have snapper; then
    run_sudo snapper list > "$SNAPSHOT_REPORT" 2>>"$DETAILS" || true
    snapshot_count=$(grep -E '^[[:space:]]*[0-9]+' "$SNAPSHOT_REPORT" | safe_count || true)

    if [[ "$snapshot_count" -gt 0 ]]; then
        finding OK "Snapper snapshots found: ${snapshot_count}. Details: $SNAPSHOT_REPORT"
        tail -n 15 "$SNAPSHOT_REPORT"
    else
        finding LOW "Snapper is installed but no snapshots were listed."
    fi
else
    finding INFO "snapper not found. If this is not a Btrfs/Snapper install, that may be expected."
fi

section "GRUB and boot config"

BOOT_REPORT="${OUTDIR}/boot_config.txt"

{
    echo "/etc/default/grub:"
    stat /etc/default/grub 2>/dev/null || true
    echo
    grep -Ev '^\s*#|^\s*$' /etc/default/grub 2>/dev/null || true
    echo
    echo "/boot files recently modified:"
    run_sudo find /boot -xdev -type f -mtime "-${DAYS_MODIFIED}" \
        -printf '%TY-%Tm-%Td %TH:%TM %u:%g %m %p\n' 2>/dev/null | sort -r || true
} > "$BOOT_REPORT"

finding INFO "Bootloader/GRUB details saved to $BOOT_REPORT"

grep -Ev '^\s*#|^\s*$' /etc/default/grub 2>/dev/null | head -n 20 || true

if [[ "$EUID" -eq 0 && -n "${REAL_USER:-}" && "$REAL_USER" != "root" ]]; then
    chown -R "$REAL_USER:$REAL_USER" "$OUTDIR" 2>/dev/null || true
fi

section "Summary"

{
    echo
    echo "Audit completed: $(date)"
    echo "Findings file: $FINDINGS"
    echo "Details log: $DETAILS"
} >> "$SUMMARY"

cat "$FINDINGS"



echo
echo "====[ AUDIT COMPLETE ]===="
echo "Summary:  $SUMMARY"
echo "Findings: $FINDINGS"
echo "Details:  $DETAILS"
echo
echo "Most important next step: review HIGH and MEDIUM findings first."
