TryHackMe Publisher

This one got me at the end and I had to look it up, but is a good learning experience.

1. nmap scan
<img width="762" height="288" alt="image" src="https://github.com/user-attachments/assets/8c8bcac7-80d3-4534-be2a-a82b06ae0ea3" />

2. Nothing too interesting in scan, so moving on to fuzzing directories:
First, ffuf
<img width="771" height="475" alt="image" src="https://github.com/user-attachments/assets/779a34b1-3433-431a-80c1-12e48ecf9221" />

Second, gobuster
<img width="1109" height="520" alt="image" src="https://github.com/user-attachments/assets/0b127d3e-10dc-49ec-9125-9421143cff6b" />


3. The main key was the spip directory. Went down a rabbit hole exploring that for a while including trying out the login page - all to no avail.
4. Used exploitDB to find a python script that allowed me to exploit SPIP and access the www-data user and user flag. 
5. Copied SSH keys to my box and explored with user ‘think.’ The /opt directory is not accessible, which apparently is a flag to look there and it has an executable of interest: /opt/run_container.sh -→ REMEMBER TO USE LINPEAS or similar for this part, looks like this is how everyone found the .sh file in writeups.
6. Needless to say, I could not figure this one out after toiling for a while, but found this helpful walkthrough that worked, but no clue how one would arrive at this conclusion yet:
[https://nasrallahbaadi.com/posts/HTM-Publisher/](https://nasrallahbaadi.com/posts/HTM-Publisher/)  

- go back to www-data shell
- copy /bin/bash to /home/think/spip (owned by www-data)
- chmod +s
- chmod 777 .
- back to SSH (think user), ran /home/think/spip/bash -p
    - gave shell as www-data
- /opt/run\_container.sh is the root file that is executable
- <img width="906" height="520" alt="image" src="https://github.com/user-attachments/assets/5f2c4cca-4f23-4d1c-80e4-10f5dba03369" />


<br>

My mangled version
<img width="615" height="442" alt="image" src="https://github.com/user-attachments/assets/c387e771-8fbe-454f-b80e-ccbcb1aabe2d" />

<img width="615" height="442" alt="image" src="https://github.com/user-attachments/assets/11bcf142-36f8-44dc-9870-6659d71a5d56" />
