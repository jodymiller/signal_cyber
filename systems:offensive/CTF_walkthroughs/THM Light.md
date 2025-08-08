TryHackMe Light

As usual, start with nmap scan:
<img width="583" height="289" alt="image" src="https://github.com/user-attachments/assets/385264bf-d748-4068-b03c-5f5a2a1e6491" />

This took a little more trial and error than I have screenshots for, but here is the gist:
<img width="614" height="130" alt="image" src="https://github.com/user-attachments/assets/ff1892fe-161f-4a0b-a324-8dcb66c4b752" />

Hint that is SQLite from error message:
<img width="525" height="33" alt="image" src="https://github.com/user-attachments/assets/2d6b3c12-33cd-4479-92b2-6ba9de0555b3" />


Trying to get table names:
<img width="614" height="36" alt="image" src="https://github.com/user-attachments/assets/93ecf234-275e-4f77-90b5-339c663781f9" />

Ended up having to research a little to get more since the one table I pulled did not do the job. Found this in another writeup linked in the TryHackMe page:
<img width="646" height="129" alt="image" src="https://github.com/user-attachments/assets/419e657c-6f74-4023-9824-524e49ce04f6" />

Now I have the username and password for admin and am able to get the flag. 

