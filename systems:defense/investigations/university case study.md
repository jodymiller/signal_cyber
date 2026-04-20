## University PCAP

<br>

**Problem**

A university professor received threatening email from a student. The professor notified the IT department of the email and provided the email headers. The IT department traced the headers to one particular dorm room with three female occupants; they subsequently set up a packet sniffer to determine who is sending these emails. The professor received another email after the sniffer was in place.

<br>

**Objective**

Review the packet capture file to determine who sent the email based on the provided list of students from the professor’s class. Must determine who specifically sent the email and identify the TCP flow that includes the hostile message. 

<br>
**Approach**

_Email Header Details_

- First, based on the email headers, the last hostile message came from a domain called “willselfdestruct.com,” so to narrow down the packets using Wireshark, I applied a text string filter searching for this domain (Edit -→ Find Packet)

_Identification of Source IP TCP stream_

- Once the domain was found, I reviewed the TCP conversation and determined the user agent and IP address of the user: 192.168.15.4

_Traffic filter/isolation_  

- _Applied “ip.addr == 192.168.15.4” filter to packets, and then used the text filter again to look for “email”, “gmail”, and the text string “login” - these stuck out to me as items that could lead to a specific name or username that could lead to the identify of the email sender._

_User attribution  
_

- “Login” hit on a HTTP response containing XML with yahoo address book details with the username: Amy78Smith. 
- Comparing this name to the provided student list, Amy Smith is in the professor’s class. 

_Correlation with additional packets_

- Using that information, searched again with the identified username “Amy789Smith” and found additional corresponding yahoo messenger packets with the same username

_Validation of Device and Timestamps_

- All packets were marked in Wireshark and then I validated that the MAC address of the device was the same in each
- Reviewed the timeline to see how these groups related and these were within a 6 minute window on the same date

<br>

> 82632 2008-07-22 02:03:27.088187 192.168.15.4 208.185.127.34 HTTP 720 GET /?d=1/&g=2&h=87M63Y06OkWA0556&hs=87M63Y06OkWA0556&t=4&r=http%3a%2f%2femail%2eabout%2ecom%2fod%2fanonymousemailservices%2fAnonymous%5fEmail%5fand%5fRemailer%5fServices%2ehtm&u=http%3A%2F%2Femail%2eabout%2ecom%2fod%2fanonymousemailservices%2fgr%2fwill%5fself%5fdestr%2ehtm HTTP/1.1   
> 82923 2008-07-22 02:03:43.720123 192.168.1.254 192.168.15.4 DNS 202 Standard query response 0x0000 A www.willselfdestruct.com CNAME willselfdestruct.com A 69.25.94.22 NS ns21.domaincontrol.com NS ns22.domaincontrol.com A 64.202.165.178 A 208.109.255.11  
> 82936 2008-07-22 02:03:43.825871 192.168.15.4 69.25.94.22 HTTP 596 GET /secure/submit HTTP/1.1   
> 82998 2008-07-22 02:03:44.210946 69.25.94.22 192.168.15.4 HTTP 75 HTTP/1.1 200 OK  (text/html)  
> 90388 2008-07-22 02:09:59.003548 192.168.15.4 66.163.181.179 YMSG 106 HELO (status=Ok)     
> 90408 2008-07-22 02:09:59.085870 192.168.15.4 66.163.181.179 YMSG 279 User Login2 (status=Ok)   

<br>

> �����.O\`EU��@8~ѿ\]3��P�����J؀�&�Z  
> 9t�I7�-�HTTP/1.0 200 OK  
> Date: Tue, 22 Jul 2008 06:10:23 GMT  
> P3P: policyref="[http://p3p.yahoo.com/w3c/p3p.xml](http://p3p.yahoo.com/w3c/p3p.xml)", CP="CAO DSP COR CUR ADM DEV TAI PSA PSD IVAi IVDi CONi TELo OTPi OUR DELi SAMi OTRi UNRi PUBi IND PHY ONL UNI PUR FIN COM NAV INT DEM CNT STA POL HEA PRE GOV"  
> Cache-Control: private,no-cache,no-store,must-revalidate,max-age=0,post-check=0,pre-check=0  
> Pragma: no-cache  
> Expires: Thu, 01 Jan 1970 00:00:00 GMT  
> Content-Length: 304  
> Connection: close  
> Content-Type: text/xml; charset=utf-8  
> <br>
> <?xml version="1.0" encoding="utf-8"?><ab k="amy789smith" fv="1.0" rs="OK" rt="1216707023" lm="1213112025" lr="1173929659" cc="1" gc="0" cy="0" at="1" sf="last\_name"><ct e0="avabook3&#64;gmail&#46;com" fn="Ava" ln="Book" yi="Ava Book" id="1" cr="1213112025" mt="1213112025" pr="0" a="1" as="0"></ct></ab>�rs�

<br>

> Yahoo YMSG Messenger Protocol (User Login2)  
>     Version: 15  
>     Vendor ID: 0  
>     Packet Length: 189  
>     Command: User Login2 (84)  
>     Status: Ok (0)  
>     Session ID: 0x00000000  
>     Content \[…\]: 30c080616d79373839736d697468c08036c0804f3d46423b583d34323b4e3d6d663b513d44303b4e3d61613b463d38653b703d61413b453d69382c4a3d63302c4e3d46383bc0803936c080423d366f2c4a3d37442c543d37352c4f3d30663b543d32653b483d64703b513d63302c4e3d  
>         Username: amy789smith  
>         Password: O=FB;X=42;N=mf;Q=D0;N=aa;F=8e;p=aA;E=i8,J=c0,N=F8;  
>         OldPassword: B=6o,J=7D,T=75,O=0f;T=2e;H=dp;Q=c0,N=Ce;I=hB,Y=6A,  
>         CurrentId: amy789smith  
>         CapabilityMatrix: 2097087  
>         Version: 8.1.0.421  
>         IconChecksum: 507095874  

<br>
<br>
**Findings**

The student first looked up anonymous email services in a search and then proceeded to willselfdestruct\[.\]com to send the email. There was no identifying information in the TCP conversation with this domain; however, the IP address could be narrowed to one device for further review. To identify the student, the packets were reviewed and several identifying packets were marked as containing the Amy789Smith username - one yahoo login TCP conversation and several other yahoo messenger logins and YMSG packets. The MAC address of the device is the same across these packets and shows the student first send the email to her professor at 2:03 and then logged into her personal email at 2:09 on the same device. Based on this activity, the user who sent the threatening email is Amy789Smith matching Amy Smith from the class registration list. 

<br>

**What I’d do in a real environment**

In a real environment, this would be the general flow of how I would go about reviewing the file. The search did not take long following several different filtering steps and enough information was given from the headers as to the origin of the email, so that part was quick to narrow down to a specific IP and then follow on from there. I would continue to search like I did here to validate the user as much as possible through other logins, the device identifier, and anything else available to ensure the conclusion is correct that it was Amy Smith who sent the email and not one of her roommates.
