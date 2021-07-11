---
layout: post
title: HTB Blocky
modified: 2021-06-08
categories: [Hack The Box]
---

<style>
img {
  width: 93%;
  height: 93%;
}
</style>

# HackTheBox | Blocky

## Initical TCP Nmap Scan

```lua
sC -sV -oA nmap/initial-tcp-blocky -v 10.10.10.37
Nmap scan report for 10.10.10.37
Host is up (0.13s latency).
Not shown: 996 filtered ports
PORT     STATE  SERVICE VERSION
21/tcp   open   ftp     ProFTPD 1.3.5a
22/tcp   open   ssh     OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp   open   http    Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
| http-methods: 
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp closed sophos
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
```

## Full TCP Nmap Scan

```lua
Nmap scan report for 10.10.10.37
Host is up (0.078s latency).
Not shown: 65530 filtered ports
PORT      STATE  SERVICE   VERSION
21/tcp    open   ftp       ProFTPD 1.3.5a
22/tcp    open   ssh       OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 d6:2b:99:b4:d5:e7:53:ce:2b:fc:b5:d7:9d:79:fb:a2 (RSA)
|   256 5d:7f:38:95:70:c9:be:ac:67:a0:1e:86:e7:97:84:03 (ECDSA)
|_  256 09:d5:c2:04:95:1a:90:ef:87:56:25:97:df:83:70:67 (ED25519)
80/tcp    open   http      Apache httpd 2.4.18 ((Ubuntu))
|_http-generator: WordPress 4.8
|_http-server-header: Apache/2.4.18 (Ubuntu)
|_http-title: BlockyCraft &#8211; Under Construction!
8192/tcp  closed sophos
25565/tcp open   minecraft Minecraft 1.11.2 (Protocol: 127, Message: A Minecraft Server, Users: 0/20)
Service Info: OSs: Unix, Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 120.40 seconds
                                              
```

## Initial Thoughts Based On Nmap Scans

Looking at the scans, there is nothing too interesting just observing the ports. Similar to my other blogs, `ports 21 and 22` are both ports where you typically need credentials of some sort. At the least a username so you could attempt to bruteforce the account. Since there is no indications about a username just based off the scan as well as no anonymous FTP being enabled, the only reasonable port to start at seems to be `port 80` which is `HTTP`. Looking at the `http-server-header` we can see that it is running `Apache/2.4.18 (Ubuntu)` so we have an idea of what this server is as well as a service version of Apache. On top of this, we also see the `http-title` which says `BlockyCraft &#8211; Under Construction!` Seeing that this is apparently "Under Construction" there are hopefully some misconfigurations laying around. Besides http, there is also a closed `8192` and there is also a Minecraft server running on `port 25565` which is pretty funny as it fits the name of the box well. Now that the initial thoughts are out of the way, let's get to enumerating.

## 80 - HTTP | Enumeration

Visiting the website we see the following:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606183037411.png" />
</p>

There are some posts here welcoming us to Blockycraft. 

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606183158640.png" />
</p>

Clicking on it we can see that this post was created by the user "Notch". Whenever we see any posts or usernames whether it was found on a web page, forum, FTP share, etc. always note down usernames. It can be super helpful in the future if we find a password somewhere and we could perform a password spray from the usernames we found. 

Before we dive in deeper doing some manual enumeration, I'm going to run a `gobuster` against this website. `gobuster` is a tool that performs a directory bruteforce so we can identify more directories and possibly find more information by enumerating through them. 

```
gobuster dir -u http://10.10.10.37/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -x .php
```
- `-u` specifies the target URL or Domain
- `-w` specifies the wordlist we want to use followed by the path to the wordlist
- `-x` searches for file extensions (dir mode only)

I utilized the `-x` flag to search for `.php` files since this is running Wordpress and it uses `PHP`. 

```
===============================================================
Gobuster v3.1.0
by OJ Reeves (@TheColonial) & Christian Mehlmauer (@firefart)
===============================================================
[+] Url:                     http://10.10.10.37/
[+] Method:                  GET
[+] Threads:                 10
[+] Wordlist:                /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
[+] Negative Status codes:   404
[+] User Agent:              gobuster/3.1.0
[+] Extensions:              php
[+] Timeout:                 10s
===============================================================
/index.php            (Status: 301) [Size: 0] [--> http://10.10.10.37/]
/wiki                 (Status: 301) [Size: 309] [--> http://10.10.10.37/wiki/]
/wp-content           (Status: 301) [Size: 315] [--> http://10.10.10.37/wp-content/]
/wp-login.php         (Status: 200) [Size: 2402]                                    
/plugins              (Status: 301) [Size: 312] [--> http://10.10.10.37/plugins/]   
/wp-includes          (Status: 301) [Size: 316] [--> http://10.10.10.37/wp-includes/]
/javascript           (Status: 301) [Size: 315] [--> http://10.10.10.37/javascript/] 
/wp-trackback.php     (Status: 200) [Size: 135]                                      
/wp-admin             (Status: 301) [Size: 313] [--> http://10.10.10.37/wp-admin/]   
/phpmyadmin           (Status: 301) [Size: 315] [--> http://10.10.10.37/phpmyadmin/] 
/xmlrpc.php           (Status: 405) [Size: 42]                                       
/wp-signup.php        (Status: 302) [Size: 0] [--> http://10.10.10.37/wp-login.php?action=register]

```

Looking at the results we see a good amount of directories we can look into. I searched through a handful of them and did not find anything interesting. The ones that definitely were interesting to me were the `phpmyadmin` directory and the `plugins` directory. 

Navigating to `10.10.10.37/phpmyadmin/` we see the following:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606185730998.png" />
</p>


So we do indeed have `phpMyAdmin` running. If you are unaware of what `phpMyAdmin` is, it is a free and open source administration tool for MySQL and MariaDB. Since this web server is running under Ubuntu, this most likely has a `LAMP` stack. `LAMP` is an acronym that stands for `Linux, Apache, MySQL/MariaDB, PHP`. All of these together help run the Wordpress web server that is running on this host. So `phpMyAdmin` makes a lot of sense to have implemented as an administrator since you can administer your databases with ease with `phpMyAdmin`. Also knowing that `phpMyAdmin` is used to administer databases, this is also a gold mine for an adversary. Since we are trying to hack into this host, this will definitely be something we should keep in the back of our mind for later if we find valid credentials somewhere.

Viewing the `plugins` directory by navigating to `10.10.10.37/plugins/` we are presented with the following:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606190141920.png" />
</p>

We are presented with two `.jar` files. I'm going to go ahead and download them and observe on my own host. If you unaware of what a `.jar` file is, it is a "Java ARchive". These are used to aggregate Java class files and associated metadata, resources, etc. into one file so it is easier to distribute. To analyze what is inside the `.jar` file, we can simply `unzip` the file using the command `unzip` and then we can also use `JD-GUI` which is a standalone graphical utility that displays Java source codes of `.class` files. 

```
unzip Blockycore.jar
```

```
Archive:  BlockyCore.jar
  inflating: META-INF/MANIFEST.MF    
  inflating: com/myfirstplugin/BlockyCore.class  
```

So now I get some directories and files I can look into: `com` and `META-INF`

```
┌──(root@kali)-[~/htb/blocky/BlockyCore]
└─# ls                                                                                                                                             
BlockyCore.jar  com  META-INF
```

Looking into the `com` directory, there is another directory named `myfirstplugin`, within the `myfirstplugin` directory is a `.class` file named `BlockyCore.class`. We are going to use `jd-gui` to observe what is in this `.class` file.

```
jd-gui
```

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606191100318.png" />
</p>

On the top right just hit `File` --> `Open File`, and then navigate to where your `BlockyCore.class` file is. 

Opening up the file we see the following:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606191144693.png" />
</p>

Instantly we see that is a `sqlUser` and `sqlPass` string variable. Noting these down and looking into the other `.jar` file, there wasn't anything particularly interesting that I saw. Seeing that I ran into a roadblock after looking around for about 15-30 minutes, I decided to take a step back and try to use what I have so far. So far we see that there is an exposed `phpMyAdmin` and we also have possible credentials. Let's go ahead and see if we can try these creds against `phpMyAdmin`.

Using the credentials `root:8YsqfCTnvxAUeduzjNSXe22` I was able to access `phpMyAdmin`. 

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606191741110.png" />
</p>

The first thing I wanted to look into was either the `wordpress` database or the `mysql` database to see if I can find any hashed passwords and see if I could crack them. I was able to find one under `wordpress --> wp_users` with the user `Notch`. I attempted to crack the password with `hashcat` which is a tool used to crack hashes given a hash and a wordlist but after awhile it seemed that the `rockyou.txt` wordlist was not going to crack this password.

<p align="center">
  <img src="{{ site.github.url }}/images/htb/blocky/image-20210606191620699.png" />
</p>

Again I hit another roadblock for about 30 minutes or so. I think back to what I have again and what I haven't tried. I jumped straight into `phpMyAdmin` to see if the hardcoded credentials I found worked for `phpMyAdmin` and it did but I haven't tried it everywhere. I remembered that `SSH` was open so maybe I can remote into the host we are attacking with credentials like `root:8YsqfCTnvxAUeduzjNSXe22` or `notch:8YsqfCTnvxAUeduzjNSXe22`. I tried `root:8YsqfCTnvxAUeduzjNSXe22` and... nothing. I then also tried `notch:8YsqfCTnvxAUeduzjNSXe22` and... it worked!

```
──(root@kali)-[~]
└─# ssh notch@10.10.10.37                                                                                                                                                                                                               130 ⨯
notch@10.10.10.37's password: 
Welcome to Ubuntu 16.04.2 LTS (GNU/Linux 4.4.0-62-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

7 packages can be updated.
7 updates are security updates.


Last login: Sun Jun  6 21:23:48 2021 from 10.10.14.36
notch@Blocky:~$ 
```

Something I always do whenever I get on a box is try to run `sudo -l`. `sudo -l` will list the allowed (and forbidden) commands for the invoking user (the user we compromised). Executing this command shows this output: 

```
notch@Blocky:~$ sudo -l
Matching Defaults entries for notch on Blocky:
    env_reset, mail_badpass, secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User notch may run the following commands on Blocky:
    (ALL : ALL) ALL
```

When we see this `(ALL : ALL) ALL`, this means that the user `notch` can run any command as sudo. So this will just be as simple as running `sudo su` and we'll get root.

```
notch@Blocky:~$ sudo su
root@Blocky:/home/notch# id && whoami
uid=0(root) gid=0(root) groups=0(root)
root
```

And that's it for this box!
