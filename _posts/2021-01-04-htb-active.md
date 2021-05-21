---
layout: post
title: HTB Active
modified: 2021-01-04
tags: [LDAP, TGT, TGS]
categories: [HTB]
toc: true
---

- TOC
{:toc}

<style>
img {
  width: 80%;
  height: 80%;
}
</style>

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/feature.jpg" />
</p>

nmap scan:

135-449 Enumeration

```bash
smbmap -H 10.10.10.100
```

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 1.png" />
</p>

Using a null session, able to read the Replication share

Trying to recursively see what is in Replication using `smbmap -R Replication -H 10.10.10.100` doesn't give me so much luck, so I use the following command:

```bash
smbclient //10.10.10.100/Replication -c 'recurse;ls'
```

Recursively looking through Replication, a Groups.xml file is found under this path:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 2.png" />
</p>

`Groups.xml` has to relate with Group Policy Preferences ("GPP"). GPP allowed admins to create domain policies with embedded credentials. GPP on paper is very useful for admins to embed credentials to do tasks such as mapping drives, creating local users, scheduling tasks, etc. But the question that comes into mind is: how are these embedded credentials protected? When a GPP is created, there is a correlating xml file that contains the configuration data as well as a password if it is provided. If there was a password provided, it would be encrypted using an Advanced Encryption Standard key ("AES")-256 bit. This encryption should be enough security, except that Microsoft published the AES private key on MSDN which would allow one to decrypt the password.

Downloading the file for further inspection:

```bash
sudo smbclient //10.10.10.100/Replication
```

```bash
cd \active.htb\Policies\{3.....}\MACHINE\Preferences\Groups
```

```bash
get Groups.xml
```

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 3.png" />
</p>

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 4.png" />
</p>

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 5.png" />
</p>

Using `gpp-decrypt` the "cpassword" can be decrypted:

```bash
gpp-decrypt <password>
```
<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 6.png" />
</p>

So the password is: GPPstillStandingStrong2k18

Using `crackmapexec` since we have valid credentials, lets see what this account has access to in terms of SMB shares:

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 7.png" />
</p>

By default, `NETLOGON` and `SYSVOL` are pretty typical in a Domain Controller, so investigating the Users share seems more urgent than the rest.

Going into the Users share, the share that is here is essentially just the users share within the Domain Controller. 

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 8.png" />
</p>

Trying to look into the Administrator directory we get an access denied. So going into SVC_TGS was my next option. There was not much here besides the user.txt file.

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 9.png" />
</p>

I decided that looking for an approach to escalate my privileges now to get system level privileges would probably be the next best choice. Interestingly enough, the username SVC_TGS seemed a bit interesting. When on a Window box and seeing TGT or TGS, Kerberoasting always comes into mind.

User accounts set in the domain that is set to run a service under Kerberos needs to have values under the `servicePrincipleName` ("SPN") attribute within the domain controller for Kerberos to properly respond to authentication requests. On top of this, it is not uncommon for services to be set to run as a user account from Active Directory. 

So firstly, running `GetUserSPNs` is essentially just running a Lightweight Directory Access Protocol ("LDAP") search to find any users accounts that has an SPN. This can be ran as long as we have valid user credentials. 

But once we use the -request option with [getuserspns.py](http://getuserspns.py), there is a bit that is going on behind the scenes. Firstly, we are logging on with are legitimate user credentials and by successfully authenticating we are getting a ticket-granting ticket ("TGT"), which basically proves we are who we say we are. So since we are logging in as SVC_TGS, the TGT is basically there to prove that we are SVC_TGS by providing valid credentials. After getting the TGT we can request a ticket for a service which is essentially a ticket-granting service ("TGS").  Now when we request a TGS, one might assume that the Kerberos service, or Domain Controller in this case would do some sort of check to see if this account is allowed to access a particular service, but it does not. So basically it just hands a TGS to us after getting a TGT which can be used to access a particular service. Then from there, the service can decide if this account is a member of particular groups, has a particular user id, etc. Essentially the service can decide if this account is allowed in or not and can deny access. Once the TGS is sent to the particular service, a TGS is returned which has an encrypted password to it which can be cracked. With the encrypted password, we can extract local tickets and save them to disk using things such as Mimikatz or the GetUserSPNs.py with the request option presents the encrypted password as well. Once the password is extracted, simply cracking the passwords using a password cracking tool such as hashcat will crack the password for a given SPN. 

```python
python3 GetUserSPNs.py -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18
```
<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 10.png" />
</p>

We can see above the SPN is an Administrator, so we can grab the Administrator encrypted password.

```python
python3 GetUserSPNs.py -request -dc-ip 10.10.10.100 active.htb/SVC_TGS:GPPstillStandingStrong2k18
```
<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 11.png" />
</p>

Now that we have the encrypted password all we have to do is paste that file into a text file which I named hash.txt and run hashcat against it. Hashcat requires a "hash mode" which correlates to a particular hash. We are working with Kerberos 5 TGS-REP etype 23 so searching for it on [https://hashcat.net/wiki/doku.php?id=example_hashes](https://hashcat.net/wiki/doku.php?id=example_hashes) shows that the hash mode is 13100. The hash modes are also available if you use the —help argument with hashcat

```python
hashcat --help
```

```python
hashcat -m 13100 hash.txt -a 0 /usr/share/wordlists/rockyou.txt --force
```
<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 12.png" />
</p>

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 13.png" />
</p>

Looking at the very end of the encrypted password shows the cracked password being "Ticketmaster1968". This is the cracked password for the Administrator account.

Since we now have Administrator credentials, throwing these into `psexec.py` will bring back a shell as system. psexec is a part of Windows' sysinternals which is there to act as a light-weight telnet-replacement to execute processes on other systems with full interactivity. But using psexec as a python script allows pentesters and ethical hackers to incorporate psexec functionality in their own code.

```python
python3 psexec.py active.htb/Administrator@10.10.10.100
```

<p align="center">
  <img src="{{ site.github.url }}/images/htb/active/Untitled 14.png" />
</p>
