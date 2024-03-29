---
layout: post
title: Red Teaming at WRCCDC 2023
modified: 2023-04-10
categories: [Red Team]
---

<style>
img {
  width: 90%;
  height: 70%;
}
</style>

# Red Teaming at WRCCDC 2023

<div style="position: absolute;">
  
</div>

* TOC
{:toc}

<div id="toc-skipped"></div>



<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409152201.png" />

</div>

From March 31st to April 1st 2023 was the Western Regional Collegiate Cyber Defense Competition's regional competition. If you are new to the Collegiate Cyber Defense Competition scene, essentially this is a competition for college students to focus on the operational aspects of protecting and managing existing network infrastructure against an active Red Team. Competitors are overall scored on their ability to keep critical business services (CMS, Databases, Web Services, DNS, etc.) up and complete administrative tasks. Whichever team is able to do these set of tasks the best while defending themselves against Red Team ends up as the winner. 

&nbsp;

To also preface the rest of the blog, I competed at WRCCDC as a Blue Teamer representing Cal Poly Pomona in 2019-2021 as a Linux main. After my time at WRCCDC and seeing the enormous amount of benefits I got from being a competitor, I wanted to give back by volunteering my time as a Red Teamer for WRCCDC. As there is not a huge amount of time for red team to discuss their experience during the debrief, I wanted to write this blog to discuss what I found in the environment, common mistakes I saw across teams, and my overall thoughts on how to better protect yourself against Red Team.
# Preparation


<div style="text-align: center; display: flex; justify-content: center; align-items: center;">


  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408160935.png" />

</div>

Similar to Blue Teamers doing preparation work for their upcoming CCDC competitions with new scripts, tools, etc. to automate tasks and defend themselves quicker, Red Team is also building out tools to not only get onto Blue Teamers' host quicker, but also to make it more difficult to find anomalous activity. I won't be going in too much detail as to what these tools do exactly, but I will discuss good ways in general to improve your prevention and incident response procedures to yield greater results in finding threats in your environment and remediating them. During my preparation, I was mostly in charge of working on Aggressor Scripts for Cobalt Strike. If you are not aware of what Cobalt Strike is, it is a commercial Command and Control application made for Penetration Testers and Red Teamers. Aggressor Script is a scripting language that is built into Cobalt Strike which allows for extensibility in Cobalt Strike. Some things Aggressor Scripts can do is run a task when a new beacon session appears on a Cobalt Strike server, run multiple tasks at once on a single or multiple beacons, etc. You may quickly realize the important of Aggressor Scripts from a Red Team prospective considering how much we need to be able to scale out. If there are 5 Windows hosts and 10 teams competing, and we hypothetically get a beacon on every single Windows host on every team, we'd have 50 active beacons. Being stuck running commands on every single beacon one by one would take a painful amount of time. If Red Team approaches beacons in a manual approach, we are going on each beacon one by one running commands and is highly likely that a team will catch on and kill our beacons which is not optimal for Red Team. So Aggressor Scripts come to our rescue by allowing us to run tasks / commands on multiple beacons. Not only does this help ensure that we can run the same commands / tasks on all teams, but it ensures that each team is affected evenly. Some things you could imagine these Aggressor Scripts could do is persistence mechanisms, malware droppers, take down services, etc. 

&nbsp;

Another thing I helped with that yielded good results but was simple to make was a way to do the same thing but with another C2 using API calls, Python libraries, etc. Since Cobalt Strike is essentially used only for Windows (what I usually main when I Red Team), I also wanted to help out the team who was mostly focused on the Linux side of things. To help, I basically made a 50-80 line Python script to connect to a C2 server (such as Mythic, Sliver, etc.) and be able to run commands on each session/beacon simultaneously to mimic how Aggressor Scripts were operating on Cobalt Strike.

&nbsp;

Note that this was just one of the many tools made by the WRCCDC Red Team and we will have more ready in the future for the next CCDC season :). I just happen to choose this as I worked on this topic the most.
# Morning of the 1st Day of Regionals

<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408162612.png" />

</div>

The morning of regionals I got up around 6 AM to make sure I got some breakfast and caffeine in my bloodstream. However, I was pretty slumped since I went to bed around 4-5 AM that night doing prep work and catching up with my good friends [NoSecurity](https://nosecurity.blog/) and `tato`. I wasn't going to let my lack of sleep stop me from performing well though. We got to Coastline College where the event was being held and started getting ready for the storm that was about to come at 9AM. We all wired into the network and got ready for the clock to hit 9AM. At 9AM it was go time. As you may expect, the first thing we need to do as Red Teamers just like the Blue Teamers have to is get an idea of what the hell they are dealing with. This would usually be done with an `nmap` scan on your given subnet(s) and try to identify what hosts are hosting important services, etc. However, I'd implore Blue Teamers to look into other tools to help with their initial reconnaissance phase and understanding of their network. At least at WRCCDC, there is a TON of web applications to deal with. It's extremely beneficial to use tools such as [Aquatone](https://github.com/michenriksen/aquatone) which is a Domain Flyover tool and helps you identify HTTP-based attack surfaces. It is able to take screenshots of HTTP-based services to give you an idea of what is being hosted on there. Essentially Red Team will be running scans to get the best idea of what is running on the environment and begin to look deeper into what is vulnerable and what is not. This is essentially done with a conglomeration of tools such as Nessus, nmap, Aquatone, and some custom tools developed to make the process of identifying vulnerable hosts easier on the Red Team side of things. But again, I'd highly suggest Blue Teamers also take the same approach that Red Team does when they are initially understanding their network as you will be able to see the exact same holes in your environment as Red Team does. 
## Default Credentials
As a Red Teamer, we would be looking for things like a login portal to try default credentials after we've done some initial reconnaissance and found some enticing services to get onto via default credentials first. You might be wondering where do we find default credentials? There's multiple ways we can get default credentials. Whether it's running Mimikatz on Windows and the host having WDigest enabled by default to show plaintext credentials or finding an endpoint that is hosting a file with passwords on it like the screenshot below.


<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

 

 <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408211041.png" />

</div>

Once we have these default credentials, using the output of Aquatone and trying the usernames and passwords we found we can start finding great success and gaining access to your web applications and backdooring them in various ways. Some of these applications we found were tied in with pretty critical infrastructure such as their Cisco Firepower and gave Red Team a way to cause havoc on day 2 by. turning off their network interface.

 
<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

 <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408173139.png" />

</div>

Aside from web applications, there's also your classic ways to get onto a host whether that's RDP, SSH, WinRM, MySQL, Postgres, etc. that have the same default creds with the user being `root`, `admin`, `Administrator`, etc. 

<div style="text-align: center; display: flex; justify-content: center; align-items: center;">  

<img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408211213.png" />

</div>

## Exploits and Misconfigurations
It is extremely common that applications and services that are running in Blue Teams' environment are crawling with exploits and misconfigurations for Red Teamers to abuse. These can range from applications and services simply being extremely outdated and having a lot of potential exploits to choose from due to nature of it being so old, host misconfigurations (i.e. log in as root with no credentials), etc. Some common ones you might see on the Windows side of things are things like EternalBlue, ZeroLogon, BlueKeep, etc. 


<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408224058.png" />

</div>

or me personally, I would use common Windows exploits like the ones I mentioned to get initial access onto the host and begin enumerating around the host for PII or anything of interest to me. Something nice about Cobalt Strike is the ability to run exploits from `msfconsole` and have the sessions go into Cobalt Strike directly as beacons compared to gaining a ton of meterpreter sessions. If you'd like to read more about how that works, I'd highly suggest you go check out a blog post by the creator of Cobalt Strike Raphael Mudge's blog post about [Interoperability with the Metasploit Framework](https://www.cobaltstrike.com/blog/interoperability-with-the-metasploit-framework/).
<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408222159.png" />

</div>

After gaining an initial beacon, I'd usually go and dump creds using CobaltStrike's built in mimikatz functionality so I can pass the hash onto other hosts as well since if we got access to the domain controller, we essentially had access to anything else connected to it.


<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408223538.png" />

</div>

Something Blue Teamers might wonder (especially with an environment as huge as WRCCDC puts out every year. shoutout to everyone who made WRCCDC possible) is how the hell do you defend yourself against Red Team with so many services that are exploitable and misconfigured due to a ton of hosts to manage and a ton of ports open on them. I'll go over some advice I'd give to Blue Teamers about that later on in the blog.


<div style="text-align: center; display: flex; justify-content: center; align-items: center;"> 

<img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408213236.png" />

</div>

## Persistence
After we get initial access to hosts, our next step is to stay on the host. Typically when people think of persistence, they think of your extremely common TTPs that adversaries use. These can be things such as Registry Run Keys, Scheduled Tasks, Malicious Services, Startup Folder Persistence, Cron Jobs, adding SSH public keys to `known_keys`, etc. However since these are extremely common and Red Team knows Blue Teamers know this, we will typically try some intricate ways of doing persistence to ensure it's a bit harder to find things. I'd highly suggest people look into security research posts about persistence mechanisms and look at the interesting ways threat actors have found ways to gain persistence in a way which is difficult for even seasoned incident responders to identify. Although we typically will go the route of trying to do persistence mechanisms that are hard to identify, that doesn't mean you might find artifacts laying around where we stick things in Registry Run Keys and common areas to do persistence. Knowing that, I would suggest looking into Sysinternal tools such as [AutoRuns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns), [ProcessExplorer](https://learn.microsoft.com/en-us/sysinternals/downloads/process-explorer), etc. to easily find low hanging persistence mechanisms Red Teamers might have left. Aside from that, even simple things like security through obscurity can work in our favor. A lot of C2 frameworks like to name their executables something like `beacon.exe` or `artifact.exe` which if ran on the target host as a process would be pretty easy to kill off. If we're lazy and don't want to do something like remote process injection, we can just name it something like `svchost.exe` or something of that nature and hope no one realizes that it isn't really `svchost.exe`. I would also highly suggest that when people find persistence mechanisms and you have a log source to rely on to go backwards from the persistence mechanisms being executed and finding the origin of it all. This will lead to good intel on possible Red Team IPs, how they executed the payload, etc. I'll go a bit more into some advice on stuff like that near the end of the blog.
## IoT Devices

<div style="text-align: center; display: flex; justify-content: center; align-items: center;">

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408185212.png" />

</div>

Something that I was looking forward to a ton this year was IoT devices. When I was competing at WRCCDC as a Blue Teamer, I had the unfortunate case of only being able to compete remotely due to COVID. I was really looking forward to competing in person due to how WRCCDC usually puts IoT devices in scope for Blue and Red Teamers to deal with. However, I was fortunate enough to get the chance to mess with some IoT devices as a Red Teamer this time around which honestly made Red Teaming at WRCCDC so fun. On their `10.200.2xx.15` host was AMCREST cameras with default credentials. For the first day or so most teams didn't even realize this was a thing. We were able to see every team's camera and had the ability to rotate 360 degrees which was perfect since some teams were writing great stuff for us to look at on their whiteboards.


<div style="text-align: center; display: flex; justify-content: center; align-items: center;">  

<img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409232837.png" />

</div>

Something on the Red Team side of things that sucked is that we weren't really able to communicate with the teams effectively to show that we're there and to say hi to them. `wall`ing on Linux and using `msg *`  on Windows to talk to teams just ended up getting our beacons killed. However, after looking around the environment some more, [NoSecurity](https://nosecurity.blog/) noticed that there was an endpoint that had some sort of printer debugging interface being hosted on port 80. There was a button to print out some debug info and we wanted to see if it actually printed out something. We picked a team, watched their camera, hit the button, and all of a sudden started to hear a printer going off. It actually started to print out crap to them. We had no idea what was on it but we started looking to see if we can do some sort of command injection or LFI on it since the debug button was calling to a file that was printing info. No luck. While we were trying to find some sort of way to get it to print out arbitrary files, text, commands, etc. [wasabi](https://twitter.com/spiceywasabi) came to the rescue and hinted to a Python library that could help us interact with a port on that host to print out text on the receipt. I went ahead and opened up `vim` and created a quick little script to get custom text onto the receipt. We followed the same process again by running the script and praying that we hear the printer go off. We hear it go and off notice the receipt was a lot smaller since I initially just tried typing in "hi" on the receipt. I decided to try something that would verify my curiosity of what I'm writing on my script is actually being written onto the receipt by sending a team some of their hashes I had from their domain controller.


<div style="text-align: center; display: flex; justify-content: center; align-items: center;"> 

 <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408232814.png" />

</div>

Seeing how huge the receipt was this was for sure the hashes. One of the competitors actually showed what the receipt looked like after the competition which was pretty funny.


<div style="text-align: center; display: flex; justify-content: center; align-items: center;"> 

 <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230408231530.png" />

</div>

Knowing that we had some sort of way to talk to the teams where they for sure would not be able to ignore the sound of the printer printing out a receipt and the curiosity of what was on it, we decided to have a lot of fun with it. Seeing teams' reactions to stuff we had on their hosts be printed out to them and just having some laughs with some teams feeding us food when we said we were hungry made us laugh and was greatly appreciated. <3


<div style="text-align: center; display: flex; justify-content: center; align-items: center;"> 

 <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409152246.png" />

</div>

# Day Two of Regionals: Melt Down
Closing out the first day of regionals left Red Team having access to tons of hosts across the board. Persistence was implemented to ensure we could stay on the host the next day and start to begin the terror that is day two of regionals. Day one of regionals is all about just gaining initial access, persistence, and messing with Blue Teams' hosts ever so slightly in a way where it disrupts the teams flow and gives a sense of urgency as to why their service is down. 
## Taking Down Services
Day two is all about finding as many ways as possible to show Red Team impact on the Blue Team. This can be done by deliberately searching for PII to report on, taking down of services in a way where it is no easily recoverable without backups, defacement of web services, etc. 

<div style="text-align: center; display: flex; justify-content: center; align-items: center;">  

<img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409170210.png" />

</div>

Aside from defacing websites, a really great way to show impact was the fact that a ton of services were getting scored through domain name resolution. I found during day 1 that the `.99` box called `BLUE-CHEESE` was the domain controller acting as the DNS server. If I am able to kill their DNS, hypothetically a ton of services would all go down at once until they figured out that their DNS was dead and was the reason for all their services being down. I ensured I maintained access to this DC throughout most of the competition on majority of the teams knowing how powerful it is to be able to kill Blue Teamers' DNS. Killing the DNS server turned the scoreboard from this:

<div style="text-align: center; display: flex; justify-content: center; align-items: center;">   

<img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409172223.png" />

</div>

To this:


<div style="text-align: center; display: flex; justify-content: center; align-items: center;"> 

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409172136.png" />

</div>


Day 1 I typically would just stop the service itself and watch the teams turn it back on which was a pretty easy win for the Blue Teamers. However, on day 2 I made it a bit more difficult. I'd highly suggest Blue Teamers look into service configurations and what you can do to them that would stop the service from properly functioning. This is something we do on the Red Team side of things through tradecraft found from Red Teaming at other competitions, labbing, etc. Aside from that, dropping databases, removing files that are being scored, etc. is what we continue to do until day 2 is over. 
## PII
Personally identifiable information is something we heavily target on day 2. The reason for this is exfiltrating PII is a huge deduction for Blue Teamers and it makes sense why that is the case. If you are working in a corporate environment in infosec and you have to relay to your CISO that PII was just exfilled out of the environment, it is not going to be a pretty story they will have to relay over to C-Suites. That being said, the repercussions of having PII being exfilled at CCDC has the same detrimental effect that it would in industry except in the form of points to win the competition. PII in CCDC environments can vary from competition to competition depending on the theme that they have. Since this WRCCDC theme was banking related, we expected to find things such as account numbers, transactions, the amount of money in someone's bank, etc. and we were able to find exactly that:


<div style="text-align: center; display: flex; justify-content: center; align-items: center;"> 

  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409173956.png" />

</div>

Similar to my suggestions previously about having an approach to reconnaissance like Red Team does, Blue Teamers should also be on the lookout for any PII that is easily accessible and try to find a way to isolate it off to ensure the data does not get exfilled. 
## Ransomware
There is one more aspect of day 2 that is interesting which is having ransomware be in scope. The ransom that teams would be paying out would be in terms of their points so that they would receive a point deduction to be supplied the key to decrypt their files.

<div style="text-align: center; display: flex; justify-content: center; align-items: center;"> 


  <img src="{{ site.github.url }}/images/red-team/ccdc-red-team/Pasted image 20230409161545.png" />

</div>


# Common Mistakes by Blue Teamers
After the regional competition was over and the award ceremony began Sunday morning, Red Team was able to get a little bit of a chance to present their findings and give suggestions. However, since the amount of time allocated was pretty short, I wanted to go and present some common mistakes I found from teams and talk about advice and steps forward to further improve Blue Teamers for the next upcoming CCDC season through this blog post. 
## Default Credentials
As someone who competed in CCDC, I understand how difficult it is to ensure every single password is changed from the default password. A lot of teams have already built out scripts for both Linux and Windows to go through all of the users and change their passwords. This is a good step forward in the right direction. However, something I have also realized that lots of teams are missing is that default credentials goes far beyond just SSHing or RDPing onto a Linux / Windows host with default credentials. Databases will have default credentials, web services will have default credentials, ioT devices will have default credentials, your physical and virtual firewalls will have default credentials, essentially assume anything will have default credentials. Understand what would be the most enticing for Red Teamers and try your best to change that as fast as possible. It is extremely common to see default credentials even up to the last 10 minutes on over half the teams at regionals.
## Firewalls
Firewalls need to be your best friends in CCDC. Especially if you have something like a Pfsense you are allowed to configure, I'd highly suggest Blue Teamers configure their firewalls as soon as possible. It can be hard to identify what ports need to be open on certain hosts, but if you are able to identify what needs to be open, you can simply deny everything else and limit your attack surface significantly. Something that I've heard other teams mention (even I had the same doubt while I was competing) is the fear of having services go down even for a little bit due to firewall rules. Something interesting about CCDC in general is the way everything is interconnected together. A host that might seem useless might actually be acting as a remote database to another host hosting web content. If that host with the DB goes down, then the other host hosting the web content has its service go down. There is a lot to map out for CCDC and firewalls can somewhat help you identify what is being connected and what isn't. If you're going and configuring firewall rules and disable a database port on a host and notice a web service goes down on another host, you can go and begin searching for any sort of interconnectivity happening from one host to another. Usually this can be found in config files pointing to another host, or even databases where you see users that are available on `0.0.0.0/0` is a good indicator that is might be reaching out to another host. By turning your firewalls on, seeing services temporarily going down and understanding why it went down due to your firewall rules, adjusting, and repeating that process will typically end in a fairly hardened external attack surface. You can apply this concept to both the network/host level for firewalls. Always remember the less ports that are open, the less room there is for Red Team to attack.
## Backups
After you identify your services and what needs to be firewalled off, you should also be looking for things to be backing up. If Red Team gets onto your host even after well implemented firewall rules, you need to ensure that if a service were to go down that you have a way of circumventing it. Red Teamers especially on day two might completely remove files that the scoring engine relies on to check that a Blue Teamers' service is properly functioning. Always ensure you have a backup somewhere and make sure the backup is stored somewhere **safely**. I've seen teams make backups in the same exact directory of where things are being scored in the service. I'd simply just delete both of them and now the team would be forced to go and do a box reset to get their service back up. Sometimes (usually for remote competitions) jump boxes will be provided to Blue Teamers to use to get into the environment. There has been times where we are actually allowed to copy files over from the environment over to the jump boxes. If you have hosts that you are explicitly told are not in scope for Red Team and you are able to go and copy files over to it, I would highly suggest you use that to your advantage and have your backups saved there.
## "Red Team Took Down Our Service!!!"
Being a part of Red Team, it is extremely common for Black Team to come into our call / room and ask if we took down "X" service on "Y" team. Almost always the answer is no. It is extremely common for Blue Teamers to take down their own services and think that it was Red Team activity. I've been in the exact same position where it seems like I did not do anything recently to the service and all of a sudden it goes down. Again, remember that almost everything in the environment is intertwined together on purpose. A good example I have when I was Blue Teaming at CCDC was our SSH service being down. We were looking at our logs and we were noticing failed login attempts to SSH from what looked like the scoring engine. We tried the credentials we had given Black Team from the password sheet and they were working. We were so confused on the Linux side as to why the service wasn't being scored. We got confirmation from the Black Team asking for a scoring check on the service and they said that it indeed is a problem on our end. After 30 minutes or so of looking at logs and wanting to rip out our hair, we realized that it probably is being scored from Domain Users since the box was joined to Active Directory. After we realized that we were able to fix the issue and get the service scored again. But this is just to reiterate the point that services going down is not all inherently Red Team. It might just be miscommunication (like it was for me) that causes a service to go down. Even someone changing a config file's database credentials could completely bork a service. For example, WordPress has a `wp-config.php` file which has variables that designate the IP address, database name, database user + password, etc. If someone changed the database user's password and did not update the config file, this would cause database connection errors and the service would stop being scored. Likewise, if you changed the config and did not change the database user's password, it also will throw database connection errors. All this to say please validate why your services are down before blaming Red Team. It'll not only hone your troubleshooting skills to ensure you are able to fix issues quicker and realize it is not Red Team, but it'll also save you deductions from Black Team if you decide to get consultation from them.
# General Advice
Aside from the common mistakes made from Blue Teamers, I also wanted to go and just give some general advice for people to up their game as Blue Teamers. To restate what was mentioned above, change ALL your passwords as soon as you can. Script out as much of it as you can and start scraping through anything with a login portal and start changing the credentials for those as soon as possible. Firewall off ports you don't need and keep the ones you do need. It's okay for your service to go down for a bit as you are configuring your firewalls. There's way too many services and interconnectivity so don't feel bad if something goes down temporarily. If anything this should just be an eye opener to Blue Teamers as the port you blocked off is mostly like critical for a service to stay up. Backups, backups, backups. Backup things that keep the service alive and store it somewhere safe if possible. If you can't, security through obscurity is your friend. A Red Teamer is more than likely going to delete something called `database-backup` compared to something called `systemd-private-backup-4dsa8dj3nmzn` even though that file name is just obscure. Lastly, make sure you hone in on troubleshooting skills. This is hands down one of the most valuable skills to have. As competitors in CCDC transitioning into the industry, being able to tackle on anything due to core troubleshooting skills will be extremely important, so let competitions be the perfect time to go and practice that skill before you get into industry. 

&nbsp;

One final thing I wanted to suggest to all Blue Teamers is to understand the process that Red Teamers go through. WRCCDC graciously supplies images from previous competitions for teams to download and deploy [here](https://archive.wrccdc.org/). Deploying these hosts and running through what a Red Teamer might do and thinking how would you prevent this is a great way to get a full understanding of everything. As I do Detection Engineering and IR at work, this is essentially what I'll be doing when I'm building out detection logic for attacker tradecraft. I might make a blog post in the future about detection engineering, but for now I'll give a quick overview of what I'd suggest Blue Teamers to do. Setup some sort of attacker VM whether it's Kali, Commando VM (my personal favorite), etc. and another VM that might be outdated such as WIndows Server 2012. What's a common exploit you can use against Windows Server 2012? EternalBlue. EB is a great exploit as it's basically point and click when it comes to how easy it is to exploit it. Before you start the attack, make sure you have some sort of log source. This can be Windows Event Log, Sysmon, etc. Once you got logs flowing now you can start your attack. Open up your attacker VM and run an attack against the Windows Server 2012 VM and get a shell on it. After you have ran through the whole attack, go back to your Windows Server 2012 and look through logs as to what happened. What exactly did this attack do? You'll start to see how everything unfolded when this exploit ran through logs which is beyond useful for Blue Teamers. The next thing to do is after you walk through what it was doing, think of preventative measures you could take to stop this exploit from working. Is there anything you can disable or block on the Windows Server that might prevent the attack? Is there a port that is open that might not need to be open? Is there a SMB share you might not need that can be removed and the attack won't work? How does it execute the payload? Is there a way to circumvent that so the payload doesn't go off? These are all questions you should be having while you try to identify preventative measures. After some time, you'll quickly realize that you can prevent this attack by doing some simple tricks and also have your service still being scored. On top of this, if for some reason a Red Teamer does the exploit in a different manner, you can most likely find interesting indicators of compromise and will be able to create an IR report off of the IOCs and get some points back. Something else I'd also suggest aside from just using logs is using [Sysinternals](https://learn.microsoft.com/en-us/sysinternals/) tools such as [ProcessMonitor](https://learn.microsoft.com/en-us/sysinternals/downloads/procmon). Some of these exploits might open up unusual binaries, write files to odd paths, etc. which ProcessMonitor will display and can be used to further understand how an attack is functioning. Essentially use these tools to your advantage to research and understand how Red Team tools and tradecraft works. When you understand how both sides of things function, you will quickly realize you are able to identify and remediate threats quicker than if you were to only have experience on the Blue Team side of things.

# Closing Remarks
If you got all the way to the end of this post, thank you for reading! I hope it was a bit insightful to see the Red Team aspect of things and my own thoughts on how people could better improve and prepare themselves for CCDC. Anyone going into CCDC is putting themselves in an amazing environment where you learn so much in a short amount of time. If you are looking to get into a CCDC team at your university or  are planning on making one, I highly suggest you do it as it was hands down one of the most impactful competitions  I participated in during my time in college. And for those already in a team reading this, I wish you all the best of luck if you are participating in nats or are preparing for the next season. Also wanted to give a huge shoutout to the WRCCDC Red Team! You all were amazing to work with and am excited to see what we got in store for the next CCDC season >:). If you have any general questions or comments, give me a follow on twitter [@bri5ee](https://twitter.com/bri5ee?lang=en) and I'd be happy to chat! Thanks for reading!
