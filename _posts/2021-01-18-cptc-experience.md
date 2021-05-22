---
layout: post
title: The Global CPTC Experience | Unraveling the Tragedy of Smallville
modified: 2021-01-18
categories: [CPTC]
toc: true
---

<style>
img {
  width: 80%;
  height: 80%;
}
</style>

# The Global CPTC Experience | Unraveling the Tragedy of Smallville

by [Alex Tselevich](https://nosecurity.blog/), Brice Lauer, [Silas Shen](https://svl.sh/)

&nbsp;


<div style="position: absolute;">
  
</div>

* TOC
{:toc}

<div id="toc-skipped"></div>
  
# Abstract:

This blog post's objective is to be used as a way to educate cybersecurity students that are interested in competing in the Collegiate Penetration Testing Competition about how we prepared as a team and what to expect from these competitions. This post can also be used as a starting guide for teams looking to become more competitive in their region. 

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/global.png" />
</p>

# Overview:

The [Collegiate Penetration Testing Competition](https://www.nationalcptc.org/) is a one of a kind cyber security competition that aims to train students to be future consultants through simulated business environments. Teams of up to 6 students will perform a penetration test against the provided fictitious business and document the findings in a [report](https://github.com/nationalcptc/report_examples). While other competitions like CTFs require competitors to locate a flag as its final goal, CPTC goes beyond and pushes for students to think from the perspective of a real threat actor. The competition organizers do an excellent job in making the infrastructure as realistic as possible, hiding confidential proprietary information and sensitive data for students to uncover.  This year's competition ran a little differently as COVID-19 pushed everything online and forced competitors to connect remotely and communicate via Zoom/Discord. While this was more of an inconvenience, we believe that this put us all in positions to practice working as a team and communicating effectively. The [regionals competition](https://cptc-west.stanford.edu/) started on Saturday at 8:30AM for testing and lasted until 5:30PM. After the testing phase, students are given until 1:00AM to write and submit a report detailing the vulnerabilities that were discovered within the environment. This year, there were 8 totals regions spanning across the United States, Canada, Europe, and the Middle East. The first place in each region automatically advances to the [National Finals](https://www.nationalcptc.org/) while the rest of the teams wait anxiously to find out whether or not they advance through wild cards. Wild cards are given to the top 7 schools across all regions, meaning that a particular region can send multiple teams to the finals. The Nationals schedule is similar to Regionals except teams are instead given two full days of testing and are required to turn in and present slides in addition to the written report. This year, the schools that placed in Nationals were Rochester Institute of Technology (1st), Stanford (2nd), and Cal Poly Pomona (3rd). Huge shoutout to all teams!

# How We Prepared

During the summer of 2020, the Cal Poly Pomona CPTC team began training students remotely who displayed an interest in penetration testing and competing amongst a team. The CPTC trainings consisted of numerous penetration testing resources which contained a high-level overview of what penetration testing entails, information on penetration testing frameworks and methodologies, threat intelligence, attack infrastructures, report writing, and more. As this blog is designed to help aid students who have an interest in CPTC, the main focus of preparation that will be discussed is the process of tryouts, information on penetration testing frameworks and methodologies and finally,  and how to practice them as a team. Topics such as planning and report writing are not discussed within this blog post as they are highly unique and should be discussed amongst your own team.

To preface, training for students at Cal Poly Pomona for CPTC began on July 11, 2020. These trainings took place every Saturday from 10:00 a.m. to 12:00 p.m. and would aid students who showed an interest in penetration testing by equipping them with knowledge that the team gauged would leave students with a well-rounded foundation in penetration testing. After a fair amount of training, students were able to tryout for the CPTC team that would be competing during the 2020-2021 academic year. The tryouts consisted of domain controllers, windows workstations, unix systems, etc. that all had their own paths to domain admin or root. Students would also be required to produce a penetration testing report as a part of the tryout process which would contain topics such as an executive summary, findings, etc.  After the tryouts, a handful of students would be selected to compete in Cal Poly Pomona's CPTC team. The finalized CPTC team would continue to practice every Saturday as a team as well as putting in the hours individually to practice during the week. The remainder of this section will be discussing what we did individually and as a team to train and prepare for CPTC.

Penetration testing frameworks and methodologies are used to define procedures to follow during a penetration test. It is important for students to understand that the general rule of thumb is not to reinvent the wheel for these frameworks and methodologies, but rather, to utilize the ones presented or utilize a few of these frameworks and create their own when performing penetration testing engagements. A few of these frameworks and methodologies are the following:

- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Cyber Kill Chain](https://www.lockheedmartin.com/en-us/capabilities/cyber/cyber-kill-chain.html)
- [Red Team: Adversarial Attack Simulation Exercises](https://abs.org.sg/docs/library/abs-red-team-adversarial-attack-simulation-exercises-guidelines-v1-06766a69f299c69658b7dff00006ed795.pdf)
- [Open Source Security Testing Methodology Manual - OSSTMM](https://www.isecom.org/research.html)
- [Threat Intelligence-Based Ethical Red Teaming TIBER-EU](https://www.ecb.europa.eu/pub/pdf/other/ecb.tiber_eu_framework.en.pdf)

With a framework decided, such as the Cyber Kill Chain, understanding what each stage of the Cyber Kill Chain is and what it consists of can aid in understanding what tools, strategies, and methodologies go into each particular stage. For example, during the reconnaissance stage of the Cyber Kill Chain, the goal is to discover and collect information about a particular target. Tools can be used to gather information regarding target validation ([WHOIS](https://linuxconfig.org/look-up-website-information-with-whois-in-linux), [nslookup ](https://linux.die.net/man/1/nslookup)[dnsrecon](https://tools.kali.org/information-gathering/dnsrecon)), finding subdomains ([dig](https://linuxize.com/post/how-to-use-dig-command-to-query-dns-in-linux/), [Nmap](https://nmap.org/), [Sublist3r](https://tools.kali.org/information-gathering/sublist3r)), and fingerprinting ([Nmap](https://nmap.org/), [NetCat](https://www.varonis.com/blog/netcat-commands/), [Wappalyzer](https://www.wappalyzer.com/)). 

With a good understanding of penetration testing methodologies and frameworks, putting them into practice is imperative. There are lots of resources the infosec community creates to allow aspiring penetration testers to practice and gain exposure to new information. A handful of these resources are:

- [VulnHub](https://www.vulnhub.com/)
- [HackTheBox](https://www.hackthebox.eu/)
- [TryHackMe](https://tryhackme.com/)

VulnHub, HackTheBox, and TryHackMe all contain material that allows penetration testers to gain hands-on experience by being able to test their skills, as well as being exposed to the feeling of having to research and learn a new topic on the spot in order to complete the CTF. All three of these resources have a wide range of difficulties which can go from easy to extremely difficult which can allow students from all different skill levels to be able to continue to learn and grow. A general tip our team would suggest is ensuring there is a methodical approach in mind when using these resources. For example, when teams are going through these vulnerable boxes there should be a fair amount of understanding on what the vulnerability is, why is it vulnerable, how an exploit is taking advantage of the vulnerability, and lastly how someone could fix the vulnerability to ensure their system is more secure. Going through this process, teams will begin to gain a better understanding of why vulnerabilities and exploits may exist and begin to develop a sense of pattern recognition that can lead teams to discover vulnerabilities quicker and have an understanding of how they may be exploited.

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/htb.png" />
</p>

The Cal Poly Pomona CPTC team also trained on material specifically applying to web application security. For this, the CPTC team utilized [PortSwigger's Web Security Academy](https://portswigger.net/web-security), which provides free online training on web application security with documentation and hands-on labs which contain topics such as SQL injection, Cross-site scripting (XSS), OAuth authentication, and much more. As CPTC attempts to replicate industry-like environments, having a good understanding of web application security is essential as there is a high likelihood of web applications being present in the CPTC environment as well as in the industry.

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/academy.png" />
</p>

Lastly, the Cal Poly Pomona CPTC team utilized [Snap Labs](https://www.snaplabs.io/) which would aid us in pentesting an environment similar to CPTC's. Snap Labs provides advanced simulated networks which contain simulated users, network sizes, vulnerabilities and escalation paths, industry theming, Windows Active Directory, and more. With Snap Labs replicating industry-like environments, it allowed the Cal Poly Pomona CPTC team to better understand the methodology that goes into attacking an industry-like environment which differs greatly from pentesting individual systems. Snap Labs allows for escalation paths to observe findings that would be in an industry-like environment, such as information disclosure of employees or possible clients. Furthermore, the methodology of pivoting, which is used when a compromised system is used to attack other systems on the same network due to firewalls configurations can be practiced as Snap Lab environments have at least 25 systems within their network being ran and can be used to pivot from one system to another.

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/snaplabs.png" />
</p>

# OSINT

Open Source Intelligence, also known as OSINT, is defined as is the practice of collecting information from published or otherwise publicly available sources. Once teams are provided information about the "client",  they are expected to perform OSINT and gather information. By using OSINT, we are able to learn about the organization and employees before beginning the engagement. OSINT is able to help steer our plan of action during competitions and can also reveal crucial information that can be used to gain knowledge of possible vectors into the network. 

This year's fictitious company was called Next Generation Power and Water, NGPEW, which was a regional power and water utility company servicing  the city of Smallville. Almost every year, there is some sort of interesting information about the company that is found on various social media platforms, GitHub, and various other sites.  NGPEW also had its own website that had a section boasting its strong password policy, even including examples of strong passwords such as: `StrongPassword1, WestThompsonDam, etc.`Funny enough, we were able to use these credentials to brute force into a  Domain  Administrator account. On NGPEW's GitHub, we discovered that there were commits on the repository that an NGPEW employee accidentally pushed that contained internal information about the [PowerBus diagram](https://github.com/Next-Generation-Power-and-Water/docs/blob/6cb3049ecc95c8ed55aa9b1c1d362e975b7d59f4/PowerBus-Overview.png) and the company [organization structure](https://github.com/Next-Generation-Power-and-Water/docs/blob/6cb3049ecc95c8ed55aa9b1c1d362e975b7d59f4/Demo_Organization_Import_09_03_2020.pdf). With an entire list of the company's employee names and roles, we were able to further investigate and find Twitter and LinkedIn profiles associated with the company.   Furthermore, the discovered employee names could be used to generate a list of usernames that the company utilizes given different possible naming conventions. The roles are equally as important as it gives teams an insight into which employees are considered high priority targets during the engagement. 

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/fakenews.png" />
</p>


OSINT is definitely a fun part of the competition and should not be underestimated as it will give you points! Dan Borges has been the lead on creating OSINT for CPTC and his [blog ](http://lockboxx.blogspot.com/search?q=osint)has lots of good information about past OSINT created!

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/dox.png" />
</p>

# Regionals Experience

Western Regionals CPTC hosted by Stanford had us RDP into Windows jumpboxes and then SSH into a Kali box. We knew in advance the tools and wordlists that we would need, so we had PowerShell and Bash scripts ready in our GitHub repo to quickly deploy everything to our competition machines. Our infrastructure team stood up a [collaborative host management server](https://svl.sh/nvis/) and we ran its client. Once the two subnets were nmapped, port scan results were forwarded to the server, which gave us a centralized interface to track our progress on each of the boxes.

When you have over 20 active systems to pentest in under a day, keeping track of each system's completion is crucial. Our red-teaming platform nVis let us mark boxes as complete, in progress, or needing a second look.

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/nVis Screenshot.png"/>
</p>

We split our efforts and everyone focused on technologies they had the strongest background in - we got initial access in multiple places pretty quick. First, our password spray against the Windows boxes hit a jackpot - Domain Admin credentials. Second, we found an exploit for and got remote code execution on the company help desk web application. And finally, we got a web shell on the main web server using the allowed PUT method.

Once we had full access to the corporate network, our efforts became focused on the industrial control systems. We couldn't figure out what was running on the power subnet and didn't see any obvious access vectors, so we spun up an OpenVAS container and started an intense nmap scan against it. What could go wrong?

Our team captain got an  emergency call from our point of contact with evacuation sirens in the background - "What the hell did you do? Smallville’s systems have been working for decades! There's water flowing everywhere". We had to stop everything we were doing, because the dam was overflowing. We scrambled to troubleshoot it and send all of our recent traffic logs to the NGPEW IT, but then we got the other end of the extreme - the water level was too low. We called our point of contact and were told that the levels are dangerously low - their nuclear power plant isn't getting enough water. Crisis was barely averted last minute when we realized our OpenVAS was still running.

Having nearly turned a city into both Atlantis and Chernobyl within the span of an hour, we learned a valuable lesson that the CPTC organizers wanted to teach us - extreme caution must be taken with industrial control systems. Despite that, we took 2nd place, even outperforming Stanford University, who came in 3rd just behind us. 

# Regionals → Nationals

Although Cal Poly Pomona had placed 2nd in the Western region, we were confident that we would receive a wildcard spot and continue competing at Nationals. One of the first things that we did post-competition was documenting all of the information that we gathered during the engagement such as version numbers of services and especially noting down the technical issues that we ran into. For certain applications, we were able to recreate and becoming more familiar with the applications on our own systems such as the [Mantis Bug Tracker ](https://www.mantisbt.org/)and [RocketChat](https://rocket.chat/). As a team, we would come up with a list of topics to research in preparation of Nationals and ensure that we have a teammate that could specialize in that topic. For most of the weeks after Regionals, our teammates would be working individually in strategizing their own game plan going into the upcoming engagement. 

It is highly encouraged that teams go into these competitions with a rough idea of what sort of tasks need to be completed within the first hour or so.  Often times, when the competitions starts and with so many things needing to be done, we sometimes freeze under the pressure and waste time trying to recuperate and gather our thoughts. Because the Nationals environment will likely contain existing Regionals infrastructure, it is especially important to note down steps for reverifying previously discovered vulnerabilities. A few weeks before Nationals competition, our team worked on rewriting sections of the report and fixed parts of the technical findings that we didn’t have time to fix during Regionals. In addition, we spent time preparing a slide deck template that contained basic information we would use during the Nationals presentation. We would recommend the teams that advance to Nationals take the time to debrief the Regionals environment and strategize in order to maximize the time given during the two days of testing. 

# Nationals Experience

The CPTC finals were a technological feat made possible thanks to the Rochester Institute of Technology, who hosted it from their new [Cyber Range](https://www.rit.edu/cybersecurity/cyber-range), which is their brand new cybersecurity training and competition center. If not for COVID-19, we would have been there in-person for the global round of CPTC.

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/GCIoutside.jpg"/>
</p>

Once we were connected to the competition VDI and all of our scripts and infrastructure was deployed, we hit a roadblock the competition organizers wanted us to face - network segmentation. Next Generation Power and Water actually took our advice from the initial engagement and implemented strict access control lists, effectively barring us from communicating with 2 of the 3 subnets in scope. To add to the difficulty of the engagement, competition organizers patched off and secured nearly every vulnerability in the 1 subnet we had access to. NGPEW sprinkled in some rabbit holes for us to go down and in the absence of any other vectors, we followed some of them. Let's just say our team can now recite the entire Rocket.Chat API documentation.

The Windows environment, usually fruitful, was hardened to stone. Our attempts to poll LDAP for enumeration failed just as our DNS zone-transfer attempts. By the end of day 1, things were looking grim for our technical findings. We were stumped when the point-of-contact asked us to list a few areas for improvement. We weren't about to give up though, so a password spray was ran against the domain, and that gave us the foothold. Turned out that several executive's workstations on the corporate subnet had the same weak local administrator password, which we managed to exploit. With barely 20 minutes left before the end of day 1, we did as much recon on the rest of the environment as we could and then began to plan for tomorrow, once VDI access was cut.

PLCs that were implemented within NGPEW's network were quite difficult to assess as they were sensitive in nature. To elaborate on how sensitive the PLCs were, if we were to run scans against the PLC there was potential for it to go down. With that in mind, we approached testing the PLC with care. The PLCs were able to be accessed through NetCat or [QModMaster](https://sourceforge.net/projects/qmodmaster/), which is a graphical user interface that can communicate with ModBus RTU and TCP slaves. Furthermore, the dam's API was also accessible by navigating to its IP address which would return a JSON object which included metrics for all power systems. Packet captures of the HMI using [Wireshark](https://www.wireshark.org/) also presented the format of POST requests which can be used for analysis. In the end, NGPEW having no authentication to their PLCs or API could have allowed attackers with malicious intent to modify power generation systems, trigger alarm systems, or exceed safety levels which could lead to equipment being damaged and workers being endangered which would not leave NGPEW in a very enjoyable position.

The first thing we did once Day 2 testing began was running  nmap scans from the corporate network, hoping that we would gain visibility into the previously segmented network. While the subnets were being scanned, our team began to enumerate through the workstation  we gained access to the other day using a simple [Powershell script](https://github.com/SighLessShen/miscScripts/blob/master/FindMediaFiles).  The script will enumerate through the `C:\Users` folder and recursively search for file types of interest such as` .txt , .exe , .pdf , etc. `While looking through each workstation, we discovered there was a folder called ThunderBird under `AppData/Roaming. `A quick visit to Google indicated that ThunderBird was an email client developed by Mozilla FireFox and that emails could be stored locally. Our team was able to read these emails and discover employees sending credentials to one another. Using this information, we were able to authenticate to an exposed VNC server.  Once we compromised the corporate subnet, we moved laterally to both power and services subnet, taking over everything in our path. Taught by the struggle of the corporate subnet, we started trying variations on "password2" that got us onto the workstations, and funny enough, it worked. Weak passwords got us onto the billing database, the former helpdesk server and the main public-facing web server. While we enumerated the systems and services that were compromised, we also ensured to do our due diligence and check the entire file systems, databases, etc. for any information disclosure or possible leads to gain more persistence in NGPEW's network. We also validated many of the regionals findings and noticed a funny pattern - NGPEW kept telling us they fixed everything, but turns out they simply moved all the vulnerable systems to a different subnet. Most of the things we outlined in our first report were still present and that gave us quite a few free points.

The international round of CPTC ended with us giving a presentation on our findings and when it was all wrapped up, we were the 3rd best team in all of the United States as well as parts of Canada, Europe and the Middle East. When we had a 1-on-1 debrief with the competition organizers, we were told that we actually got 1st place in technical findings and did consistently well overall. RIT and Stanford surely need to watch out, because Cal Poly Pomona has been steadily improving with every CPTC we've had.

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/comingforyou.png" />
</p>

# Benefits

Participating in the Western Regional CPTC as well as the CPTC Finals innately provided an exceptional amount of benefits that could only be obtained through competing; specifically the amount of experience CPTC provides. 

During CPTC, students must remember that they are not pentesting as if they are competing in a CTF, but rather, that they are consultants. Knowing this, teams will begin to feel the realism as company infrastructure needs to contain consistent uptime, exploits that may cause downtime should be discussed with your clients to gain permission to assess the vulnerability, your clients should be aware of faults in their system during your engagement, and presentations should be presented professionally amongst the team. Just having this sense of realism as if we were consultants in an internship or a full-time job gave an immense amount of benefit that other competitions do not provide. 

Not only did the interaction with clients present a vast amount of experience, but the penetration test and report would simulate industry-like penetration testing engagements. During the Western Regional CPTC, the fictitious company NGPEW would have tons of vulnerabilities and weak network segmentation. From ticketing sites that were outdated, to chatting services that employees would use to share credentials with each other; it was apparent that NGPEW had a lot of problems in their environment. Fast forwarding to the CPTC finals, it seemed clear that NGPEW had listened to a lot of the teams suggestions and had secured their infrastructure fairly well as NGPEW's networks were segmented off and at first sight seemed as if they had no vulnerabilities at all. During the first day, this gave the whole team the experience of what it feels like to dig deep into a rabbit hole. Experiencing the pain of network segmentation due to access control lists ("ACLs") and not having a foothold anywhere on the environment definitely hurt, but it did not deter us from trying everything we have studied and learned. With our team staying determined, we eventually gained credentials to a user which would  initiate our start of pivoting from system to system and gaining more and more persistence within NGPEW's infrastructure.  Overall, the team definitely ran into trouble here and there, whether it was from the ACLs or the sensitive nature of industrial control systems within NGPEW; the team gained a lot of technical experience by  learning how to overcome these obstacles.

 A few other benefits that CPTC provides is teaching students how to produce an industry standard penetration test report and provide suggestions on how to present to executives. Learning to create an industry standard penetration test report on your own without prior experience is not an easy task to do. Coming across penetration test reports used in the industry is difficult, as well as resources and examples of penetration test reports are hard to come across. As CPTC strives to educate their participants, [reports ](https://github.com/nationalcptc/report_examples)from every team that competed in the CPTC finals of 2019 have been posted on GitHub. This allows students and teams who were interested in seeing how teams produced their reports to identify some key areas of improvement for their own reports. With the ability to identify where your team may improve on by reviewing other team's reports, the quality of reports should improve over time which is great for all teams. On top of this, the volunteers of CPTC who judge your team's penetration test report and presentation will be supplying their own input on the team's strong suits as well as where they can improve based on their experience in the industry. 

Overall, the benefits the students can get by practicing and being a part of CPTC is unique as the amount of experience, knowledge, and exposure students will get is something that can only be obtained by competing in CPTC.

# Looking Forward

Next CPTC season is promising to be just as exciting - the target has been announced to be a French bakery with both storefront applications and backend production industrial control systems that we will get to hack. This year was the first CPTC season for half of our team, yet it didn't deter us from placing third internationally, because of the knowledge that's transferred from one generation to the other. 

<p align="center">
  <img src="{{ site.github.url }}/images/cptc/ErZn5GwXEAAONVb.jpg" />
</p>

Consistent excellency isn't created overnight - it has to be nurtured and eventually passed on entirely to the next roster. All but one team member will graduate by the time CPTC 2021 comes, but the new roster won't have to start from scratch - they will be building upon the knowledge accumulated by every team before them, including ours. 
