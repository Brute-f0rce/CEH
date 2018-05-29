# Resources

## Network

### Scanning / Pentesting

- [OpenVAS](http://www.openvas.org/) - OpenVAS is a framework of several services and tools offering a comprehensive and powerful vulnerability scanning and vulnerability management solution.
- [Metasploit Framework](https://github.com/rapid7/metasploit-framework) - A tool for developing and executing exploit code against a remote target machine. Other important sub-projects include the Opcode Database, shellcode archive and related research.
- [Kali](https://www.kali.org/) - Kali Linux is a Debian-derived Linux distribution designed for digital forensics and penetration testing. Kali Linux is preinstalled with numerous penetration-testing programs, including nmap (a port scanner), Wireshark (a packet analyzer), John the Ripper (a password cracker), and Aircrack-ng (a software suite for penetration-testing wireless LANs).
- [pig](https://github.com/rafael-santiago/pig) - A Linux packet crafting tool.
- [scapy](https://github.com/secdev/scapy) - Scapy: the python-based interactive packet manipulation program & library.
- [Pompem](https://github.com/rfunix/Pompem) - Pompem is an open source tool, which is designed to automate the search for exploits in major databases. Developed in Python, has a system of advanced search, thus facilitating the work of pentesters and ethical hackers. In its current version, performs searches in databases: Exploit-db, 1337day, Packetstorm Security...
- [Nmap](https://nmap.org) - Nmap is a free and open source utility for network discovery and security auditing.
- [Amass](https://github.com/caffix/amass) - Amass performs DNS subdomain enumeration by scraping the largest number of disparate data sources, recursive brute forcing, crawling of web archives, permuting and altering names, reverse DNS sweeping and other techniques.

### Monitoring / Logging

- [justniffer](http://justniffer.sourceforge.net/) - Justniffer is a network protocol analyzer that captures network traffic and produces logs in a customized way, can emulate Apache web server log files, track response times and extract all "intercepted" files from the HTTP traffic.
- [httpry](http://dumpsterventures.com/jason/httpry/) - httpry is a specialized packet sniffer designed for displaying and logging HTTP traffic. It is not intended to perform analysis itself, but to capture, parse, and log the traffic for later analysis. It can be run in real-time displaying the traffic as it is parsed, or as a daemon process that logs to an output file. It is written to be as lightweight and flexible as possible, so that it can be easily adaptable to different applications.
- [ngrep](http://ngrep.sourceforge.net/) - ngrep strives to provide most of GNU grep's common features, applying them to the network layer. ngrep is a pcap-aware tool that will allow you to specify extended regular or hexadecimal expressions to match against data payloads of packets. It currently recognizes IPv4/6, TCP, UDP, ICMPv4/6, IGMP and Raw across Ethernet, PPP, SLIP, FDDI, Token Ring and null interfaces, and understands BPF filter logic in the same fashion as more common packet sniffing tools, such as tcpdump and snoop.
- [passivedns](https://github.com/gamelinux/passivedns) - A tool to collect DNS records passively to aid Incident handling, Network Security Monitoring (NSM) and general digital forensics. PassiveDNS sniffs traffic from an interface or reads a pcap-file and outputs the DNS-server answers to a log file. PassiveDNS can cache/aggregate duplicate DNS answers in-memory, limiting the amount of data in the logfile without loosing the essens in the DNS answer.
- [sagan](http://sagan.quadrantsec.com/) - Sagan uses a 'Snort like' engine and rules to analyze logs (syslog/event log/snmptrap/netflow/etc).
- [Node Security Platform](https://nodesecurity.io/) - Similar feature set to Snyk, but free in most cases, and very cheap for others.
- [ntopng](http://www.ntop.org/products/traffic-analysis/ntop/) - Ntopng is a network traffic probe that shows the network usage, similar to what the popular top Unix command does.
- [Fibratus](https://github.com/rabbitstack/fibratus) - Fibratus is a tool for exploration and tracing of the Windows kernel. It is able to capture the most of the Windows kernel activity - process/thread creation and termination, file system I/O, registry, network activity, DLL loading/unloading and much more. Fibratus has a very simple CLI which encapsulates the machinery to start the kernel event stream collector, set kernel event filters or run the lightweight Python modules called filaments.

### IDS / IPS / Host IDS / Host IPS

- [Snort](https://www.snort.org/) - Snort is a free and open source network intrusion prevention system (NIPS) and network intrusion detection system (NIDS)created by Martin Roesch in 1998. Snort is now developed by Sourcefire, of which Roesch is the founder and CTO. In 2009, Snort entered InfoWorld's Open Source Hall of Fame as one of the "greatest [pieces of] open source software of all time".
- [Bro](https://www.bro.org/) - Bro is a powerful network analysis framework that is much different from the typical IDS you may know.
- [OSSEC](https://ossec.github.io/) - Comprehensive Open Source HIDS. Not for the faint of heart. Takes a bit to get your head around how it works. Performs log analysis, file integrity checking, policy monitoring, rootkit detection, real-time alerting and active response. It runs on most operating systems, including Linux, MacOS, Solaris, HP-UX, AIX and Windows. Plenty of reasonable documentation. Sweet spot is medium to large deployments.
- [Suricata](http://suricata-ids.org/) - Suricata is a high performance Network IDS, IPS and Network Security Monitoring engine. Open Source and owned by a community run non-profit foundation, the Open Information Security Foundation (OISF). Suricata is developed by the OISF and its supporting vendors.
- [Security Onion](http://blog.securityonion.net/) - Security Onion is a Linux distro for intrusion detection, network security monitoring, and log management. It's based on Ubuntu and contains Snort, Suricata, Bro, OSSEC, Sguil, Squert, Snorby, ELSA, Xplico, NetworkMiner, and many other security tools. The easy-to-use Setup wizard allows you to build an army of distributed sensors for your enterprise in minutes!
- [sshwatch](https://github.com/marshyski/sshwatch) - IPS for SSH similar to DenyHosts written in Python.  It also can gather information about attacker during the attack in a log.
- [Stealth](https://fbb-git.github.io/stealth/) - File integrity checker that leaves virtually no sediment. Controller runs from another machine, which makes it hard for an attacker to know that the file system is being checked at defined pseudo random intervals over SSH. Highly recommended for small to medium deployments.
- [AIEngine](https://bitbucket.org/camp0/aiengine) - AIEngine is a next generation interactive/programmable Python/Ruby/Java/Lua packet inspection engine with capabilities of learning without any human intervention, NIDS(Network Intrusion Detection System) functionality, DNS domain classification, network collector, network forensics and many others.
- [Denyhosts](http://denyhosts.sourceforge.net/) - Thwart SSH dictionary based attacks and brute force attacks.
- [Fail2Ban](http://www.fail2ban.org/wiki/index.php/Main_Page) - Scans log files and takes action on IPs that show malicious behavior.
- [SSHGuard](http://www.sshguard.net/) - A software to protect services in addition to SSH, written in C
- [Lynis](https://cisofy.com/lynis/) - an open source security auditing tool for Linux/Unix.

### Honey Pot / Honey Net

- [awesome-honeypots](https://github.com/paralax/awesome-honeypots) - The canonical awesome honeypot list.
- [HoneyPy](https://github.com/foospidy/HoneyPy) - HoneyPy is a low to medium interaction honeypot. It is intended to be easy to: deploy, extend functionality with plugins, and apply custom configurations.
- [Dionaea](https://www.edgis-security.org/honeypot/dionaea/) - Dionaea is meant to be a nepenthes successor, embedding python as scripting language, using libemu to detect shellcodes, supporting ipv6 and tls.
- [Conpot](http://conpot.org/) - ICS/SCADA Honeypot. Conpot is a low interactive server side Industrial Control Systems honeypot designed to be easy to deploy, modify and extend. By providing a range of common industrial control protocols we created the basics to build your own system, capable to emulate complex infrastructures to convince an adversary that he just found a huge industrial complex. To improve the deceptive capabilities, we also provided the possibility to server a custom human machine interface to increase the honeypots attack surface. The response times of the services can be artificially delayed to mimic the behaviour of a system under constant load. Because we are providing complete stacks of the protocols, Conpot can be accessed with productive HMI's or extended with real hardware. Conpot is developed under the umbrella of the Honeynet Project and on the shoulders of a couple of very big giants.
- [Amun](https://github.com/zeroq/amun) - Amun Python-based low-interaction Honeypot.
- [Glastopf](http://glastopf.org/) - Glastopf is a Honeypot which emulates thousands of vulnerabilities to gather data from attacks targeting web applications. The principle behind it is very simple: Reply the correct response to the attacker exploiting the web application.
- [Kippo](https://github.com/desaster/kippo) - Kippo is a medium interaction SSH honeypot designed to log brute force attacks and, most importantly, the entire shell interaction performed by the attacker.
- [Kojoney](http://kojoney.sourceforge.net/) - Kojoney is a low level interaction honeypot that emulates an SSH server. The daemon is written in Python using the Twisted Conch libraries.
- [HonSSH](https://github.com/tnich/honssh) - HonSSH is a high-interaction Honey Pot solution. HonSSH will sit between an attacker and a honey pot, creating two separate SSH connections between them.
- [Bifrozt](http://sourceforge.net/projects/bifrozt/) - Bifrozt is a NAT device with a DHCP server that is usually deployed with one NIC connected directly to the Internet and one NIC connected to the internal network. What differentiates Bifrozt from other standard NAT devices is its ability to work as a transparent SSHv2 proxy between an attacker and your honeypot. If you deployed an SSH server on Bifrozt’s internal network it would log all the interaction to a TTY file in plain text that could be viewed later and capture a copy of any files that were downloaded. You would not have to install any additional software, compile any kernel modules or use a specific version or type of operating system on the internal SSH server for this to work. It will limit outbound traffic to a set number of ports and will start to drop outbound packets on these ports when certain limits are exceeded.
- [HoneyDrive](http://bruteforce.gr/honeydrive) - HoneyDrive is the premier honeypot Linux distro. It is a virtual appliance (OVA) with Xubuntu Desktop 12.04.4 LTS edition installed. It contains over 10 pre-installed and pre-configured honeypot software packages such as Kippo SSH honeypot, Dionaea and Amun malware honeypots, Honeyd low-interaction honeypot, Glastopf web honeypot and Wordpot, Conpot SCADA/ICS honeypot, Thug and PhoneyC honeyclients and more. Additionally it includes many useful pre-configured scripts and utilities to analyze, visualize and process the data it can capture, such as Kippo-Graph, Honeyd-Viz, DionaeaFR, an ELK stack and much more. Lastly, almost 90 well-known malware analysis, forensics and network monitoring related tools are also present in the distribution.
- [Cuckoo Sandbox](http://www.cuckoosandbox.org/) - Cuckoo Sandbox is an Open Source software for automating analysis of suspicious files. To do so it makes use of custom components that monitor the behavior of the malicious processes while running in an isolated environment.
- [T-Pot Honeypot Distro](http://dtag-dev-sec.github.io/mediator/feature/2017/11/07/t-pot-17.10.html) - T-Pot is based on the network installer of Ubuntu Server 16/17.x LTS. The honeypot daemons as well as other support components being used have been containerized using docker. This allows us to run multiple honeypot daemons on the same network interface while maintaining a small footprint and constrain each honeypot within its own environment. Installation over vanilla Ubuntu - [T-Pot Autoinstall](https://github.com/dtag-dev-sec/t-pot-autoinstall) - This script will install T-Pot 16.04/17.10 on a fresh Ubuntu 16.04.x LTS (64bit). It is intended to be used on hosted servers, where an Ubuntu base image is given and there is no ability to install custom ISO images. Successfully tested on vanilla Ubuntu 16.04.3 in VMware.

### Full Packet Capture / Forensic

- [tcpflow](https://github.com/simsong/tcpflow) - tcpflow is a program that captures data transmitted as part of TCP connections (flows), and stores the data in a way that is convenient for protocol analysis and debugging. Each TCP flow is stored in its own file. Thus, the typical TCP flow will be stored in two files, one for each direction. tcpflow can also process stored 'tcpdump' packet flows.
- [Xplico](http://www.xplico.org/) - The goal of Xplico is extract from an internet traffic capture the applications data contained. For example, from a pcap file Xplico extracts each email (POP, IMAP, and SMTP protocols), all HTTP contents, each VoIP call (SIP), FTP, TFTP, and so on. Xplico isn’t a network protocol analyzer. Xplico is an open source Network Forensic Analysis Tool (NFAT).
- [Moloch](https://github.com/aol/moloch) - Moloch is an open source, large scale IPv4 packet capturing (PCAP), indexing and database system. A simple web interface is provided for PCAP browsing, searching, and exporting. APIs are exposed that allow PCAP data and JSON-formatted session data to be downloaded directly. Simple security is implemented by using HTTPS and HTTP digest password support or by using apache in front. Moloch is not meant to replace IDS engines but instead work along side them to store and index all the network traffic in standard PCAP format, providing fast access. Moloch is built to be deployed across many systems and can scale to handle multiple gigabits/sec of traffic.
- [OpenFPC](http://www.openfpc.org) - OpenFPC is a set of tools that combine to provide a lightweight full-packet network traffic recorder & buffering system. It's design goal is to allow non-expert users to deploy a distributed network traffic recorder on COTS hardware while integrating into existing alert and log management tools.
- [Dshell](https://github.com/USArmyResearchLab/Dshell) - Dshell is a network forensic analysis framework. Enables rapid development of plugins to support the dissection of network packet captures.
- [stenographer](https://github.com/google/stenographer) - Stenographer is a packet capture solution which aims to quickly spool all packets to disk, then provide simple, fast access to subsets of those packets.

### Sniffer

- [wireshark](https://www.wireshark.org) - Wireshark is a free and open-source packet analyzer. It is used for network troubleshooting, analysis, software and communications protocol development, and education. Wireshark is very similar to tcpdump, but has a graphical front-end, plus some integrated sorting and filtering options.
- [netsniff-ng](http://netsniff-ng.org/) -  netsniff-ng is a free Linux networking toolkit, a Swiss army knife for your daily Linux network plumbing if you will. Its gain of performance is reached by zero-copy mechanisms, so that on packet reception and transmission the kernel does not need to copy packets from kernel space to user space and vice versa.
- [Live HTTP headers](https://addons.mozilla.org/de/firefox/addon/live-http-headers/) - Live HTTP headers is a free firefox addon to see your browser requests in real time. It shows the entire headers of the requests and can be used to find the security loopholes in implementations.

### Security Information & Event Management

- [Prelude](https://www.prelude-siem.org/) - Prelude is a Universal "Security Information & Event Management" (SIEM) system. Prelude collects, normalizes, sorts, aggregates, correlates and reports all security-related events independently of the product brand or license giving rise to such events; Prelude is "agentless".
- [OSSIM](https://www.alienvault.com/open-threat-exchange/projects) - OSSIM provides all of the features that a security professional needs from a SIEM offering – event collection, normalization, and correlation.
- [FIR](https://github.com/certsocietegenerale/FIR) - Fast Incident Response, a cybersecurity incident management platform.

### VPN

- [OpenVPN](https://openvpn.net/) - OpenVPN is an open source software application that implements virtual private network (VPN) techniques for creating secure point-to-point or site-to-site connections in routed or bridged configurations and remote access facilities. It uses a custom security protocol that utilizes SSL/TLS for key exchange.

### Fast Packet Processing

- [DPDK](http://dpdk.org/) - DPDK is a set of libraries and drivers for fast packet processing.
- [PFQ](https://github.com/pfq/PFQ) - PFQ is a functional networking framework designed for the Linux operating system that allows efficient packets capture/transmission (10G and beyond), in-kernel functional processing and packets steering across sockets/end-points.
- [PF_RING](http://www.ntop.org/products/packet-capture/pf_ring/) - PF_RING is a new type of network socket that dramatically improves the packet capture speed.
- [PF_RING ZC (Zero Copy)](http://www.ntop.org/products/packet-capture/pf_ring/pf_ring-zc-zero-copy/) - PF_RING ZC (Zero Copy) is a flexible packet processing framework that  allows you to achieve 1/10 Gbit line rate packet processing (both RX and TX) at any packet size. It implements zero copy operations including patterns for inter-process and inter-VM (KVM) communications.
- [PACKET_MMAP/TPACKET/AF_PACKET](http://lxr.free-electrons.com/source/Documentation/networking/packet_mmap.txt) - It's fine to use PACKET_MMAP to improve the performance of the capture and transmission process in Linux.
- [netmap](http://info.iet.unipi.it/~luigi/netmap/) - netmap is a framework for high speed packet I/O. Together with its companion VALE software switch, it is implemented as a single kernel module and available for FreeBSD, Linux and now also Windows.

### Firewall
- [pfSense](https://www.pfsense.org/) - Firewall and Router FreeBSD distribution.
- [OPNsense](https://opnsense.org/) - is an open source, easy-to-use and easy-to-build FreeBSD based firewall and routing platform. OPNsense includes most of the features available in expensive commercial firewalls, and more in many cases. It brings the rich feature set of commercial offerings with the benefits of open and verifiable sources.
- [fwknop](https://www.cipherdyne.org/fwknop/) - Protects ports via Single Packet Authorization in your firewall.

### Anti-Spam
- [SpamAssassin](https://spamassassin.apache.org/) - A powerful and popular email spam filter employing a variety of detection technique.


### Docker Images for Penetration Testing & Security
- `docker pull kalilinux/kali-linux-docker` [official Kali Linux](https://hub.docker.com/r/kalilinux/kali-linux-docker/)
- `docker pull owasp/zap2docker-stable` - [official OWASP ZAP](https://github.com/zaproxy/zaproxy)
- `docker pull wpscanteam/wpscan` - [official WPScan](https://hub.docker.com/r/wpscanteam/wpscan/)
- `docker pull remnux/metasploit` - [docker-metasploit](https://hub.docker.com/r/remnux/metasploit/)
- `docker pull citizenstig/dvwa` - [Damn Vulnerable Web Application (DVWA)](https://hub.docker.com/r/citizenstig/dvwa/)
- `docker pull wpscanteam/vulnerablewordpress` - [Vulnerable WordPress Installation](https://hub.docker.com/r/wpscanteam/vulnerablewordpress/)
- `docker pull hmlio/vaas-cve-2014-6271` - [Vulnerability as a service: Shellshock](https://hub.docker.com/r/hmlio/vaas-cve-2014-6271/)
- `docker pull hmlio/vaas-cve-2014-0160` - [Vulnerability as a service: Heartbleed](https://hub.docker.com/r/hmlio/vaas-cve-2014-0160/)
- `docker pull opendns/security-ninjas` - [Security Ninjas](https://hub.docker.com/r/opendns/security-ninjas/)
- `docker pull diogomonica/docker-bench-security` - [Docker Bench for Security](https://hub.docker.com/r/diogomonica/docker-bench-security/)
- `docker pull ismisepaul/securityshepherd` - [OWASP Security Shepherd](https://hub.docker.com/r/ismisepaul/securityshepherd/)
- `docker pull danmx/docker-owasp-webgoat` - [OWASP WebGoat Project docker image](https://hub.docker.com/r/danmx/docker-owasp-webgoat/)
- `docker-compose build && docker-compose up` - [OWASP NodeGoat](https://github.com/owasp/nodegoat#option-3---run-nodegoat-on-docker)
- `docker pull citizenstig/nowasp` - [OWASP Mutillidae II Web Pen-Test Practice Application](https://hub.docker.com/r/citizenstig/nowasp/)


## Endpoint

### Anti-Virus / Anti-Malware

- [Linux Malware Detect](https://www.rfxn.com/projects/linux-malware-detect/) - A malware scanner for Linux designed around the threats faced in shared hosted environments.

### Content Disarm & Reconstruct

- [DocBleach](https://github.com/docbleach/DocBleach) - An open-source Content Disarm & Reconstruct software sanitizing Office, PDF and RTF Documents.

### Configuration Management

- [Rudder](http://www.rudder-project.org/) - Rudder is an easy to use, web-driven, role-based solution for IT Infrastructure Automation & Compliance. Automate common system administration tasks (installation, configuration); Enforce configuration over time (configuring once is good, ensuring that configuration is valid and automatically fixing it is better); Inventory of all managed nodes; Web interface to configure and manage nodes and their configuration; Compliance reporting, by configuration and/or by node.

### Authentication

- [google-authenticator](https://github.com/google/google-authenticator) - The Google Authenticator project includes implementations of one-time passcode generators for several mobile platforms, as well as a pluggable authentication module (PAM). One-time passcodes are generated using open standards developed by the Initiative for Open Authentication (OATH) (which is unrelated to OAuth). These implementations support the HMAC-Based One-time Password (HOTP) algorithm specified in RFC 4226 and the Time-based One-time Password (TOTP) algorithm specified in RFC 6238. [Tutorials: How to set up two-factor authentication for SSH login on Linux](http://xmodulo.com/two-factor-authentication-ssh-login-linux.html)

### Mobile / Android / iOS

- [android-security-awesome](https://github.com/ashishb/android-security-awesome) - A collection of android security related resources. A lot of work is happening in academia and industry on tools to perform dynamic analysis, static analysis and reverse engineering of android apps.
- [SecMobi Wiki](http://wiki.secmobi.com/) - A collection of mobile security resources which including articles, blogs, books, groups, projects, tools and conferences. *
- [OWASP Mobile Security Testing Guide](https://github.com/OWASP/owasp-mstg) - A comprehensive manual for mobile app security testing and reverse engineering.
- [OSX Security Awesome](https://github.com/kai5263499/osx-security-awesome) - A collection of OSX and iOS security resources

### Forensics

- [grr](https://github.com/google/grr) - GRR Rapid Response is an incident response framework focused on remote live forensics.
- [Volatility](https://github.com/volatilityfoundation/volatility) - Python based memory extraction and analysis framework.
- [mig](http://mig.mozilla.org/) - MIG is a platform to perform investigative surgery on remote endpoints. It enables investigators to obtain information from large numbers of systems in parallel, thus accelerating investigation of incidents and day-to-day operations security.
- [ir-rescue](https://github.com/diogo-fernan/ir-rescue) - *ir-rescue* is a Windows Batch script and a Unix Bash script to comprehensively collect host forensic data during incident response.
- [Logdissect](https://github.com/dogoncouch/logdissect) - CLI utility and Python API for analyzing log files and other data.

## Threat Intelligence

- [abuse.ch](https://www.abuse.ch/) - ZeuS Tracker / SpyEye Tracker / Palevo Tracker / Feodo Tracker tracks Command&Control servers (hosts) around the world and provides you a domain- and an IP-blocklist.
- [Emerging Threats - Open Source](http://doc.emergingthreats.net/bin/view/Main/EmergingFAQ) - Emerging Threats began 10 years ago as an open source community for collecting Suricata and SNORT® rules, firewall rules, and other IDS rulesets. The open source community still plays an active role in Internet security, with more than 200,000 active users downloading the ruleset daily. The ETOpen Ruleset is open to any user or organization, as long as you follow some basic guidelines. Our ETOpen Ruleset is available for download any time.
- [PhishTank](http://www.phishtank.com/) - PhishTank is a collaborative clearing house for data and information about phishing on the Internet. Also, PhishTank provides an open API for developers and researchers to integrate anti-phishing data into their applications at no charge.
- [SBL / XBL / PBL / DBL / DROP / ROKSO](http://www.spamhaus.org/) - The Spamhaus Project is an international nonprofit organization whose mission is to track the Internet's spam operations and sources, to provide dependable realtime anti-spam protection for Internet networks, to work with Law Enforcement Agencies to identify and pursue spam and malware gangs worldwide, and to lobby governments for effective anti-spam legislation.
- [Internet Storm Center](https://www.dshield.org/reports.html) - The ISC was created in 2001 following the successful detection, analysis, and widespread warning of the Li0n worm. Today, the ISC provides a free analysis and warning service to thousands of Internet users and organizations, and is actively working with Internet Service Providers to fight back against the most malicious attackers.
- [AutoShun](https://www.autoshun.org/) - AutoShun is a Snort plugin that allows you to send your Snort IDS logs to a centralized server that will correlate attacks from your sensor logs with other snort sensors, honeypots, and mail filters from around the world.
- [DNS-BH](http://www.malwaredomains.com/) - The DNS-BH project creates and maintains a listing of domains that are known to be used to propagate malware and spyware. This project creates the Bind and Windows zone files required to serve fake replies to localhost for any requests to these, thus preventing many spyware installs and reporting.
- [AlienVault Open Threat Exchange](http://www.alienvault.com/open-threat-exchange/dashboard) - AlienVault Open Threat Exchange (OTX), to help you secure your networks from data loss, service disruption and system compromise caused by malicious IP addresses.
- [Tor Bulk Exit List](https://metrics.torproject.org/collector.html) - CollecTor, your friendly data-collecting service in the Tor network. CollecTor fetches data from various nodes and services in the public Tor network and makes it available to the world. If you're doing research on the Tor network, or if you're developing an application that uses Tor network data, this is your place to start. [TOR Node List](https://www.dan.me.uk/tornodes) /  [DNS Blacklists](https://www.dan.me.uk/dnsbl) / [Tor Node List](http://torstatus.blutmagie.de/)
- [leakedin.com](http://www.leakedin.com/) - The primary purpose of leakedin.com is to make visitors aware about the risks of loosing data. This blog just compiles samples of data lost or disclosed on sites like pastebin.com.
- [FireEye OpenIOCs](https://github.com/fireeye/iocs) - FireEye Publicly Shared Indicators of Compromise (IOCs)
- [OpenVAS NVT Feed](http://www.openvas.org/openvas-nvt-feed.html) - The public feed of Network Vulnerability Tests (NVTs). It contains more than 35,000 NVTs (as of April 2014), growing on a daily basis. This feed is configured as the default for OpenVAS.
- [Project Honey Pot](http://www.projecthoneypot.org/) - Project Honey Pot is the first and only distributed system for identifying spammers and the spambots they use to scrape addresses from your website. Using the Project Honey Pot system you can install addresses that are custom-tagged to the time and IP address of a visitor to your site. If one of these addresses begins receiving email we not only can tell that the messages are spam, but also the exact moment when the address was harvested and the IP address that gathered it.
- [virustotal](https://www.virustotal.com/) - VirusTotal, a subsidiary of Google, is a free online service that analyzes files and URLs enabling the identification of viruses, worms, trojans and other kinds of malicious content detected by antivirus engines and website scanners. At the same time, it may be used as a means to detect false positives, i.e. innocuous resources detected as malicious by one or more scanners.
- [IntelMQ](https://github.com/certtools/intelmq/) - IntelMQ is a solution for CERTs for collecting and processing security feeds, pastebins, tweets using a message queue protocol. It's a community driven initiative called IHAP (Incident Handling Automation Project) which was conceptually designed by European CERTs during several InfoSec events. Its main goal is to give to incident responders an easy way to collect & process threat intelligence thus improving the incident handling processes of CERTs. [ENSIA Homepage](https://www.enisa.europa.eu/activities/cert/support/incident-handling-automation).
- [CIFv2](https://github.com/csirtgadgets/massive-octo-spice) - CIF is a cyber threat intelligence management system. CIF allows you to combine known malicious threat information from many sources and use that information for identification (incident response), detection (IDS) and mitigation (null route).
- [CriticalStack](https://intel.criticalstack.com/) - Free aggregated threat intel for the Bro network security monitoring platform.
- [MISP - Open Source Threat Intelligence Platform ](https://www.misp-project.org/) - MISP threat sharing platform is a free and open source software helping information sharing of threat intelligence including cyber security indicators.  A threat intelligence platform for gathering, sharing, storing and correlating Indicators of Compromise of targeted attacks, threat intelligence, financial fraud information, vulnerability information or even counter-terrorism information. The MISP project includes software, common libraries ([taxonomies](https://www.misp-project.org/taxonomies.html), [threat-actors and various malware](https://www.misp-project.org/galaxy.html)), an extensive data model to share new information using [objects](https://www.misp-project.org/objects.html) and default [feeds](https://www.misp-project.org/feeds/).

## Web

### Organization

- [OWASP](http://www.owasp.org) - The Open Web Application Security Project (OWASP) is a 501(c)(3) worldwide not-for-profit charitable organization focused on improving the security of software.

### Web Application Firewall

- [ModSecurity](http://www.modsecurity.org/) - ModSecurity is a toolkit for real-time web application monitoring, logging, and access control.
- [NAXSI](https://github.com/nbs-system/naxsi) - NAXSI is an open-source, high performance, low rules maintenance WAF for NGINX, NAXSI means Nginx Anti Xss & Sql Injection.
- [sql_firewall](https://github.com/uptimejp/sql_firewall) SQL Firewall Extension for PostgreSQL
- [ironbee](https://github.com/ironbee/ironbee) - IronBee is an open source project to build a universal web application security sensor. IronBee as a framework for developing a system for securing web applications - a framework for building a web application firewall (WAF).

### Scanning / Pentesting

- [sqlmap](http://sqlmap.org/) - sqlmap is an open source penetration testing tool that automates the process of detecting and exploiting SQL injection flaws and taking over of database servers. It comes with a powerful detection engine, many niche features for the ultimate penetration tester and a broad range of switches lasting from database fingerprinting, over data fetching from the database, to accessing the underlying file system and executing commands on the operating system via out-of-band connections.
- [ZAP](https://www.owasp.org/index.php/OWASP_Zed_Attack_Proxy_Project) - The Zed Attack Proxy (ZAP) is an easy to use integrated penetration testing tool for finding vulnerabilities in web applications. It is designed to be used by people with a wide range of security experience and as such is ideal for developers and functional testers who are new to penetration testing. ZAP provides automated scanners as well as a set of tools that allow you to find security vulnerabilities manually.
- [OWASP Testing Checklist v4](https://www.owasp.org/index.php/Testing_Checklist) -  List of some controls to test during a web vulnerability assessment. Markdown version may be found [here](https://github.com/amocrenco/owasp-testing-checklist-v4-markdown/blob/master/README.md).
- [w3af](http://w3af.org/) - w3af is a Web Application Attack and Audit Framework. The project’s goal is to create a framework to help you secure your web applications by finding and exploiting all web application vulnerabilities.
- [Recon-ng](https://bitbucket.org/LaNMaSteR53/recon-ng) - Recon-ng is a full-featured Web Reconnaissance framework written in Python. Recon-ng has a look and feel similar to the Metasploit Framework.
- [PTF](https://github.com/trustedsec/ptf) - The Penetration Testers Framework (PTF) is a way for modular support for up-to-date tools.
- [Infection Monkey](https://github.com/guardicore/monkey) - A semi automatic pen testing tool for mapping/pen-testing networks. Simulates a human attacker.
- [ACSTIS](https://github.com/tijme/angularjs-csti-scanner) - ACSTIS helps you to scan certain web applications for AngularJS Client-Side Template Injection (sometimes referred to as CSTI, sandbox escape or sandbox bypass). It supports scanning a single request but also crawling the entire web application for the AngularJS CSTI vulnerability.

### Runtime Application Self-Protection

- [Sqreen](https://www.sqreen.io/) - Sqreen is a Runtime Application Self-Protection (RASP) solution for software teams. An in-app agent instruments and monitors the app. Suspicious user activities are reported and attacks are blocked at runtime without code modification or traffic redirection.
- [OpenRASP](https://github.com/baidu/openrasp) - An open source RASP solution actively maintained by Baidu Inc. With context-aware detection algorithm the project achieved nearly no false positives. And less than 3% performance reduction is observed under heavy server load.

### Development

- [Secure by Design](https://www.manning.com/books/secure-by-design?a_aid=danbjson&a_bid=0b3fac80) - Book that identifies design patterns and coding styles that make lots of security vulnerabilities less likely. (early access, published continuously, final release fall 2017)
- [Securing DevOps](https://www.manning.com/books/securing-devops) - Book that explores how the techniques of DevOps and Security should be applied together to make cloud services safer. (early access, published continuously, final release January 2018)
- [Understanding API Security](https://www.manning.com/books/understanding-api-security) - Free eBook sampler that gives some context for how API security works in the real world by showing how APIs are put together and how the OAuth protocol can be used to protect them.
- [OAuth 2 in Action](https://www.manning.com/books/oauth-2-in-action) - Book that teaches you practical use and deployment of OAuth 2 from the perspectives of a client, an authorization server, and a resource server. 


## Usability

- [Usable Security Course](https://pt.coursera.org/learn/usable-security) - Usable Security course at coursera. Quite good for those looking for how security and usability intersects.


## Big Data

- [data_hacking](https://github.com/ClickSecurity/data_hacking) - Examples of using IPython, Pandas, and Scikit Learn to get the most out of your security data.
- [hadoop-pcap](https://github.com/RIPE-NCC/hadoop-pcap) - Hadoop library to read packet capture (PCAP) files.
- [Workbench](http://workbench.readthedocs.org/) - A scalable python framework for security research and development teams.
- [OpenSOC](https://github.com/OpenSOC/opensoc) - OpenSOC integrates a variety of open source big data technologies in order to offer a centralized tool for security monitoring and analysis.
- [Apache Metron (incubating)](https://github.com/apache/incubator-metron) - Metron integrates a variety of open source big data technologies in order to offer a centralized tool for security monitoring and analysis.
- [Apache Spot (incubating)](https://github.com/apache/incubator-spot) - Apache Spot is open source software for leveraging insights from flow and packet analysis.
- [binarypig](https://github.com/endgameinc/binarypig) - Scalable Binary Data Extraction in Hadoop. Malware Processing and Analytics over Pig, Exploration through Django, Twitter Bootstrap, and Elasticsearch.

## DevOps

- [Securing DevOps](https://manning.com/books/securing-devops?a_aid=securingdevops&a_bid=1353bcd8) - A book on Security techniques for DevOps that reviews state of the art practices used in securing web applications and their infrastructure.

## Operating Systems

### Online resources

- [Security related Operating Systems @ Rawsec](http://rawsec.ml/en/security-related-os/) - Complete list of security related operating systems
- [Best Linux Penetration Testing Distributions @ CyberPunk](https://n0where.net/best-linux-penetration-testing-distributions/) - Description of main penetration testing distributions
- [Security @ Distrowatch](http://distrowatch.com/search.php?category=Security) - Website dedicated to talking about, reviewing and keeping up to date with open source operating systems


## Datastores

- [blackbox](https://github.com/StackExchange/blackbox) - Safely store secrets in a VCS repo using GPG
- [confidant](https://github.com/lyft/confidant) - Stores secrets in AWS DynamoDB, encrypted at rest and integrates with IAM
- [dotgpg](https://github.com/ConradIrwin/dotgpg) - A tool for backing up and versioning your production secrets or shared passwords securely and easily.
- [redoctober](https://github.com/cloudflare/redoctober) - Server for two-man rule style file encryption and decryption.
- [aws-vault](https://github.com/99designs/aws-vault) - Store AWS credentials in the OSX Keychain or an encrypted file
- [credstash](https://github.com/fugue/credstash) - Store secrets using AWS KMS and DynamoDB
- [chamber](https://github.com/segmentio/chamber) - Store secrets using AWS KMS and SSM Parameter Store
- [Safe](https://github.com/starkandwayne/safe) - A Vault CLI that makes reading from and writing to the Vault easier to do.
- [Sops](https://github.com/mozilla/sops) - An editor of encrypted files that supports YAML, JSON and BINARY formats and encrypts with AWS KMS and PGP.
- [passbolt](https://www.passbolt.com/) - The password manager your team was waiting for. Free, open source, extensible, based on OpenPGP.
- [passpie](https://github.com/marcwebbie/passpie) - Multiplatform command-line password manager
- [Vault](https://www.vaultproject.io/) - An encrypted datastore secure enough to hold environment and application secrets.

## EBooks

- [Holistic Info-Sec for Web Developers](https://holisticinfosecforwebdevelopers.com/) - Free and downloadable book series with very broad and deep coverage of what Web Developers and DevOps Engineers need to know in order to create robust, reliable, maintainable and secure software, networks and other, that are delivered continuously, on time, with no nasty surprises
- [Docker Security - Quick Reference: For DevOps Engineers](https://binarymist.io/publication/docker-security/) - A book on understanding the Docker security defaults, how to improve them (theory and practical), along with many tools and techniques.


## Improve Skills
|Site name|Description|
|:--|:--|
|[$natch competition](http://blog.phdays.com/2012/05/once-again-about-remote-banking.html)|Remote banking system containing common vulnerabilities.|
|[Arizona Cyber Warfare Range](http://azcwr.org/)|The ranges offer an excellent platform for you to learn computer network attack (CNA), computer network defense (CND), and digital forensics (DF). You can play any of these roles.|
|[Avatao](https://www.avatao.com/)|More than 350 hands-on challenges (free and paid) to master IT security and it's growing day by day.|
|[BodgeIt Store](https://github.com/psiinon/bodgeit)|The BodgeIt Store is a vulnerable web application which is currently aimed at people who are new to pen testing.|
|[Bright Shadows](http://www.bright-shadows.net/)|Training in Programming, JavaScript, PHP, Java, Steganography, and Cryptography (among others).|
|[bWAPP](http://www.itsecgames.com/)|bWAPP, or a buggy web application, is a free and open source deliberately insecure web application.|
|[Cyber Degrees](http://www.cyberdegrees.org/resources/free-online-courses/)|Free online cyber security Massive Open Online Courses (MOOCS).|
|[Commix testbed](https://github.com/commixproject/commix-testbed)|A collection of web pages, vulnerable to command injection flaws.|
|[CryptOMG](https://github.com/SpiderLabs/CryptOMG)|CryptOMG is a configurable CTF style test bed that highlights common flaws in cryptographic implementations.|
|[Cyber Security Base](https://cybersecuritybase.github.io/)|Cyber Security Base is a page with free courses by the University of Helsinki in collaboration with F-Secure.|
|[Cybersecuritychallenge UK](https://pod.cybersecuritychallenge.org.uk/)|Cyber Security Challenge UK runs a series of competitions designed to test your cyber security skills.|
|[CyberTraining 365](https://www.cybertraining365.com/cybertraining/FreeClasses)|Cybertraining365 has paid material but also offers free classes. The link is directed at the free classes.|
|[Cybrary.it](https://www.cybrary.it/)|Free and Open Source Cyber Security Learning.|
|[Damn Small Vulnerable Web](https://github.com/stamparm/DSVW)|Damn Small Vulnerable Web (DSVW) is a deliberately vulnerable web application written in under 100 lines of code, created for educational purposes. It supports the majority of (most popular) web application vulnerabilities together with appropriate attacks.|
|[Damn Vulnerable Android App](https://code.google.com/archive/p/dvaa/)|Damn Vulnerable Android App (DVAA) is an Android application which contains intentional vulnerabilities.|
|[Damn Vulnerable Hybrid Mobile App](https://github.com/logicalhacking/DVHMA)|Damn Vulnerable Hybrid Mobile App (DVHMA) is a hybrid mobile app (for Android) that intentionally contains vulnerabilities.|
|[Damn Vulnerable iOS App](http://damnvulnerableiosapp.com/)|Damn Vulnerable iOS App (DVIA) is an iOS application that is damn vulnerable.|
|[Damn Vulnerable Linux](http://www.computersecuritystudent.com/SECURITY_TOOLS/DVL/lesson1/)|Damn Vulnerable Linux (DVL) is everything a good Linux distribution isn't. Its developers have spent hours stuffing it with broken, ill-configured, outdated, and exploitable software that makes it vulnerable to attacks.|
|[Damn Vulnerable Router Firmware](https://github.com/praetorian-inc/DVRF)|The goal of this project is to simulate a real-world environment to help people learn about other CPU architectures outside of the x86_64 space. This project will also help people get into discovering new things about hardware.|
|[Damn Vulnerable Stateful Web App](https://github.com/silentsignal/damn-vulnerable-stateful-web-app)|Short and simple vulnerable PHP web application that naïve scanners found to be perfectly safe.|
|[Damn Vulnerable Thick Client App](https://github.com/secvulture/dvta)|DVTA is a Vulnerable Thick Client Application developed in C# .NET with many vulnerabilities.|
|[Damn Vulnerable Web App](http://www.dvwa.co.uk/)|Damn Vulnerable Web App (DVWA) is a PHP/MySQL web application that is damn vulnerable. Its main goals are to be an aid for security professionals to test their skills and tools in a legal environment, help web developers better understand the processes of securing web applications and aid teachers/students to teach/learn web application security in a classroom environment.|
|[Damn Vulnerable Web Services](https://github.com/snoopysecurity/dvws)|Damn Vulnerable Web Services is an insecure web application with multiple vulnerable web service components that can be used to learn real-world web service vulnerabilities.|
|[Damn Vulnerable Web Sockets](https://github.com/interference-security/DVWS)|Damn Vulnerable Web Sockets (DVWS) is a vulnerable web application which works on web sockets for client-server communication.|
|[Damnvulnerable.me](https://github.com/skepticfx/damnvulnerable.me)|A deliberately vulnerable modern-day app with lots of DOM-related bugs.|
|[Dareyourmind](http://www.dareyourmind.net/)|Online game, hacker challenge.|
|[DIVA Android](https://github.com/payatu/diva-android)|Damn Insecure and vulnerable App for Android.|
|[EnigmaGroup](https://www.enigmagroup.org/)|Safe security resource, trains in exploits listed in the OWASP Top 10 Project and teach members the many other types of exploits that are found in today's applications.|
|[ENISA Training Material](https://www.enisa.europa.eu/topics/trainings-for-cybersecurity-specialists/online-training-material)|The European Union Agency for Network and Information Security (ENISA) Cyber Security Training. You will find training materials, handbooks for teachers, toolsets for students and Virtual Images to support hands-on training sessions.|
|[exploit.co.il Vulnerable Web App](https://sourceforge.net/projects/exploitcoilvuln/?source=recommended)|exploit.co.il Vulnerable Web app designed as a learning platform to test various SQL injection Techniques.|
|[Exploit-exercises.com](https://exploit-exercises.com/)|exploit-exercises.com provides a variety of virtual machines, documentation and challenges that can be used to learn about a variety of computer security issues such as privilege escalation, vulnerability analysis, exploit development, debugging, reverse engineering, and general cyber security issues.|
|[ExploitMe Mobile](http://securitycompass.github.io/AndroidLabs/index.html)|Set of labs and an exploitable framework for you to hack mobile an application on Android.|
|[Game of Hacks](http://www.gameofhacks.com/)|This game was designed to test your application hacking skills. You will be presented with vulnerable pieces of code and your mission if you choose to accept it is to find which vulnerability exists in that code as quickly as possible.|
|[GameOver](https://sourceforge.net/projects/null-gameover/)|Project GameOver was started with the objective of training and educating newbies about the basics of web security and educate them about the common web attacks and help them understand how they work.|
|[Gh0stlab](http://www.gh0st.net/?p=19)|A security research network where like-minded individuals could work together towards the common goal of knowledge.|
|[GoatseLinux](http://neutronstar.org/goatselinux.html)|GSL is a Vmware image you can run for penetration testing purposes.|
|[Google Gruyere](http://google-gruyere.appspot.com/)|Labs that cover how an application can be attacked using common web security vulnerabilities, like cross-site scripting vulnerabilities (XSS) and cross-site request forgery (XSRF). Also, you can find labs how to find, fix, and avoid these common vulnerabilities and other bugs that have a security impact, such as denial-of-service, information disclosure, or remote code execution.|
|[Gracefully Vulnerable Virtual Machine](https://www.gracefulsecurity.com/vulnvm/)|Graceful’s VulnVM is VM web app designed to simulate a simple eCommerce style website which is purposely vulnerable to a number of well know security issues commonly seen in web applications.|
|[Hack The Box](https://www.hackthebox.eu/)|Hack The Box is an online platform allowing you to test your penetration testing skills and exchange ideas and methodologies with other members of similar interests. In order to join you should solve an entry-level challenge.|
|[Hack This Site](https://www.hackthissite.org/)|More than just another hacker wargames site, Hack This Site is a living, breathing community with many active projects in development, with a vast selection of hacking articles and a huge forum where users can discuss hacking, network security, and just about everything.|
|[Hack Yourself First](https://hackyourselffirst.troyhunt.com/)|This course is designed to help web developers on all frameworks identify risks in their own websites before attackers do and it uses this site extensively to demonstrate risks.|
|[Hack.me](https://hack.me/)|Hack.me aims to be the largest collection of "runnable" vulnerable web applications, code samples and CMS's online. The platform is available without any restriction to any party interested in Web Application Security.|
|[Hackademic](https://github.com/Hackademic/hackademic)|Offers realistic scenarios full of known vulnerabilities (especially, of course, the OWASP Top Ten) for those trying to practice their attack skills.|
|[Hackazon](https://github.com/rapid7/hackazon)|A modern vulnerable web app.|
|[Hackertest.net](http://www.hackertest.net/)|HackerTest.net is your own online hacker simulation with 20 levels.|
|[Hacking-Lab](https://www.hacking-lab.com/Remote_Sec_Lab/)|Hacking-Lab is an online ethical hacking, computer network and security challenge platform, dedicated to finding and educating cyber security talents. Furthermore, Hacking-Lab is providing the CTF and mission style challenges for the European Cyber Security Challenge with Austria, Germany, Switzerland, UK, Spain, Romania and provides free OWASP TOP 10 online security labs.|
|[HackSys Extreme Vulnerable Driver](http://payatu.com/hacksys-extreme-vulnerable-driver/)|HackSys Extreme Vulnerable Driver is intentionally vulnerable Windows driver developed for security enthusiasts to learn and polish their exploitation skills at Kernel level.|
|[HackThis!!](https://www.hackthis.co.uk/)|Test your skills with 50+ hacking levels, covering all aspects of security.|
|[Hackxor](http://hackxor.sourceforge.net/cgi-bin/index.pl)|Hackxor is a web app hacking game where players must locate and exploit vulnerabilities to progress through the story. Think WebGoat but with a plot and a focus on realism&difficulty. Contains XSS, CSRF, SQLi, ReDoS, DOR, command injection, etc.|
|[Halls of Valhalla](http://halls-of-valhalla.org/beta/challenges)|Challenges you can solve. Valhalla is a place for sharing knowledge and ideas. Users can submit code, as well as science, technology, and engineering-oriented news and articles.|
|[Hax.Tor](http://hax.tor.hu/welcome/)|Provides numerous interesting “hacking” challenges to the user.|
|[Hellbound Hackers](https://www.hellboundhackers.org/)|Learn a hands-on approach to computer security. Learn how hackers break in, and how to keep them out.|
|[Holynix](https://sourceforge.net/projects/holynix/files/)|Holynix is a Linux VMware image that was deliberately built to have security holes for the purposes of penetration testing.|
|[HSCTF3](http://hsctf.com/)|HSCTF is an international online hacking competition designed to educate high schoolers in computer science.|
|[Information Assurance Support Environment (IASE)](http://iase.disa.mil/eta/Pages/index.aspx)|Great site with Cybersecurity Awareness Training, Cybersecurity Training for IT Managers, Cybersecurity Training for Cybersecurity Professionals, Cybersecurity Technical Training, NetOps Training, Cyber Law Awareness, and FSO Tools Training available online.|
|[InfoSec Institute](http://resources.infosecinstitute.com/free-cissp-training-study-guide/)|Free CISSP Training course.|
|[ISC2 Center for Cyber Safety and Education](https://safeandsecureonline.org/)|Site to empower students, teachers, and whole communities to secure their online life through cyber security education and awareness with the Safe and Secure Online educational program; information security scholarships; and industry and consumer research.|
|[Java Vulnerable Lab](https://github.com/CSPF-Founder/JavaVulnerableLab)|Vulnerable Java based Web Application.|
|[Juice Shop](https://github.com/bkimminich/juice-shop)|OWASP Juice Shop is an intentionally insecure web app for security training written entirely in Javascript which encompasses the entire OWASP Top Ten and other severe security flaws.|
|[Kioptrix VM](http://www.kioptrix.com/blog/a-new-vm-after-almost-2-years/)|This vulnerable machine is a good starting point for beginners.|
|[LAMPSecurity Training](https://sourceforge.net/projects/lampsecurity/)|LAMPSecurity training is designed to be a series of vulnerable virtual machine images along with complementary documentation designed to teach Linux,apache,PHP,MySQL security.|
|[Magical Code Injection Rainbow](https://github.com/SpiderLabs/MCIR)|The Magical Code Injection Rainbow! MCIR is a framework for building configurable vulnerability testbeds. MCIR is also a collection of configurable vulnerability testbeds.|
|[McAfee HacMe Sites](http://www.mcafee.com/us/downloads/free-tools/index.aspx)|Search the page for HacMe and you'll find a suite of learning tools.|
|[Metasploit Unleashed](https://www.offensive-security.com/metasploit-unleashed/)|Free Ethical Hacking Course.|
|[Metasploitable 3](https://github.com/rapid7/metasploitable3)|Metasploitable3 is a VM that is built from the ground up with a large number of security vulnerabilities.|
|[Microcorruption CTF](https://microcorruption.com/login)|Challenge: given a debugger and a device, find an input that unlocks it. Solve the level with that input.|
|[Morning Catch](http://blog.cobaltstrike.com/2014/08/06/introducing-morning-catch-a-phishing-paradise/)|Morning Catch is a VMware virtual machine, similar to Metasploitable, to demonstrate and teach about targeted client-side attacks and post-exploitation.|
|[Moth](http://www.bonsai-sec.com/en/research/moth.php)|Moth is a VMware image with a set of vulnerable Web Applications and scripts.|
|[Mutillidae](https://sourceforge.net/projects/mutillidae/)|OWASP Mutillidae II is a free, open source, deliberately vulnerable web application providing a target for web-security enthusiast.|
|[MysteryTwister C3](https://www.mysterytwisterc3.org/en/)|MysteryTwister C3 lets you solve crypto challenges, starting from the simple Caesar cipher all the way to modern AES, they have challenges for everyone.|
|[National Institutes of Health (NIH)](https://irtsectraining.nih.gov/publicUser.aspx)|Short courses on Information Security and Privacy Awareness. They have a section for executives, managers and IT Administrators as well.|
|[OpenSecurityTraining.info](http://opensecuritytraining.info/Training.html/)|OpenSecurityTraining.info is dedicated to sharing training material for computer security classes, on any topic, that are at least one day long.|
|[Overthewire](http://overthewire.org/wargames/)|The wargames offered by the OverTheWire community can help you to learn and practice security concepts in the form of fun-filled games.|
|[OWASP Broken Web Applications Project](https://www.owasp.org/index.php/OWASP_Broken_Web_Applications_Project)|OWASP Broken Web Applications Project is a collection of vulnerable web applications that is distributed on a Virtual Machine.|
|[OWASP GoatDroid](https://github.com/jackMannino/OWASP-GoatDroid-Project)|OWASP GoatDroid is a fully functional and self-contained training environment for educating developers and testers on Android security. GoatDroid requires minimal dependencies and is ideal for both Android beginners as well as more advanced users.|
|[OWASP iGoat](https://www.owasp.org/index.php/OWASP_iGoat_Project)|iGoat is a learning tool for iOS developers (iPhone, iPad, etc.).|
|[OWASP Mutillidae II](https://sourceforge.net/projects/mutillidae/)|OWASP Mutillidae II is a free, open source, deliberately vulnerable web-application providing a target for web-security enthusiast.|
|[OWASP Security Shepherd](https://www.owasp.org/index.php/OWASP_Security_Shepherd)|The OWASP Security Shepherd project is a web and mobile application security training platform.|
|[OWASP SiteGenerator](https://www.owasp.org/index.php/Owasp_SiteGenerator)|OWASP SiteGenerator allows the creating of dynamic websites based on XML files and predefined vulnerabilities (some simple, some complex) covering .Net languages and web development architectures (for example, navigation: Html, Javascript, Flash, Java, etc...).|
|[Pentest.Training](https://pentest.training/)|Pentest.Training offers a fully functioning penetration testing lab which is ever increasing in size, complexity and diversity. The lab has a fully functioning Windows domain with various Windows OS's. There is also a selection of Boot2Root Linux machines to practice your CTF and escalation techniques and finally, pre-built web application training machines.|
|[Pentesterlab](https://pentesterlab.com/exercises/from_sqli_to_shell)|This exercise explains how you can, from a SQL injection, gain access to the administration console, then in the administration console, how you can run commands on the system.|
|[Pentestit.ru](https://lab.pentestit.ru/)|Pentestit.ru has free labs that emulate real IT infrastructures. It is created for practicing legal pen testing and improving penetration testing skills. OpenVPN is required to connect to the labs.|
|[Peruggia](https://sourceforge.net/projects/peruggia/)|Peruggia is designed as a safe, legal environment to learn about and try common attacks on web applications. Peruggia looks similar to an image gallery but contains several controlled vulnerabilities to practice on.|
|[PicoCTF](https://picoctf.com/)|picoCTF is a computer security game targeted at middle and high school students. The game consists of a series of challenges centered around a unique storyline where participants must reverse engineer, break, hack, decrypt, or do whatever it takes to solve the challenge.|
|[Professor Messer](http://www.professormesser.com/)|Good free training video's, not only on Security but on CompTIA A+, Network and Microsoft related as well.|
|[Puzzlemall](https://code.google.com/archive/p/puzzlemall/)|PuzzleMall - A vulnerable web application for practicing session puzzling.|
|[Pwnable.kr](http://pwnable.kr/)|'pwnable.kr' is a non-commercial wargame site which provides various pwn challenges regarding system exploitation. while playing pwnable.kr, you could learn/improve system hacking skills but that shouldn't be your only purpose.|
|[Pwnos](http://www.pwnos.com/)|PwnOS is a vulnerable by design OS .. and there are many ways you can hack it.|
|[Reversing.kr](http://reversing.kr)|This site tests your ability to Cracking & Reverse Code Engineering.|
|[Ringzero](https://ringzer0team.com/challenges)|Challenges you can solve and gain points.|
|[Risk3Sixty](http://www.risk3sixty.com/free-information-security-training/)|Free Information Security training video, an information security examination and the exam answer key.|
|[Root Me](https://www.root-me.org/)|Hundreds of challenges and virtual environments. Each challenge can be associated with a multitude of solutions so you can learn.|
|[RPISEC/MBE](https://github.com/RPISEC/MBE)|Modern Binary Exploitation Course materials.|
|[RPISEC/Malware](https://github.com/RPISEC/Malware)|Malware Analysis Course materials.|
|[SANS Cyber Aces](http://www.cyberaces.org/courses/)|SANS Cyber Aces Online makes available, free and online, selected courses from the professional development curriculum offered by The SANS Institute, the global leader in cyber security training.|
|[Scene One](https://www.vulnhub.com/entry/21ltr-scene-1,3/)|Scene One is a pen testing scenario liveCD made for a bit of fun and learning.|
|[SEED Labs](http://www.cis.syr.edu/~wedu/seed/all_labs.html)|The SEED project has labs on Software, Network, Web, Mobile and System security and Cryptography labs.|
|[SentinelTestbed](https://github.com/dobin/SentinelTestbed)|Vulnerable website. Used to test sentinel features.|
|[SG6 SecGame](http://sg6-labs.blogspot.nl/2007/12/secgame-1-sauron.html)|Spanish language, vulnerable GNU/Linux systems.|
|[SlaveHack](http://www.slavehack.com/)|My personal favorite: Slavehack is a virtual hack simulation game. Great for starters, I've seen kids in elementary school playing this!|
|[SlaveHack 2 *BETA*](https://www.slavehack2.com/)|Slavehack 2 is a sequel to the original Slavehack. It's also a virtual hack simulation game but you will find features much closer to today's Cyber reality.|
|[Smashthestack](http://smashthestack.org/)|This network hosts several different wargames, ranging in difficulty. A wargame, in this context, is an environment that simulates software vulnerabilities and allows for the legal execution of exploitation techniques.|
|[SocketToMe](https://digi.ninja/projects/sockettome.php)|SocketToMe SocketToMe is little application for testing web sockets.|
|[SQLI labs](https://github.com/Audi-1/sqli-labs)|SQLI labs to test error based, Blind boolean based, Time based.|
|[Sqlilabs](https://github.com/himadriganguly/sqlilabs)|Lab set-up for learning SQL Injection Techniques.|
|[SQLzoo](http://sqlzoo.net/hack/)|Try your Hacking skills against this test system. It takes you through the exploit step-by-step.|
|[Stanford SecuriBench](https://suif.stanford.edu/~livshits/securibench/)|Stanford SecuriBench is a set of open source real-life programs to be used as a testing ground for static and dynamic security tools. Release .91a focuses on Web-based applications written in Java.|
|[The ButterFly - Security Project](https://sourceforge.net/projects/thebutterflytmp/?source=navbar)|The ButterFly project is an educational environment intended to give an insight into common web application and PHP vulnerabilities. The environment also includes examples demonstrating how such vulnerabilities are mitigated.|
|[ThisIsLegal](http://www.thisislegal.com/)|A hacker wargames site but also with much more.|
|[Try2Hack](http://www.try2hack.nl/)|Try2hack provides several security-oriented challenges for your entertainment. The challenges are diverse and get progressively harder.|
|[UltimateLAMP](http://www.amanhardikar.com/mindmaps/practice-links.html)|UltimateLAMP is a fully functional environment allowing you to easily try and evaluate a number of LAMP stack software products without requiring any specific setup or configuration of these products.|
|[Vicnum](http://vicnum.ciphertechs.com/)|Vicnum is an OWASP project consisting of vulnerable web applications based on games commonly used to kill time. These applications demonstrate common web security problems such as cross-site scripting, SQL injections, and session management issues.|
|[Vulnhub](https://www.vulnhub.com/)|An extensive  collection of vulnerable VMs with user-created solutions.|
|[Vulnix](https://www.rebootuser.com/?page_id=1041)|A vulnerable Linux host with configuration weaknesses rather than purposely vulnerable software versions.|
|[Vulnserver](http://www.thegreycorner.com/2010/12/introducing-vulnserver.html)|Windows-based threaded TCP server application that is designed to be exploited.|
|[W3Challs](https://w3challs.com)|W3Challs is a penetration testing training platform, which offers various computer challenges, in categories related to security|
|[WackoPicko](https://github.com/adamdoupe/WackoPicko)|WackoPicko is a vulnerable web application used to test web application vulnerability scanners.|
|[Web Attack and Exploitation Distro](http://www.waed.info/)|WAED is pre-configured with various real-world vulnerable web applications in a sandboxed environment. It includes pen testing tools as well.|
|[Web Security Dojo](https://sourceforge.net/projects/websecuritydojo/)|Web Security Dojo is a preconfigured, stand-alone training environment for Web Application Security.|
|[WebGoat](https://www.owasp.org/index.php/Category:OWASP_WebGoat_Project)|WebGoat is a deliberately insecure web application maintained by OWASP designed to teach web application security lessons. You can install and practice with WebGoat.|
|[Wechall](http://www.wechall.net/)|Focussed on offering computer-related problems. You will find Cryptographic, Crackit, Steganography, Programming, Logic and Math/Science. The difficulty of these challenges varies as well.|
|[XSS-game](https://xss-game.appspot.com/)|In this training program, you will learn to find and exploit XSS bugs. You'll use this knowledge to confuse and infuriate your adversaries by preventing such bugs from happening in your applications.|
|[XVWA](https://github.com/s4n7h0/xvwa)|XVWA is a badly coded web application written in PHP/MySQL that helps security enthusiasts to learn application security.|
