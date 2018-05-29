# Hacking Web Servers

> Objectives: Understanding web server concepts, understanding web server attacks, understanding webserver attack methodology, webserver attack tools, countermeasures against web server attacks, overview of patch management, webserver security tools, overview of web server penetration testing

### Web server Concepts

* A web server is a program that hosts websites, attackers usually target software vulnerabilities and config errors to compromise the servers
* Nowadays, network and OS level attacks can be well defended using proper network security measures such as firewalls, IDS, etc. Web servers are more vulnerable to attack since they are available on the web
* Why are web servers compromised
* Improper file/directory permissions
* Installing the server with default settings
* Unnecessary services enabled
* Security conflicts 
* Lack of proper security policy
* Improper Authentication
* Default Accounts
* Misconfigs
* Bugs in OS 
* Misconfigured SSL certificates
* Use of self-signed certs
* IIS \(internet information service\) is a webserver application developed by Microsoft for Windows.

## Webserver Attacks

* DoS/DDoS Attacks: Attackers may send numerous fake requests to the web server which results in the web server crash or become unavailable 
* May target high-profile web servers
* DNS Server Hijacking: Attacker compromises DNS server and changes the DNS settings so that all requests coming towards the target web server is redirected to another malicious server
* DNS Amplification Attack: Attacker takes advantage of DNS recursive method of DNS redirection to perform DNS amplification attack
* Attacker uses compromised PCs with spoofed IPs to amplify the DDoS attack by exploiting the DNS recursive method
* Directory Traversal Attack: Attackers use ../ to sequence to access restricted directories outside of the web server root directory \(trial and error\)
* Man-in-the middle Sniffing Attack: MITM attacks allow an attacker to access sensitive info by intercepting and altering communications
* Phishing Attacks: Attacker tricks user to submit login details for website that looks legit but it's not. Attempts to steal credentials
* Website Defacement: intruder maliciously alters visual appearance of a web page by inserting offending data. Variety of methods such as MYSQL injection
* Web Server Configuration: Refers configuration weaknesses in infrastructure such as directory traversal
* HTTP Responses Splitting Attack: involves adding header data into the input field so that the server split the response into two responses. The attack can control the second response to redirect user to malicious website whereas the other response will be discarded by browser
* Web Cache Poisoning: An attacker forces the web server’s cache to flush its actual cache content and sends a specially crafted requests, which will be stored in cache 
* SSH Bruteforce Attack: SSH protocols are used to create encrypted SSH Tunnel between two hosts. Attackers can brute force the SSH login credentials
* Webserver Password Cracking: An attacker tries to exploit the weaknesses to hack well-chosen passwords \(social engineering, spoofing, phishing,etc\).
* Web Application Attacks: Vulnerabilities in web apps running on a webserver provide a broad attack path for webserver compromise
* SQL Injection, Directory Traversal, DoS, Cookie Tampering, XSS Attack, Buffer Overflow, CSRF attack, 

## Attack Methodology:

Information Gathering, Webserver Footprinting, Mirroring Website, Vulnerability Scanning, Session hijacking, Hacking webserver passwords

* Information Gathering: Robots.txt file contains list of web server directory and files that website owner wants to hide from web crawlers
* .Use tools such as burp suite to automate session hijacking 

## Webserver Attack Tools

* Metasploit: Encapsulates an exploit. 
* Payload module: carries a backpack into the system to unload
* Metasploit Aux Module: Performing arbitrary, one-off actions such as port scanning, DoS, and fuzzing
* NOPS module: generate a no-operation instructions used for blocking out buffers
* Password Cracking: THC Hydra, Cain & Abel

## Countermeasures

* An ideal web hosting network should be designed with at least three segments namely: The internet segment, secure server security segment \(DMZ\), internal network 
* Placed the web server in DMZ of the network isolated from the public network as well as internal network
* Firewalls should be placed for internal network as well as internet traffic going towards DMZ
* Patches and Updates: Ensure service packs, hotfixes, and security patch levels are consistent on all domain controllers
* Protocols: block all unnecessary ports, ICMPs, and unnecessary protocols such as NetBIOS and SMB. Disable WebDav if not used 
* Files and Directories: delete unnecessary files, disable serving of directory listings, disable serving certain file types , avoid virtual directories
* Detecting Hacking Attempts: Run scripts on the server that detects any changes made in the existing executable file. Compare hash values of files on server to detect changes in codebase. Alert user upon any change in detection
* Secure the SAM \(stand-alone servers only\)
* Defending against DNS hijacking: choose ICANN accredited registrar. Install anti-virus 

## Patch Management

* Hotfixes are an update to fix a specific customer issue
* A patch is a small piece of software designed to fix problems 
* Hotfixes and Patches are sometimes combined for server packs
* Patch Management is a process used to ensure that the appropriate patches are installed on a system to help fix known vulnerabilities 
* Before installing a patch, verify the source. 
* Patch Management Tools: MBSA \(Microsoft baseline Security Analyzer\) - checks for available updates to OS, SQL Server, .NET framework etc

Webserver Security Tools

* Syhunt helps automate web app security testing and guards. N Stalker is a scanner to search vulnerabilities

Webserver Pen Testing

* Used to identify, analyze, and report vulnerabilities 

