# Hacking Mobile Platforms

> Objectives: Understanding Mobile platform attack vectors, understanding various Android Threats and Attacks, Understanding various iOS threats and attacks, understanding various Windows Phone OS Threats and Attacks, Understanding various blackberry threats as attacks, understanding mobile device management \(MDM\), Mobile Security Guidelines and Security Tools, Overview of Mobile Pen Testing


## Mobile Platform Attack Vectors


   * OWASP Mobile Top 10 Risks
         * Insecure Data Storage
         * Assumption malware won't enter system. Jailbreaking bypasses encryption 
         * Unintended Data Leakage
         * When a user places sensitive data in a location accessible to other apps 
         * Broken Cryptography
         * Weak encryption algorithms. Users should use ARS or 3DES algoirhms 
         * Security Decision via Untrusted Inputs
         * Apps use protection mechanisms dependent on input values (cookies, environmental variables, hidden form fields), but these input values can be altered by an attacker to bypass protection mechanism 


   * Lack of Binary Protections: Lack of binary protections in a mobile app exposes it and owner to wide variety of technical and business risks if insecure. Must use countermeasures such as 
         * Secure coding techniques 
         * Jailbreak detection controls
         * Checksum controls
         * Certificate Pinning Controls


   * Anatomy of a Mobile Attack        
         * The device -> the network > the data center 
         * Clicking Jacking: tricking users to click something different than what they think they are clicking. Attackers obtain sensitive info or take control of device
         * Framing: a webpage integrated into another webpage using iFrame elements in HTML
         * Drive By Downloading: unintended download of software from the internet. Android is affected by this attack
         * Man in the Middle: Attacker implants malicious code on victim's mobile device 
         * Buffer Overflows: writing data to buffer suites ,
         * Data Caching: Caching in mobile devices used to interact with web apps, attackers attempt to exploit the data caches
         * Phone/SMS-Based attacks
         * Baseband attacks: exploiting vulnerabilities in phone’s GSM/3GPP baseband processor, which sends/receives signals to towers
         * SMiShing - Type of phishing where attacker uses SMS text message to link to malicious site
         * RF (radio frequency) attacks: exploit vulnerabilities found on different peripheral communication channels normally used in nearby device-device communications
         * Application-based attacks
         * Sensitive Data Storage: Some apps employ weak security in their database architecture, which make them targets for attacker to hack and steal sensitive user information stored on them 
         * No encryption/weak encryption: apps transmit data unencrypted or weakly encrypted are susceptible to attack such as session hijacking 
         * Improper SSL validation: Security Loopholes in apps SSL validation process may allow attackers to circumvent the data security
         * Config Manipulation: Apps may use external files and libraries, modifying those entities or affecting apps’ capability of using those results in a config manipulation attack  
         * Dynamic Runtime Injection: attackers manipulate and abuse the runtime of an app to circumvent security locks, logic checks, access privileges parts of an app, and steal data
         * Unintended Permissions: Misconfigured apps can at times open doors to attackers by providing unintended permissions
         * Escalated privileges: Attackers engage in privilege escalation attacks , which take advantage of design flaws, programming errors, bugs, or config oversights to gain access to resources 
         * OS Based Attacks
         * iOS Jailbreaking: removing security mechanisms set by apple to prevent malicious code 
         * Android Rooting: allows users to attain privileged control (root access) within android's subsystem. 
         * Passwords and data accessible 
         * Carrier-loaded software: pre installed software or apps on devices may contain vulnerabilities that an attacker can exploit to perform malicious activities such as delete, modify, or steal data on the device, eavesdrop on calls
         * Zero-day exploits: launch an attack by exploiting a previously unknown vulnerability in a mobile OS or app.
         * The Network based point of attacks
         * WiFi (weak encryption or no encryption)
         * Rogue Access Points: attackers install illicit wireless access point by physical means, which allows them to access a protected network by hijacking the connections of network users 
         * Man in the Middle (MITM): attackers eaves on existing network connections between two systems 
         * SSLStrip: Type of MITM attack which exploits vulnerabilities in the SSL/TLS implementation
         * Session Hijacking: Attacker steal valid session ID’s 
         * DNS Poisoning: Attackers exploit DNS servers, redirect website users to another website of the attacker’s choice
         * Fake SSL certificates: Fake SSL certs represent another kind of MITM attacks. Attacker issues a fake SSL cert to intercept traffic on a supposedly secure HTTPS connection
         * The Data Center
         * Two main point of entry: web server and a database
         * Web server-based attacks
         * Platform vulnerabilities: Exploiting vulnerabilities in the OS, Server software, or app modules running on the web server
         * Server Misconfiguration 
         * XSS
         * CSRF
         * Weak Input Validation
         * Brute-Force Attacks
         * Database Attacks
         * SQL Injection
         * Data Dumping 
         * OS command execution 
         * Privilege Escalation
         * Sandboxing: helps protect systems and users by limiting the resources the app can access in the mobile platform; however, malicious apps may exploit vulnerabilities 
 


## Hacking Android OS 

   * The device administration API provides device administration features at the system level
         * Rooting allows android users to attain privileged control (root access) 
         * Involves exploiting security vulnerabilities in the device firmware 
         * Securing Android Devices: 
         * Enable screen locks
         * Don't root your device
         * Download apps only from android market
         * Keep device updated with google software
         * Do not directly download APK files
         * Update OS regularly 
         * Use free protector app
         * Google Apps device policy: allows domain admin to set security policies for your android device


## Hacking iOS


  * Layers of the OS
         * Cocoa Touch: key framework that help in building iOS app. Defines appearance, basic services such as touch
         * Media: contains graphics, audio, and video technology experienced in apps
         * Core Services: contains fundamental system services for apps
         * Core OS: low level feature on which most on which most other technologies are built 
         * Tethered (kernel will be patched upon restart) and untethered



## Hacking Windows Phone




## Hacking Blackberry


   * Malicious Code Signing: Blackberry apps must be signed by RIM. Attacker can obtain code-signing keys for a malicious app and post it in the store
         * JAD file exploits: A jad file allows a user to go through app details and decide whether to download the app. However, attackers created spoofed .jad files to trick user
         * PIM Data Attacks: PIM (personal information manager) includes address , books, calendars, tasks
         * Malicious apps can delete or modify this data
         * TCP/IP Connections Vulnerabilities: If the device firewall is off, signed apps can open TCP connections without the user being prompted. 
         * Malicious apps create a reverse connection with the attacker enabling him to use the infected device as a TCP proxy and gain access to organization’s internal resources


## Mobile Device Management (MDM)

   * MDM provides platforms for over the air or wired distribution of application, data and configuration settings for all types of mobile devices, smartphones, tablets, etc.
         * Helps implementing enterprise-wide policies to reduce support cost s
         * Can manage both company-owned and BYOD devices

## Mobile Security Guidelines and Tools

   * General Guidelines
   * Do not load too many apps and avoid auto-upload of photos to social networks
   * Perform a security assessment of the Application Architecture
   * Maintain configuration control and management 
         * Install apps from trusted app stores
         * Securely wipe or delete the data disposing of the device 
         * Ensure bluetooth is off by default
         * Do not share location within GPS enabled apps
         * Never connect two separate networks such as Wi-Fi and Bluetooth simultaneously



