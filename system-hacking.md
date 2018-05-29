---
description: >-
  System hacking is one of the most important and sometimes ultimate goal of an
  attacker.
---

# System Hacking

#### Information at hand before system hacking stage

1. Footprinting: IP range, Namespace, Employees

2. Scanning module: target assessment, identified systems, identified services

3. Enumeration: Intrusive probing, user lists, security flaws



#### System Hacking Goals: 

1. Gaining Access - password cracking, social engineering

2. Escalating Privileges \(get other passwords\) - exploiting known system vulnerabilities

3. Executing Applications \(backdoors\) - Trojans, Spywares, Backdoors, Keyloggers

4. Hiding Files - Rootkits, Steganography

5. Covering Tracks - Clearing logs


# Cracking Passwords


* Password cracking techniques are used to recover passwords from computer systems
* Attackers use password cracking techniques to gain unauthorized access
* Most cracks are successful due to guessable passwords
* Types of password attacks 
   * Non-electronic attacks: Attacker does not need technical knowledge to crack password (looking at keyboard/screen, convincing people, trash bins etc)
   * Active Online Attacks: Attacker performs cracking by directly communicating with the victim machine (dictionary, brute force, rule based - some info known)
   * Passive Online Attacks: Performs cracking without communicating with party
   * Offline Attack: attacker copies password file and tried to crack it 
* Default passwords are set by the manufacturer
* Trojans can collect usernames and passwords and send to attacker, run in background
* Can use USB drive for a physical approach
* Hash Injection Attack: attacker injects compromised hash into local session then use it to validate network resource. Finds and extracts a logged on domain admin account hash
* Passive Online Attack: Wire Sniffing 
   * Packet Sniffer tools on LAN 
   * Capture data may include sensitive information such as passwords
   * Sniffed credentials are used to gain unauthorized access
* Rainbow table attack 
   * Precomputed table which contains word lists like dictionary files, brute force lists, and their hash values 
   * Compare the hashes 
   * Easy to recover passwords by comparing captured password hashes to precomputed tables
* Offline Attack: Distributed Network Attack (DNA)
   * A DNA technique is used for recovering passwords from hashes or password protected files using the unused processing power of machines across the network to decrypt passwords
* Microsoft Authentication
   * Windows stores passwords in the Security Accounts Manager (SAM) Database, or in the Active Directory database in domains. They are hashed.
   * NTLM Authentication
      * NTLM authentication protocol types 
      * LM authentication protocol
      * These protocols stores user’s password in the SAM database using different hashing methods 
   * Kerberos Authentication
      * Microsoft has upgraded its default authentication protocol
   * Password Salting
      * Random strings of characters are added to the password before calculating their hases
         * Advantage: salting makes it more difficult to reverse hashes 
* Use password crackers like L0phtCrack, Cain&Abel, RainbowCrack
* Enable SYSKEY with strong password to encrypt and protect the SAM database


# Escalating Privileges


* An attacker can gain access to the network using a non-admin user account, next step is to gain admin privileges 
* Privilege Escalation Using DLL Hijacking
   * If attackers place a malicious DLL in the application directory, it will be executed in place of the real DLL
* Resetting passwords using command prompt
   * An admin can reset passwords while an administrator
* Countermeasures: restrict interactive login privileges, use least privilege policy, implement multi-factor, run services as unprivileged accounts, patch systems regularly, use encryption technique, reduce amount of code, perform debugging


# Executing Applications


* Attackers execute malicious programs remotely in the victim's machine to gather information
   * Backdoors
   * Crackers
   * Keyloggers
   * Spyware
* Software like RemoteExec can remotely install software, execute programs/scripts
* There are hardware and software keystroke loggers (USB vs App)
* Spyware
   * Records user’s interaction
   * Hides its process
   * Hidden component of freeware program
   * Gather info about victim or organization
* GPS spyware also exists
* Countermeasures for Keyloggers
   * Pop-up blocker
   * anti-spyware/virus
   * Firewall software
   * Anti-keylogging software
   * Recognize phishing emails and delete
   * Choose new passwords for different online accounts
   * Avoid opening junk emails
* There are Anti-keyloggers out there
* Rootkits are programs that hide their presence and an attacker's malicious activities, granting them full access to the server or host at the time or in future
   * Typical Rootkit has backdoor programs, DDos  programs, packet sniffers, log-wiping utilities, IRC bots, etc
* 6 Types of Rootkits
   * Hypervisor Level Rootkit: Acts as hypervisor and modifies boot sequence of the computer to load the host OS as a virtual machine. 
   * Boot Loader level rootkit: replaces original boot loader with one controlled by attacker
   * Hardware/Firmware Rootkit: Hides in hardware devices or platform firmware which is not inspected for code integrity
   * Application level rootkit: replaces regular application binaries with fake trojan, or modifies the behavior of existing applications
   * Kernel Level Rootkit: Adds malicious code or replaces original OS kernel and device driver codes
   * Library Level Rootkits: Replaces original system calls with fake ones to hide information about attacker
* Detecting Rootkits
   * Integrity-Based detection: compares a snapshot of the filesystem,boot records, or memory
   * Signature-based technology: compares characteristics of all system processes and executable files with a database of known rootkit fingerprints
   * Heuristic/Behavior based detection: any deviations in the systems normal activity
   * Runtime Execution path profiling: compares runtime execution paths of all system processes before and after rootkit infection
   * Cross View-Based detection: enumerates key elements in the computer system such as system files, processes, and registry keys and compares them to an algorithm to generate a similar data set that does not rely on common APIs
* NTFS Data Stream
   * NTFS alternate data stream (ADS) is a windows hidden stream which contains metadata for the file such as attributes, word count, author name, access and modification time of files
   * Using NTFS stream, an attacker can almost completely hide files within the system.
   * You can hide a file side another file (trojan in a readme.txt)
   * Countermeasures: use a third party file integrity checker
* Steganography
   * Steganography is a technique of hiding a secret message within an ordinary message and extracting it at the destination
   * Utilizing a graphic image as a cover is the most popular method to conceal the data in files 
   * Attackers can use steganography to hide messages such as list of compromised servers, source code for the hacking tools, plans for future attacks, etc
   * Technical Steganography: invisible ink/microdots, physical methods to hide
   * Linguistic Steganography: Type that hides the message in another file
      * Semagrams: use of symbols to hide information
   * Least Significant bit insertion: The rightmost bit of a pixel is called the LSB
   * Masking and Filtering: Making technique hides data similar to watermarks on actual paper. Can be detection with simple statistical analysis. Mostly in grayscale images.
   * Algorithms and Transformation
      * Hide data in mathematical functions used in compression algorithms
      * Data is embedded by changing the coefficients of a transform of an image
   * Audio steganography - information in hidden frequency
* Steganalysis
   * Art of discovering and rendering covert messages using steganography. It attacks steganography efforts






# Covering Tracks


* Techniques used for covering tracks 
   * Disable Auditing: disabling audit features of target system
   * Clearing logs: attacker clears/delete the system log entries for their activities
   * Manipulating logs: Manipulates logs in a way they won't be caught in legal actions 
* If system is exploited with metasploit, attacker uses meterpreter shell to wipe logs


# Penetration Testing


* Password Cracking
* Privilege Escalation
* Execute Applications
* Hiding Files
* Covering Tracks


