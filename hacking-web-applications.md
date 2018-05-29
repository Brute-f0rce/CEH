# Hacking Web Applications

> Objectives: Understanding Web Application concepts, understanding web app threats, understanding web app hacking methodology, web app hacking tools, understanding web app countermeasures, web app security tools, overview of web app pen testing



### Web App Concepts


   * Web apps provide an interface between end users and web servers through a set of pages 
   * Web tech such as Web 2.0 support critical business functions such as CRM, SCM
  



## Web App Threats


   * Cookie Poisoning: by changing info in a cookie, attackers can bypass authentication process
   * Directory Traversal: Gives access to unrestricted directories
   * Unvalidated Input: Tempering http requests, form field, hidden fields, query strings, so on. Example of these attacks include SQL injection, XSS, buffer overflows
   * Cross Site Scripting: Bypassing client-ID mechanisms to gain privileges, injecting malicious scripts into web pages
   * Injection Flaws: Injecting malicious code, commands, scripts into input gates of flawed apps
   * SQL Injection: type of attack where attackers inject SQL commands via input data, and then tamper with the data
   * LDAP Injection to obtain direct access to databases behind LDAP tree
   * Parameter/Form tampering: Manipulates the parameters exchanged between client and server to modify app data such as user cred and permissions. 
   * DoS: intended to terminate operations
   * Broken Access Control: method in which attacker identifies a flaw related to access control and bypasses the authentication, then compromises the network 
   * Cross-Site Request Forgery: attack in which an authenticated user in made to perform certain tasks on the web app that an attacker chooses. 
   * Information Leakage: can cause great losses to company. 
   * Improper Error Handling : important to define how a system or network should behave when an error occurs. Otherwise, error may provide a chance for an attacker to break into the system. Improper error can lead to DoS attack 
   * Log Tampering: Attackers can inject, delete, or tamper with app logs to hide their identities
   * Buffer Overflow: Occurs when app fails to guard its buffer property and allows writing beyond its maximum size 
   * Broken Session management:  When credentials such as passwords are not properly secured
   * Security Misconfigurations
   * Broken Account Management: account update, forgotten/lost password recovery/reset
   * Insecure Storage: Users must maintain the proper security of their storage locations
   * Platform Exploits: Each platform (BEA WEBLOGIC, COLD FUSION) has its own various vulnerabilities
   * Insecure Direct Object References: When developers expose objects such as files, records, result is insecure direct object reference
   * Insecure Cryptographic Storage: Sensitive data should be properly encrypted using cryptographic. Some cryptographic techniques have inherent weaknesses however
   * Authentication Hijacking: Once an attacker compromises a system, user impersonation can occur
   * Network Access attacks: can allow levels of access that standard HTTP app methods could not grant 
   * Cookie Snooping
   * Web Services Attack: Web services are based on XML protocols such SOAP (simple object access protocol) for communication between web services
   * Insufficient Transport layer protection
   * Hidden Manipulation
   * DMZ protocol attacks
   * Unvalidated redirects and forwards
   * Failure to restrict URL access 
   * Obfuscation Application
   * Security Management Exploits
   * Session Fixation Attack: Attacker tricks user to access a genuine web server using an explicit session ID value. Attacker assumes identity of the victim and exploits credentials on the server
   * Malicious File Execution


## Hacking Methodology


   * Hackers first footprint the web infrastructure
   * Server discovery, location
   * Service Discovery: Scan Ports
   * Banner grabbing: footprinting technique to obtain sensitive info about target. They can analyze the server response to certain requests (server identification)
   * Detecting Web App Firewalls and Proxies on target site 
   * Use Trace method for proxy, and cookie response for a firewall
   * Hidden Content discovery:  Web spidering automatically finds hidden content
   * Launch web server attack to exploit identified vulnerabilities, launch DoS
   * Attacking authentication mechanism
   * Username enumeration
   * Verbose failure messages. Predictable user names
   * Cookie Exploitation
   * Poisoning(tampering), Sniffing Replay
   * Session Attack
   * Session prediction, brute forcing, poisoning
   * Password Attack: 
   * Guessing, brute force 
   * Authorization attack: finds legitimate accounts then slowly escalates privileges
   * Attack Session Management Mechanism: involves exchanging sensitive info between server and clients. If session management is insecure, attacker can take advantage of flawed session management session
   * Bypassing authentication controls 
   * Perform injection attacks: exploiting vulnerable input validation mechanism implement
   * Attack Data connectivity: attacking database connection that forms link between a database server and its client software
   * Connection string injection: attacker injects parameters in a connection string. CSPP attacks (Connection String Parameter Attacks).
   * Connection Pool DoS: Attacker examines connection pooling settings and constructs large SQL query, and runs multiple queries simultaneously to consume all connections 


## Countermeasures
   * Encoding Schemes: employing encoding schemes for data to safely handle unusual characters and binary data in the way you intent 
   * Ex. unicode editing 
   * How to defend against SQL Injection Attacks 
   * Limit length of user input 
   * Perform input validation
   * How to defend against xss
   * Validate all headers, cookies, strings, form fields. Use firewall
   * How to configure against DoS
   * Configure firewall to deny ICMP traffic access
   * Perform thorough input validation
   * How to defend against web services attack
   * Multiple layer protection


## Tools


   * N-Stalker is effective suite of web security assessment tools 


## Pen Testing


   1. Info Gathering 
   2. Config Management Testing
   3. Authentication Testing 
   4. Session Management testing
   5. Authorization Testings 
   6. Data Validation Testing
   7. DoS Testing
   8. Web Services Testing
   9. AJAX Testing 
   10. Use Kali Linux tools
   1. Metasploit
