# Evading IDS, Firewalls, and Honeypots

> Objectives: Understanding IDS, Firewall, and Honeypot Concept : IDS, Firewall and Honeypot Solutions: Understanding different techniques to bypass IDS : Understanding different techniques to bypass firewalls, IDS/Firewall Evading Tools : Understanding different techniques to detect honeypots : Overview of IDS and Firewall Penetration Testing

### IDS, Firewall, and Honeypot Concepts

* An IDS inspects all inbound and outbound network traffic for suspicious patterns that may indicate a network security breach 
  * Checks traffic for signatures that match known intrusion patterns
  * Anomaly Detection \(behavior detection\)
  * Protocol Anomaly Detection
  * Indications of Intrusions
  * System Intrusions
  * Presence of new files/programs
  * Changes in file permissions
  * Unexplained changes in file size
  * Rogue Files
  * Unfamiliar file names in directories
  * Missing files
  * Network Intrusions
  * Repeated probes of the available services on your machines
  * Connections from unusual locations
  * Repeated login attempts from remote hosts
  * Arbitrary data in log files
  * Firewall Architecture 
  * Bastion Host
  * Computer system designed and configured to protect network resources from attack
  * Screened Subnet
  * Also known as the DMZ contains hosts that offer public services. DMZ zone only responds to public requests, and has no hosts accessed by the private network
  * Multi-homed Firewall
  * A firewall with two or more interfaces
  * DeMilitarized Zone \(DMZ\)
  * A network that serves as a buffer between the internal secure network and insecure internet 
  * Can be created using firewall with three or more main network interfaces
  * Types of Firewall
  * Packet Filters: works on the network layers of OSI. Can drop packets if needed
  * Circuit Level Gateways: Works at the sessions layer. Information passed to a remote computer through a circuit-level gateway appear to have originated from the gateway. They monitor requests to create sessions, and determines if the session will be allowed. They allow or prevent data streams    
  * Application Level Gateways: App-level proxies can filter packets at the application later of the OSI
  * Stateful Multilayer Inspection Firewalls: combines the aspects of the other three types of firewalls
  * Honeypot
  * Information system resource that is expressly set up to attract and trap people who attempt to penetrate an organization's network 
  * Honeypot can log port access attempts, monitor attacker’s keystrokes, show early signs etc
  * 2 Types of Honeypots
  * Low-interaction Honeypots: simulate only a limited number of services and apps. Cannot be compromised
  * High-interaction Honeypots: simulates all services and apps. Can be completely compromised by attackers.
  * Captures complete information about an attack vector such attack techniques

## IDS Tools

* Snort

## Evading IDS

* Insertion Attack: IDS blindly believes and accepts the packet
  * Evasion: End system accepts a packet that an IDS rejects. Attacker is exploiting the host computer
  * DoS Attack: Attackers intrusion attempts will not be logged
  * Obfuscating: encoding the attack payload in a way that the target computer understands but the IDS will not \(polymorphic code, etc\)
  * False Positive Generation: Attackers w/ knowledge of the target IDS, craft packets just to generate alerts. Causes IDS to generate large number of false positive alerts. Then use it to hide real attack traffic
  * Session Splicing
  * Unicode Evasion Technique: Attackers can convert attack strings to unicode characters to avoid pattern and signature matching at the IDS
  * Fragmentation Attack: Attackers will keep sending fragments with 15 second delays until all attack payload is reassembled at the target system
  * TTL attacks require attacker to have a prior knowledge of the topology of the victim's network
  * Invalid RST Packets
  * Uses a checksum to communicate with host even though the IDS thinks that communication has ended
  * Urgency Flag
  * A URG flag in the TCP header is used to mark the data that requires urgent processing 
  * Many IDS do not address the URG pointer
  * Polymorphic Shellcode: Most IDSs contains signatures for commonly used strings within shellcode. This can be bypassed by using encoded shellcode containing a stub that decodes the shell code
  * App Layer Attacks: IDS cannot verify signature of a compressed file

## Evading Firewalls

* Port Scanning is used to identify open ports and services running on these ports 
  * Open ports can be further probed to identify the version of services, which helps in finding vulnerabilities in these services
  * Firewalking: A technique that uses TTL values to determine gateway ACL filters 
  * Attacker sends a TCP or UDP packet to the targeted firewall with a TTL set to one hop greater
  * Banner Grabbing: Banners are service announcements provided by services in response to connection requests, and often carry vendor version information
  * IP address spoofing to a trusted machine
  * Source Routing: Allows sender of a packet to partially or completely specify the route of a packet through a network, going around a firewall
  * Tiny Fragments: Forcing some of the TCP packet’s header info into the next fragment
  * ICMP Tunneling: Allows tunneling a backdoor shell in the data portion of ICMP echo packets
  * Ack Tunneling: Allows tunneling a backdoor application with TCP packets with the ACK bit set
  * HTTP Tunneling Method: allows attackers to perform various internet tasks despite restrictions imposed by firewalls. Method can be implemented if the target company has a public web server with port 80 used for HTTP traffic 

## Detecting Honeypots

* Attackers craft malicious probe packets to scan for services such as HTTP over SSL, SMTP over SSL, and IMAP
  * Ports that show a particular service running but deny a three-way handshake indicate the presence of a honeypot 

## Countermeasures

* Shut down switch ports associated with the known attack hosts
  * Reset \(RST\) malicious TCP sessions

