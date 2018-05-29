# Scanning Networks

## Overview of Networking Scanning

* Network scanning refers to a set of procedures for identifying hosts, ports, and services in a network
* Network scanning is one of the components of intelligence gathering and attacker uses to create a profile of the target organization
* Types of scanning
  1. Port scanning \(list the open ports and services\)
  2. Network Scanning \(lists IP addresses\)
  3. Vulnerability Scanning \(shows presence of known weaknesses\)
* TCP communication Flags \(controls transmission of data\)
* URG\(urgent\): Data contained in packet should be processed immediately
* PSH\(push\): Sends all buffered data immediately 
* FIN\(Finish\): There will be no more transmissions  
* ACK\(Acknowledgement\): Acknowledges receipts of a packet
* RST\(Reset\): Resets a connection
* SYN\(Synchronization\): Initiates a connection between hosts 

## Techniques for Live Systems

1. ICMP Scanning: Ping scans involves ICMP ECHO requests to a host. If the host is live, it will return an ICMP ECHO reply
2. Useful for locating active devices and if ICMP is passing through firewall
3. Ping sweep is used to determine the live hosts from a range of IP addresses 
4. Attackers calculate subnet masks using Subnet Mask Calculators
5. Attackers then use the Ping Sweep to create an inventory of live systems in the subnet

## Techniques for Ports

1. Simple Service Discovery protocol \(SSDP\) works in conjunction with UPnP to detect plug and play devices on a networks
2. Vulnerabilities in UPnP may allow attackers to launch Buffer overflow or DoS attacks
3. Scanning IPv6 networks are computationally less feasible due to larger search space \(128 bits\)
4. Network admins can use Nmap for network inventory, managing service upgrade schedules, and monitoring host or service uptime
5. Attacker uses Nmap to extract info such as live hosts on the network, services, type of packet filters/firewalls, operating systems and OS versions
6. Hping2/Hping3: command line network scanning and packet crafting tools for the TCP/IP protocol 
   1. It can be used for network security auditing , firewall testing 
7. TCP connect scan detects when a port is open by completing the three-way handshake 
   1. TCP connect scan establishes a full connection and tears it down sending a RST packet
   2. It does not require superuser privileges
8. Attackers send TCP probe packets with a TCP flags \(FIN,URG,PSH\) set or with no flags. No responses means port is open, RST means the port is closed
9. In Xmas scan, attackers send a TCP frame to a remote device with FIN, URG, and PUSH flags set
   1. Won’t work against any current version of Microsoft Windows
10. Attackers can an ACK probe packet with random sequence number, no responses means the port is filtered \(stateful firewall is present\) and RST response means the port is not filtered
11. A port is considered open if an application is listening on the port
    1. Most web servers are on port 80 and mail servers on 25
    2. One way to determine whether a port is open is to send a “SYN” \(session establishment\) packet to the port
       1. The target machine will then send back a SYN\|ACK packet is the port is open, and a RST \(reset\) packet if the port is closed
    3. IDLE Scan
       1. Attack a zombie computer. A zombie machine is one that assigns IPID packets incrementally. 
       2. Can retrieve IPID number for IP address spoofing
12. UDP Scanning: When UDP port is open ---There is not three-way TCP handshake for UDP scan. System does not respond with a me. The system does not respond with a message when the port is open. When UDP port is closed -- the system responds with ICMP port unreachable message. Spywares, Trojan Horses, and other apps use UDP ports
13. There are port scanners for mobile as well
14. Port scanning counter measures 
    1. Configure firewall, IDS rules to detect/block probes
    2. Run port scanning tools against hosts to determine firewall properly detects port scanning activity
    3. Ensure mechanism used for routing and filtering at the routers and firewalls respectively cannot be bypassed
    4. Ensure sure the router, IDS, and firewall firmware are updated
    5. Use custom rule set to lock down the network and block unwanted ports
    6. Filter all ICMP message at the firewalls and routers
    7. Perform TCP and UDP scanning 
    8. Ensure that anti scanning and anti spoofing rules are configured

## Various IDS Evasion Techniques

1. Evasion techniques: fragmented IP packets, spoofing IP address, source routing, connect to proxy servers 
2. Lower the frequency of packets, split into parts

## Understanding Banner Grabbing

1. An attacker uses banner grabbing techniques to identify network hosts running versions of applications and OSs with known exploits. 
2. Banner grabbing or OS fingerprinting is the method to determine the operating system running on a remote target system. There are two types
   1. Active Banner Grabbing: specifically crafted packets are sent to remote OS and responses are noted, then compared with a database to determine OS. 
   2. Passive Banner Grabbing: Sniffing the network traffic. Banner grabbing from error message, and banner grabbing from page extensions \(stealthy\)
3. Identifying OS’s allow an attack to figure out the vulnerabilities running on a remote target system
4. An attacker uses banner grabbing to identify the OS used on the target host and thus determine the system vulnerabilities
5. Tools like Netcat reads and writes data across network connections
6. Countermeasures for banner grabbing
   1. Display False Banners
   2. Turn off unnecessary services
   3. Use ServerMask
7. Hiding file extensions from web pages

## Vulnerability Scanning

1. Vulnerability scanning identifies vulnerabilities and weaknesses of a system
2. Nessus is the vulnerability and configuration assessment product

## Network Mapping

1. A network diagrams helps in analyzing complete network topology. 
2. Drawing target’s network diagram shows logical or physical path to a potential target. Shows network and its architecture to attacker

## Understanding Proxies

1. Proxy servers serves as an intermediary for connecting with other computers
   1. Hides the source IP 
   2. Chain multiple proxies to avoid detection
2. Many hackers use proxies to hide his/her identity so they cannot be traced. Logs record proxy’s address rather than the attacker’s
3. Burp suite includes an intercepting proxy, which lets you inspect and modify traffic between your browser and target app. Popular.
4. Anonymizers removes all identifying information from a user’s computer while user surfs internet
5. Tails is a live operating system, that user can start on any computer from a DVD, USB stick, or SD card
6. Can use HPING2 to IPSpoof
7. IP spoofing counter measures
   1. Encrypt all network traffic
   2. Use multiple firewalls
   3. Do not rely on IP-based authentication
   4. Use random initial sequence number
   5. Ingress filtering: use routers and firewalls at network perimeter to filter incoming packets that appear to come from an internal IP address
   6. Egress filtering: Filter all outgoing packets with an invalid local IP address as source address

## Penetration Testing: Scanning

1. Pen testing a network determines the network's security posture by identifying live systems, discovering open ports, associating services and grabbing system banners to simulate a network hacking attempt
2. Here’s how to conduct a pen-test of a target network
   1. Host Discovery: detect live hosts on the target network. It is difficult to detect live hosts behind a firewall \(Nmap, Angry IP scanner, colasoft\)
   2. Port Scanning: Check for open ports \(Nmap, Netscan\)
   3. Banner Grabbing or OS fingerprinting: determine the OS running on the target host
   4. Scan the network for vulnerabilities \(nessus\)
   5. Draw Network Diagrams that help you understand the logical connection 
   6. Prepare Proxies: Hides yourself from detection
   7. Document all findings

