# Sniffing

> Objectives: Overview of sniffing concepts, understanding MAC attacks, Understanding DHCP attacks, understanding ARP poisoning, Understanding MAC spoofing attacks, Understanding DNS poisoning, Sniffing tools, Sniffing countermeasures, Understanding various techniques to detect sniffing, overview of sniffing pen testing

## Sniffing Concepts

* Sniffing is a process of monitoring and capturing all data packets passing through a given network using sniffing tools (form of wire tap)
   * Many enterprises switch ports are open 
   * Anyone in same physical location can plug into network with ethernet
* How a sniffer works
   * Sniffer turns on the NIC of a system to the promiscuous mode that it listens to all the data transmitted on its segment 
* Each computer has a MAC address and an IP address 
* Passive sniffing means through a hub (involves sending no packets), on a hub traffic is sent to all ports 
   * Most modern networks use switches
* Active Sniffing: Searches for traffic on a switched LAN by actively injecting traffic into the LAN. Involves injecting address resolution packets (ARP) into the network 
* Protocols vulnerable to sniffing:
   * HTTP, Telnet and Rlogin, POP, IMAP, SMTP and NNTP
* Sniffers operate at the Data Link layer of the OSI model   
* Hardware Protocol Analyzer: equipment that captures signals without altering the traffic in a cable segment 
   * Can be used to monitor traffic. Allows attacker to see individual data bytes
   * Span Port: A port which is configured to receive a copy of every packet that passing through a switch
   * Wiretapping: Process of monitoring telephone and internet convo’s by third party
   * Via connecting a listening device (hardware or software) to the circuit 
   * Active Wiretapping: Monitors, records, and injects something into the communication or traffic 
   * Passive Wiretapping:  It only monitors and records the traffic and gain knowledge of the data it contains 
   * Lawful interception: legally intercepting data communication
   
   
 
# MAC Attacks


   * Each switch has a fixed size dynamic content addressable memory (CAM table)
   * CAM table stores information such as MAC address available on physical ports 
   * If CAM table is flooded with more MAC address it can hold, then the switch turns into a HUB
   * Attackers exploit this 
   * Switch Port Stealing: uses mac flooding to sniff the packets
   * How to defend against MAC attacks: use a port security to restrict inbound traffic from only a selected set of mac addresses and limit MAC flooding attacks




# DHCP Attacks


   * DHCP servers maintain TCP/IP configuration information (provides leases)
   * DHCP starvation attack: attacker broadcasts forged DHCP requests and tries to lease all DHCP addresses available in the DHCP scope
   * As a result, legitimate user is unable to obtain or renew an IP address
   * Rogue DHCP: rogue DHCP server in network and responds to DHCP requests with bogus IP addresses 
   * How to defend against DHCP starvation and Rogue Server Attack: Enable port security for DHCP starvation, and enable DHCP snooping that allows switch to accept DHCP transactions from a trusted port


# ARP Poisoning


   * Address Resolution Protocol (ARP) is a stateless protocol used for resolving IP address to machine (MAC) addresses 
   * All network devices broadcasts ARP queries in the network to find machine’s MAC address
   * When one machine needs to communicate with another, it looks up to the ARP table. If it’s not there, the ARP_REQUEST is broadcasted over the network 
   * ARP packets can be forged 
   * ARP spoofing involves constructing large number of forged ARP requests 
   * Switch is set in ‘forwarding mode’ after the ARP table is flooded with spoofed ARP replies 
   * Attackers flood a target computer’s ARP cache with forged entries, which is also known as poisoning 
   * ARP spoofing is a method of attacking an ethernet LAN
   * Using Fake ARP messages, an attacker can divert all communications between two machines so that all traffic is exchanged via his/her PC
   * ARP Tools: Cain & Abel, WinArpAttacker
   * How to defend: Implement dynamic ARP inspection, DHCP Snooping, XArp spoofing detection


# Spoofing


   * Attacker can sniff network for MAC addresses, then spoof them to receive all the traffic destined for the user. Allows allows attacker to gain access to the network 
   * IRDP spoofing: ICMP Router discovery protocol allows host to discover the IP address of active routers. 
   * Attacker sends spoofed IRDP router advertisement message to the host on the subnet, causing it to change its default router 
   * How to defend: DHCP snooping, Dynamic ARP inspection, IP source guard


# DNS Poisoning


   * DNS poisoning is a technique that tricks a DNS server into believing that it has received authentication when it really has not 
   * Results in substitution of a false IP address 
   * Attacker can create fake DNS entries 
   * Intranet DNS spoofing: must be connected to LAN and able to sniff. Works well against switches with ARP poisoning the router. 
   * Intranet DNS spoofing attacker infects machine with trojan and changes DNS IP to that of attacker
   * Proxy Server DNS poisoning: attacker sends a trojan to machine that changes hosts proxy server settings in internet explorer to that of the attacker’s and redirect to fake website 
   * DNS Cache Poisoning: Refers to altering or adding forged DNS records into DNS resolver cache so that a DNS query is redirected to a malicious site
   * How to defend: resolve all DNS queries to local DNS server, Block DNS requests from going to external servers, configure firewall to restrict external DNS lookup, Implement IDS and deploy correct, Implement DNSSEC


# Sniffing Tools 
- Wireshark
  

# Counter-Measures
   * Restrict physical access
   * Use encryption 
   * Permanent add MAC address to the gateway to the ARP cache
   * Use static IP addresses
   * Turn off network ID broadcasts
   * Use IPV6 
   * Use HTTPS instead of HTTP
   * Use switch than Hub 
   * Use SFTP instead of FTP


# Sniffing Detection Techniques


   * Runs IDS and notice if mac address of certain machines have changed
   * Check which machines are running in the promiscuous mode 
   * Promiscuous mode allows a network device to intercept and read each network packet
   * Only a machine in promiscuous mode cache the ARP information 
   * A machine in promiscuous mode replies to the ping message as it has correct information about the host sending a ping request 


# Sniffing Pen Testing 


   * Sniffing pen test is used to check if the data transmission from an org is secure from sniffing and interception attacks  







