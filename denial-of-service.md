# Denial of Service

> Objectives: Overview of DOS attacks and DDoS attacks, understanding the techniques of DoS/DDoS Attack Techniques, Understanding the Botnet Network, Understanding Various DoS and DDoS attack tools, DoS/DDoS countermeasures, Overview of DoS attack penetration testing

### DoS/DDoS Concepts

* Denial of Service \(DoS\) is an attack on a computer or network that reduces, restricts or prevents accessibility of system resource to its legitimate users
* Attackers flood a victim system with non-legitimate service requests 
* DDoS attack involves a multitude of compromised systems attacking a single targeted system \(botnet\)

## DoS/DDoS Attack Techniques

* Basic categories of the attacks
* Volumetric Attacks: consumes the bandwidth of the target network or service 
* Fragmentation: overwhelms target’s ability of reassembling fragmented packets
* TCP state-exhaustion attack: consumes connection state table present such as load balancers ,firewalls, app servers
* Application layer attack: consumes app resources or service making it unavailable to other legitimate users 
* SYN Attack
* Attacker sends a large number of SYN request to target server 
* Target machine sends back a SYN ACK in response to the request waiting for the ACK to complete session
* Attacker never sends ack 
* ICMP flood attack: type of DoS where perpetrators send a large number of ICMP packets causing the system to stop responding to legitimate TCP/IP requests 
* To protect yourself: set a threshold limit that invokes a ICMP protection feature
* Peer to Peer Attack: attackers instruct clients of p2p file sharing hubs to disconnect for their p2p network and connect to victims fake website. Attackers can launch massive DoS attacks and compromise websites
* Permanent Denial-of-Service Attack: Also known as phlashing, refers to attacks that cause irreversible damage to system hardware
* Unlike other DoS attacks,, it sabotages the system hardware 
* Application-Level Flood Attack: Application-level flood attacks results in the loss of services 
* Using this attack , attackers exploit weaknesses in programming source code to prevent in the application from processing legitimate requests
* Distributed Reflection Denial of Service \(DRDoS\)
* Also known as a spoofed attack, involves the use of multiple intermediary and secondary machines that contribute to the actual DDoS attack against the target machine or application

## Botnets

* Bots are software applications that run-automated tasks over the internet 
* A botnet is a huge network of compromised systems and can be used by an attacker to launch a DoS attack
* Scanning Methods for Finding Vulnerable Machines: Random Scanning, Hit-list scanning, topological scanning, local subnet scanning, permutation scanning 
* DoS and DDoS attack tools
* LOIC, GoldenEye

## Countermeasures

* Techniques 
* Activity Profiling
* Increases in activity levels, distinct clusters, average packet rate etc
* Changepoint detection
* Filters network traffic by IP addresses, targeted port numbers, stores traffic flow data in a graph that shows the traffic flow rate vs time 
* Wavelet-based signal analysis
* Analyzes network traffic in terms of spectral components. Divides incoming signal into various frequencies for analyzation
* DoS/DDoS countermeasure strategies 
* Absorbing the attack \(requiring additional resources\)
* Degrading services \(identify critical services and stop non-critical\)
* Shutting down the services
* Deflect Attacks: Honeypots act as an enticement for an attacker. Serve as a means for gaining information about attackers, stores their activities 
* Ingress filtering: protects from flooding attacks. Enables originator be traced to its true source
* Egress Filtering: scanning packet headers of IP address leaving a network. Ensures unauthorized or malicious traffic never leaves the internal network 
* Mitigate Attack: Load balancing, throttling
* Post-Attack Forensics 
* Analyze traffic patterns for new filtering techniques, analyze router, firewall, and IDS logs , can update load-balancing and throttling countermeasures 

