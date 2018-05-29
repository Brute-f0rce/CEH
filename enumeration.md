# Enumeration

## Enumeration Concepts

* In the enumeration phase, attacker creates active connections to system and performs directed queries to gain more information. Uses this information to identify system attack points and perform password attacks
   * Conducted in an intranet environment
* Techniques for Enumeration
   * Extract user names using email IDs 
   * Extract user names using SNMP
   * Extract user groups from windows
   * Extract information using the default passwords
   * Brute force active directions
   * Extract information using DNS Zone Transfer
* Popular Ports to Enumerate
   * TCP/UDP 53 - DNS Zone Transfer
   * TCP/UDP 135 - Microsoft EPC Endpoint Manager
   * UDP 137 - NetBIOS Name Service (NBNS)
   * TCP 139 - SMB over NetBIOS
   * TCP/UDP 445 - SMB over TCP (direct host)
   * UDP 161 - Simple Network Management Protocol (SNMP)
   * TCP/UDP 389 - Lightweight Directory Access Protocol (LDAP)
   * TCP/UDP 3268 - Global Catalog Service
   * TCP 25 - Simple Mail Transfer Protocol (SMTP)
   * TCP/UDP 162 - SNMP Trap
   
   
# NetBIOS Enumeration


* NetBIOS name is a unique 16 ASCII string used to identify the network devices  (15 of it are device name, 16 is reserved for service or name record type)
* Nbtstat utility displays NetBIOS over TCP/IP protocol statistics, NetBIOS name tables/cache
* Net View utility is used to obtain a list of all the shared resources of remote hosts or workgroup


# SNMP Enumeration (simple network Management protocol enumeration)


* SNMP enumeration is a process of enumerating user accounts and devices on a target system using SNMP 
* SNMP contains a manager and agent. Agends are embedded on every network, manager installed on a seperate computer 
* SNMP has two passwords
   * Attacker uses default community strings to extract info 
   * Uses it to extract information about network resources such as hosts, routers, devices, shares
* Management Information Base (MIB)
   * MIB is a virtual database containing formal description of all the network objects managed using SNMP


# LDAP Enumeration

* LDAP is an internet protocol for accessing distributed directory services
* Attacker queries LDAP service to gather information such as valid user names, addresses, departmental details, etc


# NTP Enumeration


* Network Time Protocol (NTP) is designed to synchronize clocks of networked computers
* Uses UDP port 123 
* Can use it to find important information on a network
* Can use Nmap, Wireshark


# SMTP and DNS Enumeration


* SMTP has 3 built-in commands
   * VRFY - Validates users
   * EXPN - Tells actual delivery addresses of aliasses and mailing lists
   * RCPT TO - Defines the recipients of the message
* SMTP servers respond differently to these commands 
* Attackers can directly interact with SMTP via the telnet prompt and collect a list of valid users on the SMTP Server


# Enumeration Countermeasures


* SNMP countermeasures
   * Remove SNMP agent on turn off the SNMP service (block 161)
   * Change default community string name
   * Upgrade to SNMP3, which encrypts passwords/messages
   * Implement additional security option called “additional restrictions for anonymous connections”
   * Ensure that the access to null session pipes, null session shares, and IPsec filtering are restricted
* DNS countermeasures
   * Disable DNS zone transfers to the untrusted hosts
   * Make sure private hosts and their IP addresses are not published into DNS zone files of public DNS server
   * Use premium DNS registration services to hide sensitive information
   * Use standard network admin contacts for dns registrations in order to avoid social engineering attacks
* SMTP countermeasures
   * Ignore email messages to unknown recipients
   * Disable open relay features
   * Do not include sensitive mail server and local host information in mail responses 
* LDAP countermeasures
   * Restrict access to active directory by using software such as citrix 
   * Enable account lockout 
   * Use SSL technology for LDAP traffic
* Enumeration Pen Testing
   * Used to identify valid user accounts or poorly protected resource shares
   * Information can be users and groups, network resources 
   * Used in combination with data collected in reconnaissance phase
   * Steps in Enumeration Pen Testing
      * Find the network range
      * Calculate the subnet mask
      * Undergo host discovery
      * Perform port scanning 
      * Perform NetBIOS enumeration
      * Perform SNMP enumeration
      * Perform LDAP enumeration
      * Perform NTP enumeration
      * Perform SMTP enumeration
      * Perform DNS enumeration
      * Document all findings   
   
   

