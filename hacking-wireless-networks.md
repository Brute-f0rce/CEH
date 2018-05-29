# Hacking Wireless Networks

> Objectives: Understanding Wireless Concepts, understanding wireless encryption algorithms, understanding wireless threats, understanding wireless hacking methodology, wireless hacking tools, understanding bluetooth hacking techniques, understanding wireless hacking countermeasures, overview of wireless penetration testing



### Wireless Concepts
   * GSM: universal system used for mobile transportation for wireless network worldwide
   * Bandwidth: Describes amount of information that may be broadcasted over a connection
   * BSSID: The MAC address of an access point that has set up a basic service set
   * ISM band: a set of frequency for the international industrial, scientific, and medical communities
   * Access Point: Used to connect wireless devices to a wireless network
   * Hotspot: Places where wireless network is available for public use 
   * Association: Process of connecting a wireless device to an access point 
   * Orthogonal Frequency Division Multiplexing: method of encoding digital data on multiple carrier frequencies 
   * Direct-Sequence Spread Spectrum: original data signal is multiplied with a pseudo random noise spreading code
   * Frequency-hopping spread spectrum (FHSS): Method of transmitting radio signals rapidly switching a carrier among many frequency channels 
   * Wireless Networks
   * WiFi refers to IEEE 802.11 standard
   *      * SSID (service set identifier)
   * Open System Authentication Process: in open system, any wireless client that wants to access a WiFi networks sends a request to the wireless AP for authentication.
   * Shared Key Authentication Process: in this process, each wireless station receives a shared secret key over a secure channel that is distinct from the 802.11 comm channels.
   * Centralized Authentication server (RADIUS)
      * WiFi Chalking
      * WarChalking: draw symbols in public places to advertise open Wi-Fi networks
      * Types of Wireless Antennas
      * Directional Antennas: Used to broadcast and obtain radio waves from a single direction
      * Omni-Directional Antennas: provides 360 degrees horizontal broadcasts, used in wireless base stations
      * Parabolic Grid Antenna: Based on the idea of a satellite dish. Can pick up Wi-Fi signals ten miles or more 
      * Yagi Antenna: unidirectional antenna
      * Dipole Antenna: Bi-Directional Antenna, used to support client connection rather than site-to-site applications
      * Parabolic grid antennas let attackers attack from from farther away (10 miles!)


## Wireless Encryption

   * WEP (wired equivalent privacy): weakest encryption. Uses 24-bit initialization vector. A 64 bit WEP uses a 40 bit key etc
   * Can use Cain & Abel to crack
   * WPA (Wifi Protected Access): Stronger encryption with TKIP.
   * You can brute force the keys offline
   * You can defend by using stronger passphrases
   * WPA2: Stronger data protection with AES
   * WPA-2 personal uses a pre-shared key to protect access
   * WPA-2 Enterprise includes EAP or RADIUS for centralized authentication w/kerberos etc


## Wireless Threats
   * Access Control Attacks: Aims to penetrate a network by evading WLAN access control measures, such as AP MAC filters and Wi-Fi port access controls
   * Integrity Attacks: Sending forged control management or data frames over a wireless network
   * Confidentiality Attacks: attempt to intercept confidential information sent over wireless associations
   * Availability Attacks: DoS
   * Authentication Attacks: Steal the identity of Wi-Fi clients, their PI, logins, etc. to unauthorized access of network resources
   * Rogue Access Point Attack: Hijacking connections and acting as a middle man sniffing 
   * Client Mis-Association: Attacker sets up a rogue access point outside of the corporate perimeter and lures the employees of the organization to connect with it 
   * Misconfigured Access Point Attack: Accidents for configurations that you can exploit
   * AD Hoc connection attack: Wifi Clients communicate directly in ad-hoc and do not require AP to relay packet. Attack can attack OS direct since the encryption is weak
   * Honeyspot Access Point Attack: Attacker takes advantage of multiple WLAN’s in area and use same SID 
   * AP MAC Spoofing: Hacker spoofs the MAC address of the WLAN client equipment to mask an authorized client 
   * Jamming Signal Attack: High gain amplifier 


## Wireless Hacking Methodology


   1. WiFi Discovery: discovers the WiFi network
   2. GPS Mapping: Attackers create a map of discovered Wi-Fi network and create a database
   3. Wireless Traffic Analysis: identify vulnerabilities, WiFi reconnaissance, Tools for Packet Capture & Analysis
   4. Launch Wireless Attacks
      1.Fragmentation Attack: can obtain 1500 bytes of PRGA data that can be used for injection attacks
      2. Mac Spoofing: attackers change MAC address to that of an authenticated user to bypass the MAC filtering configured in an access point 
      3. Denial of Service: Deauthentication and Disassociation attacks
      4. Man in the middle attack MITM : Attacker spoofs his MAC, sends a deAuth requests and then puts himself in the middle
      5. Wireless ARP poisoning attack: 
      6. Rogue Access Point: Wireless APs attacker installs on a network without authorization and are not under management of the network administrator. Are not configured with any security
      7. Evil Twin: Replicates another wireless APs name via common SSID


   5. Crack Wi-Fi encryption
         1. Crack WEP using Aircrack
         2. Crack WPA-PSK using aircrack
         3. WEP cracking using Cain & Abel


   6. Compromise the Wi-Fi Network

         * What is spectrum analysis
         * RF spectrum analyzers examine Wi-Fi radio transmissions and measure power (amplitude)
         * Employ statistical analysis to plot spectral usage
         * Can be used for DoS attack


## Bluetooth Hacking


   * Exploitation of Bluetooth Stack implementation vulnerabilities
   * Bluesmacking: DoS attack which overflows Bluetooth-enabled devices with random packets causing device to crash
   * Bluejacking: sending unsolicited messages over bluetooth to bluetooth-enabled devices such as mobile phones, laptops, etc
   * Bluesnarfing: Theft of information from a wireless device through a bluetooth connection
         * Blue Sniff: Proof of concept code for a bluetooth wardriving utility 
         * Bluebugging: remotely accessing the bluetooth-enabled devices and using its features
         * BluePrinting: collecting information about bluetooth enabled devices such as manufacturer, device model, firmware
         * MAC spoofing attack: intercepting data intended for other bluetooth enabled devices 
         * MITM: Modifying data between bluetooth enabled devices communication on a piconet 
         * Bluetooth Modes:
         * Discoverable, Limited Discoverable (timed), Non-discoverable
         * Pairing Modes
         * Non-pairable models: rejects every pairing request
         * Pairable mode: will pair upon request


## Countermeasures


   * How to defend against bluetooth hacking
         * Use non-regular patterns such as PIN keys
         * Keep device in non-discoverable mode
         * Keep a check of all paired devices
         * Always enable encryptions


## Wireless Security Tools


   * Wireless Intrusion Prevention Systems 


