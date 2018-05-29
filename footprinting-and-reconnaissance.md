# Footprinting and Reconnaissance

## Concepts

* Footprinting is process of collecting as much information as possible about a target network
* Footprinting Threats: social engineering, system and network attacks, information leakage, privacy loss, corporate espionage, business loss

## Methodology

1. Footprinting through search engines
   1. Google, Netcraft \(restricted URL’s, Determine OS\), SHODAN Search Engine,GMAPS, Google Finance, etc
2. Footprinting using advanced Google Hacking Techniques
   1. Using technique to locate specific strings of text within search results using an advanced operator in the search engine \(finding vulnerable targets\), Google Operators to locate specific strings of text, GHDB
3. Footprinting through social networking sites
   1. Fake identifies of co-workers, finding personal info, tracking their groups, etc, Facebook, Twitter, LinkedIn etc
4. Website Footprinting 
   1. Looking at system information from websites, personal information, examining HTML source comments, Web Spiders, archive.org, mirroring sites etc
5. Email Footprinting 
   1. Can get recipient's IP address, Geolocation, Email Received and Read, Read Duration, Proxy Detection, Links, OS and Browser info, Forward Email
6. Competitive Intelligence 
   1. Competitive Intelligence gathering is the process of identifying, gathering, analyzing, and verifying, and using the information about your competitors from sources such as the internet. Monitoring web traffic etc.
   2. Non-interfering and subtle in nature
   3. This method is legal
7. WHOIS Footprinting
   1. WHOIS databases are maintained by regional internet registries and contain PI of domain owners
8. DNS Footprinting
   1. Attacker can gather DNS information to determine key hosts in the network
9. Network Footprinting 
   1. Network range information assists attackers to create a map of the target network
   2. Find the range of IP addresses using ARIN whois database search
   3. Traceroute programs work on the concept of ICMP protocol and use the TTL field in the header of ICMP packets to discover on the path to a target host
10. Footprinting through Social Engineering
    1. Art in exploiting human behaviour to extract confidential information
    2. Social engineers depend on the fact that people are unaware

## Tools

* Maltego
* Recon-NG \(Web Reconnaissance Framework\)

## Countermeasures

1. Restrict the employees to access social networking sites
2. Configure web servers to avoid information leakage
3. Educate employees to use pseudonyms
4. Limit the amount of information that you are publishing
5. Use footprinting techniques to discover and remove sensitive information
6. Use anonymous registration services
7. Enforce security policies

## Penetration Testing: Footprinting

1. Footprinting pen testing is used to determine organization’s public available information
2. Tester attempts to gather as much information as possible from the internet and other publicly accessible sources
3. Define scope and then use footprint search engines
4. Report Templates

