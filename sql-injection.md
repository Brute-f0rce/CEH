# SQL Injection

> Objectives: Understanding SQL injection concepts, understanding various types of SQL injection attacks, understanding SQL injection methodology, SQL injection tools, understanding different IDS evasion techniques, SQL injection countermeasures, SQL injection detection tools

### SQL Injection Concepts
   * SQL injection is a technique used to take advantage of non-validated input vulnerabilities to pass SQL commands through a web app for execution by the backend database
   * Usually to retrieve information
   * This is a flaw in web apps
   * Attacker can deface a web page with this attack
   * They can add info to your website, extract data, and insert new data


## Types of SQL Injection


   * Error based SQL Injection: Attacker puts intentional bad input into app to see the database-level error messages. Uses this to create carefully designed SQL Injections
   * Blind SQL Injection: Attacker has no error messages from the system with which to work. Instead, attack simply sends a malicious SQL query to the database
   * Whenever you see SELECT, it is probably a SQL command 
   * Union SQL command, joining a forged query to the original query 
   * Time-Based SQL Injection: evaluates time delay in response to true-false queries


## SQL Injection Methodology


   * Information gathering and SQL vulnerability detection
   * Attackers analyze web GET and POST requests to identify all input fields
   * Afterwards, launch attack
   * Advanced SQL injections
   * SQL Injection Black Box Pen Testing
   * Send single quotes and input data to see where the user input is not sanitized
   * Send long strings of junk data to detect buffer overruns 
   * Used right square bracket as input data


## Evasion Techniques 


   * Evading IDS
   * Obscure input strings
   * Hex Encoding 
   * Manipulating whitespace
   * Inline Comment
   * Char encoding


## Countermeasures


   * Use Firewalls on SQL server 
   * Make no assumptions about size, type, or content of the data that is received by the application
   * Avoid constructing dynamic SQL with concatenated input values 
