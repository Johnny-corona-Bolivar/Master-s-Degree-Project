# 🛡️ Practical Case: Secure Development with WackoPicko
---
This project is part of a cybersecurity master's program, focusing on vulnerability research, reverse engineering practices, and secure development techniques. Beyond identifying and exploiting application flaws, it emphasizes analyzing control flow and extracting logic from raw behavior. 
This hands-on work helps build understanding of low-level operations and secure coding principles.

---
## 🎯 Objectives 

- Identify vulnerabilities in the WackoPicko application using OWASP ZAP.
- Exploit the discovered vulnerabilities to understand their real-world impact.
- Propose preventive and corrective measures, including code-level fixes.
- Document the deployment of WackoPicko within Docker as a controlled environment for web vulnerability analysis.

---

## 📖 Overview / Description

A vulnerable web application (WackoPicko) was deployed in a Docker container, then scanned using OWASP ZAP. Discovered issues were correlated with the OWASP Top Ten 2021 framework.
Techniques such as XSS testing, SQL injection, and directory enumeration were performed, followed by remediation strategies and server hardening suggestions.

---
 
## 📝 Task Instructions

1- Identify the vulnerabilities present in the application (using a semi-automatic tool such as Vega or OWASP Zap).
As a result of this exercise, on one hand, the number of occurrences identified and classified according to their severity level will be shown; on the other hand, the classification of all these occurrences by types of vulnerabilities.

2- Exploit the vulnerabilities, indicating how each vulnerability was exploited and what the outcome was (including screenshots).

3- Propose at least one preventive measure for each analyzed vulnerability (understood as code modifications where the problem is found).
Additionally, further measures related to security best practices specific to the vulnerability type may be provided.

---

## 🔧 Tools & Technologies Used

    
- Docker Desktop
- OWASP ZAP
- Kali Linux 
- Vega (alternative scanning tool)
- Gobuster
- Bash shell within Docker container
- SQL and PHP code analysis

---

## ⚙️ How to Run / Installation

### Requirements

- Windows 10/11 with virtualization enabled and WSL2
- Docker installed → [Official Guide](https://docs.docker.com/get-docker)

### Deployment Steps

     ```bash
      docker pull adamdoupe/wackopicko:latest
      docker run -p 127.0.0.1:8080:80 -it adamdoupe/wackopicko

Access via browser: http://localhost:8080
Set OWASP ZAP to a different port (e.g. 8090) to avoid proxy conflicts

---

## 🔍 Steps Taken

## Previous Steps: 

### 1- Docker Machine Setup

 🎯 Objective
  Deploy the vulnerable application WackoPicko in a controlled environment using Docker, in order to practice web vulnerability analysis.

🧰 Prerequisites
    - Operating System: Windows / Linux / macOS
    - Docker installed: https://docs.docker.com/get-docker

 1 – Installing Docker on Windows
 🧰 Prerequisites
- Operating System:
    - Windows 10 Pro, Enterprise, or Education (build 15063 or higher)
    - Windows 11 (any edition supported by WSL2)

- **Virtualization Enabled:**
   - Ensure virtualization is enabled in the BIOS/UEFI.
- **Windows Subsystem for Linux (WSL2):**
   - Docker Desktop uses WSL2 as the backend.

📥 2 – Download Docker Desktop for Windows
  Visit the official Docker website:  --->  https://www.docker.com/products/docker-desktop/ ---> Click on "Download for Windows (WSL2)".

🧑‍💻 3 – Install Docker Desktop
    - Run the .exe installer you downloaded.
    - Accept the terms and conditions.
   - Ensure the option is checked:
 **Install required components for WSL 2**
   - Wait for the installation to complete.
   - Restart your computer if prompted.

⚙️ 4 – Enable WSL2 (if not already enabled)
    - Open PowerShell as Administrator and run:

    ´´´powershell
    
         wsl --install

  🚀 5 – Start Docker Desktop
- Search for Docker Desktop in the Start Menu and open it.
- Docker will start running in the background.
- You should see the whale icon in the system tray.

  ✅ 6 – Verify Installation
Open PowerShell or CMD and run the following commands:

       ´´´bash
  
          docker --version
          docker run hello-world
  
  This will run a test container and confirm that Docker is working properly.



 ### 2- Downloading the WackoPicko Image:
 
  1- The image was downloaded from GitHub Container Registry using:

     ´´´bash

         docker pull adamdoupe/wackopicko:latest
         docker run -p 127.0.0.1:8080:80 -it adamdoupe/wackopicko

2- 🌐 Accessing the Application
Open your browser and go to: --- > http://localhost:8080

 Note: This can also be done using Kali Linux if preferred.


## 📝 Elaboration

The following analysis of the WackoPicko application will be conducted using the OWASP Top 10 – 2021 model, which outlines the ten most common vulnerabilities found in web applications.

<img width="800" height="323" alt="image" src="https://github.com/user-attachments/assets/1e8aba98-bea4-44aa-9a77-5f42775b945b" />

 **Comparison between OWASP 2017 and 2021 Models**
  Model Description ----> (Information sourced from: https://owasp.org/Top10/es/)
  
  We will briefly break down each of the vulnerabilities to gain a better understanding of them. After the analysis, we will correlate the vulnerabilities identified in the web application with the OWASP framework and propose mitigation measures based on the recommended practices.


### OWASP Top 10 (2021) Vulnerability Breakdown

#### 1. **Broken Access Control**
This refers to the improper implementation of permission policies for users or groups. It includes several CWE (Common Weakness Enumeration):

- **CWE-200**: Exposure of sensitive information to an unauthorized actor  
- **CWE-201**: Exposure of confidential data via sent information  
- **CWE-352**: Cross-Site Request Forgery (CSRF)

---

#### 2. **Cryptographic Failures**
The absence or poor implementation of cryptography leads to exposure of sensitive data like credit card numbers or medical records. This area aligns with privacy laws like **GDPR** and standards like **PCI DSS**.

Related CWEs:
- **CWE-259**: Use of hard-coded password  
- **CWE-327**: Broken or risky cryptographic algorithm  
- **CWE-331**: Insufficient entropy

---

#### 3. **Injection**
Occurs when attackers inject malicious code into form fields or queries due to poor input handling. A web app is vulnerable when:

- User input is not validated, filtered, or sanitized.
- Dynamic or non-parameterized queries are used.
- Malicious data is injected into ORM queries.
- Inputs are directly concatenated in commands or procedures.

Related CWEs:
- **CWE-79**: Cross-site scripting (XSS)  
- **CWE-89**: SQL Injection  
- **CWE-73**: External control of file name or path

---

#### 4. **Insecure Design**
Focuses on design risks and architecture flaws. Emphasizes threat modeling, secure design patterns, and reference architectures to implement **Security by Design**.

Related CWEs:
- **CWE-209**: Generation of error messages containing sensitive information  
- **CWE-256**: Plaintext storage of passwords  
- **CWE-501**: Trust boundary violation  
- **CWE-522**: Insufficiently protected credentials

---

#### 5. **Security Misconfiguration**
Common mistakes in configuring servers, applications, databases, or cloud services. Risks include:

- Missing security hardening  
- Unnecessary services enabled  
- Default accounts/passwords unchanged  
- Overly verbose error handling  
- Disabled or insecure security features

---

#### 6. **Vulnerable and Outdated Components**
This relates to using software libraries or frameworks with known vulnerabilities that lack security updates or patches.

Main CWE:
- **CWE-1104**: Use of unmaintained third-party components  

Vulnerabilities occur when:
- Component versions are unknown or untracked  
- No regular vulnerability scanning is done  
- Underlying platforms are not patched promptly  
- Developers fail to test updated or patched libraries

---

#### 7. **Identification and Authentication Failures**
Weaknesses in user authentication or session management can lead to various attacks:

- Credential stuffing  
- Brute-force attacks  
- Default/weak passwords  
- Poor password recovery methods  
- Plaintext or weakly hashed passwords  
- Lack of MFA  
- Session fixation or reuse

Related CWEs:
- **CWE-297**: Improper validation of certificate with host mismatch  
- **CWE-287**: Improper authentication  
- **CWE-384**: Session fixation

---

#### 8. **Software and Data Integrity Failures**
These failures involve code or data that is not protected against tampering. Examples include:

- Relying on untrusted plugins, libraries, CDNs  
- Insecure CI/CD pipelines  

Related CWEs:
- **CWE-829**: Inclusion of functionality from untrusted control sphere  
- **CWE-494**: Lack of code integrity checks  
- **CWE-502**: Deserialization of untrusted data

---

#### 9. **Security Logging and Monitoring Failures**
Lack of logging and monitoring delays the detection of security breaches. Though it lacks many CVEs, it is critical for:

- Auditability  
- Incident alerts  
- Forensic investigations  

Related CWEs:
- **CWE-117**: Improper output neutralization for logs  
- **CWE-223**: Omission of relevant security information  
- **CWE-532**: Insertion of sensitive information into logs

---
#### 10. **Server-Side Request Forgery (SSRF)**

SSRF vulnerabilities occur when a web application fetches a remote resource without properly validating the user-supplied URL. This allows an attacker to coerce the application into sending a forged request to an unexpected destination, 
even if it's protected by a firewall, VPN, or other network access control lists (ACLs).
As modern web applications increasingly offer users convenient features like URL fetching, SSRF has become a more common scenario. 
Additionally, the severity of SSRF attacks is rising due to the adoption of cloud services and the growing complexity of application architectures.

---

## 🧠 Vulnerability Analysis of WackoPicko

### 📝 Part 1: The analysis will be carried out from Docker Desktop using an image.

<img width="886" height="85" alt="image" src="https://github.com/user-attachments/assets/f45bb164-d45c-4a29-8114-d156848c5333" />
<img width="800" height="500" alt="image" src="https://github.com/user-attachments/assets/24096a3c-6890-45b0-8a03-b47d87b73c38" />
<img width="800" height="436" alt="image" src="https://github.com/user-attachments/assets/f69e8212-8ee2-4639-9d4e-f87ec20ccbe5" />

The next step is to analyze WackoPicko using ZAP Proxy, but first, a small configuration change must be made. This adjustment is required whether you're using Windows or Kali Linux.
If we look at the Docker images, the container is running by default on port :80, and the same applies to ZAP Proxy. Therefore, we need to modify the port used by ZAP Proxy.

let`s go to Owasp-Zap ----> Tools

<img width="489" height="648" alt="image" src="https://github.com/user-attachments/assets/3323101e-62ca-4186-ac85-83c008e0e83b" />

Options:

<img width="597" height="460" alt="image" src="https://github.com/user-attachments/assets/efd83041-ad39-4dee-b1b6-316e3e45a237" />

Then, go to "Network", and under the "Local Servers/Proxies" section, proceed to change the port. You can use any available port, but I chose 8090 since it's even and likely won’t cause issues — we'll see.

Once the configuration is correctly set up, we will proceed to analyze the web application.
OWASP ZAP offers various scanning options, but we will focus on the automated scan.

<img width="886" height="274" alt="image" src="https://github.com/user-attachments/assets/bffd7d1a-5194-4d4e-b5df-9e31d98dead4" />
<img width="800" height="700" alt="image" src="https://github.com/user-attachments/assets/b4de0b2e-cf9a-421e-9230-c6520f5f795d" />
<img width="800" height="556" alt="image" src="https://github.com/user-attachments/assets/aa803ff8-27a4-4d3f-93be-54ae76b0d238" />


As we can see, the analysis shows a total of 13 vulnerabilities found. We will review them one by one


- Absence of Anti-CSRF Tokens: No Anti-CSRF tokens were found in the HTML form submission.
  
    <img width="839" height="314" alt="image" src="https://github.com/user-attachments/assets/e810059b-6689-40f4-9685-1e3c0a0c90ad" />

- Content Security Policy (CSP) Header Not Configured: The Content Security Policy (CSP) is an additional layer of security that helps detect and mitigate certain types of attacks, including Cross-Site Scripting (XSS) and data injection attacks.

   <img width="800" height="321" alt="image" src="https://github.com/user-attachments/assets/b0c6c050-e776-46a7-9576-506bc81c8f73" />

- Missing Anti-Clickjacking Header: The response does not protect against Clickjacking attacks. You should include a Content-Security-Policy header with the frame-ancestors directive or use the X-Frame-Options header.

  <img width="684" height="303" alt="image" src="https://github.com/user-attachments/assets/c6445e6b-6514-41e9-a66e-0aa5c40358e3" />

- Cookie Without HttpOnly Flag: A cookie has been set without the HttpOnly flag, which means JavaScript can access it. If a malicious script is executed on this page, the cookie can be accessed and potentially transmitted to another site. If it's a session cookie, session hijacking may be possible.

  <img width="589" height="305" alt="image" src="https://github.com/user-attachments/assets/5a9a595e-03a4-48bf-aff5-2d8e8df3242b" />

- Cookie Without SameSite Attribute: A cookie has been set without the SameSite attribute, which means it may be sent as part of a cross-site request. The SameSite attribute is an effective countermeasure against cross-site request forgery (CSRF), cross-site scripting (XSS), and timing attacks.

  <img width="656" height="316" alt="image" src="https://github.com/user-attachments/assets/dfb1898c-d5e0-46d0-8398-d846e90bb143" />

- Unix Timestamp Disclosure: A Unix timestamp was revealed by the application or web server. This information can sometimes aid an attacker in understanding application logic, session expiration times, or even help in predicting or replaying requests if timestamps are used insecurely.

  <img width="692" height="320" alt="image" src="https://github.com/user-attachments/assets/21c8c4b5-4ecc-43ee-9760-95dc32805d26" />

- Server Leaks Information via “X-Powered-By” HTTP Response Header: The web server/application is disclosing information through one or more HTTP response headers, specifically "X-Powered-By".
  This disclosure can help attackers identify underlying frameworks or components your application relies on, and consequently, the known vulnerabilities that may affect those components.

  <img width="886" height="193" alt="image" src="https://github.com/user-attachments/assets/4cecf39e-9a0d-48ed-9e82-2f4a6cde45b5" />

- Server Leaks Version Information via "Server" HTTP Response Header: The web server/application is leaking version information through the "Server" field in the HTTP response header.
  Access to this information can make it easier for attackers to identify additional vulnerabilities that your web server/application may be susceptible to.

  <img width="886" height="241" alt="image" src="https://github.com/user-attachments/assets/7fab3624-7f4e-4434-ab86-d4da4e86186d" />

- Missing X-Content-Type-Options Header: The Anti-MIME-Sniffing header X-Content-Type-Options has not been set to 'nosniff'.
  This omission allows older versions of Internet Explorer and Chrome to perform MIME-sniffing on the response body, potentially causing the content to be interpreted and displayed as a different MIME type than declared.
  Current (as of early 2014) and legacy versions of Firefox will use the declared content type (if one is set) instead of MIME-sniffing.

  <img width="766" height="281" alt="image" src="https://github.com/user-attachments/assets/1e1f08bc-a3a9-4270-a166-8ac5349c4c25" />

- Missing X-Content-Type-Options Header:
  The Anti-MIME-Sniffing header X-Content-Type-Options has not been set to 'nosniff'.

  <img width="816" height="292" alt="image" src="https://github.com/user-attachments/assets/0d2da9ec-2852-4995-80e5-5c1f65ebf761" />

- User-Controlled HTML Element Attribute (Potential XSS):
  This check examines user-supplied input in query string parameters and POST data to identify where certain HTML attribute values might be controlled by the user

  <img width="886" height="274" alt="image" src="https://github.com/user-attachments/assets/c7a49123-1c51-465d-910e-683f380947ba" />

- Information Disclosure – Sensitive Information in URL:
  The request appeared to contain sensitive information leaked in the URL. This can violate PCI compliance policies and those of most organizations.

  <img width="881" height="289" alt="image" src="https://github.com/user-attachments/assets/92f8aca8-50e7-4cc3-a6eb-7ac76fba6d9e" />

- Authentication Request Identified:
  The request in question has been identified as an authentication request. The "Additional Information" field contains a set of key=value lines that identify any relevant fields.
  If the request is in a context where the authentication method is set to "Auto-detect," this rule will adjust the authentication to match the identified request.

  <img width="706" height="284" alt="image" src="https://github.com/user-attachments/assets/abed8c3f-92a1-4aef-9e11-ef1ca5cbf4e1" />

- Session Management Response Identified:
  The response has been identified to contain a session management token. The "Other Info" field includes a set of header tokens that can be used with the Header-Based Session Management method.
  If the request is in a context where the Session Management method is set to "Auto-Detect," this rule will update the session management to use the identified tokens.

  <img width="858" height="286" alt="image" src="https://github.com/user-attachments/assets/c28c31eb-2347-422b-83cd-6ae0c3b9afe3" />

  **At the end of the project, the report generated by OWASP ZAP will be attached**

| Detected Issues                       | OWASP-ZAP Category                             | Relation to OWASP-ZAP                                   |
|-------------------------------------- |----------------------------------------------  |---------------------------------------------------------|
| Absence of anti-CSRF tokens           | A01 - Broken Access Control                    | ZAP detects forms without CSRF tokens                   |
| Content Security Policy (CSP) header not configured | A05 - Security Misconfiguration  | Absence of CSP facilitates XSS or content injection     |
| Missing Anti-Clickjacking header      | A05 – Security Misconfiguration                | Missing X-Frame-Options (Clickjacking)                  | 
| Cookie without HttpOnly flag          | A02 – Cryptographic Failures                   | Cookies exposed to theft via XSS                        |
| Cookie without SameSite attribute     | A02 – Cryptographic Failures                   | Cookies exposed to cross-site request forgery (CSRF)    |
| Unix Timestamp Disclosure             | A06 – Vulnerable and Outdated Components / A09 – Security Logging Failures | Sensitive information in responses aiding fingerprinting or profiling |
| Disclosure via X-Powered-By header    | A06 – Vulnerable and Outdated Components       | Stack info (PHP/Apache) disclosure aiding recognition    |
| Disclosure via Server header          | A06 – Vulnerable and Outdated Components       | Same as above: fingerprinting                            |
| Missing X-Content-Type-Options header | A05 – Security Misconfiguration                | Allows content sniffing and MIME confusion               |
| User-controlled HTML attribute (Potential XSS) | A03 – Injection                       | Possible reflected XSS if exploited                      |
| Information Disclosure in URL         | A01 – Broken Access Control / A06 – Information Disclosure | Exposure of sensitive information (tokens/IDs)|
| Authentication Request Identified     | A07 – Identification and Authentication Failures | Login endpoint potentially vulnerable to brute force   |
| Session Management Response Identified| A07 – Identification and Authentication Failures | Information about session management exposed           |


---

### 📝 Part 2 : Now we are going to test the vulnerabilities of WackoPicko:

  - 1 Cross-Site Scripting (XSS)
  - We use the JavaScript code:

        ´´´html
    
            <script>alert('Hello world')</script>

    <img width="800" height="419" alt="image" src="https://github.com/user-attachments/assets/88e70592-635e-4472-8b81-446c220b43d3" />
    <img width="800" height="136" alt="image" src="https://github.com/user-attachments/assets/7e9a43f4-1e25-40e2-929e-7267f2e93658" />

We also tested it in the guestbook:

   <img width="800" height="520" alt="image" src="https://github.com/user-attachments/assets/1f67675b-564e-4151-8051-f805d4917370" />

   We obtain the session cookies:
   
          ´´´html
        <script>alert(document.cookie);</script>

   <img width="886" height="388" alt="image" src="https://github.com/user-attachments/assets/a9b0a64b-45d3-4728-ae58-5afba7014f22" />
   <img width="645" height="272" alt="image" src="https://github.com/user-attachments/assets/23befcfc-1438-40ec-a373-70646aa02bb2" />

   
How to fix it:
In this case, we need to take some extra steps since WackoPicko is running inside a container and not on a physical machine. First, we have to create a bash shell inside the container:

- 1 Find the container ID: 

      ´´´bash
       *sudo docker ps
        Example output: b3f178b38865

- 2 Open a shell inside the container:

      ´´´bash
       sudo docker exec -it <container_name_or_ID> /bin/bash
  
  This command will put you inside the container as if it were a virtual machine. From here, you can navigate and find the information that needs to be fixed.

  As we can see, we are now inside the machine. Next, we proceed to search for guestbook.php.

    <img width="800" height="1000" alt="image" src="https://github.com/user-attachments/assets/0cfe6c33-81d3-44d3-aa8e-b196c4d41296" />


- Código saneado y solventado:

    <img width="800" height="1000" alt="image" src="https://github.com/user-attachments/assets/92acf47f-45e3-47bd-9ff5-5fe9099d18e1" />


   
  - 2 SQL Injection:

      <img width="545" height="286" alt="image" src="https://github.com/user-attachments/assets/fd0315e2-33f2-45e2-b4fe-f7a0ecc91f47" />
      <img width="886" height="174" alt="image" src="https://github.com/user-attachments/assets/a16fab62-f2c5-467e-9085-dce392b207b6" />
      

      - How the injection was done by the user could be described as:
   
            ´´´sql
               SELECT * FROM users WHERE username = '' ' AND password = SHA1(CONCAT('', salt)) LIMIT 1;

        We see that an injection attempt was made both in the username and password fields:

          <img width="819" height="347" alt="image" src="https://github.com/user-attachments/assets/79b488fb-0bb0-4133-b83f-e6639f193a01" />

- It says it’s incorrect. WackoPicko has default users provided in the repository:
  - Regular users:
    - scanner1 / scanner1
    - scanner2 / scanner2
    - bryce / bryce


    <img width="886" height="402" alt="image" src="https://github.com/user-attachments/assets/855e2a1d-3572-4c01-9f6b-0a1bbaa39294" />

  - we have access:
    
    <img width="886" height="306" alt="image" src="https://github.com/user-attachments/assets/4af89c42-8705-4029-9b3b-b5a48cd66645" />
    <img width="886" height="326" alt="image" src="https://github.com/user-attachments/assets/ee53f624-19a9-4cd8-a31d-bb6fe9b43b8d" />
    <img width="827" height="306" alt="image" src="https://github.com/user-attachments/assets/2cd06a93-e6fa-42ac-8267-455880eaa5ed" />

- Code

    <img width="800" height="800" alt="image" src="https://github.com/user-attachments/assets/451058d0-3b51-4b23-890d-15eb98b1ff29" />

- Corrections: The corrected and sanitized check_login() function.

    <img width="886" height="394" alt="image" src="https://github.com/user-attachments/assets/0c157d27-489e-417b-b25b-d6e2fb82d467" />

  The vulnerable check_login() function is replaced by this PDO version. Adjust the database username/password in the new PDO(...) accordingly.


 
 -  3 Remote File
   
     <img width="631" height="270" alt="image" src="https://github.com/user-attachments/assets/34f0d634-2421-40de-9834-a54c3a965d8e" />
     <img width="553" height="191" alt="image" src="https://github.com/user-attachments/assets/a21611f6-4e49-44bd-8535-632a35b7dd74" />
     <img width="553" height="236" alt="image" src="https://github.com/user-attachments/assets/52413cb9-6f7e-406e-b4b5-383dab11e710" />

     
We can observe that it is possible to upload a file or image, which could potentially be used for a reverse shell. However, on this occasion, we were unable to exploit it because, for some reason, the upload process got stuck during verification.



- 4 Directory Browsing
  We can also do this with OWASP ZAP by configuring the proxy to intercept all traffic, but this time we use Gobuster from the command line.

    <img width="750" height="700" alt="image" src="https://github.com/user-attachments/assets/c6d2ab90-f1b0-4634-9fdf-11a2e2cf7ad9" />
    <img width="750" height="666" alt="image" src="https://github.com/user-attachments/assets/2f3c030d-d41a-4d8d-8aa0-a62eae18ee00" />
    <img width="750" height="691" alt="image" src="https://github.com/user-attachments/assets/7b6f52b8-61f6-4fae-972f-c3aea01df043" />


**Preventing Directory Browsing**
     To avoid directory browsing and protect your website, you should disable directory listing in your web server configuration.
    This can be done by either creating an empty index file (such as index.html or index.php) in each directory or, preferably, configuring your web server not to display directory listings.

   1. **Disable Directory Listing in the Server Configuration:**
    - Apache: Edit the .htaccess file in your website’s root directory and add:

      Options -Indexes

  -  Nginx: Edit your site's configuration file and add:
    
      autoindex off;
     inside the relevant location block.

  - IIS: Disable directory browsing using the IIS Manager by navigating to Features View > Directory Browsing, then selecting Disable.
  - cPanel: Use the Index Manager feature in your control panel to select "No Indexing" for the directories you want to protect.

2. **Use a Firewall or WAF:**
A Web Application Firewall (WAF) can help protect your website against attacks and may also be configured to block directory browsing.





         


    



  





## 📊 Key Results / Findings

A total of 13 vulnerabilities were uncovered, including:

| Vulnerability                                  | OWASP 2021 Category                   |
|-----------------------------------------------|----------------------------------------|
| Missing Anti-CSRF Tokens                      | A01 – Broken Access Control            |
| Absent CSP and Anti-Clickjacking Headers      | A05 – Security Misconfiguration        |
| Insecure Cookies (HttpOnly, SameSite)         | A02 – Cryptographic Failures           |
| Reflected XSS Possibilities                   | A03 – Injection                        |
| Information Disclosure (Headers & Timestamps) | A06 – Vulnerable Components            |
| Session Management Tokens Revealed            | A07 – Auth Failures                    |
| Directory Browsing Enabled                    | A05 – Misconfiguration                 |

---

## 🚨 Exploit Examples

- **Cross-Site Scripting (XSS):**
  - Triggered using: `<script>alert(document.cookie)</script>`
  - Vulnerable page: `guestbook.php`
- **SQL Injection:**
  - Exploit used: `scanner1'--`
  - Result: unauthorized access
- **Directory Enumeration:**
  - Tool: Gobuster CLI
  - Outcome: Revealed hidden directories

---


## 🧠 Skills Acquired

- Docker environment setup and security configurations
- Automated web vulnerability scanning with OWASP ZAP
- Exploitation techniques (XSS, SQLi, enumeration)
- Vulnerability correlation with OWASP Top Ten methodology
- Code-level mitigation and server hardening practices

---

🧩 Additional Notes / Future Work
- 🛠️ Nano editor couldn't be installed inside the container, limiting live editing.
- 🐳 Future version could use a custom Docker image with editors preinstalled.
- 🔍 Further research could explore SSRF, Burp Suite integration, and custom payload crafting.
- 📎 ZAP report and detailed vulnerability mapping are available in the appendices







