# Cybersecurity Master's Project Portfolio

This repository showcases six hands-on cybersecurity projects completed as part of a master's degree. Each project focuses on a key area of security such as secure development, malware analysis, mobile app security, or incident response. The goal of this portfolio is to demonstrate practical experience using industry-standard tools, methodologies, and reporting practices.

---

## 📱 Project 1 – Mobile Application Vulnerability Analysis

**Objective:**  
Analyze three Android applications (.apk) for vulnerabilities using OWASP Mobile Top 10 as a reference.

**Apps Analyzed:**  
- A deliberately vulnerable APK for training purposes  
- An APK from an unofficial repository  
- An APK from an official store

**Steps Followed:**  
1. **Information Gathering:** Defined app structure and analysis scope  
2. **Static Analysis:** Inspected AndroidManifest.xml and extracted configuration files using tools like `Apktool`, `Jadx`, `MobSF`  
3. **Dynamic Analysis:** Monitored real-time app behavior using `Android Studio`, `ADB`, and `VirusTotal`

**Skills Developed:**
- Mobile app reverse engineering  
- Static and dynamic analysis methodologies  
- Using MobSF in Docker for automated analysis  
- Threat identification using ShenmeApp and VirusTotal  
- Interpreting AndroidManifest.xml permissions and intents

---

## 🔍 Project 2 – Malware Analysis in Windows Environment

**Objective:**  
Analyze malicious files and behaviors within a Windows virtual environment, using real malware samples and sandboxed analysis techniques.

**Key Activities:**
- Collected suspicious samples from public malware repositories  
- Ran malware in isolated VMs using tools like `Any.run`, `Hybrid Analysis`, and `VirusTotal`  
- Captured malicious network traffic and API calls  
- Analyzed persistence mechanisms, payload delivery, and data exfiltration patterns  

**Skills Developed:**
- Safe handling of malware in sandboxed environments  
- Analysis of process injection and command execution  
- Indicators of compromise (IOCs) identification  
- Use of MITRE ATT&CK framework for TTP classification  
- Network traffic inspection for malware behavior patterns

---

## 🔓 Project 3 – Web Application Vulnerability Assessment

**Objective:**  
Audit a custom-developed web application to detect and exploit vulnerabilities, then propose mitigation strategies.

**Steps Followed:**
1. Performed vulnerability scanning using `Burp Suite`, `OWASP ZAP`, `Gobuster`, and `DirBuster`  
2. Identified critical issues such as XSS, SQLi, and insecure file upload  
3. Exploited vulnerabilities to demonstrate real-world impact  
4. Proposed code-level and configuration-based security measures

**Skills Developed:**
- Manual and automated web vulnerability scanning  
- Exploitation of XSS, LFI, SQLi, etc.  
- Secure coding practices  
- OWASP Top 10 vulnerability mitigation  
- Report writing with technical and business-level language

---

## 🔐 Project 4 – Secure Coding & Static Analysis

**Objective:**  
Review source code for security flaws and improve the secure development lifecycle using static analysis techniques.

**Tasks Performed:**
- Code review and auditing of a sample insecure PHP web application  
- Used tools like `SonarQube`, `Bandit`, and `Semgrep`  
- Identified hardcoded credentials, insecure deserialization, and input validation flaws  
- Suggested secure design principles and secure code refactoring techniques

**Skills Developed:**
- Static code analysis and review  
- Applying secure coding standards (e.g., OWASP Code Guidelines)  
- Source-level vulnerability detection  
- Integrating security into CI/CD pipelines  
- Interpreting analysis results to prioritize fixes

---

## ⚙️ Project 5 – Vulnerability Exploitation & Docker Deployment

**Objective:**  
Set up and analyze the WackoPicko vulnerable web application in Docker. Identify and exploit vulnerabilities, then provide remediation suggestions.

**Steps Followed:**
1. Deployed WackoPicko via Docker and documented the setup  
2. Detected vulnerabilities using `OWASP ZAP` and `Vega`  
3. Exploited flaws such as XSS and SQLi, showing impact  
4. Proposed fixes in application code and highlighted security best practices

**Skills Developed:**
- Dockerized deployment of vulnerable applications  
- Use of semiautomated scanning tools  
- Hands-on vulnerability exploitation  
- Secure development recommendations  
- Reporting vulnerabilities with evidence

---

## 🛡️ Project 6 – Incident Response and Threat Analysis (Multisite Case Study)

**Objective:**  
Act as part of a corporate incident response team investigating three different incidents across Australia, Italy, and Spain.

**Incident Summaries:**

- **Australia (Phishing & Data Leak):**  
  Analyzed proxy logs to identify users affected by credential phishing using Office365 spoofed pages. Proposed user awareness training and 2FA deployment.

- **Italy (Unauthorized Server Access):**  
  Evaluated response procedures; proposed isolating and imaging hardware before involving a third-party forensic team.

- **Spain (Ransomware Infection):**  
  Investigated ransomware attack affecting textile server with .NM4 extension. Reviewed open ports and ransom note, proposed network segmentation and backup strategies.

**Skills Developed:**
- Parsing logs with custom scripts  
- Detection of phishing campaigns and leaked credentials  
- Threat modeling and risk assessment  
- Ransomware analysis and containment  
- Implementation of preventive countermeasures

---

## 🚀 Final Notes

Each of these projects reflects real-world cybersecurity scenarios with a focus on practicality, tooling, and methodical analysis. No certifications yet, but actively working toward CompTIA Security+ and OSCP in the near future.

---
