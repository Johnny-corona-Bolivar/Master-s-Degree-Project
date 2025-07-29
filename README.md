# Cybersecurity Master's Project Portfolio

This repository showcases six hands-on cybersecurity projects completed as part of a master's degree. Each project focuses on a key area of security such as secure development, malware analysis, mobile app security, or incident response. The goal of this portfolio is to demonstrate practical experience using industry-standard tools, methodologies, and reporting practices.

---

## 📱 Project 1 – Mobile Application Vulnerability Analysis 

## 🎯 Objectives 
Analyze three Android applications (.apk) for vulnerabilities using OWASP Mobile Top 10 as a reference.

- Perform static and dynamic security analysis on three Android applications: **AndroGoat** (intentionally vulnerable), **TodoList** (official), and **Vanced** (from an unofficial repository).
- Identify and compare vulnerabilities based on the **OWASP Mobile Top 10** and **MASVS** standards.
- Highlight security risks introduced by outdated Android APIs, insecure permissions, and weak configurations.
- Analyze app behavior, data handling, network communication, and permission models.
- Gain hands-on experience with modern mobile security testing tools in a controlled, virtualized lab environment.

**Apps Analyzed:**  
- A deliberately vulnerable APK for training purposes  
- An APK from an unofficial repository  
- An APK from an official store

**Steps Followed:**  
1. **Information Gathering:** Defined app structure and analysis scope  
2. **Static Analysis:** Inspected AndroidManifest.xml and extracted configuration files using tools like `Apktool`, `Jadx`, `MobSF`  
3. **Dynamic Analysis:** Monitored real-time app behavior using `Android Studio`, `ADB`, and `VirusTotal`

## 📚 Skills Developed

- Static analysis of APK files, including inspection of source code, configuration files, and declared permissions.
- Dynamic analysis of app behavior, using emulators and monitoring tools to detect suspicious activity, network connections, and resource usage.
- Identification of mobile vulnerabilities based on the OWASP Mobile Top 10, such as insecure data storage, improper cryptography, or data exposure.
- Comparative risk evaluation based on APK source (unofficial, unverified repository, and official store), building critical thinking for mobile security assessment.
- Conducting full lifecycle mobile app security testing
- Manual reverse engineering using Apktool and JADX 
- Network traffic inspection and endpoint detection  
- Certificate analysis and validation  
- Writing structured and evidence-based security reports

---

## 🔍 Project 2 –  Cyber Intelligence 

## 📜 Project Description

This project involves conducting an analysis and simulation of a cyberattack scenario, choosing one of the following options:

- Phishing attack analysis and simulation  
- Malware attack analysis and simulation

The topic is open and fully flexible, allowing you to explore different techniques and tools within cyber intelligence.

## ✅ Objectives  
Analyze malicious files and behaviors within a Windows virtual environment, using real malware samples and sandboxed analysis techniques.

- Plan and simulate a realistic phishing campaign
- Create customized templates based on user roles and behavior
- Monitor user interaction with phishing emails and landing pages
- Raise awareness of phishing threats through education and analysis
- Understand the tactics, techniques, and procedures (TTPs) used in phishing or malware attacks.
- Perform a detailed analysis of the chosen attack vector.
- Simulate the attack in a controlled environment to study its behavior and impact.
- Identify indicators of compromise (IOCs) and develop detection strategies.
- Enhance practical skills in cyber threat intelligence gathering and incident response

## 🔑 Key Activities

- Research current phishing or malware attack methodologies and tools.
- Set up a virtual lab environment to safely simulate the attack.
- Capture and analyze network traffic, logs, and artifacts generated during the simulation.
- Document the attack lifecycle, including reconnaissance, delivery, exploitation, and persistence.
- Develop mitigation and detection recommendations based on findings.
- Present a detailed report summarizing the attack, analysis, and lessons learned.


## 📚 Skills Developed

- Cyber Threat Intelligence (CTI) collection and analysis  
- Practical experience with phishing or malware simulation tools  
- Network traffic analysis and log investigation  
- Understanding of attack frameworks and kill chains  
- Incident response and forensic investigation techniques  
- Report writing and technical documentation  
- Critical thinking and problem-solving in cybersecurity contexts


---

# 🔍 Project 3– Reverse Engineering 

This repository contains the analysis and reconstruction of an x86 assembly function as part of a reverse engineering final project.

## 📄 Project Description

The objective of this project is to reverse engineer a compiled program by analyzing the `main` function in x86 assembly, identifying its structure and logic, reconstructing it in C code, and modifying its behavior.

### 🔧 Original Assembly Function

The project starts with a dumped version of the `main` function in x86 assembly, which performs operations on a hardcoded string and generates a numeric code based on its content.

Key elements:
- Stack alignment and preservation of registers
- Retrieval of a static string (`"3jd9cjfk98hnd"`)
- Calculation using each character of the string and its position
- Output of a result using `printf`

---

## ✅ Objectives

1. **Divide the assembly into basic blocks**  
   Identify segments of code with single entry and exit points, considering jump conditions and control flow.

2. **Create the control flow diagram**  
   Diagram showing how the basic blocks connect, representing conditional and sequential execution.

3. **Identify control structures**  
   Recognize if the function uses loops or conditionals and specify which blocks are involved.

4. **Translate assembly to C code**  
   Convert the entire `main` function to readable and functional C code.

5. **Compile and execute**  
   Compile the C version using:
   ```bash
   gcc source.c -o source -m32
   
## 📚 Skills Developed
- Assembly Language Analysis: Understanding and interpreting x86 assembly instructions and function structure.
- Basic Blocks & Control Flow: Identifying basic blocks and constructing control flow diagrams from low-level code.
- Reverse Engineering: Translating assembly code into high-level C code by analyzing program logic and behavior.
- C Programming: Writing and modifying C code based on reverse engineered logic.
- Compilation & Execution: Using GCC with 32-bit flags (-m32) to compile and run C programs.
- Debugging & Testing: Validating the correctness of the translated code through compilation and runtime testing.
-Problem Solving: Applying logical reasoning to infer high-level constructs from low-level assembly.
- Software Engineering Best Practices: Documenting reverse engineering processes clearly and professionally.

---

# 🛡️  Ethical Hacking

## 📜 Project Description

This project is the capstone exercise for the Ethical Hacking module. It is divided into two main parts

### Part 1 – Targeted Reconnaissance and Scanning  
Given only the name of an organization (freely chosen), the task is to gather as much publicly available information as possible through open-source intelligence (OSINT) and active scanning techniques.

Focus phases include:
- **Reconnaissance (Passive & Active)**  
- **Fingerprinting**
- **Scanning (Ports & Services)**

The goal is to identify:
- Employee information
- Domains and subdomains
- Public IP addresses and servers
- Exposed services or technologies

All findings must be documented along with the tools used and the corresponding phase of the ethical hacking process.

---


## 📚 Skills Developed
- Static code analysis and review  
- Applying secure coding standards (e.g., OWASP Code Guidelines)  
- Source-level vulnerability detection  
- Integrating security into CI/CD pipelines  
- Interpreting analysis results to prioritize fixes

---
### Part 2 – Vulnerability Analysis & Exploitation  
Using a prepared virtual machine (target system), the task involves simulating a vulnerability assessment and exploitation exercise.

Steps include:
- Launching a **semi-automated vulnerability scan**
- **Validating vulnerabilities** (identify false positives)
- **Exploiting confirmed vulnerabilities** using alternative tools
- **Privilege escalation**
- **Manual inspection** of additional running services

---
## 🎯 Objectives

- Apply ethical hacking methodologies in a structured manner.
- Develop OSINT capabilities for real-world reconnaissance.
- Perform safe and effective port and service scanning.
- Simulate vulnerability identification and exploitation in a lab environment.
- Analyze system weaknesses and suggest security improvements.
- Practice privilege escalation in a controlled system.

---
## 📚 Skills Developed

- OSINT (Open Source Intelligence) gathering  
- Network scanning and fingerprinting  
- Service enumeration and technology detection  
- Vulnerability assessment methodology  
- Exploitation of common web/server vulnerabilities  
- Privilege escalation techniques  
- Ethical reporting and documentation  
- Safe use of offensive security tools in lab environments  

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
