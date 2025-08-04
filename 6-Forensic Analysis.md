# 🛡️ Forensic Analysis - Incident Response Report 

This project is part of a cybersecurity master's program, focusing on real-world incident response across multiple organizational sites. The goal is to analyze diverse attack scenarios — including phishing, ransomware, and unauthorized access —
by examining network captures, log files, and relevant forensic artifacts. It aims to extract indicators of compromise, reconstruct attack paths, and propose effective mitigation measures aligned with industry frameworks such as OWASP and MITRE ATT&CK. 
This practical exercise strengthens skills in threat analysis, evidence handling, and the development of resilient security controls for enterprise environments.

---


## 🎯 Objectives

- Identify and categorize the threats affecting each site.
- Analyze logs and evidence provided for Australia and Spain.
- Manually extract indicators of compromise (IOCs), such as IP addresses, domains, and user credentials.
- Propose response actions and technical countermeasures.
- Correlate findings with typical attack vectors and frameworks (e.g., MITRE ATT&CK).

---
## 🛠️ Tools & Techniques Used

- 🐳 **Docker Desktop**: Controlled testing environments.
- 🧪 **Wireshark**: PCAP analysis, DNS inspection, HTTP stream extraction.
- 🛜 **Suricata / tshark**: For parsing traffic (optionally).
- 🔐 **Burp Suite**: Manual HTTP request inspection.
- 🔍 **VirusTotal / Cisco Talos Intelligence**: IP/domain analysis.
- 📄 **Base64 decoding tools**: For extracting obfuscated credentials.
- 💻 **PowerShell / Linux CLI**: Network and log filtering.

---


## 📌 Project Overview

This project simulates a real-world incident response case for the company **Invent S.L.**, which operates across three countries: **Australia, Italy, and Spain**.  
Each location has experienced a different cybersecurity incident. The project aims to analyze these incidents, extract affected data, identify threat vectors, and implement technical and procedural countermeasures.

📝 Case Description
The company Invent S.L, which operates branches in Australia, Italy, and Spain, has suffered a security incident in each of its locations.

**🇦🇺 Australia Branch**

In the Australian branch, a leak of sensitive information involving several employees (email addresses and passwords) has been detected. The affected employees reported receiving suspicious email campaigns with HTML attachments resembling the Office 365 login portal over the past few days.
The company does not have two-factor authentication (2FA) in place, making it possible for an attacker to access corporate email and other public-facing applications hosted on Microsoft.
Due to the company having over 10,000 employees, it is not feasible to reset and block all accounts for business continuity reasons. Therefore, it is crucial to identify only the affected users.

**🇮🇹 Italy Branch**

In the Italian branch, an unauthorized access was discovered on one of the accounting servers. This access was detected during a routine audit by the IT team. The team plans to hire an external provider to handle the investigation and remediation.

**🇪🇸 Spain Branch**

At the Spanish site, an attack was identified on one of the factory servers. All files on the server have been encrypted with the “.NM4” extension. The systems were patched against MS17-010.
As part of the company’s Incident Response Team, our mission is to investigate and determine what occurred in each of the situations described.

🔍 Evidence Provided

- Australia: Proxy traffic logs covering the time window when the incident occurred.
- Italy: No evidence provided, as an external provider will handle the investigation.
- Spain: A scan of open ports on the affected system and a partial ransom note.

✅ Tasks

- Pre-Analysis Questions
   - What type of threat impacted the Australian branch?
   - What type of threat impacted the Madrid (Spain) branch?
   - What risk does an organization face when experiencing an information leak like the one described in Australia?

- Regarding the Italy incident
   - Should the affected system be disconnected from the network for analysis?
   - What hardware component of the server should be cloned/dumped before shutting it down?

📊 Evidence Analysis – Australia
    - Develop a script to parse the provided traffic capture so that it shows the final output in the terminal.
    - Which user email addresses were affected? A manual analysis may be performed if the above script is not completed.

📊 Evidence Analysis – Spain
   - How does this type of threat work? (max. 5 lines)
   - Can the data be recovered as of today?
   - What was the entry vector used by this threat? (Refer to the “spain.jpg” evidence)
   - Propose countermeasures for the Australian branch to prevent recurrence.
   - Propose countermeasures for the Spanish branch to prevent recurrence.

---

### 🔍 PART I: Pre-Evidence Analysis – Tasks Requested

  Before proceeding with the technical analysis of the provided evidence, the following tasks are requested:

  #### 🕵️‍♂️ Incident Analysis – Threat Identification and Risk Assessment

  📍 What type of threat affected the Australia branch?
  
   The attack identified appears to be a phishing or possibly a spear phishing campaign targeting high-ranking personnel. The use of HTML attachments and Office 365 impersonation suggests that the main objective was credential theft.
  Once the attacker obtained valid credentials, they could potentially access multiple files and services—especially since the company lacks multi-factor authentication (MFA), increasing vulnerability to unauthorized access of critical assets such as corporate emails, SharePoint, Teams, etc.

✅ Threat classification: Credential theft via phishing using HTML files impersonating Microsoft Office 365.

🔐 What risks arise for an organization following a data breach like the one in Australia?

- **This incident introduces several serious risks, including:**

   - Exposure of sensitive/confidential information
   - Unauthorized access to internal systems and high-privilege resources
   - Risk of privilege escalation if stolen accounts have elevated permissions
   - Identity impersonation, particularly if executive accounts are compromised
   - These outcomes can severely compromise both operations and reputation.


📍 What type of threat affected the Madrid branch?

The detected threat was a ransomware attack, specifically from the nm4 family.
The impact was total encryption of the server’s files.
According to the provided information, the system had been patched using MS17-010, which addresses critical vulnerabilities in the SMBv1 protocol.

✅ Threat classification: Ransomware attack targeting vulnerable SMBv1 services.


🇮🇹 Incident Response – Italy Branch

🔌 Should the system be disconnected from the network for analysis?
  Yes. The system should be disconnected immediately and a backup should be performed before shutdown.
  The machine must remain powered on until live data is captured, including memory (RAM), to enable forensic analysis.
  Disconnecting prevents data exfiltration, attacker persistence, and lateral movement.

  💾 What hardware components should be dumped or cloned before shutting down the server?
  
 **RAM memory: A live memory dump is essential to capture:**

 - Running malware
 - Active network connections
 - In-memory commands
   
 **Hard disk: A bit-by-bit disk image should be created to:**
 - Analyze logs
 - Recover deleted files
 - Preserve evidence

📋 Pre-handover steps (before giving the machine to a third-party provider):

- Disconnect the server from the network
- Capture a RAM dump
- Create a forensic image of the hard drive
  
**Thorough documentation of:**
- Date and time
- Operating system
- Hostname and blocked state
- Server name and its role
- Maintain the chain of custody to ensure forensic integrity.


---

### 🧩 Part II: Evidence Analysis – Madrid Branch

🔐 How does this type of threat operate? (max. 5 lines)

The .NM4 ransomware operates by encrypting user files using a combination of AES and RSA encryption algorithms. This dual-layer encryption makes decryption highly complex without the corresponding private key.
The use of asymmetric encryption ensures that even if the AES key is obtained, files remain inaccessible without the RSA private key. The goal is to extort payment in exchange for decryption capabilities.

🔐 Could the data be recovered today?

Recovery depends on several factors. If a backup exists, data can be restored from it. However, if the ransomware variant uses strong encryption (such as AES or RSA) and no decryption tool or key was left behind by the malware, recovery becomes highly unlikely.
It’s important to note that paying the ransom is not recommended, as it does not guarantee data recovery and may encourage further attacks.

- 🔐 What was the entry vector used by this threat? (Use the spain.jpg evidence)

    <img width="819" height="258" alt="image" src="https://github.com/user-attachments/assets/2ace920b-4f74-425f-a18e-15ec6733a9f0" />

The image shows a series of connections that are "listening" and waiting to receive incoming traffic, indicating that the ports are open. Among the open ports, the most noteworthy are:
- 135: RPC
- 445: SMB
- 3389: RDP
- 139: NetBIOS Session Service, used for SMB
  
**If we assess the vulnerability of these ports, the ones most likely to be exploited by ransomware stand out as potential entry vectors:**

- 445 and 139 are both associated with the SMB protocol and may be exposed to malware like WannaCry, among others.
- Port 3389, if exposed to the internet, could also serve as a potential entry point.


**Implement countermeasures at the Madrid headquarters to prevent recurrence of this type of incident:**

- Eliminate the ransomware (if possible).
- Restore backups to recover data and systems.
- Change access credentials, ideally for all personnel.
- Secure exposed RDP services to avoid remote exploitation.
- Activate antivirus protection, and deploy EDR (Endpoint Detection and Response) or XDR (Extended Detection and Response) solutions.
- Isolate and clean infected host.
- Harden RDP (NLA + IP restrictions).
- Implement **EDR or XDR**.
- Block unused ports on firewalls.
---

### 🕵️‍♂️ Evidence Analysis for the Australia Office

 Before answering the questions, we'll carry out a general analysis of the PCAP capture.
 Within the capture file properties, we will observe the following information:
  
- Duration of the capture
- Total number of captured packets
- Other useful metadata
- Hierarchy Protocols
  
    <img width="800" height="595" alt="image" src="https://github.com/user-attachments/assets/07479ca1-e4d4-4b89-a2ad-ce1e37719b42" />
    <img width="800" height="312" alt="image" src="https://github.com/user-attachments/assets/d9676975-9ba5-4bd1-816c-29b4fa0012a5" />
    <img width="800" height="457" alt="image" src="https://github.com/user-attachments/assets/52c4ea88-b1f8-4093-86ab-0fa544506483" />

    We observe that the IPs involved are src: 10.6.0.81 and dst: 213.133.98.98, which is a public IP or belongs to a server. The number of packets sent exceeds 2000, making this the most frequently used and most suspicious connection from the start.

   <img width="800" height="406" alt="image" src="https://github.com/user-attachments/assets/3b7ca199-bed2-4aea-9a68-905155894f88" />
   
   If we examine the following image, we can see that communications occurred through ports 80 and 443.
  
    Now, if we proceed to export the objects:
  
   <img width="800" height="453" alt="image" src="https://github.com/user-attachments/assets/cfe0f3e2-974a-4910-928d-f641fd5d09fc" />
   <img width="800" height="452" alt="image" src="https://github.com/user-attachments/assets/9e6802ae-a5fe-43b2-a347-d877e4498246" />

   We first observe a significant amount of traffic to websites that should not typically be accessed from an office environment—pages such as Marca, GoDaddy, 20minutos, among many others. Based on this browsing activity, we can infer that malware could later be introduced, as users appear to be navigating freely without restrictions.
   However, when analyzing packet number 10610, we clearly see the domain: suspicious.microsoft.logon.fadel.id, containing HTML content. This already meets several of the suspicious characteristics being investigated. If we examine the filename field, we can confirm that this was triggered by a GET request.

 

   <img width="886" height="42" alt="image" src="https://github.com/user-attachments/assets/dc1b9c4b-fef8-45ba-ab0e-830bf846d44d" />
   <img width="886" height="215" alt="image" src="https://github.com/user-attachments/assets/06d3c65e-8e37-46d4-bb4b-335d58b32ded" />

  We observe that the GET request contains a link or code snippet, making it potentially suspicious. At this point, we'll use ChatGPT to examine what it might be.

**Analyze DNS logs**

followed by GET and POST requests,
and finally, email analysis using the SMTP protocol.
In some cases, the content and affected email addresses are encrypted, which is why it's necessary to decrypt the SMTP traffic hidden by the TLS protocol. This protocol is the evolution of the previous SSL protocol and encrypts connections that use HTTPS.

**To decrypt the logs, there are several methods:**

The first involves obtaining the SSLKEYLOGFILE from the browser used to capture the packets.
In other cases, a .der certificate file is provided along with the .pcap capture file, which enables decryption of TLS v1.2 traffic, ultimately revealing the hidden content

There are several ways to decrypt TLS traffic for analysis:

- Using SSLKEYLOGFILE:
Extract session keys from the browser performing the packet capture. These keys allow tools like Wireshark to decrypt TLS sessions, provided the traffic was captured from that system.

- Using a .der certificate file along with the .pcap capture:
If the server’s private key is available (in .der format), it can be loaded into packet analysis tools to decrypt TLS 1.2 traffic and reveal the hidden content within SMTP sessions.



  <img width="886" height="371" alt="image" src="https://github.com/user-attachments/assets/44ccb600-bf7e-43a1-9057-05c85c71349c" />

  By performing a follow stream, we see that the host matches the one previously identified: suspicious.microsoft. We also observe that the user agent is Linux

  <img width="886" height="589" alt="image" src="https://github.com/user-attachments/assets/db4ebafa-8768-4342-b55b-34455020986c" />

Through the HTTP stream, we see that the connection was made via port 80.

**We then take the GET request and use AI to investigate what’s happening:**

**user?bWdhcmNpYUBpbnZlbnQuY29tOm1hbnphbmExMjMK==&aHR0cHM6Ly9wYXN0ZWJpbi5jb20vMlIwRmVtM0MK== HTTP/1.1**
We discover a Pastebin URL, which could potentially be used to download malicious code and is encoded in base64.
Normally, Pastebin is a service that allows snippets of text (such as code fragments, logs, or configurations) to be uploaded and easily shared via a link (source: es.wikipedia.org).
It’s commonly used by developers, support teams, and even malicious actors to rapidly exchange information.
It is deduced that Pastebin was used to exfiltrate data or store payloads. Given that it appears in network logs, it suggests that someone—via a phishing attack—may have tried to either upload malicious files or download sensitive information.
After decoding the Pastebin values, we find an exposed credential:
**mgarcia@invent.com:manzana123**

It tells us that the user mgarcia with the password manzana123 is involved. If we paste the code into the internet: https://pastebin.com/2R0Fem3C, we find that there are three email addresses associated with the Pastebin:

- hifid@invent.com:123dmr
- hjerfs@invent.com:applepup
- jdarwin@invent.com:redcar#

    <img width="886" height="398" alt="image" src="https://github.com/user-attachments/assets/2cee2740-0f60-436b-8d44-2f688f05ca54" />
    <img width="886" height="73" alt="image" src="https://github.com/user-attachments/assets/9b15319c-f23d-4f98-8504-dae6e91a7003" />

 In the image, we see that IP 10.6.0.81:42046 attempts to communicate with IP 23.133.98.98:53, which corresponds to the domain suspicious.microsoft.logon, and receives a response from it.
 By applying the filter:
**(ip.src == 10.6.0.81 && udp.srcport == 42046 && udp.dstport == 53) ||   (ip.dst == 213.13.98.98 && udp.dstport == 42046 && udp.srcport == 53)**
we can view the full conversation and, by performing a UDP follow stream, observe the interaction between the client and the suspicious server.

   <img width="886" height="207" alt="image" src="https://github.com/user-attachments/assets/b6d83fee-8900-48b7-859c-311ac6afd76d" />

In the image, we observe the conversation where the client attempts to connect to the suspicious server.

  <img width="886" height="81" alt="image" src="https://github.com/user-attachments/assets/8d493a6f-16d8-4a18-b9a1-39e0598d4bce" />
  
They communicate successfully; now we’ll see if there was successful HTTP and HTTPS communication—we applied the filter

  <img width="886" height="43" alt="image" src="https://github.com/user-attachments/assets/ff387c0a-0946-444c-8178-ba26a7593d69" />
  <img width="886" height="613" alt="image" src="https://github.com/user-attachments/assets/1200cc00-6629-4567-bed4-c99f76f9f287" />
  <img width="886" height="133" alt="image" src="https://github.com/user-attachments/assets/54d7566b-6c22-4a00-8107-1b5373699acb" />

  **Analyzing:**
  
We observe that IP 10.6.0.81 initiates a three-way handshake through port 35180 to IP 49.50.8.230 (upon searching with sandbox tools like AbuseIPDB, Talos Intelligence, and VirusTotal, this IP is flagged as neutral, BUT one should not rely solely on that information).
Continuing with the analysis of the communication, we see the initial SYN, followed by a response from IP .230 with SYN and ACK. Then, we observe data exchange involving a GET request and the loading of a malicious file. 
Finally, IP .81 responds with FIN, ACK. Although an HTTP/1.1 404 Not Found is seen and no useful content was retrieved, it can be deduced that:

– There was an attempt to exfiltrate data
– C2 (command and control) communication
– Active malware or phishing in execution.

**Recommendations:
- Block IP 49.50.8.230 and the domain
- Isolate the host 10.6.0.81
- Search for other infected machines
- Escalate the case if applicable to the appropriate level
- Activate two-factor authentication
- Enable firewalls*


---

### 🟢 **Australia – Phishing Campaign**

- Attack type: Spear phishing with malicious HTML attachments spoofing Microsoft login pages.
- Domain involved: `suspicious.microsoft.logon.fadel.id`
- Exfiltration observed via: `http://pastebin.com/2R0Fem3C` (Base64 decoded credentials).
- Affected emails:
  - `mgarcia@invent.com:manzana123`
  - `hifid@invent.com:123dmr`
  - `hjerfs@invent.com:applepup`
  - `jdarwin@invent.com:redcar#`
- IP involved: `49.50.8.230` (neutral on VirusTotal, suspicious behavior).
- Communication over ports `80`, `443`, and `53` observed.
- Methods used: packet stream analysis, HTTP follow-up, Base64 decoding.

#### 🛡️ Countermeasures:
- Enable **2FA** company-wide.
- Block domain `*.fadel.id` and IP `49.50.8.230`.
- Inspect host `10.6.0.81` for lateral movement.
- Activate and monitor DNS logging and mail gateway filters.

---



## 🧠 Skills Acquired

- Network log analysis with Wireshark.
- Detection of phishing and exfiltration techniques.
- Correlation of domain/IP reputation with traffic patterns.
- Base64 decoding and credential extraction.
- Ransomware behavior and attack vector identification.
- Forensics procedures and evidence handling.

---



## 📎 Attachments

- 🧪 `australia-analysis.pcap` — Proxy traffic analysis
- 📸 `spain.jpg` — Open ports evidence

---


## ✅ Recommendations Summary

| Location  | Action Items                                                                 |
|-----------|------------------------------------------------------------------------------|
| Australia | Block malicious IP/domain, implement 2FA, enhance email filtering            |
| Spain     | Isolate host, restore backups, review RDP/SMB exposure, deploy EDR           |
| Italy     | Clone RAM/disk, disconnect server, document and escalate to forensics vendor |



## 🌍 Summary of Incidents by Region

| Location   | Incident Type                  | Description                                                                 |
|------------|--------------------------------|-----------------------------------------------------------------------------|
| Australia  | **Phishing / Credential Theft** | HTML attachments spoofing Office 365 were used to steal credentials.       |
| Italy      | **Unauthorized Access**         | Detected on an accounting server; no evidence provided; vendor involved.   |
| Spain      | **Ransomware (.NM4)**           | All files encrypted; MS17-010 patch applied; suspected SMB exploitation.   |

---

¡



