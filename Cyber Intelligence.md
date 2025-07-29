# 🎣 Phishing Campaign Simulation using GoPhish

This project is part of a cybersecurity master's program, focusing on the simulation of a phishing campaign for educational and awareness purposes. The objective is to understand the full phishing workflow — from planning and deployment to tracking and reporting — using realistic templates and behavior-based targeting.

---

## 🧠 Project Overview

Phishing continues to be one of the most effective attack vectors, often exploiting human vulnerabilities more than technical ones. This project simulates a real-world phishing campaign in a controlled, virtualized environment using **GoPhish** as the phishing framework.

The goal is to understand how attackers design campaigns, how users interact with suspicious emails, and how defenders can track metrics and improve organizational awareness.

---

## 🎯 Objectives

- Plan and simulate a realistic phishing campaign
- Create customized templates based on user roles and behavior
- Monitor user interaction with phishing emails and landing pages
- Raise awareness of phishing threats through education and analysis

---

## 🛠️ Tools & Technologies

- **VirtualBox** – Virtualization platform for secure testing  
- **Kali Linux** – OS for security tools and framework setup  
- **GoPhish** – Open-source phishing simulation tool  
- **Gmail SMTP** – Used for sending test phishing emails over port 465  

---

## ⚙️ Campaign Setup

### 📧 Sending Profile
- Configured Gmail’s SMTP (port 465) within GoPhish’s sending profile
- Personalized headers and sender email for realism
- Used application-specific password for authentication

### 🌐 Landing Page
- Targeted the **Netflix login page** as the spoofed site
- Imported HTML directly from the live site or URL
- Enabled options:
  - `Capture submitted data`
  - `Capture passwords`
- Set redirection behavior after login attempt

### ✉️ Email Template
- Customized HTML emails to closely resemble official Netflix communication
- Embedded images and text for higher realism
- Imported templates for consistency and engagement

### 👥 Users & Groups
- Created user group `Marketing ABC` with 2 members
- Each user entry included:
  - First Name  
  - Last Name  
  - Email  
  - Position

### 📆 Campaign Launch
- Defined campaign frequency and end date  
- Selected:
  - Email Template  
  - Landing Page  
  - Target URL  
- Configured the phishing server in `config.json` to run on port 80, matching the campaign URL

---

## 📊 Results & Reporting

Once the campaign was launched:
- Emails were sent to all users in the selected group
- Interaction data was collected:
  - Emails sent
  - Emails opened
  - Links clicked
  - Credentials submitted
  - Reports from users

### Example Result:
- User `Johnny` opened the email and clicked on the phishing link
- Due to browser protection, the spoofed page was blocked, but in a real scenario, credentials would be captured and stored in CSV format

---

## 🔐 Ethical Disclaimer

> This project was carried out strictly for educational purposes in a controlled environment. No real users or external systems were involved. The goal was to raise awareness about phishing threats and learn how attackers operate so defenses can be improved.

---

## 📚 Key Skills Acquired

- Phishing lifecycle planning and execution  
- GoPhish platform configuration and customization  
- Social engineering awareness  
- HTML email and landing page manipulation  
- Security metrics collection and interpretation  
- Secure lab setup using VirtualBox and Kali Linux

---

## 🧩 Next Steps

- Expand simulation to additional departments with tailored scenarios  
- Integrate reporting into a central SIEM for automated alerts  
- Combine phishing awareness training with recurring campaigns  
- Test different phishing tactics (e.g., invoice scams, credential harvesting, drive-by downloads)

---

