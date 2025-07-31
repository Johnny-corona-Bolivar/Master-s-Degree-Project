# 🕵️‍♂️ Final Project – Ethical Hacking

## 📌 Project Overview

This project consists of two parts:

1. **Passive and active information gathering** on a selected target organization, the **Universidad Complutense de Madrid (UCM)**, using OSINT tools and reconnaissance techniques.
2. **Analysis and exploitation** of a vulnerable machine in a controlled environment, simulating real-world attacks such as FTP exploitation, bypass login, command injection, and privilege escalation.

The goal is to apply ethical hacking techniques responsibly and document each step taken to understand the attack surface and potential vulnerabilities.

## 🎯 Objectives

- Conduct OSINT and reconnaissance activities to identify valuable information about UCM.
- Scan and enumerate exposed services and systems in a safe lab environment.
- Identify, exploit, and document vulnerabilities found in the target machine.
- Practice web and system exploitation techniques such as login bypass, RCE, and privilege escalation.
- Reflect on the importance of ethical responsibility, scope limitations, and legal compliance.

---
## 🛠️ Tools Used

| Tool              | Purpose                                  |
|-------------------|------------------------------------------|
| Google Dorks      | Passive reconnaissance                   |
| Shodan            | Public asset and port discovery          |
| Censys            | Additional OSINT                         |
| Whois             | Domain registration info                 |
| The Harvester     | Email and host enumeration               |
| Maltego           | OSINT visualization                      |
| VirusTotal/Talos  | IP and domain reputation                 |
| Nmap              | Network scanning                         |
| Netdiscover       | IP identification in local network       |
| Burp Suite        | HTTP interception and injection          |
| Gobuster          | Directory brute-forcing                  |
| nc (Netcat)       | Reverse shell listener                   |
| Bash / Shell      | Manual command execution & exploitation  |

---

## 🔍 Task 1 Description:  Passive Reconnaissance Results
You are required to gather as much information as possible about a specific organization (you may choose any organization). The analysis will focus only on the reconnaissance phases—specifically, 
reconnaissance and fingerprinting, as well as scanning (basic commands, ports, and services).

As a result of this exercise:
You must present the information collected—such as details about employees, domains, IP addresses, public servers, and any other relevant data—along with the tools used and the phase each test corresponds to. 
The information may be grouped by analysis phase, and the steps followed during the process should be clearly explained.

For this project, I selected **Complutense University of Madrid** as the target organization.  
The following tools will be used to perform **passive information gathering** and reconnaissance during the analysis:

-	Google Docks o Docking
-	Shodan
-	Censys
-	Whois
-	The Harvester
-	Maltego

Other complementary tools include:

- Dominio.es
- Dns Lookup
- Cisco Tool Intelligence
- Archive.org

1. **Google Dorks**:  
By performing targeted search queries, several PDF documents were found.  
However, after analysis, no significant or sensitive information was discovered.

 <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/8ecbf099-bd22-4bc1-9346-e77ed915a1bf" />

The following command can reveal if any PHP-based pages on the UCM site contain potentially leaked information linked to an ID parameter: "site:ucm.es inurl:php?id="


 <img width="600" height="462" alt="image" src="https://github.com/user-attachments/assets/84daf412-4e8d-4a83-abc1-c53438243efa" />

 With the following command, we will search the **ucm.es** domain for any PDF documents that may have been exposed and contain the keyword **"restricted"**: "site:ucm.es filetype:pdf intext:restricted"

 <img width="600" height="483" alt="image" src="https://github.com/user-attachments/assets/09b2413d-f81d-4b5e-9e58-ab16b8e94855" />

 “With the following command, we will search for subdomains of UCM, and as can be seen, there are several that share the domain ucm.es.”

  <img width="447" height="402" alt="image" src="https://github.com/user-attachments/assets/6381e505-5bb2-48f6-916b-8598b74c8d2a" />
  <img width="429" height="400" alt="image" src="https://github.com/user-attachments/assets/ec5f7d4c-0b43-400a-b5b9-9b4957b90a14" />

 "We will now use Dominio.es to analyze the ucm.es domain."
 
  <img width="886" height="138" alt="image" src="https://github.com/user-attachments/assets/d555fddf-4da2-488f-be44-1fe4a3eeb076" />

  "We are given the following results. We open the first result and obtain:"
  
  <img width="700" height="628" alt="image" src="https://github.com/user-attachments/assets/cb879f57-86a0-4650-bcf8-eaa4fa4ad919" />
  <img width="700" height="225" alt="image" src="https://github.com/user-attachments/assets/f946a866-4c54-4d13-896a-16149e4974df" />
  

  "We found valuable information such as a DNS, which in simple terms is a Domain Name System — essentially an address book that organizes and identifies each domain on the web. It also provides IP addresses, 
   which can be used for further analysis. We will take advantage of this information and perform a DNS lookup.
  
  We will analyze only two domains: one of them is crispin.sim.ucm.es."

  <img width="660" height="219" alt="image" src="https://github.com/user-attachments/assets/896cc920-db74-44b5-a270-aca52a57c2dd" />
  
  "We verified and found that it is an A-type domain, which resolves the domain to an IPv4 address.
   We used WHOIS to analyze the given IP address: 147.96.1.9.
   From the results, we observed information that could be valuable for a more in-depth analysis."

   <img width="551" height="329" alt="image" src="https://github.com/user-attachments/assets/e5dc1054-8733-47b3-b9d7-ce0b8a63ac0b" />
   <img width="552" height="367" alt="image" src="https://github.com/user-attachments/assets/1f9b575d-ac0a-40ee-89ff-17ff9ddd22ea" />
   <img width="549" height="287" alt="image" src="https://github.com/user-attachments/assets/377eaeb1-466f-474f-891a-90841f5a28c5" />
   <img width="642" height="401" alt="image" src="https://github.com/user-attachments/assets/3602b7cd-5f0f-4483-b257-757eca9b25b0" />

  "We will analyze the following DNS: crispin.sim.ucm.es with IP address 147.96.2.4.
   We can see that it is an A-type domain:"
   
   <img width="700" height="146" alt="image" src="https://github.com/user-attachments/assets/91806109-35dc-4806-9776-8025135c1c68" />

   "We identified the IP's location as follows:"

   <img width="700" height="409" alt="image" src="https://github.com/user-attachments/assets/056709f5-5330-4b2a-a8f2-e73778088fc6" />
   <img width="600" height="367" alt="image" src="https://github.com/user-attachments/assets/d916dc35-161c-43af-a099-295ef764c273" />
   <img width="600" height="600" alt="image" src="https://github.com/user-attachments/assets/04028782-d353-4d12-bd88-5ab9127200bb" />
   <img width="600" height="331" alt="image" src="https://github.com/user-attachments/assets/e2efe519-09bc-4fca-8bdf-47bf8acb340a" />
   
   "Now, by using VirusTotal to analyze with Cisco Talos Intelligence, we are able to gather the following information: we observe the location, the email volume — which might be useful — and the mail servers, which can be of great value."

   <img width="800" height="306" alt="image" src="https://github.com/user-attachments/assets/0e0f4f68-a6ae-4e28-a1e9-1acdab68014f" />
   <img width="800" height="343" alt="image" src="https://github.com/user-attachments/assets/41e705b5-69bb-44b1-b8eb-f6351915b001" />

   "Furthermore, we discovered a significant amount of additional information:"

   <img width="700" height="407" alt="image" src="https://github.com/user-attachments/assets/89a28ce1-7dac-4605-98c0-5902bc556dcf" />

   "Now we will focus on a more in-depth passive analysis using tools such as Shodan, TheHarvester, and Maltego."

   - Shodan:

     "As seen in Shodan, we obtained 73 results, but we will focus on the one that matches our domain ucm.es. We can see a list of the most commonly used ports — specifically ports 443 and 80."

     <img width="621" height="414" alt="image" src="https://github.com/user-attachments/assets/4ea262ce-71c9-4341-8238-1476d952929e" />


     "When accessing the second option, we have:
      Basic information:"

     <img width="618" height="400" alt="image" src="https://github.com/user-attachments/assets/8062bfe0-e83d-4018-87a7-80f1a5ea76d2" />

     "The most used ports:"

     <img width="700" height="411" alt="image" src="https://github.com/user-attachments/assets/32497950-d733-46c7-a6f9-c4591cbb1234" />

     "Normally, when the web application has any detected vulnerabilities, Shodan will show them; however, in this case, there appear to be no leaks.

   - The Harvester:
     
     "theHarvester -d ucm.es -b yahoo,bing,duckduckgo,github-code -s -l 100"

     We will use the above command to indicate that we will search within the domain ucm.es, querying sources such as Yahoo, Bing, DuckDuckGo, and GitHub code, and that we will verify results in Shodan with a limit of 100 results.

     <img width="324" height="540" alt="image" src="https://github.com/user-attachments/assets/ba97b7f6-9aa6-473b-9f3d-d41f2c53a7d6" />
     <img width="402" height="515" alt="image" src="https://github.com/user-attachments/assets/ce6e69ab-26d7-4bac-b758-6f9b8a1982ef" />

     "We can see that we found some emails which could potentially be used for phishing attacks to obtain credentials. We also obtained a series of hosts and subdomains.
     However, after further investigation, I will use an earlier version of TheHarvester, which provides results in a more readable format and includes more sources."

     <img width="685" height="688" alt="image" src="https://github.com/user-attachments/assets/5147e662-81e5-4793-951d-b5aa745e504f" />

     "As we can see, this is an older version which, when running the Python script:
      
     theHarvester.py -d ucm.es -b google,bing,yahoo,trello,virustotal,duckduckgo,linkedin -l 100 -f escaneo

     we are instructing it to search the mentioned sources with a limit of 100 results and save the entire query about the domain ucm.es into an HTML file named 'escaneo'. It even shows the associated IP address, which we will analyze later:
     www.ucm.es: 147.96.1.15"

     "The report"
     <img width="886" height="116" alt="image" src="https://github.com/user-attachments/assets/a72033fc-1fc0-47bf-926b-21dc3cc869f2" />
     <img width="886" height="327" alt="image" src="https://github.com/user-attachments/assets/87d130a1-aa0f-46af-8bbb-589a79671afa" />
     <img width="886" height="581" alt="image" src="https://github.com/user-attachments/assets/ee2f2d3c-2090-4356-856a-c0d0ea1f9fea" />


   - Maltego:

     "By executing some transforms, we can find a lot of information like the following, using one of the emails we previously discovered with TheHarvester."

     <img width="800" height="546" alt="image" src="https://github.com/user-attachments/assets/1b1df9fa-6054-45ed-9f7f-a2534d290c78" />

     "If we apply more transforms focused on the organization itself, we obtain additional information such as leaked documents. It would then be a matter of investigating those documents further to uncover more information."

     <img width="800" height="392" alt="image" src="https://github.com/user-attachments/assets/4272826a-e422-4d85-b958-dedb3771e61d" />

     "We could analyze many things with Nmap, but since I do not have permission, I will not execute any code. However, we could run, for example, the following command:"
     
      <img width="770" height="72" alt="image" src="https://github.com/user-attachments/assets/7784a36d-af29-4ab2-bc5a-4b8477ed1322" />


      ## 🔍 Task 2 Description: vulnerability assessment

     "This would involve performing a vulnerability assessment against the detected servers. In this case, due to the criticality of the environment, we do not have permission to conduct such tests and currently lack a testing environment to perform attacks. Therefore, for this second exercise, it is necessary to download a virtual machine that has been prepared for this purpose:

     - Launch a semi-automated scan to identify possible web vulnerabilities.
     - For detected vulnerabilities, verify whether they are false positives or genuine threats.
     - Exploit the detected vulnerabilities using tools different from those used for vulnerability detection.
     - Perform privilege escalation.
     - Analyze the other running services."
    
       
  - The virtual Machine

    <img width="700" height="400" alt="image" src="https://github.com/user-attachments/assets/73404b11-80a9-4136-b1cb-881fbf4728ca" />

    "We will use Netdiscover to find out the IP address of the machine and begin the scan."

    <img width="733" height="128" alt="image" src="https://github.com/user-attachments/assets/8f768fd6-d447-4543-92b0-cc85d9b08915" />
    <img width="733" height="274" alt="image" src="https://github.com/user-attachments/assets/4d34328e-7032-4296-a24f-8d7dd8fd77a5" />

    VM: 192.168.153.147

    <img width="700" height="405" alt="image" src="https://github.com/user-attachments/assets/70fafd91-be26-40c9-a5d8-4202aa873c07" />

    "We inspect the source code and obtain a FLAG:
      FLAG{B13N_Y4_T13N3S_UN4_+}

    Bypass_Login_1

    <img width="700" height="356" alt="image" src="https://github.com/user-attachments/assets/2eb7de2a-fdee-42fb-8ff4-8455001efb81" />

    Source Code:

    <img width="866" height="485" alt="image" src="https://github.com/user-attachments/assets/0a22d671-a0ef-47d7-add0-cd4093725c72" />

    password.value==’supersecret’ and admin.
    flag: BIEN! Tu flag es: FLAG{LOGIN_Y_JAVASCRIPT}
    <img width="692" height="188" alt="image" src="https://github.com/user-attachments/assets/f6c8af82-88fa-48cb-b0be-09ddfafcf25e" />





    

    


    

    

    


     


     



     

     


     

     








     



   






  


   
---

## 💡 Skills Developed

- OSINT gathering using search engines and threat intelligence platforms  
- Subdomain and IP analysis  
- Manual and automated service enumeration  
- Exploiting FTP, web vulnerabilities, and command injection  
- Web application analysis with Burp Suite  
- Reverse shell creation and privilege escalation  
- Directory and file enumeration techniques  
- Secure handling of evidence and ethical best practices  


---

## 📎 Notes

⚠️ All exploitation was performed in a controlled environment.  
✅ No real systems were harmed.  
🛑 Real-world scanning without authorization is illegal and unethical.
