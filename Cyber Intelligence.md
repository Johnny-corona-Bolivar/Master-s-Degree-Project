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
- Understand the tactics, techniques, and procedures (TTPs) used in phishing or malware attacks.
- Perform a detailed analysis of the chosen attack vector.
- Simulate the attack in a controlled environment to study its behavior and impact.
- Identify indicators of compromise (IOCs) and develop detection strategies.
- Enhance practical skills in cyber threat intelligence gathering and incident response

---

## 🛠️ Tools & Technologies

- **VirtualBox** – Virtualization platform for secure testing  
- **Kali Linux** – OS for security tools and framework setup  
- **GoPhish** – Open-source phishing simulation tool  
- **Gmail SMTP** – Used for sending test phishing emails over port 465  

---

## ⚙️ Campaign Setup

### 📧 Sending Profile : The first step is to configure the Sending Profile section. In this section, we set up our HOST and SMTP server, as shown in the image
- Configured Gmail’s SMTP (port 465) within GoPhish’s sending profile
- Personalized headers and sender email for realism
- Used application-specific password for authentication
  
  <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/78dbcee7-96ff-4334-9396-a5b581e8c47a" />
  <p>We use Gmail’s SMTP server with port 465.
  This setup allows us to send a test email to verify that emails are delivered correctly. We can customize the email header to make it look more professional.
  There is a section for the sender’s name and the SMTP "from" address, which is the email address used to send the phishing emails.
  Using port 465, the username will be the same email address as the SMTP "from" field, and the password can be set in two   ways: either using the email account’s actual password or, as I did, by generating an app-specific password.</p>


### 🌐 Landing Page : Here, we will configure the page to be spoofed — that is, the page that will be displayed. As shown in the image
- Targeted the **Netflix login page** as the spoofed site
- Imported HTML directly from the live site or URL
- Enabled options:
  - `Capture submitted data`
  - `Capture passwords`
- Set redirection behavior after login attempt

  <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/c92f5b6c-6acc-4c8f-bee8-05a1931c6996" />
  <img width="500" height="221" alt="image" src="https://github.com/user-attachments/assets/770bad9b-d254-4586-beb7-7160d9888e96" />
  <p>We observed that for this project we will use the Netflix website (although it can be done with any website desired). In this section, we can configure it as follows: we can import a site through its URL.</p>

  <img width="500" height="212" alt="image" src="https://github.com/user-attachments/assets/39ac45ee-5728-41e6-9a75-a22af54366e9" />

   <p>Alternatively, if desired, we can work directly with an HTML file. As shown in the first image, by clicking the Source button, we can view the HTML code of the Netflix page being observed.
     The most interesting options are Capture Submitted Data and Capture Passwords, which are the features we will use in this campaign for educational purposes. These two options allow us to capture data and passwords entered by victims. The captured        information is stored in a CSV file, which we will review later.
     Additionally, we can set up a redirection once the victim clicks the phishing link.</p>
     <p>The most interesting options are Capture Submitted Data and Capture Passwords, which we will use in this campaign for educational purposes. These two options allow us to capture the data and passwords entered by the victims. This information is        stored in a CSV file, which we will review later.
      We can also set up a redirection after the victim clicks the link.</p>


### ✉️ Email Template :  In this section, we will configure the email that the victim will receive. Here, it is possible to import an existing email previously used on the platform, making the phishing attempt more credible.
- Customized HTML emails to closely resemble official Netflix communication
- Embedded images and text for higher realism
- Imported templates for consistency and engagement

   <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/a13767da-c23d-4872-965b-96bf032d2a5b" />
   
   <p>En la sección HTML podemos personalizar el mensaje inclusive incluir imágenes, puedes escribir el texto y el mismo Gophish lo lleva al HTML.</p>


### 👥 Users & Groups: In this section, we can create the groups and users who will receive the phishing email. In the image, we can see that I already have a group created called Marketing ABC, which contains 2 members.
- Created user group `Marketing ABC` with 2 members
- Each user entry included:
  - First Name  
  - Last Name  
  - Email  
  - Position
 
    <img width="500" height="102" alt="image" src="https://github.com/user-attachments/assets/d6cf7a87-dcc1-4415-9a28-c9934b261571" />
    <p>The name can be anything; in this example, we used that name just to distinguish it. As shown, it is possible to add the first name, last name, email address, and position.</p>

    <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/064e0035-7020-4f43-bf99-9565cfcfa0b3" />



### 📆 Campaign Launch : Here, we will define the campaign and schedule how often the phishing emails will be sent, when the campaign will end, and other related options.
- Defined campaign frequency and end date  
- Selected:
  - Email Template : Here, the email template that was previously created is selected. 
  - Landing Page  :The previously created template will be selected.
  - Target URL  : This is where it gets interesting, as GoPhish operates with the phishing server on port 80. This port and the URL must match the configuration in the GoPhish JSON file, which can also be edited from Kali Linux. This is shown more      clearly here.


  <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/314799fa-ac2e-4bf0-8f87-15451023c42c" />
  


- Configured the phishing server in `config.json` to run on port 80, matching the campaign URL

  <img width="500" height="500" alt="image" src="https://github.com/user-attachments/assets/71a49d60-7e22-44b5-a048-93708a77c886" />


<p>As we can see in the JSON file, the phishing server matches our configured URL.
Once all the options are set, we click Launch Campaign, and the email should be delivered automatically — we will verify this.

After the email is sent, we are redirected to a dashboard where we can view the campaign statistics, including: </p>

  - Emails sent

  - Emails opened (indicating whether the victim opened the message)

  - Links clicked

  - Data submitted

  - Whether the victim reported the email


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
 
    <img width="886" height="166" alt="image" src="https://github.com/user-attachments/assets/a59abc29-98a5-44bd-90b9-15b4ea6c97f7" />
    
    Acá observamos el proceso del correo una vez se envio.

    <img width="886" height="156" alt="image" src="https://github.com/user-attachments/assets/9986ce43-0904-4e33-89f4-c87c52bf85da" />

   <p>Correo recibido:</p>

    
    <img width="886" height="297" alt="image" src="https://github.com/user-attachments/assets/afa05b3d-e4ea-43a7-8bd9-d99102f51231" />


     <p>Once the email is received, the user will either click the link or report it, and the statistics will be displayed accordingly.</p>

     <img width="886" height="239" alt="image" src="https://github.com/user-attachments/assets/3d3e8ad0-082a-426c-b29f-b742c195d220" />

     We will observe how it shows that the user Johnny opened the email and clicked the link.
  
     <img width="886" height="169" alt="image" src="https://github.com/user-attachments/assets/5ab634fe-7ca7-4b14-a711-ce1c0be972b8" />


  






### Example Result:
- User `Johnny` opened the email and clicked on the phishing link
- Due to browser protection, the spoofed page was blocked, but in a real scenario, credentials would be captured and stored in CSV format
- Once the link is opened, it should display a page identical to the one being spoofed, allowing the user to enter their credentials. In this case, the computer blocks the page, so we are unable to input any data. However,
  if credentials were entered, they would be shown in the Export CSV option, where the stolen credentials would be stored.

<img width="886" height="350" alt="image" src="https://github.com/user-attachments/assets/f8cda5e4-ef1a-4c10-836c-55be223ce91d" />
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

