## 📱 Mobile App Vulnerability Analysis using AndroGoat

This project is part of a cybersecurity master's program and focuses on the security analysis of Android applications through static and dynamic testing techniques. The primary goal is to identify vulnerabilities in a deliberately insecure app (AndroGoat), following the OWASP Mobile Top 10 and MASVS guidelines. By inspecting permissions, configuration files, and app behavior, the project aims to simulate real-world mobile threat assessments and highlight common security misconfigurations in outdated Android environments.

---

## 🧠 Project Overview

This project focuses on the static and dynamic analysis of a deliberately vulnerable Android application, **AndroGoat**, as part of a broader study on mobile security. Using tools aligned with OWASP Mobile Top 10, the application is reverse-engineered and tested for multiple categories of vulnerabilities. The goal is to better understand common mobile threats, app misconfigurations, and outdated security practices.


## 🧠 Project Brief:
Throughout the course content, topics such as OWASP, static and dynamic analysis, vulnerabilities, and secure development have been discussed. Smartphones are not immune to attacks. OWASP defines a Top 10 list of risks for mobile applications (OWASP Mobile Top 10 - 2016).

Task:
Based on the material studied and the context provided, analyze at least three Android applications (.apk files) to identify potential vulnerabilities:

One unofficial APK, with deliberately introduced vulnerabilities, commonly shared online for training purposes.

One APK downloaded from an unofficial APK repository.

One APK downloaded from an official app store.

The analysis must incorporate both stand-alone and online tools to provide complementary results and deliver a comprehensive evaluation of the applications.

Once the tools are selected, the analysis can be organized into the following tasks:

Information Gathering – Define the scope and identify sections of the app to evaluate.

Static Analysis – Inspect app resources, source code, configuration files, permissions, etc.

Dynamic Analysis – Execute the app and monitor its activity and behavior in real-time.


---



## 🎯 Objectives

- Perform static and dynamic security analysis on three Android applications: **AndroGoat** (intentionally vulnerable), **TodoList** (official), and **Vanced** (from an unofficial repository).
- Identify and compare vulnerabilities based on the **OWASP Mobile Top 10** and **MASVS** standards.
- Highlight security risks introduced by outdated Android APIs, insecure permissions, and weak configurations.
- Analyze app behavior, data handling, network communication, and permission models.
- Gain hands-on experience with modern mobile security testing tools in a controlled, virtualized lab environment.

## 📚 Skills Acquired


- Static analysis of APK files, including inspection of source code, configuration files, and declared permissions.
- Dynamic analysis of app behavior, using emulators and monitoring tools to detect suspicious activity, network connections, and resource usage.
- Identification of mobile vulnerabilities based on the OWASP Mobile Top 10, such as insecure data storage, improper cryptography, or data exposure.
- Comparative risk evaluation based on APK source (unofficial, unverified repository, and official store), building critical thinking for mobile security assessment.
- Conducting full lifecycle mobile app security testing
- Manual reverse engineering using Apktool and JADX 
- Network traffic inspection and endpoint detection  
- Certificate analysis and validation  
- Writing structured and evidence-based security reports  


## 🔧 Tools & Technologies Used

- **Android Studio**– Integrated development environment (IDE) for building, running, and debugging Android applications.
- **Apktool** – Tool for reverse engineering Android APKs to decode resources and analyze app structure.
- **ADB (Android Debug Bridge)** – Command-line tool to communicate with Android devices for debugging and app interaction.
- **VirusTotal**/ **ShenmeApp** – Online analysis platforms for scanning APKs and detecting malware or suspicious behavior.
- **JADX** – Decompiler that converts Android APKs into readable Java source code for static analysis.
- **MobSF (Mobile Security Framework)**– All-in-one automated mobile security framework for static and dynamic analysis of Android/iOS apps.
- **APK Downloader** – Tool to obtain APKs for offline analysis



## Steps :
*Now we will proceed to extract the files for analysis using the apktool tool with the command:
apktool d [app name]*

*Ref 1:  Unpacking files*

- Vanced
   <img width="950" height="379" alt="image" src="https://github.com/user-attachments/assets/2ab91594-b852-47fc-8a12-d5ca2a55df8c" />

- AndroGoat
   <img width="950" height="305" alt="image" src="https://github.com/user-attachments/assets/d76f589d-4eb9-4b8b-aed8-b55f89706e9f" />

- TodoList
   <img width="950" height="470" alt="image" src="https://github.com/user-attachments/assets/d0709ab2-60c3-4cdd-b00b-ad425e0b7b6d" />

*Once the files have been extracted, we proceed to analyze the AndroidManifest.xml one by one, searching for potential vulnerabilities.*


## Ref 1: Static Analysis :
*In the following analysis, we used a combination of tools to achieve better results. We started with Android Studio, followed by MobSF, and complemented the findings with VirusTotal and ShenmeApp.*



 - *Permissions:*
 We will begin by analyzing the permissions of the AndroGoat app:

The permissions WRITE_EXTERNAL_STORAGE and READ_EXTERNAL_STORAGE are no longer required starting from API level 18, which already suggests that the Android software version is outdated and likely to have many security issues, which we will explore further later.

According to: https://developer.android.com/guide/topics/manifest/uses-permission-element?hl=es-419 — I quote:

“For example, starting in Android 4.4 (API level 19), your app no longer needs the WRITE_EXTERNAL_STORAGE permission to write to its own app-specific directories on external storage, which are provided by getExternalFilesDir(). However, the permission is required up to API level 18. Therefore, you can declare that this permission is only needed up to API level 18. This way, starting in API level 19, the system no longer grants your app the WRITE_EXTERNAL_STORAGE permission.”

This was added in API level 19.

Considering that the current Android API version is 35, it is clear that the app has not received updates and that the permissions can cause greater harm due to their sensitivity.

Additionally, by inspecting the manifest, we can also observe a vulnerability related to the use of the HTTPS protocol, as it only uses HTTP instead.

  - *Apk AndroGoat with Android Studio*
  <img width="950" height="270" alt="image" src="https://github.com/user-attachments/assets/716578d1-8fce-443f-9f6f-9c9cb4566a56" />
  <img width="950" height="131" alt="image" src="https://github.com/user-attachments/assets/068fb7d8-5e96-48a1-8a0b-113aae42831f" />

- *Apk AndroGoat con MobSF*
  <img width="1009" height="274" alt="image" src="https://github.com/user-attachments/assets/1051cb1d-11c5-43bd-9f87-ae07e8df03eb" />

 - *Score Security:*
   *We have general information about the APK, and what stands out the most is the security score, which is only 43 out of 100.*
   <img width="950" height="250" alt="image" src="https://github.com/user-attachments/assets/aba6fb3f-f0fd-4f6a-b5e7-d7436831369a" />

 - *Signer Certificate:*
  *When reviewing the following code, we can see that the signing certificate is v1, which is highly vulnerable.*
   <img width="950" height="473" alt="image" src="https://github.com/user-attachments/assets/86d8b454-0438-406a-9ad4-6b9fb9d1ccde" />

 - Permission and Network:
   *It can be seen that the app easily allows cleartext traffic across the entire network, which would expose all network packets to potential attacks aimed at obtaining private information.*
   <img width="950" height="430" alt="image" src="https://github.com/user-attachments/assets/667dbd57-c368-43f9-be33-a42e084663ff" />
   <img width="950" height="335" alt="image" src="https://github.com/user-attachments/assets/4d7713cf-68f8-4078-ad9d-419462ad22f7" />


 - *Certicates Analysis:*
   *The application uses certificates that are, or will become, vulnerable. Additionally, the hash may lead to a collision within the network.
    We also observe that it is vulnerable to the Janus vulnerability, due to the fact that it is signed using signature scheme v1. This makes it insecure, especially considering that the latest APK signature scheme is v4.    This further confirms that the Android version is outdated and most likely will no longer receive updates or official support from Google.*
   <img width="950" height="279" alt="image" src="https://github.com/user-attachments/assets/3aae75e3-9a7e-4a6d-8b74-54903ef3db58" />

   
 
 - *Android Manifest and Code:*
   
   <img width="950" height="550" alt="image" src="https://github.com/user-attachments/assets/4c140964-9687-4fc7-a78a-4a5b7e953188" />
   <img width="950" height="527" alt="image" src="https://github.com/user-attachments/assets/a9eeafb0-d53e-4aa2-9c64-cd7cdc7594c8" />


#### OWASP MAS Testing Methodology
- Architecture, Design, and Threat Modeling:
As we observed during the analysis, the application does not comply with secure architecture or design principles, since it is based on an outdated software version that no longer receives maintenance or support from Google.

- Privacy and Data Storage:
The use of the HTTP protocol instead of HTTPS compromises user privacy when transmitting data over the network. In terms of storage, the app uses deprecated permissions that are no longer supported in newer Android versions.

- Cryptography:
The app is vulnerable to the Janus vulnerability due to being signed with APK Signature Scheme v1, which is outdated and insecure. The current standard is v4, and this discrepancy confirms the app relies on an old Android version, likely without updates or official support. Additionally, the app does not use TLS, which weakens its encryption standards.

- Authentication and Session Management:
Sensitive application data should not be stored insecurely or logged, yet traces of such data can be found, which indicates poor session management practices.

- Network Communication:
The use of HTTP instead of HTTPS represents a critical failure in ensuring secure network communication.

- Platform Interaction:
The app shows poor security practices in its use of platform APIs and components, lacking proper restrictions and controls.

- Code Quality and Build Configuration:
The code reveals multiple development issues, such as improper permission handling, the use of SSL instead of TLS, and inadequate protections (e.g., the code is not marked as debuggable, but other issues persist).

- Resilience:
The application lacks any mechanisms to prevent or mitigate attacks, making it highly vulnerable.


 


## Ref 2: DYNAMIC ANALYSIS: The following analysis was conducted manually due to issues encountered with the MobSF application.




  <img width="394" height="773" alt="image" src="https://github.com/user-attachments/assets/97cea5e9-2a54-411d-8d89-bde2a6ba02bb" />
  <img width="653" height="536" alt="image" src="https://github.com/user-attachments/assets/9fe15791-3426-4fd0-bbe4-6d8272cd6776" />
  <img width="652" height="405" alt="image" src="https://github.com/user-attachments/assets/6720455d-e904-4d35-a0a2-c6804fc87c99" />
  <img width="641" height="458" alt="image" src="https://github.com/user-attachments/assets/72d739d9-d0b0-4ce0-a006-3cc4c38e091e" />
  <img width="659" height="506" alt="image" src="https://github.com/user-attachments/assets/fed5fc02-6b47-4f79-b992-59378c54a0d5" />
  <img width="650" height="448" alt="image" src="https://github.com/user-attachments/assets/4330e591-6717-477d-bdcf-e872249f9487" />
  <img width="666" height="517" alt="image" src="https://github.com/user-attachments/assets/44697fc6-6570-44be-bf90-daf7fe11bc7a" />
  <img width="648" height="450" alt="image" src="https://github.com/user-attachments/assets/8492777b-a7e5-4e4b-8879-11f2daf27a4a" />
  <img width="650" height="414" alt="image" src="https://github.com/user-attachments/assets/ebae706d-3985-43ca-968a-4a6984ef5e10" />
  

*During application usage, its ease of use can be appreciated by some users; however, the overall design lacks intuitiveness. The app is lightweight and performs well even when run on an emulator. A notable drawback is the very plain interface, with minimal use of colors, which may pose accessibility challenges for users with visual impairments. Furthermore, the main interface is cluttered with numerous options but provides insufficient descriptions of their functions, resulting in user confusion and difficulty navigating the app.*







 
