# Linux Privilege Escalation Toolkit — LinPEASAuto

An advanced **automated Linux privilege escalation enumeration toolkit**   
This tool scans a Linux system for **real-world privilege escalation vectors**, identifies **high-risk misconfigurations**, generates **clear actionable reports** and provides **clear mitigation steps** to secure the system.

---

##  Project Overview

"LinPEASAuto" is a Python-based Linux privilege escalation scanner inspired by **real-world penetration testing workflows, red-team methodologies, and CTF challenges**.

It automates the discovery of common and advanced local privilege escalation attack paths and includes a built-in mitigation engine that provides actionable remediation guidance to securely harden vulnerable Linux systems.

This dual offensive + defensive approach makes LinPEASAuto useful not only for penetration testers and red-teamers, but also for blue teams, system administrators, and cybersecurity students focused on secure system configuration and hardening.


---

## Attack Vectors Covered :

This toolkit enumerates and analyzes the following **Linux Privilege Escalation Vectors**:

### 🔹 1. SUID / SGID Misconfigurations
- Detection of SUID & SGID binaries  
- World & group writable SUID binaries  
- GTFOBins-based exploitation candidates  
- Custom malicious SUID detection  

---

### 🔹 2. Weak File & Directory Permissions
- Writable sensitive files (`/etc/passwd`, `/etc/shadow`, `/etc/sudoers`)  
- Writable system configuration files  
- World-writable root-owned directories  
- Writable log & service directories  

---

### 🔹 3. Sudo Misconfiguration Detection
- `NOPASSWD` sudo rules  
- Full sudo privileges  
- Broad sudo permission patterns  
- Privilege abuse via allowed binaries  

---

### 🔹 4. Cron Job Privilege Escalation
- Writable root cron directories  
- Writable cron scripts  
- Scheduled job abuse detection  
- Insecure cron configurations  

---

### 🔹 5. Linux Capabilities Abuse
- Dangerous capabilities (`cap_setuid`, `cap_setgid`)  
- Powerful filesystem capabilities (`cap_dac_override`, `cap_sys_admin`)  
- Privilege escalation via misconfigured capabilities  
- Filtering of legitimate system capabilities  

---

### 🔹 6. PATH Hijacking Vulnerabilities
- Writable directories inside `$PATH`  
- Insecure PATH ordering  
- Binary hijacking detection  
- User-controlled executable injection  

---

### 🔹 7. Kernel Privilege Escalation Mapping
- Kernel version detection  
- Known vulnerable kernel mapping  
- CVE-based heuristic detection  
- Exploit exposure identification  

---

### 🔹 8. NFS Misconfiguration Detection
- Writable exported NFS shares  
- Root squash misconfiguration  
- Insecure NFS mount permissions  
- Network privilege escalation vectors
---

 ### 🔹 9. Automated Mitigation & Hardening Guidance
- Security remediation commands
- System hardening recommendations
- Defensive configuration guidance
- Secure baseline enforcement suggestions

---

## Mitigation Engine 
LinPEASAuto includes an integrated Mitigation Engine that provides security hardening recommendations and remediation commands for every detected vulnerability.

Instead of only reporting privilege escalation risks, the tool also suggests how to fix them, enabling:

• Secure system hardening
• Rapid vulnerability remediation
• Defensive security learning
• Blue team operational support
---

## 🛠 Tech Stack

- Python 3  
- Linux System Commands  
- OS Permission Enumeration  
- JSON & Text Reporting  
- Security Enumeration Automation  

---

## ⚙️ Installation

```bash
git clone https://github.com/BittuKumar362/Linux-Privilege-Escalation-Toolkit.git
cd Linux-Privilege-Escalation-Toolkit
chmod +x install.sh
./install.sh
```

## 🚀 Usage
### Basic Scan

```bash
python3 linpeas_auto.py

```

## 📊 Output Example
<img width="1918" height="658" alt="Screenshot_2026-02-11_15_39_23" src="https://github.com/user-attachments/assets/f2c9da80-211a-4a6f-ac60-91f06bec48df" />


---

## 🎯 Learning Outcomes

- Linux privilege escalation techniques  
- Penetration testing automation  
- Red-team enumeration methodologies  
- Secure system configuration auditing  

---

## ⚠️ Usage Disclaimer

This tool is intended **strictly for educational purposes, authorized security testing, and cybersecurity research only.**

❌ Unauthorized use against systems you do not own or have **explicit written permission** to test is illegal and punishable under cybercrime laws.

The author assumes **no responsibility** for misuse or damage caused by this tool.

---

## 📜 Ethical Usage Guidelines

- Use only on systems you own or have legal permission to test  
- Follow responsible disclosure practices  
- Do not use for unauthorized exploitation  
- Respect privacy and data protection laws  

---

## 👨‍💻 Author

**Bittu Kumar**  
B.Tech CSE | Cybersecurity Enthusiast  

- GitHub: https://github.com/BittuKumar362  
- LinkedIn: https://www.linkedin.com/in/bittu-kumar-ab2373339/  


