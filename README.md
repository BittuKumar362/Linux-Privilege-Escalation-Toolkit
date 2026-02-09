# Linux Privilege Escalation Toolkit — LinPEASAuto

An advanced **automated Linux privilege escalation enumeration toolkit**   
This tool scans a Linux system for **real-world privilege escalation vectors**, identifies **high-risk misconfigurations**, and generates **clear actionable reports**.

---

##  Project Overview

"LinPEASAuto" is a Python-based Linux privilege escalation scanner inspired by **real-world penetration testing workflows, red-team methodologies, and CTF challenges**.

It automates the discovery of common and advanced **local privilege escalation attack paths**, helping security professionals and students identify **system misconfigurations that could lead to root compromise**.

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
chmod +x linpeas_auto.py




