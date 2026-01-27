# Linux-Privilege-Escalation-Toolkit
It is a lightweight Python-based security tool that scans Linux systems for real-world privilege escalation risks and generates clear, actionable reports.
Features :
✔ Scans SUID/SGID binaries and filters false positives
✔ Detects writable SUID binaries (critical privesc risk)
✔ Identifies GTFOBins-style SUID abuse
✔ Checks permissions on sensitive files
✔ Analyzes sudo misconfigurations
✔ Detects writable root cron directories
✔ Flags potentially vulnerable kernel versions
✔ Generates TXT and JSON reports automatically
DEMO IMAGES :
Image 1: Scan on a hardened system → 0 findings (secure)
<img width="1914" height="876" alt="Screenshot from 2026-01-27 08-44-00" src="https://github.com/user-attachments/assets/a1270a4b-9eff-4970-a8ce-f795b7f29fa5" />

Image 2: Scan on a vulnerable system → privilege escalation detected
<img width="1914" height="866" alt="Screenshot from 2026-01-27 08-41-55" src="https://github.com/user-attachments/assets/69cfd6f1-24c5-4487-b9f9-e6918bd32895" />
These screenshots demonstrate real detection, not simulated output.

TECH STACK:
Python 3
Linux internals (permissions, SUID/SGID, cron, sudo)
OS-level enumeration
JSON reporting


