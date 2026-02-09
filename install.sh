#!/bin/bash
# Installation script for LinPEAS Auto Toolkit

echo "[+] Installing Linux Privilege Escalation Automation Toolkit..."

# Make main script executable
chmod +x linpeas_auto.py


# Check root
if [[ $EUID -ne 0 ]]; then
   echo "[-] Please run as root: sudo bash install.sh"
   exit 1
fi


echo "[+] Installation completed successfully."
echo "[+] Run the tool using: python3 linpeas_auto.py"
