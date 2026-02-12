

#!/usr/bin/env python3
import subprocess
import os
import json
import platform
import stat

class LinPEASAuto:
    def __init__(self):
        self.critical = 0
        self.high = 0
        self.findings = []

    # ---------------- HELPER ----------------
    def run(self, cmd, timeout=25):
        try:
            p = subprocess.run(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=True,
                timeout=timeout
            )
            return p.stdout.strip()
        except subprocess.TimeoutExpired:
            return ""

    # ---------------- MITIGATION ENGINE ----------------
    def mitigate(self, issue, target):
        fixes = {
            "suid_writable": f"chmod 755 {target} && chown root:root {target}",
            "suid_gtfobin": f"chmod u-s {target}",
            "weak_sensitive": f"chmod 640 {target} && chown root:root {target}",
            "sudo_nopasswd": "Edit /etc/sudoers and remove NOPASSWD entries",
            "capability": f"setcap -r {target}",
            "cron_writable": f"chmod 755 {target} && chown root:root {target}",
            "path_writable": f"chmod 755 {target}",
            "nfs_noroot": "Remove no_root_squash from /etc/exports and reload NFS",
            "kernel": "Apply latest security patches / upgrade kernel"
        }
        return fixes.get(issue, "Manual review required")

    # ---------------- SUID / SGID ----------------
    def scan_suid_sgid(self):
        print("[+] Scanning SUID / SGID binaries...")
        paths = self.run("find / -perm -4000 -o -perm -2000 2>/dev/null").splitlines()

        gtfobins = {
            "bash", "sh", "find", "vim", "less", "nano",
            "python", "perl", "ruby", "awk", "cp"
        }

        for p in paths:
            try:
                st = os.stat(p)
            except:
                continue

            if not stat.S_ISREG(st.st_mode):
                continue

            name = os.path.basename(p)

            if (st.st_mode & stat.S_IWOTH) or (st.st_mode & stat.S_IWGRP):
                self.critical += 1
                self.findings.append({
                    "severity": "CRITICAL",
                    "issue": f"World/Group-writable SUID binary → {p}",
                    "mitigation": self.mitigate("suid_writable", p)
                })

            elif any(name.startswith(b) for b in gtfobins):
                self.high += 1
                self.findings.append({
                    "severity": "HIGH",
                    "issue": f"SUID GTFOBin → {p}",
                    "mitigation": self.mitigate("suid_gtfobin", p)
                })

    # ---------------- WEAK FILE PERMISSIONS ----------------
    def scan_weak_permissions(self):
        print("[+] Scanning sensitive file permissions...")
        sensitive = ["/etc/passwd", "/etc/shadow", "/etc/sudoers"]

        for f in sensitive:
            if not os.path.isfile(f):
                continue

            try:
                st = os.stat(f)
            except:
                continue

            if (st.st_mode & stat.S_IWOTH) or (st.st_mode & stat.S_IWGRP):
                self.critical += 1
                self.findings.append({
                    "severity": "CRITICAL",
                    "issue": f"Writable sensitive file → {f}",
                    "mitigation": self.mitigate("weak_sensitive", f)
                })

    # ---------------- SUDO ----------------
    def scan_sudo(self):
        print("[+] Checking sudo permissions...")
        out = self.run("sudo -l")

        if not out:
            return

        if "NOPASSWD: ALL" in out:
            self.critical += 1
            self.findings.append({
                "severity": "CRITICAL",
                "issue": "Full sudo access (NOPASSWD: ALL)",
                "mitigation": self.mitigate("sudo_nopasswd", "")
            })

        elif "NOPASSWD" in out:
            self.high += 1
            self.findings.append({
                "severity": "HIGH",
                "issue": "sudo NOPASSWD command allowed",
                "mitigation": self.mitigate("sudo_nopasswd", "")
            })

    # ---------------- CAPABILITIES ----------------
def scan_capabilities(self):
        print("[+] Scanning Linux capabilities...")

        if not self.run("which getcap"):
            return

        out = self.run("getcap -r / 2>/dev/null")
        if not out:
            return

        critical_caps = ["cap_setuid", "cap_setgid"]
        high_caps = ["cap_sys_admin", "cap_dac_override", "cap_dac_read_search"]

        allowed_binaries = {
            "ping", "ping6", "traceroute", "traceroute6",
            "mtr", "mtr-packet", "snap-confine", "gst-ptp-helper"
        }

        for line in out.splitlines():
            if "=" not in line:
                continue

            path, caps = line.split("=", 1)
            binary = os.path.basename(path.strip())

            if binary in allowed_binaries:
                continue

            if any(cap in caps for cap in critical_caps):
                self.critical += 1
                self.findings.append(
                    f"🚨 CRITICAL: Privilege-escalation capability → {line}"
                )

            elif any(cap in caps for cap in high_caps):
                self.high += 1
                self.findings.append(
                    f"🟠 HIGH: Dangerous capability requires review → {line}"
                )
  # ---------------- CRON ----------------
    def scan_cron(self):
        print("[+] Scanning cron directories...")
        cron_dirs = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly"]

        for d in cron_dirs:
            if not os.path.isdir(d):
                continue

            try:
                st = os.stat(d)
            except:
                continue

            if (st.st_mode & stat.S_IWOTH) or (st.st_mode & stat.S_IWGRP):
                self.critical += 1
                self.findings.append({
                    "severity": "CRITICAL",
                    "issue": f"Writable root cron directory → {d}",
                    "mitigation": self.mitigate("cron_writable", d)
                })

    # ---------------- PATH ----------------
    def scan_path(self):
        print("[+] Checking PATH environment...")

        for p in os.environ.get("PATH", "").split(":"):
            if p == ".":
                self.critical += 1
                self.findings.append({
                    "severity": "CRITICAL",
                    "issue": "Current directory (.) in PATH",
                    "mitigation": "Remove . from PATH variable"
                })
            elif os.path.isdir(p):
                try:
                    st = os.stat(p)
                except:
                    continue

                if st.st_mode & stat.S_IWOTH:
                    self.critical += 1
                    self.findings.append({
                        "severity": "CRITICAL",
                        "issue": f"World-writable PATH directory → {p}",
                        "mitigation": self.mitigate("path_writable", p)
                    })

    # ---------------- NFS ----------------
    def scan_nfs(self):
        print("[+] Checking NFS exports...")

        if not os.path.isfile("/etc/exports"):
            return

        with open("/etc/exports") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue

                if "no_root_squash" in line:
                    self.critical += 1
                    self.findings.append({
                        "severity": "CRITICAL",
                        "issue": f"NFS no_root_squash → {line}",
                        "mitigation": self.mitigate("nfs_noroot", "")
                    })

     # ---------------- KERNEL ----------------
    def scan_kernel(self):
        print("[+] Checking kernel version...")

        kernel_full = platform.release()
        kernel_short = ".".join(kernel_full.split(".")[:2])

        vuln_kernels = {
            "4.4":  ("CVE-2016-5195", "Dirty COW — race condition in copy-on-write"),
            "4.8":  ("CVE-2017-1000112", "OverlayFS Privilege Escalation"),
            "5.3":  ("CVE-2021-3493", "OverlayFS Local Privilege Escalation"),
            "5.8":  ("CVE-2022-0847", "Dirty Pipe"),
            "5.9":  ("CVE-2022-0847", "Dirty Pipe"),
            "5.10": ("CVE-2022-0847", "Dirty Pipe"),
            "5.11": ("CVE-2022-0847", "Dirty Pipe"),
            "5.12": ("CVE-2022-0847", "Dirty Pipe"),
            "5.13": ("CVE-2022-0847", "Dirty Pipe"),
            "5.14": ("Multiple CVEs", "io_uring Privilege Escalation"),
            "5.15": ("Multiple CVEs", "io_uring Privilege Escalation"),
        }

        if kernel_short in vuln_kernels:
            cve, desc = vuln_kernels[kernel_short]
            self.high += 1
            self.findings.append({
                "severity": "HIGH",
                "issue": f"Vulnerable kernel detected → {kernel_full}",
                "cve": cve,
                "description": desc,
                "mitigation": "Apply latest kernel security updates or upgrade system"
            })

    # ---------------- REPORT ----------------
    def report(self):
        print("\n" + "=" * 60)
        print("LINUX PRIVILEGE ESCALATION REPORT + MITIGATIONS")
        print("=" * 60)

        print(f"Critical: {self.critical}")
        print(f"High    : {self.high}")
        print(f"Total   : {len(self.findings)}\n")

        if not self.findings:
            print("✅ SYSTEM APPEARS SECURE")
        else:
            for f in self.findings:
                print(f"[{f['severity']}] {f['issue']}")
                print(f"    Fix → {f['mitigation']}\n")

    # ---------------- SAVE REPORT ----------------
    def save_report(self, path="/tmp/linpeasauto_report"):
        txt_file = path + ".txt"
        json_file = path + ".json"

        with open(txt_file, "w") as f:
            for item in self.findings:
                f.write(f"[{item['severity']}] {item['issue']}\n")
                f.write(f"    Fix → {item['mitigation']}\n\n")

        with open(json_file, "w") as f:
            json.dump(self.findings, f, indent=4)
        
        print("\n📄 Report saved:")
        print(f"   TXT  → {txt_file}")
        print(f"   JSON → {json_file}")

        

# ---------------- MAIN ----------------
if __name__ == "__main__":
    scanner = LinPEASAuto()
    scanner.scan_suid_sgid()
    scanner.scan_weak_permissions()
    scanner.scan_sudo()
    scanner.scan_capabilities()
    scanner.scan_cron()
    scanner.scan_path()
    scanner.scan_nfs()
    scanner.scan_kernel()
    scanner.report()
    scanner.save_report()
