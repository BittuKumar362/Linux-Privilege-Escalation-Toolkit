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
    def run(self, cmd, timeout=15):
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

            # Ignore directories and non-regular files
            if not stat.S_ISREG(st.st_mode):
                continue

            name = os.path.basename(p)

            # CRITICAL: world/group writable SUID binary
            if (st.st_mode & stat.S_IWOTH) or (st.st_mode & stat.S_IWGRP):
                self.critical += 1
                self.findings.append(
                    f"🚨 CRITICAL: World/Group-writable SUID binary → {p}"
                )

            # HIGH: GTFOBins SUID binary
            elif name in gtfobins:
                self.high += 1
                self.findings.append(
                    f"🟠 HIGH: SUID GTFOBin → {p}"
                )

        print(f"    Checked {len(paths)} SUID/SGID entries")

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
                self.findings.append(
                    f"🚨 CRITICAL: Writable sensitive file → {f}"
                )

    # ---------------- SUDO ----------------
    def scan_sudo(self):
        print("[+] Checking sudo permissions...")
        out = self.run("sudo -l")

        if not out:
            return

        if "NOPASSWD: ALL" in out:
            self.critical += 1
            self.findings.append(
                "🚨 CRITICAL: Full sudo access (NOPASSWD: ALL)"
            )

        elif "NOPASSWD" in out:
            self.high += 1
            self.findings.append(
                "🟠 HIGH: sudo NOPASSWD command allowed"
            )

        elif "(ALL) ALL" in out:
            self.high += 1
            self.findings.append(
                "🟠 HIGH: Broad sudo permissions"
            )

    # ---------------- CRON ----------------
    def scan_cron(self):
        print("[+] Scanning cron directories...")
        cron_dirs = [
            "/etc/cron.d",
            "/etc/cron.daily",
            "/etc/cron.hourly",
            "/etc/cron.weekly",
            "/etc/cron.monthly"
        ]

        for d in cron_dirs:
            if not os.path.isdir(d):
                continue

            try:
                st = os.stat(d)
            except:
                continue

            if (st.st_mode & stat.S_IWOTH) or (st.st_mode & stat.S_IWGRP):
                self.critical += 1
                self.findings.append(
                    f"🚨 CRITICAL: Writable root cron directory → {d}"
                )

    # ---------------- KERNEL ----------------
    def scan_kernel(self):
        print("[+] Checking kernel version...")
        kernel = platform.release()

        vulnerable_versions = ["4.4", "4.8", "5.3"]
        if any(v in kernel for v in vulnerable_versions):
            self.high += 1
            self.findings.append(
                f"🟠 HIGH: Potentially vulnerable kernel → {kernel}"
            )

    # ---------------- REPORT ----------------
    def report(self):
        print("\n" + "=" * 50)
        print("LINUX PRIVILEGE ESCALATION REPORT")
        print("=" * 50)
        print(f"Total Findings: {len(self.findings)}")
        print(f"Critical: {self.critical}")
        print(f"High: {self.high}\n")

        if not self.findings:
            print("✅ SYSTEM APPEARS SECURE")
        else:
            for f in self.findings:
                print(f)

        print("=" * 50)

    # ---------------- SAVE REPORT ----------------
    def save_report(self, path="/tmp/linpeasauto_report"):
        txt_file = path + ".txt"
        json_file = path + ".json"

        data = {
            "critical": self.critical,
            "high": self.high,
            "total": len(self.findings),
            "findings": self.findings
        }

        with open(txt_file, "w") as f:
            f.write("LINUX PRIVILEGE ESCALATION REPORT\n")
            f.write("=" * 50 + "\n")
            f.write(f"Critical: {self.critical}\n")
            f.write(f"High: {self.high}\n")
            f.write(f"Total Findings: {len(self.findings)}\n\n")
            for item in self.findings:
                f.write(item + "\n")

        with open(json_file, "w") as f:
            json.dump(data, f, indent=4)

        print("\n📄 Report saved:")
        print(f"   TXT  → {txt_file}")
        print(f"   JSON → {json_file}")

# ---------------- MAIN ----------------
if __name__ == "__main__":
    scanner = LinPEASAuto()
    scanner.scan_suid_sgid()
    scanner.scan_weak_permissions()
    scanner.scan_sudo()
    scanner.scan_cron()
    scanner.scan_kernel()
    scanner.report()
    scanner.save_report()
