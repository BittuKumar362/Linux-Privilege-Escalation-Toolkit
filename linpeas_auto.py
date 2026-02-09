
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
    def run(self, cmd, timeout=20):
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

            if not stat.S_ISREG(st.st_mode):
                continue

            name = os.path.basename(p)

            if (st.st_mode & stat.S_IWOTH) or (st.st_mode & stat.S_IWGRP):
                self.critical += 1
                self.findings.append(
                    f"🚨 CRITICAL: World/Group-writable SUID binary → {p}"
                )

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

    # ---------------- PATH Privilege Escalation ----------------
    def scan_path(self):
        print("[+] Checking PATH for privilege escalation risks...")

        path = os.environ.get("PATH", "")
        if not path:
            return

        paths = path.split(":")

        for p in paths:
            if p == ".":
                self.critical += 1
                self.findings.append(
                    "🚨 CRITICAL: Current directory (.) present in PATH"
                )
                continue

            if not os.path.isdir(p):
                continue

            try:
                st = os.stat(p)
            except:
                continue

            # World-writable PATH directory
            if st.st_mode & stat.S_IWOTH:
                self.critical += 1
                self.findings.append(
                    f"🚨 CRITICAL: World-writable directory in PATH → {p}"
                )

            # Group-writable PATH directory
            elif st.st_mode & stat.S_IWGRP:
                self.high += 1
                self.findings.append(
                    f"🟠 HIGH: Group-writable directory in PATH → {p}"
                )

    # ---------------- NFS ----------------
    def scan_nfs(self):
        print("[+] Checking NFS exports...")

        # If NFS exports file does not exist, exit safely
        if not os.path.isfile("/etc/exports"):
            return

        try:
            with open("/etc/exports", "r") as f:
                exports = f.read()
        except:
            return

        for line in exports.splitlines():
            line = line.strip()

            # Skip empty lines and comments
            if not line or line.startswith("#"):
                continue

            # CRITICAL: no_root_squash
            if "no_root_squash" in line:
                self.critical += 1
                self.findings.append(
                    f"🚨 CRITICAL: NFS export with no_root_squash → {line}"
                )

            # HIGH: broad writable export
            elif "(rw" in line and "*" in line:
                self.high += 1
                self.findings.append(
                    f"🟠 HIGH: Broad writable NFS export → {line}"
                )

    
        # ---------------- KERNEL ----------------
    def scan_kernel(self):
        print("[+] Checking kernel version...")
        kernel = platform.release()

        vulnerable_versions = [
            "2.6",     # very old kernels
            "3.13",    # overlayfs
            "3.16",
            "4.4",     # dirty cow, overlayfs
            "4.8",
            "5.3",     # dirty cow variants
            "5.10",    # dirty pipe
            "5.11",
            "5.12",
            "5.13",
            "5.14",
            "5.15"
        ]

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
    scanner.scan_capabilities()
    scanner.scan_cron()
    scanner.scan_path()
    scanner.scan_nfs()
    scanner.scan_kernel()
    scanner.report()
    scanner.save_report()

