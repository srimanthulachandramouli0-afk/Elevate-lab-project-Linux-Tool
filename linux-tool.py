#!/usr/bin/env python3

import os
import subprocess
import json
import stat
from datetime import datetime

results = []
score = 0
total = 0


def add_check(name, passed, details, recommendation=""):
    global score, total

    total += 1
    if passed:
        score += 1

    results.append({
        "check": name,
        "status": "PASS" if passed else "FAIL",
        "details": details,
        "recommendation": recommendation
    })


def run_command(command):
    try:
        result = subprocess.run(
            command,
            shell=True,
            capture_output=True,
            text=True,
            timeout=10
        )
        return result.stdout.strip()
    except Exception as e:
        return str(e)


# --------------------------------------------------
# 1. Firewall Check
# --------------------------------------------------

def check_firewall():
    ufw = run_command("ufw status 2>/dev/null")

    if "Status: active" in ufw:
        add_check(
            "Firewall",
            True,
            "UFW firewall is active."
        )
        return

    nft = run_command("nft list ruleset 2>/dev/null")

    if nft and len(nft) > 20:
        add_check(
            "Firewall",
            True,
            "Firewall rules detected through nftables."
        )
    else:
        add_check(
            "Firewall",
            False,
            "No active firewall detected.",
            "Enable and configure UFW or another firewall."
        )


# --------------------------------------------------
# 2. SSH Configuration
# --------------------------------------------------

def check_ssh():
    config = "/etc/ssh/sshd_config"

    if not os.path.exists(config):
        add_check(
            "SSH Configuration",
            True,
            "SSH server configuration file not found."
        )
        return

    try:
        with open(config, "r", errors="ignore") as f:
            data = f.read()

        root_login_disabled = False
        password_login_disabled = False

        for line in data.splitlines():
            line = line.strip()

            if line.startswith("PermitRootLogin"):
                if "no" in line.lower():
                    root_login_disabled = True

            if line.startswith("PasswordAuthentication"):
                if "no" in line.lower():
                    password_login_disabled = True

        if root_login_disabled:
            add_check(
                "SSH Root Login",
                True,
                "PermitRootLogin is disabled."
            )
        else:
            add_check(
                "SSH Root Login",
                False,
                "Root SSH login may be enabled.",
                "Set PermitRootLogin no."
            )

        if password_login_disabled:
            add_check(
                "SSH Password Authentication",
                True,
                "Password authentication is disabled."
            )
        else:
            add_check(
                "SSH Password Authentication",
                False,
                "Password authentication may be enabled.",
                "Use SSH keys and consider PasswordAuthentication no."
            )

    except PermissionError:
        add_check(
            "SSH Configuration",
            False,
            "Permission denied while reading sshd_config."
        )


# --------------------------------------------------
# 3. Critical File Permissions
# --------------------------------------------------

def check_permissions():

    files = {
        "/etc/passwd": 0o644,
        "/etc/shadow": 0o640,
        "/etc/group": 0o644
    }

    for path, recommended in files.items():

        if not os.path.exists(path):
            continue

        try:
            mode = stat.S_IMODE(os.stat(path).st_mode)

            # Check whether file is writable by group/others
            unsafe = mode & 0o022

            if unsafe == 0:
                add_check(
                    "Permission: " + path,
                    True,
                    "File is not group/other writable."
                )
            else:
                add_check(
                    "Permission: " + path,
                    False,
                    oct(mode),
                    "Remove unnecessary group/other write permissions."
                )

        except PermissionError:
            add_check(
                "Permission: " + path,
                False,
                "Permission denied."
            )


# --------------------------------------------------
# 4. Listening Services
# --------------------------------------------------

def check_services():

    output = run_command(
        "ss -tuln 2>/dev/null"
    )

    if output:
        lines = output.splitlines()

        listening = [
            x for x in lines
            if "LISTEN" in x or "udp" in x.lower()
        ]

        if len(listening) <= 5:
            add_check(
                "Listening Services",
                True,
                "Limited number of listening network endpoints detected."
            )
        else:
            add_check(
                "Listening Services",
                False,
                f"{len(listening)} listening endpoints detected.",
                "Review listening services and disable unnecessary services."
            )
    else:
        add_check(
            "Listening Services",
            False,
            "Unable to inspect listening services."
        )


# --------------------------------------------------
# 5. Password File Check
# --------------------------------------------------

def check_password_accounts():

    passwd = "/etc/passwd"

    try:
        with open(passwd, "r") as f:
            users = f.readlines()

        uid_zero = []

        for line in users:
            parts = line.strip().split(":")

            if len(parts) >= 3:
                username = parts[0]
                uid = parts[2]

                if uid == "0":
                    uid_zero.append(username)

        if uid_zero == ["root"]:
            add_check(
                "UID 0 Accounts",
                True,
                "Only root has UID 0."
            )
        else:
            add_check(
                "UID 0 Accounts",
                False,
                "UID 0 accounts: " + ", ".join(uid_zero),
                "Review unnecessary accounts with UID 0."
            )

    except Exception as e:
        add_check(
            "Password Accounts",
            False,
            str(e)
        )


# --------------------------------------------------
# 6. Rootkit Indicators
# --------------------------------------------------

def check_rootkit_indicators():

    suspicious_paths = [
        "/tmp/.rootkit",
        "/tmp/rootkit",
        "/var/tmp/.rootkit",
        "/dev/shm/.rootkit"
    ]

    found = []

    for path in suspicious_paths:
        if os.path.exists(path):
            found.append(path)

    if not found:
        add_check(
            "Rootkit Indicators",
            True,
            "No basic known indicator paths detected."
        )
    else:
        add_check(
            "Rootkit Indicators",
            False,
            "Suspicious paths: " + ", ".join(found),
            "Investigate suspicious files/processes using trusted security tools."
        )


# --------------------------------------------------
# 7. World Writable Important Directories
# --------------------------------------------------

def check_world_writable():

    directories = [
        "/etc",
        "/usr/bin",
        "/usr/sbin"
    ]

    unsafe = []

    for directory in directories:

        if os.path.exists(directory):

            try:
                mode = stat.S_IMODE(
                    os.stat(directory).st_mode
                )

                if mode & stat.S_IWOTH:
                    unsafe.append(directory)

            except PermissionError:
                pass

    if not unsafe:
        add_check(
            "Important Directory Permissions",
            True,
            "No world-writable critical directories detected."
        )
    else:
        add_check(
            "Important Directory Permissions",
            False,
            ", ".join(unsafe),
            "Remove unnecessary world-write permissions."
        )


# --------------------------------------------------
# 8. Automatic Security Updates
# --------------------------------------------------

def check_updates():

    if os.path.exists("/etc/debian_version"):

        unattended = os.path.exists(
            "/etc/apt/apt.conf.d/20auto-upgrades"
        )

        if unattended:
            add_check(
                "Automatic Updates",
                True,
                "Automatic update configuration detected."
            )
        else:
            add_check(
                "Automatic Updates",
                False,
                "Automatic update configuration not detected.",
                "Enable automatic security updates where appropriate."
            )

    else:
        add_check(
            "Automatic Updates",
            True,
            "Distribution-specific automatic update check not available."
        )


# --------------------------------------------------
# Report Generation
# --------------------------------------------------

def generate_report():

    compliance = round((score / total) * 100, 2) if total else 0

    report = {
        "tool": "Linux Hardening Audit Tool",
        "date": datetime.now().isoformat(),
        "score": compliance,
        "checks_passed": score,
        "total_checks": total,
        "results": results
    }

    # JSON
    with open("linux_audit_report.json", "w") as f:
        json.dump(report, f, indent=4)

    # TXT
    with open("linux_audit_report.txt", "w") as f:

        f.write("=" * 60 + "\n")
        f.write("       LINUX HARDENING AUDIT REPORT\n")
        f.write("=" * 60 + "\n\n")

        f.write("Date: " + str(datetime.now()) + "\n")
        f.write(f"Compliance Score: {compliance}%\n")
        f.write(f"Passed: {score}/{total}\n\n")

        f.write("-" * 60 + "\n")

        for item in results:

            f.write(
                f"\n[{item['status']}] {item['check']}\n"
            )

            f.write(
                "Details: " + item["details"] + "\n"
            )

            if item["recommendation"]:
                f.write(
                    "Recommendation: "
                    + item["recommendation"]
                    + "\n"
                )

        f.write("\n" + "=" * 60 + "\n")
        f.write("Audit completed.\n")

    return compliance


# --------------------------------------------------
# Main
# --------------------------------------------------

def main():

    print("\n" + "=" * 60)
    print("        LINUX HARDENING AUDIT TOOL")
    print("=" * 60)

    print("\nRunning security checks...\n")

    check_firewall()
    check_ssh()
    check_permissions()
    check_services()
    check_password_accounts()
    check_rootkit_indicators()
    check_world_writable()
    check_updates()

    compliance = generate_report()

    print("\n" + "=" * 60)
    print("AUDIT RESULT")
    print("=" * 60)

    for item in results:

        symbol = "✓" if item["status"] == "PASS" else "✗"

        print(
            f"{symbol} {item['check']}: {item['status']}"
        )

    print("\n" + "-" * 60)
    print(f"Compliance Score: {compliance}%")
    print("-" * 60)

    print("\nReports created:")
    print("  linux_audit_report.txt")
    print("  linux_audit_report.json")

    print("\nAudit completed.")


if __name__ == "__main__":
    main()