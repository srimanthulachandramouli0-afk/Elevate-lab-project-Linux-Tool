# Elevate-lab-project-Linux-Tool
# 🔐 Linux Hardening Audit Tool

A Python-based cybersecurity tool designed to audit basic Linux system security configurations and generate a security compliance report.

## 🎯 Objective

The objective of this project is to identify common Linux security configuration issues and provide a simple compliance score with recommended hardening actions.

## 🛠️ Technologies Used

- Python 3
- Linux Security
- `os` module
- `subprocess` module
- `json` module
- File permissions
- System configuration auditing

## 🔍 Features

The tool performs several security checks:

- 🔥 Firewall status
- 🔑 SSH configuration
- 🌐 Listening network services
- 👤 Password and account configuration
- 🛡️ Basic rootkit indicators
- 📁 Important directory permissions
- 🔄 Automatic update configuration
- 📊 Compliance score generation
- 📄 TXT report generation
- 📋 JSON report generation

## 📊 Sample Result

Example test result:

```text
LINUX HARDENING AUDIT TOOL

AUDIT RESULT

✗ Firewall: FAIL
✓ SSH Configuration: PASS
✓ Listening Services: PASS
✗ Password Accounts: FAIL
✓ Rootkit Indicators: PASS
✓ Important Directory Permissions: PASS
✓ Automatic Updates: PASS

Compliance Score: 71.43%

Reports created:
    linux_audit_report.txt
    linux_audit_report.json

Audit completed.