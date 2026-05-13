# Smart Monitor v3.0 — Setup Guide

## Quickstart — One Command Install

Everything is handled automatically by `install.sh` — auditd, rules, service, .env, **and all security hardening**:

```bash
# 1. Clone / copy the project folder to your server
# 2. Run from inside the folder:
sudo bash install.sh
```

That's it. The script does all steps below automatically — including locking the monitor directory so only root can access it.

---

## 🔒 Root-Only Access — 3 Security Layers

The install script applies **3 independent layers** so not even a sudo user can read the monitor files:

### Layer 1 — File Permissions
```
/opt/smart_monitor/          → chmod 700  (root: rwx, everyone else: ---)
/opt/smart_monitor/*.py      → chmod 500  (root: r-x, everyone else: ---)
/opt/smart_monitor/.env      → chmod 600  (root: rw-, everyone else: ---)
/var/log/smart_monitor.log   → chmod 600
/var/log/smart_monitor_alerts.json → chmod 600
```
A regular user doing `ls /opt/smart_monitor` gets: **Permission denied**

### Layer 2 — Sudoers Deny Rules
```bash
# Created at: /etc/sudoers.d/99-block-smart-monitor
# Blocks ALL sudo users from:
sudo cat /opt/smart_monitor/.env              # ❌ blocked
sudo ls /opt/smart_monitor/                  # ❌ blocked
sudo cat /var/log/smart_monitor_alerts.json  # ❌ blocked
sudo systemctl start smart_monitor           # ❌ blocked
sudo systemctl stop smart_monitor            # ❌ blocked
sudo journalctl -u smart_monitor             # ❌ blocked
```

### Layer 3 — AppArmor (Kernel-Level Enforcement)
Even if a user does `sudo bash` and gets a root shell — AppArmor's kernel-level profile blocks any process (other than `smart_monitor.py` itself) from reading `/opt/smart_monitor`:
```bash
# Even as root via 'sudo bash':
cat /opt/smart_monitor/.env    # ❌ AppArmor denies it
```

### To Access as True Root (not sudo)
```bash
sudo -i               # switch to a real root session
cat /opt/smart_monitor/.env          # ✅ works
cat /var/log/smart_monitor_alerts.json  # ✅ works
systemctl restart smart_monitor      # ✅ works
```

> **Why `sudo -i` works but `sudo cat` doesn't?**
> `sudo -i` opens a full root login shell — AppArmor treats it as root.
> `sudo cat` runs cat as root but via the user's session — the sudoers deny rule blocks it.

---

## What `install.sh` Does (Step by Step)

| Step | What happens |
|------|-------------|
| 1 | Installs `auditd`, `python3-pip` via `apt-get` |
| 2 | Installs Python dependency `boto3` |
| 3 | Creates directories: `/opt/smart_monitor`, `/var/lib/smart_monitor`, `/var/log/smart_monitor` |
| 4 | Copies `smart_monitor.py` → `/opt/smart_monitor/` (chmod 750) |
| 5 | Creates `/opt/smart_monitor/.env` template (chmod 600) |
| 6 | Copies `smart_monitor_auditd.rules` → `/etc/audit/rules.d/smart_monitor.rules` and reloads auditd |
| 7 | Installs and starts the `smart_monitor` systemd service |

---

## Why the Rules File (`smart_monitor_auditd.rules`) is Critical

> **Do not skip or delete this file.** It is what gives the monitor kernel-level visibility.

Without it, the monitor falls back to `auth.log` only — which gives **no attribution** for who ran
a command inside a `sudo` shell, and **no file deletion tracking**.

With it, the monitor knows:

| What the rules watch | What the monitor can do |
|---|---|
| `rm`, `shred`, `rmdir`, `truncate` binaries | Know exactly who deleted what file, even inside `sudo su` |
| `execve` syscall for `auid >= 1000` | See every command run by any real login user |
| `execve` for `uid=0` with `auid != unset` | See every root command and who originally triggered it |
| `sudo`, `su`, `newgrp` | Detect privilege escalation and track the identity chain |
| `useradd`, `userdel`, `usermod`, `groupadd` | Detect account/group changes |
| `/etc/passwd`, `/etc/shadow`, `/etc/sudoers`, `/etc/ssh/sshd_config`, `/root/.ssh/` | Detect sensitive file reads/writes at kernel level |
| `/etc/crontab`, `/etc/cron.d/`, `/var/spool/cron/` | Detect cron persistence |
| `/var/log/auth.log`, `/var/log/audit/`, `/var/log/syslog` | Detect log tampering |
| `insmod`, `rmmod`, `modprobe` | Detect rootkit kernel module loads |
| `nmap`, `tcpdump`, `nc`, `socat` | Detect network recon tools |

---

## After Install — Configure Email (Optional)

Edit the `.env` file to set up AWS SES email alerts:

```bash
sudo nano /opt/smart_monitor/.env
```

```ini
# AWS SES email alerting (leave blank to run log-only mode)
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=ap-south-1
SES_SENDER_EMAIL=monitor@your-domain.com
SES_RECIPIENT_EMAILS=admin@your-domain.com,soc@your-domain.com

# Set to false to disable email and log alerts only (JSON log still written)
MAIL_ENABLED=true

# Override auto-detected hostname in alerts (optional)
HOSTNAME=prod-server-01
```

> **JSON alerts are always written** to `/var/log/smart_monitor_alerts.json` regardless of
> `MAIL_ENABLED`. The file is `chmod 600` owned by `root` — only root can read it.

---

## Useful Commands After Install

```bash
# Check if the service is running
sudo systemctl status smart_monitor

# Watch live alerts
sudo tail -f /var/log/smart_monitor.log

# Read the JSON alert audit trail (root only)
sudo cat /var/log/smart_monitor_alerts.json

# Pretty-print the JSON log (one alert at a time)
sudo python3 -c "
import json, sys
data = open('/var/log/smart_monitor_alerts.json').read()
for block in data.strip().split('\n\n'):
    block = block.strip()
    if block:
        obj = json.loads(block)
        print(obj.get('human_summary',''))
        print('  Email:', obj.get('notification',{}).get('email_status'))
        print()
"

# Verify auditd rules are loaded
sudo auditctl -l

# Restart monitor after config change
sudo systemctl restart smart_monitor
```

---

## Investigate Alerts with auditd Tools

```bash
# See all file deletions in the last hour
sudo ausearch -k delete_events -ts recent | aureport -f

# See every command run by a specific user today
sudo ausearch -ua naveen -ts today

# See all privilege escalations (sudo / su)
sudo ausearch -k priv_escalation -ts recent

# See who accessed /etc/shadow
sudo ausearch -f /etc/shadow -ts recent

# Full user activity summary
sudo aureport -u --summary -ts today
```

---

## Verify Delete Attribution is Working

```bash
# As a regular user (e.g. naveen):
touch /tmp/test_file
sudo rm /tmp/test_file

# Check the audit log — you should see naveen as auid, root as uid:
sudo ausearch -k delete_events -ts recent

# Check the JSON alert log:
sudo tail -20 /var/log/smart_monitor_alerts.json
```

Expected JSON detail:
```
"naveen used sudo and deleted /tmp/test_file"
```
