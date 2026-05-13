# Smart Monitor v3.0 — auditd Setup Guide

## Why auditd?
The monitor uses `/var/log/audit/audit.log` to **definitively attribute**:
- **Who deleted what** — even inside a `sudo` or `su` shell
- **Identity chain** — original login user (`auid`) vs effective user (`uid`)
- **Every command run as root** — including commands inside interactive root shells

Without auditd, deletion/attribution is "best effort" from auth.log only.

---

## Step 1: Install auditd

```bash
# Ubuntu / Debian
sudo apt-get install -y auditd audispd-plugins

# RHEL / CentOS / Amazon Linux
sudo yum install -y audit

# Start and enable
sudo systemctl enable --now auditd
```

---

## Step 2: Deploy the rules

```bash
sudo cp smart_monitor_auditd.rules /etc/audit/rules.d/smart_monitor.rules
sudo augenrules --load
sudo systemctl restart auditd

# Verify rules loaded
sudo auditctl -l
```

---

## Step 3: Test deletion attribution

```bash
# Run as yourself (e.g., user "dev"):
sudo rm /tmp/test_delete_file

# Check audit log — you should see YOUR username as auid and root as uid:
sudo ausearch -k delete_events -ts recent
```

Expected output will show:
```
uid=0 (root)  auid=1001 (dev)   comm="rm"   name="/tmp/test_delete_file"
```

The monitor will alert: **"File Deletion: dev (via sudo/su as root)"**

---

## Step 4: Verify the monitor sees it

```bash
sudo journalctl -u smart_monitor -f
# Or:
sudo tail -f /var/log/smart_monitor.log
```

---

## Useful audit investigation commands

```bash
# See all deletions in last hour
sudo ausearch -k delete_events -ts recent | aureport -f

# See all commands run by a specific user
sudo ausearch -ua <username> -ts today

# See all sudo/su escalations
sudo ausearch -k priv_escalation -ts recent

# Generate a full user activity summary
sudo aureport -u --summary -ts today

# See who accessed /etc/shadow
sudo ausearch -f /etc/shadow -ts recent
```

---

## Environment file (.env) additions (optional)

You can add `HOSTNAME=my-server-name` to `/opt/smart_monitor/.env`
to override the auto-detected hostname in alert emails.
