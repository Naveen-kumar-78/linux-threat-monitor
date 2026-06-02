# Smart Security Monitor v3.0

A Python-based Linux server monitor that watches what your users are actually doing — every command, every file they touch, every time someone switches to another account, every suspicious thing that happens at 3am. It sends you an email when something needs your attention and keeps a full audit trail regardless.

Built for servers where you have real human users logging in over SSH — developers, admins, contractors. Not for containers. Not for read-only infrastructure. For the kind of server where people actually sit in shells and do things.

---

## What it watches

### Who's doing what as root

When someone runs `sudo` or does `su -`, the monitor starts tracking them. Any command they run as root gets attributed back to the original person, not just "root". So instead of seeing "root deleted /var/log/auth.log", you see "naveen switched to root via sudo shell and deleted /var/log/auth.log".

This attribution survives even the sneaky case where someone does `su - anotheruser` instead of going straight to root. If ubuntu `su`'s into naveen's account and naveen's session does something bad, the alert says ubuntu did it. The innocent user doesn't take the blame.

### Commands that should never happen

There's a list of around 60 command patterns the monitor watches for. Things like:

- `rm -rf /` or any recursive delete of system paths
- Reverse shells — netcat, bash `/dev/tcp/`, Python socket tricks, perl
- Crypto miners running under any user
- Disk wipes with `dd` or `mkfs`
- Someone reading `/etc/shadow`
- Firewall rules getting flushed
- `curl something | bash` — the classic "install malware" pattern
- Password cracking tools (john, hashcat, hydra)
- Kernel modules being loaded or unloaded

These fire whether the user is running as root or as themselves. That second part was broken before — the old code only checked root commands. Now a developer running `nmap` or `hydra` from their own account gets caught too.

### SSH access

- Brute-force detection: 5+ failed logins from the same IP within 5 minutes → CRITICAL alert
- Successful login after those failures → another CRITICAL, because that means they got in
- IPv4 and IPv6 both covered
- First time a known user logs in from a new IP they've never used before → alert

### SSH backdoor keys

Watches every user's `~/.ssh/authorized_keys`, not just root's. If someone adds an SSH key to any account on the server — including normal user accounts — you'll hear about it within 60 seconds. The alert tells you how many keys are now in the file. If someone writes to a different user's `.ssh/` directory, that's flagged as CRITICAL immediately.

### File deletions

Tracks when someone runs `rm`, `shred`, or `rmdir` and attributes it back to the person who actually typed the command, not the process uid. System processes that legitimately delete files (Docker, apt, npm, pip, logrotate, etc.) are whitelisted so you don't get spammed.

### Critical system files

SHA256 hashes of important files are checked every cycle:

- `/etc/passwd`, `/etc/shadow` — user accounts and password hashes
- `/etc/sudoers` — who can sudo
- `/etc/hosts` — DNS override (attackers use this for redirect attacks)
- `/root/.ssh/authorized_keys` — root's SSH keys
- `/etc/ssh/sshd_config` — SSH server config
- `/etc/ld.so.preload` — library injection file (this one's a rootkit classic)
- `/etc/crontab` and cron directories

Hash-based means you can't fool it with `touch -t` to restore the timestamp. If the content changed, it fires.

### Sensitive file access

auditd watches `/etc/shadow`, `/etc/sudoers`, `/root/.ssh/`, cron directories, and others. Any access by a real login user (not a system process) fires an alert. `/etc/ld.so.preload` being written to is always CRITICAL — that's how library injection rootkits work.

### Log tampering

If someone tries to erase their tracks by:
- Deleting auth.log, syslog, or audit.log
- Truncating them with `> /var/log/auth.log`
- Running `truncate` on them

...the monitor catches it. It also distinguishes between `logrotate` (legitimate, happens at scheduled times, creates a `.1` backup) and actual tampering (no backup, unexpected shrink).

### Kernel modules

Tracks what kernel modules are loaded. New modules appearing = potential rootkit. Modules disappearing = attacker covering their tracks by unloading audit or security modules. Common transient kernel modules are filtered out so you don't get noise from normal disk and network operations.

### Sysrq trigger

Writing to `/proc/sysrq-trigger` lets root instantly reboot, crash, or kill all processes with a single character. It's one of the most destructive things you can do on a Linux server with no time to respond. The monitor catches any write to this file and tells you which character was used and what it would do.

### Network connections

Checks for active connections on ports commonly used by reverse shells and C2 frameworks: 4444, 1337, 31337, 6666, 8888, 9999, and others. Looks up which process owns the connection and which user owns that process.

### Home directory snooping

When a user reads files in another user's home directory, that fires an alert. Reading your own files is fine. Reading `/home/someone_else/` is not. Accessing another user's `.ssh/`, `.bash_history`, or anything with "password" or "secret" in the path bumps the severity to HIGH.

### `su` to another user (local brute force)

Repeated failed `su` attempts — wrong password on `su - root` or `su - someuser` — get tracked the same way SSH brute force does. Three failures within 5 minutes fires an alert. This catches someone with a shell trying to escalate locally.

### Dormant accounts

If a user account hasn't been used in 90+ days and suddenly logs in, that's worth knowing about. Could be a forgotten account being used by a former employee or an attacker who found old credentials.

### Processes running from `/tmp`

No legitimate software runs from `/tmp`, `/dev/shm`, or `/var/tmp`. If a process is executing from those locations, something's wrong. This is one of the most reliable malware indicators on Linux.

### Data exfiltration

Flags commands that look like they're moving data out — `scp` to a remote host, `rsync` over SSH, `sftp` sessions, `tar` piped to `curl` or `netcat`.

### Threat scoring

Every suspicious event adds points to a per-user threat score. The score decays over time so a single incident doesn't haunt someone forever. When a user's score crosses the threshold, you get an alert summarising the pattern. This catches the case where someone does a bunch of medium-severity things that individually might not warrant a page, but together look like an active attack.

---

## Alert levels

**CRITICAL** — stop what you're doing and look at this now. Something is either actively happening or recently happened that requires immediate response.

**HIGH** — needs investigation within the hour. Could be legitimate (admin doing their job) or could be something bad. Either way, you should know.

**MEDIUM** — worth reviewing. Probably nothing, but log it and check it.

**LOW** — informational. Gets logged and counted toward the threat score but doesn't usually warrant immediate action.

---

## Requirements

- Ubuntu 20.04, 22.04, or 24.04 (or any Debian-based distro)
- Python 3.8+
- `auditd` (installed by the setup script)
- `boto3` Python package for email alerts (installed by the setup script)
- An AWS account with SES set up if you want email alerts (optional — the monitor still logs everything without it)
- Run as root (it reads `/etc/shadow`, `/proc/*/`, and audit logs)

---

## Setup

### Step 1 — Clone or copy the files

Get these files onto your server in the same directory:

```
smart_monitor.py
smart_monitor.service
smart_monitor_auditd.rules
install.sh
.env.example
```

### Step 2 — Configure your `.env` file

Copy the example and fill it in:

```bash
cp .env.example .env
nano .env
```

The things you need to set:

```env
# Give this server a name so you know which one sent the alert
SERVER_NAME=prod-web-01

# Email alerts via AWS SES
MAIL_ENABLED=true
AWS_ACCESS_KEY_ID=your_key_here
AWS_SECRET_ACCESS_KEY=your_secret_here
AWS_REGION=ap-south-1

# The address SES sends from (must be verified in SES)
SES_SENDER_EMAIL=alerts@your-domain.com

# Who gets the alerts (comma-separated for multiple people)
SES_RECIPIENT_EMAILS=you@your-domain.com,teammate@your-domain.com
```

If you don't have SES set up yet, set `MAIL_ENABLED=false`. The monitor will still run and write everything to the JSON log — you just won't get emails until you configure it.

### Step 3 — Run the installer

```bash
sudo bash install.sh
```

That's it. The installer:

1. Installs `auditd`, `python3-pip`, and `apparmor` via apt
2. Installs `boto3` for email
3. Creates `/opt/smart_monitor/` with root-only permissions
4. Copies your `.env` and the monitor script there
5. Loads the auditd rules
6. Creates and starts the systemd service
7. Adds sudoers rules that block regular sudo users from reading monitor files
8. Installs an AppArmor profile as a second layer of protection

### Step 4 — Verify it's running

```bash
sudo systemctl status smart_monitor
```

Watch the live log to make sure it's cycling:

```bash
sudo tail -f /var/log/smart_monitor.log
```

You should see lines like `--- Cycle 1 ---`, `--- Cycle 2 ---` appearing every 60 seconds. If you see errors there, they'll tell you what's wrong.

### Step 5 — Verify auditd rules loaded

```bash
sudo auditctl -l
```

You should see rules for `delete_events`, `exec_user`, `exec_root`, `sensitive_files`, `priv_escalation`, and others. If you see "No rules" then auditd didn't load them — run `sudo augenrules --load && sudo systemctl restart auditd` manually.

---

## AWS SES setup (if you haven't done this before)

1. Go to AWS Console → SES → Verified identities
2. Verify your sender email address (or your whole domain)
3. If your SES account is in sandbox mode, also verify the recipient email addresses
4. Create an IAM user with the `AmazonSESFullAccess` policy (or a narrower custom policy that only allows `ses:SendEmail`)
5. Generate access keys for that IAM user and put them in your `.env`

If you're in SES sandbox mode and keep getting delivery failures, that's why — every address has to be individually verified until AWS lifts the sandbox restriction. Go to SES → Account dashboard and request production access.

---

## Multiple servers

Run the same setup on each server. The `SERVER_NAME` in `.env` is what distinguishes them in alerts — set it to something meaningful like `db-primary`, `app-server-2`, `bastion`. Every alert email subject and JSON record includes this name.

---

## Where the files live after install

| Path | What it is |
|---|---|
| `/opt/smart_monitor/smart_monitor.py` | The monitor script |
| `/opt/smart_monitor/.env` | Your config and AWS credentials |
| `/var/log/smart_monitor.log` | Live operational log (what the monitor is doing each cycle) |
| `/var/log/smart_monitor_alerts.json` | Every alert ever fired, in JSON — root-only |
| `/var/lib/smart_monitor/state.json` | Saved state between restarts (offsets, hashes, session tracking) |
| `/etc/audit/rules.d/smart_monitor.rules` | auditd rules |
| `/etc/systemd/system/smart_monitor.service` | Systemd service definition |

All log files are `chmod 600 root:root` — only readable by root, not by sudo users.

---

## Useful commands

```bash
# Check if it's running
sudo systemctl status smart_monitor

# Watch logs live
sudo tail -f /var/log/smart_monitor.log

# See all alerts that have fired
sudo cat /var/log/smart_monitor_alerts.json

# Restart after changing .env
sudo systemctl restart smart_monitor

# Check auditd rules are active
sudo auditctl -l

# Check auditd is healthy
sudo systemctl status auditd
```

---

## Adjusting what gets alerted

Everything is controlled by the `.env` file and the constants at the top of `smart_monitor.py`.

**To disable email and only log:** set `MAIL_ENABLED=false` in `.env`. Restart the service.

**To change cooldown periods** (how often the same alert can fire): edit `COOLDOWNS` near the top of the script. Default is 2 min for CRITICAL, 10 min for HIGH, 30 min for MEDIUM, 2 hours for LOW.

**To whitelist a system user** from deletion alerts (e.g. a monitoring agent you installed): add its username to `DELETION_WHITELIST_USERS`.

**To whitelist a process binary** from deletion alerts: add it to the `DELETION_WHITELIST_EXES` regex.

**To turn off home directory snooping** on shared dev servers where it gets noisy: comment out the `home_dir_access` lines in `smart_monitor_auditd.rules` and reload auditd.

---

## What auditd is and why it matters

auditd is a Linux kernel-level event logger. When the monitor uses auditd, it's not reading shell history or parsing `ps` output — it's getting events directly from the kernel before any userspace process can tamper with them. That's why the attribution works even when someone tries to hide what they're doing.

The key thing auditd gives you that nothing else can: when someone `su`'s to root and runs a command, the kernel records both the original user ID (auid — the person who logged in) and the effective user ID (uid — root). The monitor uses this to always know who the real human is behind a root command, even if they're running inside a `sudo -i` shell that's been open for hours.

---

## Known limitations

- **60-second cycle time** — there's up to a 60 second delay between something happening and the alert firing. For most scenarios this is fine. If you need faster detection, reduce the `time.sleep(60)` at the bottom of `main()` — but watch your CPU and auditd log volume.

- **auditd required for best results** — several checks fall back to parsing auth.log and syslog if auditd isn't running, but the attribution quality drops. Keep auditd running.

- **Email delivery depends on AWS SES** — if SES has issues or your credentials expire, alerts still go to the JSON log but you won't get emails. Check the log periodically or set up a secondary alert channel.

- **Home directory snooping can be noisy** on servers where users legitimately collaborate and read shared files. The `home_dir_access` auditd rule can be commented out if it produces too many false positives for your setup.

- **The monitor runs as root** because that's what's required to read audit logs, `/proc/*/`, `/etc/shadow`, and other protected files. The systemd service has hardening options enabled (NoNewPrivileges, ProtectHome, etc.) to limit blast radius if the monitor process itself were somehow compromised.
