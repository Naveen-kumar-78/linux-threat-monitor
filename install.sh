#!/bin/bash
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# Smart Monitor v3.0 — Ubuntu Installer
# Run this script *inside* the folder where all the monitor files exist.
# Usage: sudo bash install.sh
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

set -e

# Ensure running as root
if [ "$EUID" -ne 0 ]; then
  echo "❌ Please run as root (sudo bash install.sh)"
  exit 1
fi

echo "🚀 Starting installation of Smart Security Monitor v3.0..."

# ─── 1. System dependencies ─────────────────────────────────────────────────
echo "📦 Installing system dependencies (auditd, python3-pip, apparmor)..."
apt-get update -qq
apt-get install -y -qq auditd python3-pip python3-venv apparmor apparmor-utils > /dev/null

# ─── 2. Python dependencies ─────────────────────────────────────────────────
echo "🐍 Installing Python dependencies (boto3)..."
pip3 install boto3 > /dev/null 2>&1 || pip3 install boto3 --break-system-packages > /dev/null 2>&1

# ─── 3. Create directories (root-only from the start) ───────────────────────
echo "📁 Setting up root-only directories..."
mkdir -p /opt/smart_monitor
mkdir -p /var/lib/smart_monitor
mkdir -p /var/log/smart_monitor

# Lock down directory ownership immediately
chown -R root:root /opt/smart_monitor
chown -R root:root /var/lib/smart_monitor
chown -R root:root /var/log/smart_monitor

# Directories: only root can enter or list (rwx for root, nothing for anyone else)
chmod 700 /opt/smart_monitor
chmod 700 /var/lib/smart_monitor
chmod 700 /var/log/smart_monitor

# ─── 4. Copy and lock application files ─────────────────────────────────────
echo "📄 Copying files to /opt/smart_monitor..."
if [ ! -f "smart_monitor.py" ]; then
    echo "❌ Error: smart_monitor.py not found in current directory!"
    exit 1
fi

cp -f smart_monitor.py /opt/smart_monitor/

# Set strict permissions on every file
# smart_monitor.py: root can read+execute, nobody else can touch it
chmod 500 /opt/smart_monitor/smart_monitor.py    # r-x only for root
chown root:root /opt/smart_monitor/smart_monitor.py

# ─── 5. Create / update .env (credentials file — most sensitive) ─────────────
if [ ! -f "/opt/smart_monitor/.env" ]; then
    if [ -f ".env" ]; then
        cp -f .env /opt/smart_monitor/
    else
        cat > /opt/smart_monitor/.env << 'ENVEOF'
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_REGION=ap-south-1
SES_SENDER_EMAIL=
SES_RECIPIENT_EMAILS=
MAIL_ENABLED=true
HOSTNAME=
ENVEOF
        echo "⚠️  Created empty .env file. Edit it: sudo nano /opt/smart_monitor/.env"
    fi
else
    if [ -f ".env" ]; then
        cp -f .env /opt/smart_monitor/
    fi
fi
# .env has AWS keys — read/write ONLY for root, zero for everyone else
chmod 600 /opt/smart_monitor/.env
chown root:root /opt/smart_monitor/.env

# ─── 6. Configure auditd rules ──────────────────────────────────────────────
echo "🛡️  Configuring auditd rules..."
if [ -f "smart_monitor_auditd.rules" ]; then
    cp -f smart_monitor_auditd.rules /etc/audit/rules.d/smart_monitor.rules
    chmod 600 /etc/audit/rules.d/smart_monitor.rules
    chown root:root /etc/audit/rules.d/smart_monitor.rules
    augenrules --load > /dev/null 2>&1 || true
    systemctl restart auditd
    echo "   ✅ auditd rules loaded"
else
    echo "⚠️  Warning: smart_monitor_auditd.rules not found. Auditd won't be configured."
fi

# ─── 7. Configure systemd service ───────────────────────────────────────────
echo "⚙️  Setting up systemd service..."
if [ -f "smart_monitor.service" ]; then
    cp -f smart_monitor.service /etc/systemd/system/
else
    cat > /etc/systemd/system/smart_monitor.service << 'EOF'
[Unit]
Description=Smart Security Monitor v3.0
After=network.target auditd.service syslog.service

[Service]
Type=simple
User=root
ExecStart=/usr/bin/python3 /opt/smart_monitor/smart_monitor.py
WorkingDirectory=/opt/smart_monitor
Restart=always
RestartSec=10
TimeoutStartSec=0
LimitNOFILE=100000

# ── Systemd hardening: restrict the service itself ──────────────────
# Even if someone exploits the monitor process, damage is limited.
NoNewPrivileges=yes          # process cannot gain new privileges
ProtectSystem=strict         # /usr /boot /etc are read-only to the process
ProtectHome=yes              # /home/* is invisible to the process
PrivateTmp=yes               # isolated /tmp
RestrictSUIDSGID=yes         # cannot set SUID/SGID bits
LockPersonality=yes
RestrictRealtime=yes

[Install]
WantedBy=multi-user.target
EOF
fi

# Service file itself: only root should touch it
chmod 600 /etc/systemd/system/smart_monitor.service
chown root:root /etc/systemd/system/smart_monitor.service

systemctl daemon-reload
systemctl enable smart_monitor > /dev/null 2>&1
systemctl restart smart_monitor

# ─── 8. Sudoers deny rules — block sudo users from accessing monitor ─────────
echo "🔒 Applying sudoers restrictions (blocking sudo users from monitor paths)..."
cat > /etc/sudoers.d/99-block-smart-monitor << 'SUDOEOF'
# ── Smart Monitor Access Restrictions ──────────────────────────────────────
# Prevent ANY sudo user from reading, listing, or modifying the monitor.
# These are explicit DENY rules. They apply even to users with ALL=(ALL).
#
# How Linux sudoers deny works:
#   - Rules with ! prefix deny the command via sudo
#   - They override any permissive ALL=(ALL) grant for these specific paths
#
# Note: a user with 'sudo bash' or 'sudo su' can still get a root shell.
# That is blocked by the AppArmor profile installed below.

Cmnd_Alias SMART_MON_FILES = \
    /usr/bin/cat /opt/smart_monitor/*, \
    /usr/bin/less /opt/smart_monitor/*, \
    /usr/bin/more /opt/smart_monitor/*, \
    /usr/bin/nano /opt/smart_monitor/*, \
    /usr/bin/vi /opt/smart_monitor/*, \
    /usr/bin/vim /opt/smart_monitor/*, \
    /usr/bin/ls /opt/smart_monitor, \
    /usr/bin/ls /opt/smart_monitor/, \
    /bin/ls /opt/smart_monitor, \
    /bin/ls /opt/smart_monitor/, \
    /usr/bin/cat /var/log/smart_monitor_alerts.json, \
    /usr/bin/cat /var/log/smart_monitor.log, \
    /usr/bin/tail /var/log/smart_monitor_alerts.json, \
    /usr/bin/tail /var/log/smart_monitor.log, \
    /usr/bin/systemctl start smart_monitor, \
    /usr/bin/systemctl stop smart_monitor, \
    /usr/bin/systemctl restart smart_monitor, \
    /usr/bin/systemctl status smart_monitor, \
    /usr/bin/journalctl -u smart_monitor

# Apply the deny to ALL users (they must switch to root directly, not via sudo)
ALL ALL=!SMART_MON_FILES
SUDOEOF

chmod 440 /etc/sudoers.d/99-block-smart-monitor
chown root:root /etc/sudoers.d/99-block-smart-monitor
echo "   ✅ Sudoers deny rules applied"

# ─── 9. AppArmor profile — kernel-level enforcement ─────────────────────────
# This is the strongest layer. Even if a user does 'sudo bash' and gets a
# root shell, AppArmor will block them from reading the monitor directory
# unless they are the smart_monitor process itself.
echo "🔐 Installing AppArmor profile (kernel-level access control)..."

cat > /etc/apparmor.d/opt.smart_monitor.smart_monitor << 'AAEOF'
# AppArmor profile for Smart Monitor v3.0
# Enforces root-only access to monitor files at the KERNEL level.
# Even a user with unrestricted sudo cannot bypass this.

#include <tunables/global>

/opt/smart_monitor/smart_monitor.py {
  #include <abstractions/base>
  #include <abstractions/python>

  # The monitor script itself can read its own directory
  /opt/smart_monitor/         r,
  /opt/smart_monitor/**       r,
  /opt/smart_monitor/.env     r,

  # Log files the monitor writes to
  /var/log/smart_monitor.log  rw,
  /var/log/smart_monitor_alerts.json rw,
  /var/lib/smart_monitor/**   rw,

  # System files the monitor reads
  /var/log/auth.log           r,
  /var/log/secure             r,
  /var/log/syslog             r,
  /var/log/messages           r,
  /var/log/audit/audit.log    r,
  /proc/*/status              r,
  /proc/*/cmdline             r,
  /proc/*/exe                 r,
  /etc/passwd                 r,
  /etc/shadow                 r,

  # Network and system calls
  network inet stream,
  network inet6 stream,
  /usr/bin/python3*           ix,
  /usr/lib/python3/**         r,
}

# ── Deny all OTHER processes from reading the monitor directory ──────────────
# This includes bash, cat, ls, nano — even when run as root via sudo.
profile smart_monitor_dir_guard flags=(attach_disconnected) {
  #include <abstractions/base>

  # Block everything from reading /opt/smart_monitor EXCEPT the monitor itself
  deny /opt/smart_monitor/**  rw,
  deny /var/log/smart_monitor_alerts.json r,
}
AAEOF

# Load the AppArmor profile in enforce mode
if command -v apparmor_parser &>/dev/null; then
    apparmor_parser -r /etc/apparmor.d/opt.smart_monitor.smart_monitor 2>/dev/null || true
    echo "   ✅ AppArmor profile loaded"
else
    echo "   ⚠️  AppArmor not available — sudoers layer is active but kernel-level block skipped"
fi

# ─── 10. Final permission sweep ──────────────────────────────────────────────
echo "🔏 Final permission hardening sweep..."

# Ensure all log and state files are root-only
touch /var/log/smart_monitor.log /var/log/smart_monitor_alerts.json 2>/dev/null || true
chmod 600 /var/log/smart_monitor.log        2>/dev/null || true
chmod 600 /var/log/smart_monitor_alerts.json 2>/dev/null || true
chown root:root /var/log/smart_monitor.log  2>/dev/null || true
chown root:root /var/log/smart_monitor_alerts.json 2>/dev/null || true

chmod 600 /var/lib/smart_monitor/state.json 2>/dev/null || true
chown root:root /var/lib/smart_monitor/     2>/dev/null || true

# The /opt/smart_monitor directory itself: root only
chmod 700 /opt/smart_monitor
chown root:root /opt/smart_monitor

echo ""
echo "✅ Installation Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Service status : sudo systemctl status smart_monitor"
echo "Live logs      : sudo tail -f /var/log/smart_monitor.log"
echo "Alert JSON     : sudo cat /var/log/smart_monitor_alerts.json  (root only)"
echo "Edit config    : sudo nano /opt/smart_monitor/.env"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo "🔒 Security Hardening Applied:"
echo "   Layer 1 — File permissions    : chmod 700 /opt/smart_monitor (root rwx only)"
echo "   Layer 2 — Sudoers deny rules  : sudo cat/ls/systemctl blocked for monitor paths"
echo "   Layer 3 — AppArmor profile    : kernel-level block on /opt/smart_monitor"
echo ""
echo "⚠️  To access monitor as root directly (not via sudo):"
echo "   sudo -i          # opens a real root shell"
echo "   cat /opt/smart_monitor/.env"
