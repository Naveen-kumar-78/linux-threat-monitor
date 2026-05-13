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

# 1. Update and install dependencies
echo "📦 Installing system dependencies (auditd, python3-pip)..."
apt-get update -qq
apt-get install -y -qq auditd python3-pip python3-venv > /dev/null

# 2. Install boto3 globally (or use venv based on Ubuntu version)
echo "🐍 Installing Python dependencies (boto3)..."
# On newer Ubuntu versions (22.04+), global pip installs error out without --break-system-packages.
# We will just run it and handle it gracefully if it complains.
pip3 install boto3 > /dev/null 2>&1 || pip3 install boto3 --break-system-packages > /dev/null 2>&1

# 3. Create necessary directories
echo "📁 Setting up directories..."
mkdir -p /opt/smart_monitor
mkdir -p /var/lib/smart_monitor
mkdir -p /var/log/smart_monitor/

# 4. Copy application files
echo "📄 Copying files to /opt/smart_monitor..."
if [ ! -f "smart_monitor.py" ]; then
    echo "❌ Error: smart_monitor.py not found in current directory!"
    exit 1
fi

cp -f smart_monitor.py /opt/smart_monitor/
chmod 750 /opt/smart_monitor/smart_monitor.py

# Create .env if it doesn't exist, else copy it
if [ ! -f "/opt/smart_monitor/.env" ]; then
    if [ -f ".env" ]; then
        cp -f .env /opt/smart_monitor/
    else
        echo "AWS_ACCESS_KEY_ID=" > /opt/smart_monitor/.env
        echo "AWS_SECRET_ACCESS_KEY=" >> /opt/smart_monitor/.env
        echo "AWS_REGION=ap-south-1" >> /opt/smart_monitor/.env
        echo "ALERT_FROM_EMAIL=" >> /opt/smart_monitor/.env
        echo "ALERT_TO_EMAIL=" >> /opt/smart_monitor/.env
        echo "HOSTNAME=$(hostname)" >> /opt/smart_monitor/.env
        echo "⚠️  Created dry .env file. YOU MUST EDIT /opt/smart_monitor/.env LATER!"
    fi
else
    # if it exists in the current folder, update it
    if [ -f ".env" ]; then
        cp -f .env /opt/smart_monitor/
    fi
fi
chmod 600 /opt/smart_monitor/.env

# 5. Configure Auditd
echo "🛡️  Configuring auditd rules..."
if [ -f "smart_monitor_auditd.rules" ]; then
    cp -f smart_monitor_auditd.rules /etc/audit/rules.d/smart_monitor.rules
    # Reload auditd rules
    augenrules --load > /dev/null 2>&1 || true
    systemctl restart auditd
else
    echo "⚠️  Warning: smart_monitor_auditd.rules not found in current directory. Auditd won't be configured."
fi

# 6. Configure systemd service
echo "⚙️  Setting up systemd service..."
if [ -f "smart_monitor.service" ]; then
    cp -f smart_monitor.service /etc/systemd/system/
else
    # Create the service file if it doesn't exist
    cat << 'EOF' > /etc/systemd/system/smart_monitor.service
[Unit]
Description=Smart Security Monitor v3.0
After=network.target auditd.service syslog.service

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/smart_monitor/smart_monitor.py
WorkingDirectory=/opt/smart_monitor
Restart=always
RestartSec=10
TimeoutStartSec=0
LimitNOFILE=100000

[Install]
WantedBy=multi-user.target
EOF
fi

systemctl daemon-reload
systemctl enable smart_monitor > /dev/null 2>&1
systemctl restart smart_monitor

echo ""
echo "✅ Installation Complete!"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "Status check:  sudo systemctl status smart_monitor"
echo "View Logs:     sudo tail -f /var/log/smart_monitor.log"
echo "Edit Config:   sudo nano /opt/smart_monitor/.env"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
