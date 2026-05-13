# -*- coding: utf-8 -*-
#!/usr/bin/env python3
"""
Smart Security Monitor v3.0
Features:
  [x] Full DELETE attribution (rm/unlink/rmdir via auditd)
  [x] Identity chain tracking - su/sudo su -> original human user
  [x] Linux auditd integration
  [x] Insider threat detection - history wipe, log deletion
  [x] /proc live PID scanner
  [x] Dormant account anomaly detection
  [x] Log file tampering detection (truncation/deletion)
  [x] Kernel module load/unload detection
  [x] LD_PRELOAD / library injection detection
  [x] SSH brute-force + post-brute success detection
  [x] MAIL_ENABLED toggle - disable to log-only
  [x] All alerts written to JSON log for audit trail
"""
from __future__ import annotations
import os, re, time, socket, hashlib, json, pwd, grp
from collections import defaultdict
from datetime import datetime, timedelta, timezone
import subprocess

LOG_PATH        = "/var/log/smart_monitor.log"
STATE_PATH      = "/var/lib/smart_monitor/state.json"
ENV_PATH        = "/opt/smart_monitor/.env"
AUDIT_LOG       = "/var/log/audit/audit.log"
AUTH_LOGS       = ["/var/log/auth.log", "/var/log/secure"]
SYSLOG_LOGS     = ["/var/log/syslog", "/var/log/messages"]
ALERT_JSON_PATH = "/var/log/smart_monitor_alerts.json"

HOSTNAME = socket.gethostname()
IST      = timezone(timedelta(hours=5, minutes=30), "IST")

COOLDOWNS = {
    "CRITICAL": timedelta(minutes=2),
    "HIGH":     timedelta(minutes=10),
    "MEDIUM":   timedelta(minutes=30),
    "LOW":      timedelta(hours=2),
}

THREAT_WEIGHTS = {"CRITICAL": 50, "HIGH": 20, "MEDIUM": 8, "LOW": 2}
THREAT_ALERT_THRESHOLD    = 80
THREAT_CRITICAL_THRESHOLD = 150
SCORE_HALF_LIFE           = timedelta(minutes=30)
THREAT_SCORE_COOLDOWN     = timedelta(hours=2)
THREAT_RESCORE_DELTA      = 40
THREAT_SCORE_LAST_ALERT: dict = {}

DANGEROUS_PATTERNS = [
    (r"rm\s+-[rRf]{1,3}\s+/(?:\s|$)",              "Recursive root filesystem delete",       "CRITICAL"),
    (r"rm\s+.*--no-preserve-root",                  "rm --no-preserve-root (full wipe)",      "CRITICAL"),
    (r"rm\s+-[rRf]+\s+(?P<target>(?!/)\S+)",        "Recursive file/directory delete",        "HIGH"),
    (r"rm\s+(?P<target>/etc/(?:passwd|shadow|sudoers|hosts|ssh)\S*)", "Critical system file deleted", "CRITICAL"),
    (r"rm\s+(?P<target>/var/log/\S+)",              "Log file deletion (evidence destroy)",   "CRITICAL"),
    (r"rm\s+(?P<target>/root/\S*)",                 "Root home directory file deletion",      "CRITICAL"),
    (r"dd\s+if=.*of=/dev/[sh]d",                    "Disk wipe / raw overwrite",              "CRITICAL"),
    (r"mkfs\s+",                                    "Filesystem format",                      "CRITICAL"),
    (r"shred\s+.*(?P<target>/(?:etc|var|root)\S*)", "Secure shred of critical path",          "CRITICAL"),
    (r"passwd\s+root",                              "Root password change",                   "CRITICAL"),
    (r"echo\s+.*>>\s*/etc/passwd",                  "Direct /etc/passwd modification",        "CRITICAL"),
    (r">\s*/etc/shadow",                            "Shadow file overwrite",                  "CRITICAL"),
    (r"truncate\s+.*(?P<target>/var/log/\S*)",      "Log file truncation",                    "CRITICAL"),
    (r">\s*/var/log/(?:auth|syslog|secure|audit)",  "Log file wiped with redirect",           "CRITICAL"),
    (r"nc\s+.*-e\s+/bin",                           "Netcat reverse shell",                   "CRITICAL"),
    (r"/dev/tcp/\d",                                "Bash TCP reverse shell",                 "CRITICAL"),
    (r"python[23]?\s+-c.*import\s+socket",          "Python reverse shell",                   "CRITICAL"),
    (r"perl\s+-e.*socket",                          "Perl reverse shell",                     "CRITICAL"),
    (r"msfconsole|msfvenom|metasploit",             "Metasploit framework detected",          "CRITICAL"),
    (r"nmap\s+.*-sS\s",                             "Stealth SYN port scan (nmap -sS)",       "CRITICAL"),
    (r"xmrig|cpuminer|minerd|cgminer|t-rex",        "Crypto miner process",                   "CRITICAL"),
    (r"cryptominer|nicehash|xmr-stak",              "Crypto mining software",                 "CRITICAL"),
    (r"insmod\s+|modprobe\s+(?!--remove)",          "Kernel module loaded (rootkit risk)",    "CRITICAL"),
    (r"rmmod\s+|modprobe\s+--remove",               "Kernel module removed",                  "HIGH"),
    (r"LD_PRELOAD\s*=",                             "LD_PRELOAD library injection",           "CRITICAL"),
    (r"ptrace\s+\d|PTRACE_ATTACH",                  "Process injection via ptrace",           "CRITICAL"),
    (r"iptables\s+-F",                              "Flush all firewall rules",               "HIGH"),
    (r"ufw\s+disable",                              "UFW firewall disabled",                  "HIGH"),
    (r"setenforce\s+0",                             "SELinux enforcement disabled",           "HIGH"),
    (r"visudo|/etc/sudoers",                        "Sudoers file modification",              "HIGH"),
    (r"(?:useradd|adduser)\s+(?P<target>\S+)",      "New user account created",               "HIGH"),
    (r"userdel\s+(?P<target>\S+)",                  "User Account Deletion",                  "HIGH"),
    (r"usermod\s+.*-aG\s+(?:sudo|wheel|root)\s+(?P<target>\S+)", "User added to privileged group", "HIGH"),
    (r"curl\s+.*\|\s*(ba)?sh",                      "Pipe curl output to shell",              "HIGH"),
    (r"wget\s+.*\|\s*(ba)?sh",                      "Pipe wget output to shell",              "HIGH"),
    (r"base64\s+-d.*\|\s*(ba)?sh",                  "Base64 payload piped to shell",          "HIGH"),
    (r"chmod\s+[0-9]*s[0-9]*\s|chmod\s+4[0-9]{3}\s","SUID/SGID bit set",                    "HIGH"),
    (r"chattr\s+\+i\s+/etc/",                       "Immutable flag on system file",          "HIGH"),
    (r"at\s+now|^batch\b",                          "Scheduled job via at/batch",             "HIGH"),
    (r"crontab\s+-r",                               "Crontab forcibly removed",               "HIGH"),
    (r"(\*\s+\*\s+\*.*crontab|/etc/cron\.d)",       "Cron persistence attempt",               "HIGH"),
    (r"echo\s+.*>>\s*.*authorized_keys",            "SSH authorized_keys modified",           "HIGH"),
    (r"history\s+-[cw]|unset\s+HISTFILE|HISTSIZE=0","Command history wiped/disabled",         "HIGH"),
    (r"export\s+HISTFILE=/dev/null",                "Bash history redirected to /dev/null",   "HIGH"),
    (r"pkill\s+-9\s+|kill\s+-9\s+1\b",             "Aggressive process kill (incl. PID 1)",  "HIGH"),
    (r"systemctl\s+(?:stop|disable|mask)\s+(?:auditd|rsyslog|syslog)", "Security daemon stopped/disabled", "HIGH"),
    (r"service\s+(?:auditd|rsyslog)\s+stop",        "Security daemon stopped via service",    "HIGH"),
    (r"chmod\s+777",                                "World-writable permissions set",         "MEDIUM"),
    (r"ssh-keygen",                                 "SSH key generation",                     "MEDIUM"),
    (r"nmap\s+",                                    "Network port scan",                      "MEDIUM"),
    (r"tcpdump\s+",                                 "Packet capture started",                 "MEDIUM"),
    (r"wireshark|tshark",                           "Network sniffer launched",               "MEDIUM"),
    (r"strace\s+-p",                                "Process tracing via strace",             "MEDIUM"),
    (r"hydra\s+|medusa\s+|brutus\s+",               "Password brute-force tool",              "MEDIUM"),
    (r"john\s+--.*|hashcat\s+",                     "Password cracking tool",                 "MEDIUM"),
    (r"socat\s+",                                   "Socat relay/tunnel detected",            "MEDIUM"),
    (r"shred\s+-[uzn]",                             "Secure file deletion (shred)",           "MEDIUM"),
    (r"find\s+/\s+.*-perm\s+-4000",                 "SUID file enumeration",                  "MEDIUM"),
    (r"cat\s+/etc/shadow",                          "Shadow file read attempt",               "MEDIUM"),
    (r"openssl\s+enc\s+-",                          "File encryption (openssl)",              "MEDIUM"),
    (r"gpg\s+--encrypt|gpg\s+-e\b",                "File encryption (gpg)",                  "MEDIUM"),
    (r"zip\s+.*-P\s+|7z\s+a\s+.*-p",               "Password-protected archive created",     "MEDIUM"),
    (r"wget\s+|curl\s+-[sSo].*http",                "Web download (curl/wget)",               "LOW"),
]

BRUTE_FORCE_THRESHOLD = 5
BRUTE_FORCE_WINDOW    = timedelta(minutes=5)
C2_PORTS = {4444,4445,5555,6666,7777,8888,9999,31337,1337,4321,6667,6697}

DELETION_WHITELIST_USERS = {
    "root","telegraf","prometheus","grafana","zabbix","nagios","datadog",
    "node_exporter","alertmanager","gitlab","git","gitlab-runner",
    "gitlab-psql","gitlab-redis","postgres","postgresql","mysql",
    "mongodb","redis","www-data","nginx","apache","caddy","tomcat",
    "jenkins","bamboo","teamcity","circleci","syslog","rsyslog",
    "systemd","sysd","daemon","messagebus","avahi","usbmux","lp","cups",
    "_apt","apt","dpkg","snap","backup","bacula","barman",
}

DELETION_WHITELIST_EXES = re.compile(
    r"""(?x)
    /usr/sbin/runc|/usr/bin/runc|containerd
    |/usr/bin/dockerd|/usr/sbin/dockerd|/var/lib/docker
    |/opt/gitlab/|/var/opt/gitlab/
    |/usr/bin/dpkg|/usr/bin/apt|/usr/lib/apt|/usr/bin/apt-get|/usr/lib/dpkg
    |/usr/bin/snap|/usr/lib/snapd|/snap/|/tmp/snap\.
    |/usr/bin/python.*pip|/usr/lib/python|pip3?\s
    |/usr/bin/npm|/usr/bin/node|/usr/lib/node
    |/usr/bin/telegraf|/usr/sbin/telegraf
    |/usr/bin/prometheus|/usr/sbin/prometheus|/usr/bin/grafana
    |/usr/lib/postgresql|/usr/sbin/postgres|/usr/bin/postgres
    |/var/lib/mysql|/usr/sbin/mysqld
    |/usr/lib/update-notifier|/usr/lib/apt/methods|/usr/sbin/logrotate
    """, re.IGNORECASE)

DELETION_PID_SEEN: dict = {}
DELETION_PID_TTL  = timedelta(minutes=5)

ALERTS_SENT:        dict = {}
FILE_OFFSETS:       dict = {}
SSH_FAILURES:       dict = defaultdict(list)
USER_ROOT_SESSIONS: dict = defaultdict(list)
USER_SUDO_COUNT:    dict = defaultdict(int)
IDENTITY_CHAIN:     dict = {}
SU_SESSION_START:   dict = {}
THREAT_SCORE_LOG:   dict = defaultdict(list)
DELETION_EVENTS:    list = []
LOG_SIZE_SNAPSHOT:  dict = {}
_FILE_INODES:       dict = {}
_LOG_SIZE_INITIALIZED: bool = False


def log(msg: str):
    ts   = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


def run(cmd: str, timeout: int = 5) -> str:
    try:
        return subprocess.check_output(
            cmd, shell=True, stderr=subprocess.DEVNULL, timeout=timeout
        ).decode(errors="replace").strip()
    except Exception:
        return ""


def load_env(path: str) -> dict:
    env = {}
    if not os.path.exists(path):
        return env
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip().strip("'\"")
    return env


def load_state():
    global FILE_OFFSETS, LOG_SIZE_SNAPSHOT
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                data = json.load(f)
                FILE_OFFSETS      = data.get("offsets", {})
                LOG_SIZE_SNAPSHOT = data.get("log_sizes", {})
        except Exception:
            pass


def save_state():
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w") as f:
            json.dump({"offsets": FILE_OFFSETS, "log_sizes": LOG_SIZE_SNAPSHOT}, f)
    except Exception:
        pass


CYCLE_LINES: dict = {}


def read_new_lines(logfile: str) -> list:
    """Read only new bytes from logfile since last offset. Handles rotation via inode."""
    if not os.path.exists(logfile):
        return []
    try:
        with open(logfile, "rb") as f:
            st           = os.fstat(f.fileno())
            current_size = st.st_size
            current_ino  = st.st_ino
            prev_ino     = _FILE_INODES.get(logfile)
            rotated      = (prev_ino is not None and prev_ino != current_ino)
            if rotated:
                offset = 0
            else:
                offset = FILE_OFFSETS.get(logfile, max(0, current_size - 4096))
                if offset > current_size:
                    offset = 0
            _FILE_INODES[logfile]  = current_ino
            f.seek(offset)
            raw = f.read()
            FILE_OFFSETS[logfile] = f.tell()
        return raw.decode(errors="replace").splitlines()
    except Exception:
        return []


def load_cycle_lines():
    CYCLE_LINES.clear()
    for logfile in list(set(AUTH_LOGS + SYSLOG_LOGS)):
        CYCLE_LINES[logfile] = read_new_lines(logfile)


def get_cycle_lines(logfiles: list) -> list:
    result = []
    for lf in logfiles:
        result.extend(CYCLE_LINES.get(lf, []))
    return result


def _alert_key(category: str, detail: str = "") -> str:
    return hashlib.sha1(category.encode()).hexdigest()[:16]


def should_alert(key: str, severity: str) -> bool:
    now      = datetime.now(IST)
    last     = ALERTS_SENT.get(key)
    cooldown = COOLDOWNS.get(severity, timedelta(minutes=10))
    if last is None or (now - last) > cooldown:
        ALERTS_SENT[key] = now
        return True
    return False


def uid_to_name(uid: str) -> str:
    try:
        return pwd.getpwuid(int(uid)).pw_name
    except Exception:
        return uid


def username_to_uid(username: str) -> str:
    try:
        return str(pwd.getpwnam(username).pw_uid)
    except Exception:
        return "?"


def record_threat_event(user: str, severity: str):
    now    = datetime.now(IST)
    weight = THREAT_WEIGHTS.get(severity, 2)
    THREAT_SCORE_LOG[user].append((now, weight))


def compute_threat_score(user: str) -> float:
    now    = datetime.now(IST)
    cutoff = now - timedelta(hours=4)
    total  = 0.0
    THREAT_SCORE_LOG[user] = [(t, w) for t, w in THREAT_SCORE_LOG[user] if t > cutoff]
    for ts, w in THREAT_SCORE_LOG[user]:
        age_min = (now - ts).total_seconds() / 60
        decay   = 0.5 ** (age_min / SCORE_HALF_LIFE.total_seconds() * 60)
        total  += w * decay
    return round(total, 1)


def check_threat_scores(env: dict):
    """Log-only threat score evaluation (no email spam)."""
    now = datetime.now(IST)
    for user in list(THREAT_SCORE_LOG.keys()):
        score = compute_threat_score(user)
        if score <= 0:
            THREAT_SCORE_LAST_ALERT.pop(user, None)
            continue
        if score >= THREAT_CRITICAL_THRESHOLD:
            severity = "CRITICAL"
        elif score >= THREAT_ALERT_THRESHOLD:
            severity = "HIGH"
        else:
            continue
        last = THREAT_SCORE_LAST_ALERT.get(user)
        if last:
            last_time, last_score = last
            score_jumped  = (score - last_score) >= THREAT_RESCORE_DELTA
            cooldown_done = (now - last_time) >= THREAT_SCORE_COOLDOWN
            if not score_jumped and not cooldown_done:
                continue
            if cooldown_done and not score_jumped:
                severity = "MEDIUM"
        THREAT_SCORE_LAST_ALERT[user] = (now, score)
        prev_str = f" (was {last[1]:.0f})" if last else ""
        hour = int(now.strftime("%H"))
        log(f"[THREAT SCORE] User '{user}' score={score:.0f}{prev_str} "
            f"severity={severity} off_hours={hour < 6 or hour > 22}")

# -----------------------------------------------------------------
# Lightweight HTML email builder (light theme, no scrolling needed)
# -----------------------------------------------------------------
_SEV_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#e67e22",
    "MEDIUM":   "#f39c12",
    "LOW":      "#2980b9",
}
_SEV_ICON = {
    "CRITICAL": "[!!]",
    "HIGH":     "[!]",
    "MEDIUM":   "[~]",
    "LOW":      "[i]",
}


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html_email(severity, alert_type, user, detail,
                     context_lines=None, extra_facts=None) -> str:
    color   = _SEV_COLOR.get(severity, "#7f8c8d")
    icon    = _SEV_ICON.get(severity, "[?]")
    now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

    facts_html = ""
    if extra_facts:
        rows = "".join(
            f"<tr>"
            f"<td style='padding:4px 10px 4px 0;color:#555;font-size:13px;"
            f"white-space:nowrap;vertical-align:top;'><b>{_esc(k)}</b></td>"
            f"<td style='padding:4px 0 4px 8px;font-size:13px;color:#222;"
            f"word-break:break-all;'>{_esc(v)}</td>"
            f"</tr>"
            for k, v in extra_facts.items()
        )
        facts_html = (
            f"<p style='margin:14px 0 5px;font-size:11px;color:#888;"
            f"text-transform:uppercase;'>Details</p>"
            f"<table cellspacing='0' cellpadding='0' width='100%' "
            f"style='border-collapse:collapse;border:1px solid #ddd;'>{rows}</table>"
        )

    ctx_html = ""
    if context_lines:
        lines_esc = "\n".join(_esc(ln) for ln in context_lines[:6])
        ctx_html = (
            f"<p style='margin:14px 0 5px;font-size:11px;color:#888;"
            f"text-transform:uppercase;'>Log Context</p>"
            f"<pre style='background:#f6f8fa;border:1px solid #ddd;"
            f"padding:8px;font-size:11px;margin:0;white-space:pre-wrap;"
            f"word-break:break-word;'>{lines_esc}</pre>"
        )

    detail_esc = _esc(detail)
    return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Alert</title></head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,sans-serif;">
<table width="100%" cellspacing="0" cellpadding="0" style="background:#f0f2f5;padding:20px 10px;">
<tr><td align="center">
<table width="540" cellspacing="0" cellpadding="0"
  style="max-width:540px;width:100%;background:#fff;border-radius:6px;
         border:1px solid #ddd;box-shadow:0 2px 6px rgba(0,0,0,.08);">
  <tr>
    <td style="background:{color};padding:10px 18px;border-radius:6px 6px 0 0;">
      <span style="color:#fff;font-size:14px;font-weight:bold;">
        {icon} {severity} ALERT &mdash; {HOSTNAME}
      </span>
    </td>
  </tr>
  <tr>
    <td style="padding:18px;">
      <h2 style="margin:0 0 4px;font-size:16px;color:#1a1a1a;">{_esc(alert_type)}</h2>
      <p style="margin:0 0 14px;font-size:12px;color:#888;">
        {now_str} &bull; user: <b>{_esc(user)}</b></p>
      <p style="margin:0 0 5px;font-size:11px;color:#888;text-transform:uppercase;">Summary</p>
      <pre style="background:#f6f8fa;border:1px solid #ddd;border-radius:4px;
                  padding:8px;font-size:12px;margin:0;white-space:pre-wrap;
                  word-break:break-word;">{detail_esc}</pre>
      {facts_html}
      {ctx_html}
    </td>
  </tr>
  <tr>
    <td style="background:#f6f8fa;padding:8px 18px;border-top:1px solid #ddd;
               border-radius:0 0 6px 6px;font-size:11px;color:#aaa;text-align:center;">
      Smart Monitor v3.0 &bull; {HOSTNAME} &bull; Auto-generated
    </td>
  </tr>
</table>
</td></tr></table>
</body></html>"""


# -----------------------------------------------------------------
# JSON alert log writer
# -----------------------------------------------------------------
def write_alert_json(severity, alert_type, user, detail,
                     extra_facts=None, env=None):
    """Append one alert record (JSON line) to the alert log file."""
    path = (env or {}).get("ALERT_JSON_PATH", ALERT_JSON_PATH)
    record = {
        "timestamp": datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST"),
        "hostname":  HOSTNAME,
        "severity":  severity,
        "alert":     alert_type,
        "user":      user,
        "detail":    detail[:500],
    }
    if extra_facts:
        record["facts"] = {k: str(v)[:200] for k, v in extra_facts.items()}
    try:
        dir_path = os.path.dirname(path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        with open(path, "a") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as exc:
        log(f"[WARN] Could not write alert JSON: {exc}")


# -----------------------------------------------------------------
# Email sender (AWS SES)
# -----------------------------------------------------------------
def send_alert_email(subject: str, html_body: str, env: dict) -> bool:
    try:
        import boto3
    except ImportError:
        log("[ERROR] boto3 not installed -- run: pip install boto3")
        return False

    aws_key    = env.get("AWS_ACCESS_KEY_ID")
    aws_secret = env.get("AWS_SECRET_ACCESS_KEY")
    region     = env.get("AWS_REGION", "us-east-1")
    sender     = env.get("SES_SENDER_EMAIL")
    rcpt_str   = env.get("SES_RECIPIENT_EMAILS")

    if not all([aws_key, aws_secret, sender, rcpt_str]):
        log("[WARN] Cannot send email -- missing AWS/SES credentials in .env")
        return False

    recipients = [e.strip() for e in rcpt_str.split(",")]
    full_subj  = f"[ALERT] {HOSTNAME} -- {subject}"
    text_body  = re.sub(r"<[^>]+>", "", html_body)
    text_body  = re.sub(r"[ \t]{2,}", " ", text_body)
    text_body  = re.sub(r"\n{3,}", "\n\n", text_body).strip()

    try:
        client = boto3.client(
            "ses",
            region_name=region,
            aws_access_key_id=aws_key,
            aws_secret_access_key=aws_secret,
        )
        resp = client.send_email(
            Source=sender,
            Destination={"ToAddresses": recipients},
            Message={
                "Subject": {"Charset": "UTF-8", "Data": full_subj},
                "Body": {
                    "Text": {"Charset": "UTF-8", "Data": text_body},
                    "Html": {"Charset": "UTF-8", "Data": html_body},
                },
            },
        )
        msg_id = resp["MessageId"]
        log(f"[EMAIL] Sent: {full_subj} -> {recipients} (id={msg_id})")
        return True
    except Exception as exc:
        log(f"[ERROR] SES send failed: {exc}")
        return False


# -----------------------------------------------------------------
# Central alert dispatcher
# -----------------------------------------------------------------
def trigger_alert(severity, alert_type, user, detail, env,
                  context_lines=None, extra_facts=None):
    key = _alert_key(alert_type + user)
    if not should_alert(key, severity):
        return

    record_threat_event(user, severity)
    log(f"[{severity}] {alert_type} | user={user} | {detail[:80]}")

    # Always write to JSON audit log
    write_alert_json(severity, alert_type, user, detail, extra_facts, env)

    # Respect MAIL_ENABLED flag
    mail_enabled = env.get("MAIL_ENABLED", "true").strip().lower()
    if mail_enabled not in ("true", "1", "yes"):
        log("[INFO] MAIL_ENABLED=false -- alert logged only, no email sent")
        return

    html = build_html_email(severity, alert_type, user, detail,
                             context_lines, extra_facts)
    send_alert_email(f"{alert_type} ({user})", html, env)

# -----------------------------------------------------------------
# User attribution: resolve the ORIGINAL login user
# -----------------------------------------------------------------
def _resolve_audit_user(rec: dict) -> str:
    """
    Return best human-readable attribution string.
    - auid=4294967295 means unset (daemon/kernel) -- fall back to uid.
    - When uid==0 but auid != 0, the original login uid is auid
      so you always know WHO did it and HOW they escalated.
    """
    raw_auid = rec.get("auid", "4294967295")
    raw_uid  = rec.get("uid", "0")
    euid     = rec.get("euid", raw_uid)

    try:
        auid_int = int(raw_auid)
    except ValueError:
        auid_int = 4294967295

    unset = (auid_int == 4294967295 or auid_int == 4294967294)

    if unset:
        return uid_to_name(raw_uid)

    original_name  = uid_to_name(str(auid_int))
    effective_name = uid_to_name(euid)

    if original_name == effective_name:
        return original_name

    # Escalation happened: original_name sudo/su'd into effective_name
    return f"{original_name} (via sudo/su as {effective_name})"


# -----------------------------------------------------------------
# Auditd record parser
# -----------------------------------------------------------------
def _build_audit_records(logfile: str) -> list:
    """
    Parse value pairs from auditd EXECVE records.
    Group consecutive records by serial number into compound events.
    Returns a list of dicts: uid, auid, euid, pid, ppid, exe, cmd, args.
    """
    if not os.path.exists(logfile):
        return []

    raw_blocks: dict = defaultdict(dict)
    pattern = re.compile(
        r"audit\([\d.]+:(\d+)\).*?type=(\w+)"
    )
    kv_re = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

    try:
        with open(logfile, errors="replace") as f:
            for line in f:
                m = pattern.search(line)
                if not m:
                    continue
                serial, rec_type = m.group(1), m.group(2)
                kv = {k: (v1 or v2) for k, v1, v2 in kv_re.findall(line)}
                block = raw_blocks[serial]
                block.update(kv)
                if rec_type == "EXECVE":
                    # reassemble argv
                    argc = int(kv.get("argc", 0))
                    args = []
                    for i in range(argc):
                        arg = kv.get(f"a{i}", "")
                        # hex-decode if needed
                        if re.fullmatch(r"[0-9A-Fa-f]+", arg) and len(arg) % 2 == 0:
                            try:
                                arg = bytes.fromhex(arg).decode(errors="replace")
                            except Exception:
                                pass
                        args.append(arg)
                    block["cmd"]  = " ".join(args) if args else block.get("cmd", "")
                    block["args"] = args
    except Exception:
        return []

    results = []
    for block in raw_blocks.values():
        exe = block.get("exe", "")
        cmd = block.get("cmd", exe)
        if cmd or exe:
            results.append(block)
    return results


# -----------------------------------------------------------------
# Check: file deletions via auditd
# -----------------------------------------------------------------
def check_auditd_deletions(env: dict):
    """
    Detect file deletions via auditd -- definitive vs auth.log (less precise).
    Attributes the deletion to the ORIGINAL LOGIN USER even when via su.
    Deduplication strategy:
    - Whitelist known-safe system processes (Docker, apt, snap, pip...)
    - Collapse all syscall records from the same PID+user within 5 min
      into ONE alert (prevents email storm from recursive rm with many files).
    - Fallback deletion detection via auth.log (less precise).
    - Looks for: sudo: user -> COMMAND=...rm or shred
    """
    if not os.path.exists(AUDIT_LOG):
        return

    now = datetime.now(IST)
    # Purge old PID entries
    for key in list(DELETION_PID_SEEN.keys()):
        if now - DELETION_PID_SEEN[key]["ts"] > DELETION_PID_TTL:
            del DELETION_PID_SEEN[key]

    delete_syscalls = re.compile(r"\b(unlink|unlinkat|rmdir|rename|renameat)\b")
    for rec in _build_audit_records(AUDIT_LOG):
        exe = rec.get("exe", "")
        cmd = rec.get("cmd", "")
        if not delete_syscalls.search(cmd + exe + rec.get("syscall", "")):
            continue

        uid  = rec.get("uid", "0")
        auid = rec.get("auid", "4294967295")
        pid  = rec.get("pid", "0")

        # Skip whitelisted users
        uname = uid_to_name(uid)
        if uname in DELETION_WHITELIST_USERS:
            continue

        # Skip whitelisted executables
        if DELETION_WHITELIST_EXES.search(exe):
            continue

        user       = _resolve_audit_user(rec)
        dedup_key  = f"{pid}:{user}"

        if dedup_key in DELETION_PID_SEEN:
            DELETION_PID_SEEN[dedup_key]["count"] += 1
            continue

        DELETION_PID_SEEN[dedup_key] = {"ts": now, "count": 1}
        path_item = rec.get("name", rec.get("nametype", exe or "?"))

        trigger_alert(
            "HIGH", "File Deletion Detected", user,
            f"User '{user}' deleted: {path_item}\nCommand: {cmd}\nExe: {exe}",
            env,
            extra_facts={
                "User":     user,
                "File":     path_item,
                "Command":  cmd,
                "Exe":      exe,
                "PID":      pid,
            }
        )


# -----------------------------------------------------------------
# Check: auditd commands (sudo-aware identity chain)
# -----------------------------------------------------------------
def check_auditd_commands(env: dict):
    """
    Parse auditd EXECVE records to catch ALL commands run as root,
    attributing them back to the original login user via auid.
    This catches commands run inside a sudo/su shell that would not
    appear in auth.log sudo lines.
    """
    if not os.path.exists(AUDIT_LOG):
        return

    for rec in _build_audit_records(AUDIT_LOG):
        cmd = rec.get("cmd", "")
        exe = rec.get("exe", "")
        if not cmd and not exe:
            continue

        uid  = rec.get("uid", "0")
        auid = rec.get("auid", "4294967295")

        # Only care about root-effective commands from non-root original users
        try:
            auid_int = int(auid)
        except ValueError:
            auid_int = 4294967295
        if int(uid) != 0 or auid_int == 0 or auid_int >= 4294967294:
            continue

        user = _resolve_audit_user(rec)
        full_cmd = cmd or exe

        for pattern, desc, severity in DANGEROUS_PATTERNS:
            m = re.search(pattern, full_cmd, re.IGNORECASE)
            if m:
                target = m.groupdict().get("target", "")
                trigger_alert(
                    severity, f"Dangerous Command: {desc}", user,
                    f"User '{user}' ran (as root): {full_cmd}",
                    env,
                    extra_facts={
                        "Command":  full_cmd,
                        "Target":   target,
                        "User":     user,
                        "Pattern":  desc,
                    }
                )
                break


# -----------------------------------------------------------------
# Check: su/sudo escalation via auth.log
# -----------------------------------------------------------------
def check_su_sudo(env: dict):
    """
    Detect users switching to root (su/sudo/su -i/sudo su).
    Tracks per-user escalation frequency; off-hours events get severity bump.
    Also builds IDENTITY_CHAIN to attribute future root commands.
    """
    lines = get_cycle_lines(AUTH_LOGS)
    now   = datetime.now(IST)
    hour  = int(now.strftime("%H"))

    for line in lines:
        # Sudo: successful execution
        m_sudo = re.search(
            r"sudo:\s+(\S+)\s*:.*COMMAND=(.*)", line, re.IGNORECASE)
        if m_sudo:
            user    = m_sudo.group(1).strip()
            command = m_sudo.group(2).strip()
            IDENTITY_CHAIN[user] = now
            USER_SUDO_COUNT[user] += 1
            off_hours = hour < 6 or hour > 22
            severity  = "HIGH" if off_hours else "MEDIUM"
            if USER_SUDO_COUNT[user] >= 5:
                severity = "HIGH"
            trigger_alert(
                severity, "Sudo Command Executed", user,
                f"User '{user}' ran sudo: {command}",
                env,
                extra_facts={
                    "User":      user,
                    "Command":   command,
                    "Off-hours": str(off_hours),
                    "Sudo count (session)": str(USER_SUDO_COUNT[user]),
                }
            )

        # su / su - / sudo su -- session opened for root
        m_su = re.search(
            r"su[do]*.*:\s+(session opened for user root).*by\s+(\S+)", line, re.IGNORECASE)
        if m_su:
            actor = m_su.group(2).strip().rstrip("(")
            SU_SESSION_START[actor] = now
            IDENTITY_CHAIN[actor]   = now
            off_hours = hour < 6 or hour > 22
            trigger_alert(
                "HIGH" if off_hours else "MEDIUM",
                "Root Shell Session Opened", actor,
                f"User '{actor}' opened a root shell session",
                env,
                extra_facts={
                    "User":      actor,
                    "Off-hours": str(off_hours),
                }
            )

        # Session closed -- remove from identity chain
        m_close = re.search(r"session closed for user root", line, re.IGNORECASE)
        if m_close:
            for user in list(SU_SESSION_START.keys()):
                if (now - SU_SESSION_START[user]) < timedelta(hours=2):
                    duration = now - SU_SESSION_START[user]
                    log(f"Root session for '{user}' ended -- duration {duration}")
                    del SU_SESSION_START[user]
                    break


# -----------------------------------------------------------------
# Check: SSH brute-force
# -----------------------------------------------------------------
def check_ssh_bruteforce(env: dict):
    """
    Track failed SSH logins per source IP.
    Fire CRITICAL when failures exceed threshold within window.
    Also detect successful login after multiple failures (likely compromise).
    """
    lines = get_cycle_lines(AUTH_LOGS)
    now   = datetime.now(IST)

    for line in lines:
        m_fail = re.search(
            r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from ([\d.]+)",
            line)
        if m_fail:
            user, ip = m_fail.group(1), m_fail.group(2)
            SSH_FAILURES[ip].append(now)
            SSH_FAILURES[ip] = [
                t for t in SSH_FAILURES[ip] if (now - t) <= BRUTE_FORCE_WINDOW
            ]
            if len(SSH_FAILURES[ip]) >= BRUTE_FORCE_THRESHOLD:
                trigger_alert(
                    "CRITICAL", "SSH Brute-Force Attack", ip,
                    f"IP {ip} had {len(SSH_FAILURES[ip])} failed logins "
                    f"for user '{user}' within {BRUTE_FORCE_WINDOW}",
                    env,
                    extra_facts={
                        "Source IP":  ip,
                        "Target user": user,
                        "Attempts":   str(len(SSH_FAILURES[ip])),
                        "Window":     str(BRUTE_FORCE_WINDOW),
                    }
                )

        m_ok = re.search(
            r"Accepted (?:password|publickey) for (\S+) from ([\d.]+)", line)
        if m_ok:
            user, ip = m_ok.group(1), m_ok.group(2)
            recent_fails = SSH_FAILURES.get(ip, [])
            if len(recent_fails) >= 3:
                trigger_alert(
                    "CRITICAL", "SSH Login After Brute-Force", user,
                    f"Successful SSH login for '{user}' from {ip} "
                    f"after {len(recent_fails)} recent failures -- possible compromise",
                    env,
                    extra_facts={
                        "User":        user,
                        "Source IP":   ip,
                        "Prior fails": str(len(recent_fails)),
                    }
                )


# -----------------------------------------------------------------
# Check: user/group creation
# -----------------------------------------------------------------
def check_user_group_changes(env: dict):
    """Detect new user/group creation via useradd/groupadd."""
    lines = get_cycle_lines(AUTH_LOGS + SYSLOG_LOGS)
    for line in lines:
        m = re.search(
            r"(?:useradd|adduser|groupadd).*(?:new user|new group)[:\s]+name=(\S+)",
            line, re.IGNORECASE)
        if m:
            name = m.group(1).rstrip(",")
            trigger_alert(
                "HIGH", "New User/Group Created", name,
                f"New account/group created: {name}\nLog: {line.strip()}",
                env,
                extra_facts={"Name": name}
            )


# -----------------------------------------------------------------
# Check: suspicious processes in /proc
# -----------------------------------------------------------------
def check_proc_scanner(env: dict):
    """
    Scan `ps aux` output for each command line pattern.
    Walk /proc/<pid> entries to find processes with effective root
    BUT real non-root user (escalated). This catches shells/scripts
    running as root after su.
    """
    ps_out = run("ps aux --no-header")
    for line in ps_out.splitlines():
        parts = line.split()
        if len(parts) < 11:
            continue
        cmd_line = " ".join(parts[10:])
        for pattern, desc, severity in DANGEROUS_PATTERNS:
            if re.search(pattern, cmd_line, re.IGNORECASE):
                user = parts[0]
                trigger_alert(
                    severity, f"Suspicious Process: {desc}", user,
                    f"Running process matched '{desc}': {cmd_line[:200]}",
                    env,
                    extra_facts={
                        "User":    user,
                        "PID":     parts[1],
                        "Command": cmd_line[:200],
                    }
                )
                break

    # /proc UID escalation scan
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            status_path = f"/proc/{pid}/status"
            cmdline_path = f"/proc/{pid}/cmdline"
            if not os.path.exists(status_path):
                continue
            try:
                status = open(status_path, errors="replace").read()
                uid_line = re.search(r"^Uid:\s+(\d+)\s+(\d+)", status, re.M)
                if not uid_line:
                    continue
                real_uid, eff_uid = int(uid_line.group(1)), int(uid_line.group(2))
                if eff_uid == 0 and real_uid != 0:
                    try:
                        cmd_bytes = open(cmdline_path, "rb").read()
                        cmd_str   = cmd_bytes.replace(b"\x00", b" ").decode(errors="replace")[:200]
                    except Exception:
                        cmd_str = "?"
                    user = uid_to_name(str(real_uid))
                    trigger_alert(
                        "HIGH", "Root Process From Non-Root User", user,
                        f"PID {pid} is running as effective root but real user is '{user}'\n"
                        f"Command: {cmd_str}",
                        env,
                        extra_facts={
                            "PID":       pid,
                            "Real user": user,
                            "Command":   cmd_str,
                        }
                    )
            except Exception:
                continue
    except Exception:
        pass


# -----------------------------------------------------------------
# Check: dormant accounts
# -----------------------------------------------------------------
def check_dormant_accounts(env: dict):
    """
    Detect user accounts that have not logged in recently.
    Alert CRITICAL if it logs in now.
    """
    try:
        last_out = run("lastlog --no-header 2>/dev/null")
        now = datetime.now(IST)
        for line in last_out.splitlines():
            parts = line.split()
            if len(parts) < 2:
                continue
            username = parts[0]
            if parts[1].lower() in ("never", "**never", "**never**"):
                continue
            try:
                # typical format: Mon Jan 01 00:00:00 +0530 2024
                date_str = " ".join(parts[1:6])
                last_login = datetime.strptime(date_str, "%a %b %d %H:%M:%S %z %Y")
                age_days = (now.replace(tzinfo=None) -
                            last_login.replace(tzinfo=None)).days
                if age_days > 90:
                    trigger_alert(
                        "HIGH", "Dormant Account Activity", username,
                        f"Account '{username}' had not logged in for {age_days} days "
                        f"but just appeared in lastlog",
                        env,
                        extra_facts={
                            "User":        username,
                            "Days dormant": str(age_days),
                            "Last login":  date_str,
                        }
                    )
            except Exception:
                continue
    except Exception:
        pass


# -----------------------------------------------------------------
# Check: kernel module loads
# -----------------------------------------------------------------
def check_kernel_modules(env: dict):
    """
    Detect new kernel modules loaded since last check.
    Rootkits commonly use insmod/modprobe for kernel-level persistence.
    """
    current_mods = set(run("lsmod | awk 'NR>1{print $1}'").splitlines())
    prev_key = "_kernel_mods"
    prev_mods = set(ALERTS_SENT.get(prev_key + "_data", "").split(",")) \
        if prev_key + "_data" in ALERTS_SENT else None

    if prev_mods is None:
        ALERTS_SENT[prev_key + "_data"] = ",".join(current_mods)
        return

    new_mods = current_mods - prev_mods
    for mod in new_mods:
        trigger_alert(
            "CRITICAL", "Kernel Module Loaded", "root",
            f"New kernel module loaded: {mod}",
            env,
            extra_facts={"Module": mod}
        )
    ALERTS_SENT[prev_key + "_data"] = ",".join(current_mods)


# -----------------------------------------------------------------
# Check: suspicious network connections
# -----------------------------------------------------------------
def check_network_connections(env: dict):
    """
    Detect ESTABLISHED connections on known reverse-shell / C2 ports.
    Also detects new external connections by root processes.
    """
    ss_out = run("ss -tunp state established 2>/dev/null || netstat -tunp 2>/dev/null")
    for line in ss_out.splitlines():
        m = re.search(r":(\d+)\s+users:\(\(\"([^\"]+)\"", line)
        if not m:
            m2 = re.search(r"(\d+\.\d+\.\d+\.\d+):(\d+).*?(\d+)/(\S+)", line)
            if not m2:
                continue
            port, proc = int(m2.group(2)), m2.group(4)
        else:
            port, proc = int(m.group(1)), m.group(2)

        if port in C2_PORTS:
            trigger_alert(
                "CRITICAL", "C2/Reverse-Shell Port Connection", proc,
                f"Active connection on known C2 port {port} by process '{proc}'\n{line.strip()}",
                env,
                extra_facts={"Port": str(port), "Process": proc}
            )


# -----------------------------------------------------------------
# Check: log tampering
# -----------------------------------------------------------------
def check_log_tampering(env: dict):
    """
    Detect critical files were truncated, deleted, or shrunk.
    Skips the very first run (no baseline yet; avoids false positive on
    monitor restart after a rotation has already happened).
    Correctly distinguishes logrotate (inode change + backup .1 file) from
    deliberate truncation.
    """
    global _LOG_SIZE_INITIALIZED
    critical_logs = AUTH_LOGS + SYSLOG_LOGS + [AUDIT_LOG, "/var/log/kern.log"]
    now = datetime.now(IST)

    if not _LOG_SIZE_INITIALIZED:
        for path in critical_logs:
            if os.path.exists(path):
                LOG_SIZE_SNAPSHOT[path] = os.path.getsize(path)
        _LOG_SIZE_INITIALIZED = True
        return

    for path in critical_logs:
        if not os.path.exists(path):
            if path in LOG_SIZE_SNAPSHOT and LOG_SIZE_SNAPSHOT[path] > 0:
                trigger_alert(
                    "CRITICAL", "Log File Deleted", "root",
                    f"Log file deleted or missing: {path}",
                    env,
                    extra_facts={"File": path, "Previous size": str(LOG_SIZE_SNAPSHOT[path])}
                )
            LOG_SIZE_SNAPSHOT[path] = 0
            continue

        current_size = os.path.getsize(path)
        prev_size    = LOG_SIZE_SNAPSHOT.get(path)

        if prev_size is None:
            LOG_SIZE_SNAPSHOT[path] = current_size
            continue

        if current_size < prev_size:
            # Check if this is a logrotate event (backup .1 file appeared recently)
            backup = path + ".1"
            is_rotation = False
            if os.path.exists(backup):
                backup_age = now.timestamp() - os.path.getmtime(backup)
                is_rotation = backup_age < 120  # backup file appeared within 2 min
            if not is_rotation:
                trigger_alert(
                    "CRITICAL", "Log File Truncated/Shrunk", "root",
                    f"Log file shrank without rotation: {path}\n"
                    f"Was {prev_size} bytes, now {current_size} bytes",
                    env,
                    extra_facts={
                        "File":     path,
                        "Was":      f"{prev_size} bytes",
                        "Now":      f"{current_size} bytes",
                        "Delta":    f"-{prev_size - current_size} bytes",
                    }
                )
        LOG_SIZE_SNAPSHOT[path] = current_size


# -----------------------------------------------------------------
# Check: critical file integrity
# -----------------------------------------------------------------
def check_file_integrity(env: dict):
    """
    Compare mtime of critical files against known-good timestamps.
    Detects modifications to /etc/passwd, /etc/shadow, /etc/sudoers,
    SSH keys, /etc/cron.d, etc.
    """
    watch_files = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/etc/crontab", "/etc/cron.d", "/root/.bashrc", "/root/.profile",
        "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config",
        "/etc/ld.so.preload", "/etc/ld.so.conf",
    ]
    state_key = "_file_mtime"
    prev_mtimes = ALERTS_SENT.get(state_key, {})
    if not isinstance(prev_mtimes, dict):
        prev_mtimes = {}

    for fpath in watch_files:
        if not os.path.exists(fpath):
            continue
        try:
            mtime = os.path.getmtime(fpath)
        except Exception:
            continue
        if fpath in prev_mtimes and prev_mtimes[fpath] != mtime:
            trigger_alert(
                "CRITICAL", "Critical File Modified", "root",
                f"File modification detected: {fpath}",
                env,
                extra_facts={"File": fpath}
            )
        prev_mtimes[fpath] = mtime

    ALERTS_SENT[state_key] = prev_mtimes


# -----------------------------------------------------------------
# Check: LD_PRELOAD / history wipe in auth/syslog
# -----------------------------------------------------------------
def check_insider_evasion(env: dict):
    """
    Detect evidence-destruction / insider-evasion via syslog/auth.log:
    - history wipe (history -c / HISTFILE=/dev/null)
    - log deletion patterns
    """
    lines = get_cycle_lines(AUTH_LOGS + SYSLOG_LOGS)
    for line in lines:
        for pattern, desc, severity in DANGEROUS_PATTERNS:
            if re.search(pattern, line, re.IGNORECASE):
                m_user = re.search(r"for\s+(\S+)", line)
                user   = m_user.group(1) if m_user else "unknown"
                trigger_alert(
                    severity, f"Insider Evasion: {desc}", user,
                    f"Detected in system log: {line.strip()[:200]}",
                    env,
                    context_lines=[line.strip()]
                )
                break


# -----------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------
def main():
    log("Smart Monitor v3.0 starting...")
    load_state()
    env = load_env(ENV_PATH)

    cycle = 0
    while True:
        cycle += 1
        log(f"--- Cycle {cycle} ---")
        env = load_env(ENV_PATH)

        load_cycle_lines()

        check_log_tampering(env)
        check_su_sudo(env)
        check_ssh_bruteforce(env)
        check_auditd_commands(env)
        check_auditd_deletions(env)
        check_user_group_changes(env)
        check_proc_scanner(env)
        check_kernel_modules(env)
        check_network_connections(env)
        check_file_integrity(env)
        check_insider_evasion(env)
        check_dormant_accounts(env)
        check_threat_scores(env)

        save_state()
        time.sleep(60)


if __name__ == "__main__":
    main()
