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

# HOSTNAME is loaded from .env (SERVER_NAME key) so every alert and email
# clearly shows which server it came from. Falls back to socket.gethostname()
# only if SERVER_NAME is not set in .env.
_AUTO_HOSTNAME = socket.gethostname()
HOSTNAME = _AUTO_HOSTNAME   # overwritten at startup and each cycle from env

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
SSH_KNOWN_IPS:      dict = defaultdict(set)   # user -> set of seen source IPs
SSH_SUDO_FAILURES:  dict = defaultdict(list)   # user -> list of failure timestamps
USER_ROOT_SESSIONS: dict = defaultdict(list)
USER_SUDO_COUNT:    dict = defaultdict(int)
IDENTITY_CHAIN:     dict = {}   # user -> datetime of last escalation (to root)
SU_SESSION_START:   dict = {}   # user -> datetime root shell opened
# user -> user they su'd into (non-root lateral movement tracking)
LATERAL_SU_CHAIN:   dict = {}   # actor -> (target_user, datetime)
THREAT_SCORE_LOG:   dict = defaultdict(list)
DELETION_EVENTS:    list = []
LOG_SIZE_SNAPSHOT:  dict = {}
_FILE_INODES:       dict = {}
_LOG_SIZE_INITIALIZED: bool = False
C2_SEEN_CONNECTIONS: dict = {}  # conn_key -> first_seen datetime
DORMANT_ALERTED:    set  = set()  # accounts already alerted this run

# Patterns ONLY for insider evasion / anti-forensic detection.
# Dangerous commands (rm -rf, reverse shells, etc.) are caught by
# check_auditd_commands which has better attribution via auditd.
EVASION_PATTERNS = [
    (r"history\s+-[cw]|unset\s+HISTFILE|HISTSIZE=0",
     "Command history wiped/disabled",                 "HIGH"),
    (r"export\s+HISTFILE=/dev/null",
     "Bash history redirected to /dev/null",            "HIGH"),
    (r">\s*/var/log/(?:auth|syslog|secure|audit)",
     "Log file wiped with shell redirect",              "CRITICAL"),
    (r"truncate\s+.*(?P<target>/var/log/\S*)",
     "Log file truncated via truncate command",         "CRITICAL"),
    (r"shred\s+.*(?P<target>/(?:etc|var|root)\S*)",
     "Secure shred of critical system path",            "CRITICAL"),
    (r"LD_PRELOAD\s*=",
     "LD_PRELOAD library injection attempt",            "CRITICAL"),
]


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
    global FILE_OFFSETS, LOG_SIZE_SNAPSHOT, IDENTITY_CHAIN, SU_SESSION_START, LATERAL_SU_CHAIN, DORMANT_ALERTED
    if os.path.exists(STATE_PATH):
        try:
            with open(STATE_PATH) as f:
                data = json.load(f)
                FILE_OFFSETS      = data.get("offsets", {})
                LOG_SIZE_SNAPSHOT = data.get("log_sizes", {})
                # Restore escalation chain (stored as ISO strings)
                for user, ts_str in data.get("identity_chain", {}).items():
                    try:
                        IDENTITY_CHAIN[user] = datetime.fromisoformat(ts_str)
                    except Exception:
                        pass
                for user, ts_str in data.get("su_sessions", {}).items():
                    try:
                        SU_SESSION_START[user] = datetime.fromisoformat(ts_str)
                    except Exception:
                        pass
                # Restore lateral su chain
                for actor, entry in data.get("lateral_su_chain", {}).items():
                    try:
                        LATERAL_SU_CHAIN[actor] = (entry["target"], datetime.fromisoformat(entry["ts"]))
                    except Exception:
                        pass
                # Restore dormant-alerted set so restarts don't re-spam
                DORMANT_ALERTED = set(data.get("dormant_alerted", []))
        except Exception:
            pass


def save_state():
    try:
        os.makedirs(os.path.dirname(STATE_PATH), exist_ok=True)
        with open(STATE_PATH, "w") as f:
            json.dump({
                "offsets":        FILE_OFFSETS,
                "log_sizes":      LOG_SIZE_SNAPSHOT,
                # Persist escalation chain so attribution survives restarts
                "identity_chain": {
                    u: ts.isoformat() for u, ts in IDENTITY_CHAIN.items()
                },
                "su_sessions":    {
                    u: ts.isoformat() for u, ts in SU_SESSION_START.items()
                },
                # Persist lateral su chain (user1 -> su -> user2)
                "lateral_su_chain": {
                    actor: {"target": target, "ts": ts.isoformat()}
                    for actor, (target, ts) in LATERAL_SU_CHAIN.items()
                },
                # Persist dormant-alerted so restarts don't re-spam
                "dormant_alerted": list(DORMANT_ALERTED),
            }, f, indent=2)
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
    """Read new lines from all monitored log files including audit.log."""
    CYCLE_LINES.clear()
    all_logs = list(set(AUTH_LOGS + SYSLOG_LOGS + [AUDIT_LOG]))
    for logfile in all_logs:
        CYCLE_LINES[logfile] = read_new_lines(logfile)


def get_cycle_lines(logfiles: list) -> list:
    result = []
    for lf in logfiles:
        result.extend(CYCLE_LINES.get(lf, []))
    return result


def _alert_key(category: str, detail: str = "") -> str:
    """
    Build a dedup key for should_alert().
    Including 'detail' means different targets/files by the same user
    get distinct keys — e.g. deleting file A and file B are two separate
    alert buckets, not one.  Callers pass the target/resource as detail.
    """
    return hashlib.sha1((category + detail).encode()).hexdigest()[:16]


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
    """Evaluate accumulated threat scores; write to JSON audit log when threshold crossed."""
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
        prev_str  = f" (was {last[1]:.0f})" if last else ""
        hour      = int(now.strftime("%H"))
        off_hours = hour < 6 or hour > 22
        detail = (
            f"User '{user}' has accumulated a threat score of {score:.0f}{prev_str}. "
            f"This means multiple suspicious events were detected for this user in a "
            f"short period. Off-hours activity: {off_hours}."
        )
        log(f"[THREAT SCORE] {detail}")
        # Write to JSON audit trail so threat score breaches are visible in the log
        write_alert_json(
            severity, "Accumulated Threat Score Breach", user,
            detail,
            env=env,
            email_status="log_only",
            extra_facts={
                "Threat score":   f"{score:.0f}",
                "Previous score": f"{last[1]:.0f}" if last else "0",
                "Threshold":      str(THREAT_ALERT_THRESHOLD),
                "Off-hours":      "Yes — outside business hours" if off_hours else "No",
                "Note":           "Score decays over time; sustained suspicious activity raises it",
            }
        )

# -----------------------------------------------------------------
# Lightweight HTML email builder (light theme, inbox-friendly)
# -----------------------------------------------------------------
_SEV_COLOR = {
    "CRITICAL": "#c0392b",
    "HIGH":     "#d35400",
    "MEDIUM":   "#d4a017",
    "LOW":      "#2471a3",
}
_SEV_BG = {
    "CRITICAL": "#fdf2f2",
    "HIGH":     "#fdf6f0",
    "MEDIUM":   "#fefdf0",
    "LOW":      "#f0f6fd",
}
_SEV_BADGE = {
    "CRITICAL": "background:#c0392b;color:#fff;",
    "HIGH":     "background:#d35400;color:#fff;",
    "MEDIUM":   "background:#d4a017;color:#fff;",
    "LOW":      "background:#2471a3;color:#fff;",
}
_SEV_NEXT_STEP = {
    "CRITICAL": (
        "Investigate immediately. SSH to the server and check running processes, "
        "open connections, and recent auth.log entries. If the event is confirmed "
        "malicious, consider isolating the server from the network."
    ),
    "HIGH": (
        "Review within the next hour. Log into the server and verify whether the "
        "activity was authorised. Check who was logged in at the time and what "
        "else they did around the same timestamp."
    ),
    "MEDIUM": (
        "Review at your earliest convenience. Confirm whether this activity was "
        "expected. If not, escalate to HIGH and investigate the user's recent "
        "session history."
    ),
    "LOW": (
        "No immediate action required. This event has been logged for your "
        "records and contributes to the user's threat score."
    ),
}


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def build_html_email(severity, alert_type, user, detail,
                     context_lines=None, extra_facts=None) -> str:
    color      = _SEV_COLOR.get(severity, "#7f8c8d")
    badge_css  = _SEV_BADGE.get(severity, "background:#7f8c8d;color:#fff;")
    body_bg    = _SEV_BG.get(severity, "#f9f9f9")
    next_step  = _SEV_NEXT_STEP.get(severity, "")
    now_str    = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

    # ── Severity badge (pill shape) ──────────────────────────────────
    badge_html = (
        f"<span style='{badge_css}padding:3px 10px;border-radius:12px;"
        f"font-size:11px;font-weight:bold;letter-spacing:0.5px;"
        f"text-transform:uppercase;'>{_esc(severity)}</span>"
    )

    # ── Details table (zebra rows, only show real data) ──────────────
    facts_html = ""
    if extra_facts:
        rows = ""
        for i, (k, v) in enumerate(extra_facts.items()):
            row_bg = "#f8f8f8" if i % 2 == 0 else "#ffffff"
            rows += (
                f"<tr style='background:{row_bg};'>"
                f"<td style='padding:6px 12px 6px 0;color:#555;font-size:13px;"
                f"white-space:nowrap;vertical-align:top;width:1%;'>"
                f"<b>{_esc(k)}</b></td>"
                f"<td style='padding:6px 0 6px 12px;font-size:13px;color:#222;"
                f"word-break:break-all;border-left:2px solid #ececec;padding-left:12px;'>"
                f"{_esc(v)}</td>"
                f"</tr>"
            )
        facts_html = (
            f"<p style='margin:18px 0 6px;font-size:10px;font-weight:bold;"
            f"color:#999;text-transform:uppercase;letter-spacing:0.8px;'>Details</p>"
            f"<table cellspacing='0' cellpadding='0' width='100%' "
            f"style='border-collapse:collapse;border:1px solid #e8e8e8;"
            f"border-radius:4px;overflow:hidden;'>{rows}</table>"
        )

    # ── Log context block ────────────────────────────────────────────
    ctx_html = ""
    if context_lines:
        lines_esc = "\n".join(_esc(ln) for ln in context_lines[:6])
        ctx_html = (
            f"<p style='margin:18px 0 6px;font-size:10px;font-weight:bold;"
            f"color:#999;text-transform:uppercase;letter-spacing:0.8px;'>Log Context</p>"
            f"<pre style='background:#1e1e1e;color:#d4d4d4;border-radius:4px;"
            f"padding:10px 12px;font-size:11px;margin:0;white-space:pre-wrap;"
            f"word-break:break-word;font-family:\"Courier New\",monospace;'>"
            f"{lines_esc}</pre>"
        )

    # ── Next-step guidance ───────────────────────────────────────────
    next_step_html = ""
    if next_step:
        next_step_html = (
            f"<div style='margin-top:18px;padding:10px 14px;"
            f"background:#f0f7ff;border-left:3px solid {color};"
            f"border-radius:0 4px 4px 0;'>"
            f"<p style='margin:0 0 3px;font-size:10px;font-weight:bold;"
            f"color:{color};text-transform:uppercase;letter-spacing:0.8px;'>"
            f"Suggested action</p>"
            f"<p style='margin:0;font-size:12px;color:#333;line-height:1.5;'>"
            f"{_esc(next_step)}</p>"
            f"</div>"
        )

    detail_esc = _esc(detail)

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Alert — {_esc(severity)}</title>
</head>
<body style="margin:0;padding:0;background:#f0f2f5;font-family:Arial,Helvetica,sans-serif;">
<table width="100%" cellspacing="0" cellpadding="0"
       style="background:#f0f2f5;padding:24px 12px;">
<tr><td align="center">

<!-- Card -->
<table width="560" cellspacing="0" cellpadding="0"
       style="max-width:560px;width:100%;background:#ffffff;border-radius:8px;
              border:1px solid #dde1e7;box-shadow:0 2px 8px rgba(0,0,0,.09);">

  <!-- Colour bar -->
  <tr>
    <td style="background:{color};height:4px;border-radius:8px 8px 0 0;
               font-size:0;line-height:0;">&nbsp;</td>
  </tr>

  <!-- Header -->
  <tr>
    <td style="padding:20px 24px 14px;border-bottom:1px solid #eef0f3;
               background:{body_bg};border-radius:0;">
      <table width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="vertical-align:middle;">
            {badge_html}
            <span style="font-size:11px;color:#888;margin-left:8px;">{_esc(now_str)}</span>
          </td>
          <td align="right" style="vertical-align:middle;">
            <span style="font-size:11px;color:#aaa;">{_esc(HOSTNAME)}</span>
          </td>
        </tr>
        <tr>
          <td colspan="2" style="padding-top:10px;">
            <h1 style="margin:0;font-size:18px;font-weight:bold;
                        color:#1a1a1a;line-height:1.3;">
              {_esc(alert_type)}
            </h1>
            <p style="margin:4px 0 0;font-size:12px;color:#666;">
              Affected user: <b style="color:#333;">{_esc(user)}</b>
            </p>
          </td>
        </tr>
      </table>
    </td>
  </tr>

  <!-- Body -->
  <tr>
    <td style="padding:20px 24px;">

      <!-- Summary -->
      <p style="margin:0 0 6px;font-size:10px;font-weight:bold;
                color:#999;text-transform:uppercase;letter-spacing:0.8px;">What happened</p>
      <div style="background:#f6f8fa;border:1px solid #e1e4e8;border-radius:4px;
                  padding:10px 14px;font-size:13px;color:#24292e;line-height:1.6;
                  white-space:pre-wrap;word-break:break-word;font-family:inherit;">
{detail_esc}
      </div>

      {facts_html}
      {ctx_html}
      {next_step_html}

    </td>
  </tr>

  <!-- Footer -->
  <tr>
    <td style="background:#f6f8fa;padding:10px 24px;
               border-top:1px solid #eef0f3;border-radius:0 0 8px 8px;">
      <table width="100%" cellspacing="0" cellpadding="0">
        <tr>
          <td style="font-size:10px;color:#aaa;">
            Smart Monitor v3.0 &bull; {_esc(HOSTNAME)}
          </td>
          <td align="right" style="font-size:10px;color:#aaa;">
            Full logs: <code style="font-size:10px;">
            sudo tail -f /var/log/smart_monitor.log</code>
          </td>
        </tr>
      </table>
    </td>
  </tr>

</table>
<!-- /Card -->

</td></tr></table>
</body></html>"""


# -----------------------------------------------------------------
# JSON alert log writer  (human-readable format)
# -----------------------------------------------------------------
def write_alert_json(severity, alert_type, user, detail,
                     extra_facts=None, env=None, email_status="unknown",
                     email_recipients=None):
    """
    Append one alert record to the JSON alert log.

    Each record is a self-contained, human-readable JSON object that
    includes:
      - A plain-English 'human_summary' field
      - A 'notification' block describing whether an e-mail was sent
      - All original technical fields for forensic correlation

    Records are separated by a blank line so the file is easy to read
    with a text editor (not just a JSON parser).
    """
    path = (env or {}).get("ALERT_JSON_PATH", ALERT_JSON_PATH)
    now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")

    # ── Plain-English summary ────────────────────────────────────────
    sev_label = {
        "CRITICAL": "CRITICAL  ⛔",
        "HIGH":     "HIGH      ⚠️",
        "MEDIUM":   "MEDIUM    🔶",
        "LOW":      "LOW       ℹ️",
    }.get(severity, severity)

    human_summary = (
        f"{sev_label} security event detected on '{HOSTNAME}'.\n"
        f"  Alert  : {alert_type}\n"
        f"  User   : {user}\n"
        f"  Time   : {now_str}\n"
        f"  Detail : {detail[:300]}"
    )

    # ── Notification block ───────────────────────────────────────────
    notification: dict = {"email_status": email_status}
    if email_recipients:
        notification["email_recipients"] = email_recipients
    if email_status == "disabled":
        notification["note"] = (
            "MAIL_ENABLED is set to false in .env  --  "
            "alert is recorded here only; no email was sent."
        )
    elif email_status == "sent":
        notification["note"] = (
            "Email alert successfully dispatched via AWS SES."
        )
    elif email_status == "skipped_no_credentials":
        notification["note"] = (
            "Email could NOT be sent -- AWS/SES credentials are "
            "missing or incomplete in .env."
        )
    elif email_status == "send_failed":
        notification["note"] = (
            "Email send attempted but AWS SES returned an error. "
            "Check smart_monitor.log for details."
        )

    # ── Full record ──────────────────────────────────────────────────
    record = {
        "human_summary": human_summary,
        "timestamp":     now_str,
        "hostname":      HOSTNAME,
        "severity":      severity,
        "alert_type":    alert_type,
        "affected_user": user,
        "detail":        detail[:500],
        "notification":  notification,
    }
    if extra_facts:
        record["extra_facts"] = {k: str(v)[:200] for k, v in extra_facts.items()}

    try:
        dir_path = os.path.dirname(path)
        if dir_path:
            os.makedirs(dir_path, exist_ok=True)
        # Open in append mode
        with open(path, "a") as f:
            f.write(json.dumps(record, indent=2, ensure_ascii=False))
            f.write("\n\n")
        # Enforce root-only permissions: chmod 600 + chown root:root
        # Only root (the process owner) can read this file.
        # sudo users cannot read it without switching to root first.
        os.chmod(path, 0o600)
        try:
            os.chown(path, 0, 0)   # uid=0 (root), gid=0 (root)
        except AttributeError:
            pass   # Windows (dev machine) -- skip chown
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
    # Dedup key: alert_type + user + first 80 chars of detail
    # This ensures "naveen deleted /etc/passwd" and "naveen deleted /var/log/auth.log"
    # are separate alert buckets while still collapsing rapid duplicates.
    key = _alert_key(alert_type + str(user), detail[:80])
    if not should_alert(key, severity):
        return

    record_threat_event(user, severity)

    now_str = datetime.now(IST).strftime("%Y-%m-%d %H:%M:%S IST")
    separator = "=" * 72

    # ── Human-readable banner in the .log file (always written) ─────
    log(separator)
    log(f"  SECURITY ALERT  [{severity}]")
    log(f"  Alert Type : {alert_type}")
    log(f"  User       : {user}")
    log(f"  Host       : {HOSTNAME}")
    log(f"  Time       : {now_str}")
    log(f"  Detail     : {detail[:120]}")
    if extra_facts:
        for k, v in list(extra_facts.items())[:6]:
            log(f"  {k:<12}: {str(v)[:100]}")
    log(separator)

    # ── Determine email status & dispatch ───────────────────────────
    mail_enabled = env.get("MAIL_ENABLED", "true").strip().lower()
    rcpt_str     = env.get("SES_RECIPIENT_EMAILS", "")
    recipients   = [e.strip() for e in rcpt_str.split(",") if e.strip()]

    if mail_enabled not in ("true", "1", "yes"):
        email_status = "disabled"
        log(f"[INFO] MAIL_ENABLED=false  --  alert logged only, no email sent")
    elif not all([env.get("AWS_ACCESS_KEY_ID"), env.get("AWS_SECRET_ACCESS_KEY"),
                  env.get("SES_SENDER_EMAIL"), rcpt_str]):
        email_status = "skipped_no_credentials"
        log("[WARN] Email skipped -- AWS/SES credentials incomplete in .env")
    else:
        html = build_html_email(severity, alert_type, user, detail,
                                 context_lines, extra_facts)
        ok   = send_alert_email(f"{alert_type} ({user})", html, env)
        email_status = "sent" if ok else "send_failed"

    # ── Always write enriched human-readable JSON audit record ───────
    write_alert_json(
        severity, alert_type, user, detail,
        extra_facts=extra_facts,
        env=env,
        email_status=email_status,
        email_recipients=recipients or None,
    )

# -----------------------------------------------------------------
# Escalation context helpers
# -----------------------------------------------------------------
def _active_root_actor() -> tuple[str, str]:
    """
    Return (original_user, how_they_escalated) for whoever currently
    holds an active root session in IDENTITY_CHAIN / SU_SESSION_START.

    'How' is one of:
      'su/sudo shell'  -- opened a full root shell (su -, sudo su)
      'sudo'           -- ran individual sudo commands (no full shell)
      ''               -- no known escalation (direct root login)

    Returns ('root', '') if no escalated user is tracked.
    """
    now     = datetime.now(IST)
    cutoff  = timedelta(hours=2)   # forget escalations older than 2h

    # Prefer full su/sudo-shell sessions (strongest signal)
    for user, started_at in SU_SESSION_START.items():
        if (now - started_at) <= cutoff:
            return user, "su/sudo shell"

    # Fall back to identity chain (individual sudo commands)
    best_user, best_ts = None, None
    for user, ts in IDENTITY_CHAIN.items():
        if (now - ts) <= cutoff:
            if best_ts is None or ts > best_ts:
                best_user, best_ts = user, ts
    if best_user:
        return best_user, "sudo"

    return "root", ""


def _get_lateral_actor(target_user: str) -> tuple[str, str]:
    """
    If someone su'd into target_user recently, return (original_actor, target_user).
    This is the 'innocent user2' scenario: user1 su -> user2 -> does bad things.
    Returns (target_user, '') if no lateral chain is tracked.
    """
    now    = datetime.now(IST)
    cutoff = timedelta(hours=2)
    for actor, (target, ts) in LATERAL_SU_CHAIN.items():
        if target == target_user and (now - ts) <= cutoff:
            return actor, target_user
    return target_user, ""


def _escalation_context(user: str, how: str, action: str = "") -> str:
    """
    Build a plain-English one-liner explaining who did what and how
    they got elevated privileges.

    Examples
    --------
    _escalation_context("ubuntu", "su/sudo shell", "changed naveen's password")
    → "ubuntu switched to root via su/sudo shell and changed naveen's password"

    _escalation_context("naveen", "sudo", "deleted /var/log/auth.log")
    → "naveen used sudo to delete /var/log/auth.log"

    _escalation_context("root", "", "modified /etc/shadow")
    → "root (direct login) modified /etc/shadow"
    """
    if how == "su/sudo shell":
        verb = "switched to root via su/sudo shell"
    elif how == "sudo":
        verb = "used sudo"
    else:
        verb = "(direct root login)"

    if action:
        return f"{user} {verb} and {action}"
    return f"{user} {verb}"


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
# Auditd record parser  (uses cycle lines -- no full file re-read)
# -----------------------------------------------------------------
def _build_audit_records(logfile: str) -> list:
    """
    Parse auditd EXECVE records from the NEW lines read this cycle.
    Uses CYCLE_LINES (offset-tracked) so old events are never re-processed.
    Falls back to reading the last 4 KB of the file on first run.
    Returns a list of dicts: uid, auid, euid, pid, ppid, exe, cmd, args.
    """
    lines = CYCLE_LINES.get(logfile)
    if lines is None:
        # First cycle or file not yet in CYCLE_LINES -- read tail only
        if not os.path.exists(logfile):
            return []
        try:
            with open(logfile, "rb") as f:
                f.seek(max(0, os.path.getsize(logfile) - 4096))
                lines = f.read().decode(errors="replace").splitlines()
        except Exception:
            return []

    raw_blocks: dict = defaultdict(dict)
    pattern = re.compile(
        r"audit\([\d.]+:(\d+)\).*?type=(\w+)"
    )
    kv_re = re.compile(r'(\w+)=(?:"([^"]*)"|(\S+))')

    for line in lines:
        m = pattern.search(line)
        if not m:
            continue
        serial, rec_type = m.group(1), m.group(2)
        kv = {k: (v1 or v2) for k, v1, v2 in kv_re.findall(line)}
        block = raw_blocks[serial]
        block.update(kv)
        if rec_type == "EXECVE":
            argc = int(kv.get("argc", 0))
            args = []
            for i in range(argc):
                arg = kv.get(f"a{i}", "")
                if re.fullmatch(r"[0-9A-Fa-f]+", arg) and len(arg) % 2 == 0:
                    try:
                        arg = bytes.fromhex(arg).decode(errors="replace")
                    except Exception:
                        pass
                args.append(arg)
            block["cmd"]  = " ".join(args) if args else block.get("cmd", "")
            block["args"] = args

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
    - Collapse all records from the same PID+user within 5 min
      into ONE alert (prevents email storm from recursive rm with many files).

    Detection method: uses auditd key 'delete_events' (set in rules by watching
    rm/shred/rmdir binaries) rather than syscall-name matching in cmd/exe
    (which is unreliable -- syscall is a number in EXECVE records).
    """
    if not os.path.exists(AUDIT_LOG):
        return

    now = datetime.now(IST)
    # Purge old PID entries
    for key in list(DELETION_PID_SEEN.keys()):
        if now - DELETION_PID_SEEN[key]["ts"] > DELETION_PID_TTL:
            del DELETION_PID_SEEN[key]

    # Delete detection: match on auditd key='delete_events' OR exe paths of
    # rm/shred/rmdir/truncate binaries. This is reliable across all architectures.
    _DELETE_EXE_RE = re.compile(
        r"(?:/usr)?/bin/(?:rm|shred|rmdir|truncate)\b", re.IGNORECASE)

    for rec in _build_audit_records(AUDIT_LOG):
        exe = rec.get("exe", "")
        cmd = rec.get("cmd", "")
        key_tag = rec.get("key", "")

        # Match on auditd key OR exe binary name
        is_delete = (key_tag == "delete_events") or _DELETE_EXE_RE.search(exe or "")
        if not is_delete:
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

        # Skip kernel/daemon events
        try:
            if int(auid) >= 4294967294 and int(uid) == 0:
                continue
        except ValueError:
            pass

        user = _resolve_audit_user(rec)

        # Check lateral su attribution: if user2 deleted something but user1
        # su'd into user2, blame user1
        base_username = uid_to_name(uid)
        real_actor, lateral_target = _get_lateral_actor(base_username)
        if lateral_target:
            user = f"{real_actor} (acting as '{lateral_target}' via su)"

        dedup_key  = f"{pid}:{user}"

        if dedup_key in DELETION_PID_SEEN:
            DELETION_PID_SEEN[dedup_key]["count"] += 1
            continue

        DELETION_PID_SEEN[dedup_key] = {"ts": now, "count": 1}

        # Use the file path from the auditd record. 'name' is the actual
        # path. 'nametype' is an auditd token like NORMAL/DELETE/PARENT —
        # never show it as the file path. Fall back to exe only.
        path_item = rec.get("name", "") or exe or "unknown path"
        # Strip auditd NAMETYPE tokens that look like paths but aren't
        if path_item.upper() in ("NORMAL", "DELETE", "PARENT", "CREATE", "UNKNOWN"):
            path_item = exe or "unknown path"

        # Build a clean attribution sentence for the detail field
        if lateral_target:
            who_line = f"{real_actor} (switched to '{lateral_target}' via su)"
        else:
            who_line = user
        detail_msg = f"{who_line} deleted: {path_item}  [command: {cmd or exe}]"

        facts: dict = {
            "Deleted file": path_item,
            "Command":      cmd or exe,
            "PID":          pid,
        }
        if lateral_target:
            facts["Actual actor"] = real_actor
            facts["Account used"] = lateral_target

        trigger_alert(
            "HIGH", "File Deletion Detected", user,
            detail_msg,
            env,
            extra_facts=facts,
        )


# -----------------------------------------------------------------
# Check: auditd commands (sudo-aware identity chain)
# -----------------------------------------------------------------
def check_auditd_commands(env: dict):
    """
    Parse auditd EXECVE records to catch ALL dangerous commands:
    1. Commands run as root (uid=0) -- attributed back to original login user via auid.
    2. Commands run by regular users (uid>=1000) -- catches nmap, hydra, reverse
       shells, miners, etc. run WITHOUT escalation.
    3. Commands run via lateral su (user1 su'd into user2): attribute bad
       actions back to the original actor (user1), not the innocent user2.

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

        try:
            uid_int  = int(uid)
            auid_int = int(auid)
        except ValueError:
            continue

        # Skip pure kernel/daemon events (no login session)
        if auid_int >= 4294967294:
            continue

        # Determine context:
        # Case A: running as root (uid=0), original user != root
        is_root_cmd = (uid_int == 0 and auid_int != 0)
        # Case B: running as normal user (uid>=1000) with a login session
        is_user_cmd = (uid_int >= 1000)

        if not is_root_cmd and not is_user_cmd:
            continue

        user     = _resolve_audit_user(rec)
        full_cmd = cmd or exe

        # Check if this is actually user1 who su'd into user2
        # (lateral chain): attribute to user1 not user2
        base_username = uid_to_name(uid)
        real_actor, lateral_target = _get_lateral_actor(base_username)
        if lateral_target:
            # user1 su'd into user2; user2 ran this command -- blame user1
            attribution = (
                f"{real_actor} (su'd into '{lateral_target}') ran: {full_cmd}"
            )
            alert_user = real_actor
        else:
            attribution = f"User '{user}' ran: {full_cmd}"
            alert_user  = user

        for pattern, desc, severity in DANGEROUS_PATTERNS:
            m = re.search(pattern, full_cmd, re.IGNORECASE)
            if m:
                target = m.groupdict().get("target", "")
                # For non-root users, cap max severity at HIGH (they can't
                # do kernel-level damage without escalation)
                if is_user_cmd and not is_root_cmd and severity == "CRITICAL":
                    if not any(kw in desc.lower() for kw in ("reverse shell", "miner", "crypto", "metasploit")):
                        severity = "HIGH"

                facts: dict = {
                    "Command":    full_cmd,
                    "Running as": "root (via su/sudo)" if is_root_cmd else "own account",
                }
                if target:
                    facts["Target"] = target
                if lateral_target:
                    facts["Actual actor"] = real_actor
                    facts["Account used"] = lateral_target

                trigger_alert(
                    severity, f"Dangerous Command: {desc}", alert_user,
                    attribution,
                    env,
                    extra_facts=facts,
                )
                break


# -----------------------------------------------------------------
# Check: su/sudo escalation via auth.log
# -----------------------------------------------------------------
def check_su_sudo(env: dict):
    """
    Detect users switching to root (su/sudo/su -i/sudo su).
    Also detects lateral su: user1 -> su -> user2 (non-root).
    Tracks per-user escalation frequency; off-hours events get severity bump.
    Also builds IDENTITY_CHAIN and LATERAL_SU_CHAIN to attribute future commands.

    Sudo alert suppression: only alert on sudo commands that are NOT
    already caught by check_auditd_commands (dangerous pattern match).
    Routine sudo (apt, service restart, etc.) is logged at LOW severity
    to reduce noise. Off-hours or high-frequency sudo stays HIGH.
    """
    lines = get_cycle_lines(AUTH_LOGS)
    now   = datetime.now(IST)
    hour  = int(now.strftime("%H"))

    # Commands that are routine admin work -- don't alert at HIGH for these
    _ROUTINE_SUDO_RE = re.compile(
        r"""(?x)
        /usr/bin/apt|apt-get|apt\s|dpkg|
        /usr/bin/systemctl\s+(?:start|stop|restart|reload|status)|
        /usr/sbin/service\s|
        /usr/bin/journalctl|
        /usr/bin/tail|/usr/bin/less|/usr/bin/cat|/usr/bin/grep|
        /usr/bin/find\s|/usr/bin/ls\s|
        /usr/bin/nano|/usr/bin/vi|/usr/bin/vim|
        /usr/bin/pip|/usr/bin/python|
        /usr/bin/npm|/usr/bin/node
        """, re.IGNORECASE
    )

    for line in lines:
        # ── Sudo: successful execution ───────────────────────────────
        m_sudo = re.search(
            r"sudo:\s+(\S+)\s*:.*COMMAND=(.*)", line, re.IGNORECASE)
        if m_sudo:
            user    = m_sudo.group(1).strip()
            command = m_sudo.group(2).strip()

            # ── Key fix: when user is "root", look up the real human ──
            # Inside a root shell, auth.log logs commands as:
            #   sudo: root : COMMAND=/usr/sbin/swapoff -a
            # The real person is whoever is in SU_SESSION_START / IDENTITY_CHAIN.
            # We suppress a separate "Sudo Command Executed" alert in this case
            # because check_auditd_commands already fires with full attribution.
            # We still update IDENTITY_CHAIN so the session stays warm.
            if user == "root":
                real_actor, how = _active_root_actor()
                if real_actor != "root":
                    # Command already covered by auditd attribution — just keep
                    # the session alive and skip the duplicate sudo alert.
                    IDENTITY_CHAIN[real_actor] = now
                    continue
                # If we genuinely don't know who this root is, fall through
                # and log it attributed to root.

            IDENTITY_CHAIN[user] = now
            USER_SUDO_COUNT[user] += 1
            off_hours = hour < 6 or hour > 22

            # Determine severity: only escalate for suspicious patterns,
            # high frequency, or off-hours. Routine admin work → LOW.
            is_routine = bool(_ROUTINE_SUDO_RE.search(command))
            if USER_SUDO_COUNT[user] >= 5 or off_hours:
                severity = "HIGH"
            elif is_routine:
                severity = "LOW"
            else:
                severity = "MEDIUM"

            trigger_alert(
                severity, "Sudo Command Executed", user,
                f"{user} ran sudo: {command}",
                env,
                extra_facts={
                    "Off-hours":            "Yes — outside business hours" if off_hours else "No",
                    "Sudo count (session)": str(USER_SUDO_COUNT[user]),
                }
            )

        # ── Failed sudo (wrong password / not in sudoers) ────────────
        m_sudo_fail = re.search(
            r"sudo:\s+(\S+)\s*:.*(?:authentication failure|NOT in sudoers|incorrect password)",
            line, re.IGNORECASE)
        if m_sudo_fail:
            user = m_sudo_fail.group(1).strip()
            SSH_SUDO_FAILURES[user].append(now)
            SSH_SUDO_FAILURES[user] = [
                t for t in SSH_SUDO_FAILURES[user]
                if (now - t) <= BRUTE_FORCE_WINDOW
            ]
            if len(SSH_SUDO_FAILURES[user]) >= 3:
                trigger_alert(
                    "HIGH", "Repeated Sudo Authentication Failures", user,
                    f"{user} failed sudo authentication "
                    f"{len(SSH_SUDO_FAILURES[user])} times in {BRUTE_FORCE_WINDOW} — "
                    f"possible privilege escalation attempt",
                    env,
                    extra_facts={
                        "Risk": "Could be insider trying to escalate or stolen credentials",
                    }
                )

        # ── su / su - / sudo su -> ROOT session opened ───────────────
        m_su_root = re.search(
            r"su[do]*.*:\s+(session opened for user root).*by\s+(\S+)", line, re.IGNORECASE)
        if m_su_root:
            # Strip everything after the first '(' to clean "prajwal(uid=0)" -> "prajwal"
            raw_actor = m_su_root.group(2).strip()
            actor     = re.sub(r'\(.*', '', raw_actor).strip()
            SU_SESSION_START[actor] = now
            IDENTITY_CHAIN[actor]   = now
            off_hours = hour < 6 or hour > 22
            trigger_alert(
                "HIGH" if off_hours else "MEDIUM",
                "Root Shell Session Opened", actor,
                f"{actor} opened a root shell (su/sudo). All commands run as root "
                f"in this session will be attributed to {actor}.",
                env,
                extra_facts={
                    "Off-hours": "Yes — outside business hours (6am–10pm)" if off_hours else "No",
                }
            )

        # ── su -> NON-ROOT user session opened (lateral movement) ────
        # e.g. "su: session opened for user naveen by ubuntu(uid=1001)"
        m_su_lateral = re.search(
            r"su(?:do)?.*:\s+session opened for user (\S+) by (\S+)", line, re.IGNORECASE)
        if m_su_lateral:
            target_user = re.sub(r'\(.*', '', m_su_lateral.group(1).strip())
            actor       = re.sub(r'\(.*', '', m_su_lateral.group(2).strip())
            if target_user.lower() == "root":
                pass  # already handled above
            elif actor not in ("root", target_user):
                # user1 su'd into user2 -- record for later attribution
                LATERAL_SU_CHAIN[actor] = (target_user, now)
                off_hours = hour < 6 or hour > 22
                trigger_alert(
                    "HIGH" if off_hours else "MEDIUM",
                    "User Switched Account (su)", actor,
                    f"{actor} used su to switch into the '{target_user}' account. "
                    f"Any suspicious activity from '{target_user}' will be attributed back to {actor}.",
                    env,
                    extra_facts={
                        "Switched from": actor,
                        "Switched into": target_user,
                        "Off-hours":     "Yes — outside business hours" if off_hours else "No",
                        "Risk":          f"Commands run as '{target_user}' are actually {actor} — check what happens next",
                    }
                )

        # ── Session closed -- clean up identity tracking ─────────────
        m_close_root = re.search(r"session closed for user root", line, re.IGNORECASE)
        if m_close_root:
            for user in list(SU_SESSION_START.keys()):
                if (now - SU_SESSION_START[user]) < timedelta(hours=2):
                    duration = now - SU_SESSION_START[user]
                    log(f"Root session for '{user}' ended -- duration {duration}")
                    del SU_SESSION_START[user]
                    break

        # Clean up lateral su sessions on close
        m_close_lateral = re.search(
            r"su(?:do)?.*:\s+session closed for user (\S+)", line, re.IGNORECASE)
        if m_close_lateral:
            closed_user = re.sub(r'\(.*', '', m_close_lateral.group(1).strip())
            if closed_user.lower() != "root":
                for actor in list(LATERAL_SU_CHAIN.keys()):
                    if LATERAL_SU_CHAIN[actor][0] == closed_user:
                        log(f"Lateral su session: '{actor}' -> '{closed_user}' ended")
                        del LATERAL_SU_CHAIN[actor]
                        break


# -----------------------------------------------------------------
# Check: SSH brute-force and new-IP login
# -----------------------------------------------------------------
def check_ssh_bruteforce(env: dict):
    """
    Track failed SSH logins per source IP (IPv4 and IPv6).
    Fire CRITICAL when failures exceed threshold within window.
    Also detect:
    - Successful login after multiple failures (likely compromise)
    - Successful login from a never-before-seen IP for a known user
    """
    lines = get_cycle_lines(AUTH_LOGS)
    now   = datetime.now(IST)
    hour  = int(now.strftime("%H"))

    # IPv4 and IPv6 address pattern
    _IP_RE = r"([\da-fA-F:\.]+)"

    for line in lines:
        m_fail = re.search(
            r"Failed (?:password|publickey) for (?:invalid user )?(\S+) from " + _IP_RE,
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
                    f"{len(SSH_FAILURES[ip])} failed SSH logins from {ip} "
                    f"targeting user '{user}' in the last {BRUTE_FORCE_WINDOW}. "
                    f"This IP is actively trying to break in.",
                    env,
                    extra_facts={
                        "Source IP":   ip,
                        "Target user": user,
                        "Attempts":    str(len(SSH_FAILURES[ip])),
                    }
                )

        m_ok = re.search(
            r"Accepted (?:password|publickey) for (\S+) from " + _IP_RE, line)
        if m_ok:
            user, ip = m_ok.group(1), m_ok.group(2)
            recent_fails = SSH_FAILURES.get(ip, [])
            off_hours    = hour < 6 or hour > 22

            # Alert: login after brute-force
            if len(recent_fails) >= 3:
                trigger_alert(
                    "CRITICAL", "SSH Login After Brute-Force", user,
                    f"{user} successfully logged in from {ip} after "
                    f"{len(recent_fails)} recent failed attempts from that IP. "
                    f"This strongly suggests the password was cracked or credentials were leaked.",
                    env,
                    extra_facts={
                        "Source IP":    ip,
                        "Failed attempts before login": str(len(recent_fails)),
                    }
                )

            # Alert: login from a new/unknown IP for this user
            known_ips = SSH_KNOWN_IPS[user]
            if ip not in known_ips:
                if known_ips:  # only alert if we have a baseline (not first-ever login)
                    trigger_alert(
                        "HIGH" if off_hours else "MEDIUM",
                        "SSH Login From New IP", user,
                        f"{user} logged in from {ip} — this IP has never been seen for this account before.",
                        env,
                        extra_facts={
                            "New IP":     ip,
                            "Off-hours":  "Yes — outside business hours" if off_hours else "No",
                            "Risk":       "Could indicate stolen credentials or account takeover",
                        }
                    )
                known_ips.add(ip)
                SSH_KNOWN_IPS[user] = known_ips


# -----------------------------------------------------------------
# Check: user/group creation
# -----------------------------------------------------------------
def check_user_group_changes(env: dict):
    """Detect new user/group creation via useradd/groupadd."""
    lines = get_cycle_lines(AUTH_LOGS + SYSLOG_LOGS)
    actor, how = _active_root_actor()
    for line in lines:
        m = re.search(
            r"(?:useradd|adduser|groupadd).*(?:new user|new group)[:\s]+name=(\S+)",
            line, re.IGNORECASE)
        if m:
            name = m.group(1).rstrip(",")
            # Try to find who ran the command from the log line itself
            m_by = re.search(r"by\s+(\S+)", line, re.IGNORECASE)
            creator = m_by.group(1) if m_by else (actor if how else "root")

            trigger_alert(
                "HIGH", "New User/Group Created", creator,
                f"{creator} created a new account or group: '{name}'. "
                f"Verify this was authorized.",
                env,
                extra_facts={
                    "New account/group": name,
                    "Created by":        creator,
                }
            )


# -----------------------------------------------------------------
# SUID process whitelist
# These binaries legitimately run as effective-root from non-root users
# because they carry the SUID bit. They are NOT security threats.
# -----------------------------------------------------------------
SUID_EXE_WHITELIST = re.compile(
    r"""(?x)
    fusermount3?          # FUSE filesystem mounter (GNOME portal, etc.)
    |/usr/bin/mount       # Standard mount
    |/usr/bin/umount      # Standard umount
    |/usr/bin/sudo        # sudo itself
    |/usr/bin/su\b        # su command
    |/usr/bin/newgrp      # newgrp group switch
    |/usr/bin/passwd      # passwd (own password change)
    |/usr/bin/chfn        # Change finger info
    |/usr/bin/chsh        # Change login shell
    |/usr/bin/gpasswd     # Group password admin
    |/usr/bin/expiry      # Password expiry check
    |/usr/sbin/pam_      # PAM helpers
    |/usr/lib/policykit   # Polkit
    |/usr/lib/polkit      # Polkit agent
    |/usr/bin/pkexec      # Polkit exec helper
    |gnome-keyring-daemon # GNOME keyring
    |/usr/lib/gnome       # GNOME components
    |/usr/lib/xorg        # Xorg helpers
    |Xorg\.wrap           # Xorg wrapper
    |/usr/sbin/unix_chkpwd  # PAM Unix password checker
    |/usr/bin/ksu         # Kerberos su
    |/usr/bin/ssh-agent   # SSH agent
    |at-spi               # Accessibility
    |dbus-daemon          # D-Bus
    |/usr/lib/dbus        # D-Bus helpers
    |/usr/bin/crontab     # crontab editor
    |ping\b|/bin/ping     # ping (SUID on some distros)
    |/usr/bin/traceroute  # traceroute
    |snap-confine         # Snap confinement
    """, re.IGNORECASE)


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
                proc_user = parts[0]
                actor, how = _active_root_actor()

                if how and actor != proc_user:
                    narrative = (
                        f"{actor} switched to root via {how} and a suspicious "
                        f"process is now running under '{proc_user}': {cmd_line[:150]}"
                    )
                    alert_user = actor
                else:
                    narrative = (
                        f"{proc_user} has a suspicious process running: {cmd_line[:150]}"
                    )
                    alert_user = proc_user

                facts: dict = {
                    "PID":     parts[1],
                    "Command": cmd_line[:200],
                }
                if how:
                    facts["Escalated from"] = actor
                    facts["How"]            = how

                trigger_alert(
                    severity, f"Suspicious Process: {desc}", alert_user,
                    narrative,
                    env,
                    extra_facts=facts,
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

                    # Skip whitelisted SUID binaries -- legitimate setuid helpers
                    exe_path = ""
                    try:
                        exe_path = os.readlink(f"/proc/{pid}/exe")
                    except Exception:
                        pass
                    check_str = exe_path or cmd_str
                    if SUID_EXE_WHITELIST.search(check_str):
                        continue

                    # Also skip system/service accounts (uid < 1000)
                    if real_uid < 1000:
                        continue

                    user = uid_to_name(str(real_uid))
                    actor, how = _active_root_actor()
                    if how and actor == user:
                        narrative = (
                            f"{user} escalated to root via {how} and has a process "
                            f"running with full root privileges. PID {pid}: {cmd_str}"
                        )
                    else:
                        narrative = (
                            f"{user} has a process running with effective root privileges "
                            f"but no sudo/su session was recorded for them — possible SUID "
                            f"exploit or untracked escalation. PID {pid}: {cmd_str}"
                        )

                    facts: dict = {
                        "PID":     pid,
                        "Exe":     exe_path or "unknown",
                        "Command": cmd_str,
                    }
                    if how:
                        facts["Escalated via"] = how

                    trigger_alert(
                        "HIGH", "Root Process From Non-Root User", user,
                        narrative,
                        env,
                        extra_facts=facts,
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
            # Skip accounts already alerted this run (no re-alert every 2h)
            if username in DORMANT_ALERTED:
                continue
            try:
                date_str   = " ".join(parts[1:6])
                last_login = datetime.strptime(date_str, "%a %b %d %H:%M:%S %z %Y")
                age_days   = (now.replace(tzinfo=None) -
                              last_login.replace(tzinfo=None)).days
                if age_days > 90:
                    # Try to get login source from 'last' command
                    src_ip = run(f"last -n 1 {username} 2>/dev/null | awk 'NR==1{{print $3}}'")
                    DORMANT_ALERTED.add(username)
                    from_str = f" from {src_ip}" if src_ip and src_ip != username else ""
                    trigger_alert(
                        "HIGH", "Dormant Account Logged In", username,
                        f"{username} just logged in{from_str} after {age_days} days of inactivity. "
                        f"This account was last used on {date_str}.",
                        env,
                        extra_facts={
                            "Days inactive":  str(age_days),
                            "Last seen":      date_str,
                            "Login from":     src_ip or "unknown",
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
    Also detect modules that were unloaded (rootkit covering tracks).
    """
    current_mods = set(run("lsmod | awk 'NR>1{print $1}'").splitlines())
    prev_key = "_kernel_mods"
    prev_mods = set(ALERTS_SENT.get(prev_key + "_data", "").split(",")) \
        if prev_key + "_data" in ALERTS_SENT else None

    if prev_mods is None:
        ALERTS_SENT[prev_key + "_data"] = ",".join(current_mods)
        return

    new_mods     = current_mods - prev_mods
    removed_mods = prev_mods - current_mods

    if new_mods or removed_mods:
        actor, how = _active_root_actor()

        for mod in new_mods:
            action  = f"loaded kernel module '{mod}' — possible rootkit persistence"
            context = _escalation_context(actor, how, action)
            facts: dict = {"Module": mod}
            if how:
                facts["Escalated via"] = how
            trigger_alert(
                "CRITICAL", "Kernel Module Loaded", actor,
                context,
                env,
                extra_facts=facts,
            )

        for mod in removed_mods:
            if re.match(r"^(dm_|loop|nf_|ip_tables|iptable_)", mod):
                continue
            action  = f"unloaded kernel module '{mod}' — possibly covering tracks"
            context = _escalation_context(actor, how, action)
            facts: dict = {
                "Module": mod,
                "Risk":   "Attackers unload audit/security modules to evade detection",
            }
            if how:
                facts["Escalated via"] = how
            trigger_alert(
                "HIGH", "Kernel Module Unloaded", actor,
                context,
                env,
                extra_facts=facts,
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
            # ── Dedup: only alert once per unique connection ────────
            conn_key = f"{port}:{proc}:{line.strip()[-60:]}"
            now      = datetime.now(IST)
            if conn_key in C2_SEEN_CONNECTIONS:
                # Re-alert after 30 min if connection is still alive
                if (now - C2_SEEN_CONNECTIONS[conn_key]) < timedelta(minutes=30):
                    continue
            C2_SEEN_CONNECTIONS[conn_key] = now

            # Try to resolve the real user owning the process via /proc
            proc_user = "unknown"
            pid_match = re.search(r"pid=(\d+)", line)
            if pid_match:
                try:
                    status_txt = open(f"/proc/{pid_match.group(1)}/status",
                                      errors="replace").read()
                    uid_m = re.search(r"^Uid:\s+(\d+)", status_txt, re.M)
                    if uid_m:
                        proc_user = uid_to_name(uid_m.group(1))
                except Exception:
                    pass

            actor, how = _active_root_actor()
            if how and (proc_user == "root" or proc_user == actor):
                who_narrative = f"{actor} (root via {how})"
                alert_user    = actor
            elif proc_user not in ("unknown", "root"):
                who_narrative = proc_user
                alert_user    = proc_user
            else:
                who_narrative = "an unidentified root process"
                alert_user    = "root"

            facts: dict = {
                "Port":    str(port),
                "Process": proc,
                "Risk":    "This port is commonly used for reverse shells and C2 beacons",
            }
            if how:
                facts["Escalated from"] = actor
                facts["Via"]            = how

            trigger_alert(
                "CRITICAL", "C2/Reverse-Shell Port Connection", alert_user,
                f"{who_narrative} has an active connection on port {port} — "
                f"this port is used for reverse shells and attacker C2 channels. "
                f"Process: {proc}",
                env,
                extra_facts=facts,
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

    actor, how = _active_root_actor()

    for path in critical_logs:
        if not os.path.exists(path):
            if path in LOG_SIZE_SNAPSHOT and LOG_SIZE_SNAPSHOT[path] > 0:
                action  = f"deleted log file: {path}"
                context = _escalation_context(actor, how, action)
                facts: dict = {"File": path}
                if how:
                    facts["Escalated via"] = how
                trigger_alert(
                    "CRITICAL", "Log File Deleted", actor,
                    context,
                    env,
                    extra_facts=facts,
                )
            LOG_SIZE_SNAPSHOT[path] = 0
            continue

        current_size = os.path.getsize(path)
        prev_size    = LOG_SIZE_SNAPSHOT.get(path)

        if prev_size is None:
            LOG_SIZE_SNAPSHOT[path] = current_size
            continue

        if current_size < prev_size:
            backup = path + ".1"
            is_rotation = False
            if os.path.exists(backup):
                backup_age = now.timestamp() - os.path.getmtime(backup)
                is_rotation = backup_age < 120
            if not is_rotation:
                action  = f"truncated log file: {path}  (was {prev_size:,} bytes, now {current_size:,} bytes)"
                context = _escalation_context(actor, how, action)
                facts: dict = {
                    "File":  path,
                    "Was":   f"{prev_size:,} bytes",
                    "Now":   f"{current_size:,} bytes",
                    "Lost":  f"{prev_size - current_size:,} bytes removed",
                }
                if how:
                    facts["Escalated via"] = how
                trigger_alert(
                    "CRITICAL", "Log File Truncated/Shrunk", actor,
                    context,
                    env,
                    extra_facts=facts,
                )
        LOG_SIZE_SNAPSHOT[path] = current_size


# -----------------------------------------------------------------
# Check: critical file integrity
# -----------------------------------------------------------------
def check_file_integrity(env: dict):
    """
    Detect modifications to critical system files using SHA256 hashes.
    SHA256 is tamper-proof -- an attacker cannot fool this by restoring
    the original mtime with 'touch -t' (which would defeat mtime-only checks).
    """
    watch_files = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
        "/etc/crontab", "/etc/cron.d", "/root/.bashrc", "/root/.profile",
        "/root/.ssh/authorized_keys", "/etc/ssh/sshd_config",
        "/etc/ld.so.preload", "/etc/ld.so.conf",
    ]
    state_key   = "_file_sha256"
    prev_hashes = ALERTS_SENT.get(state_key, {})
    if not isinstance(prev_hashes, dict):
        prev_hashes = {}

    actor, how = _active_root_actor()

    _file_label = {
        "/etc/passwd":                "the user account database",
        "/etc/shadow":                "the password hash database (shadow file)",
        "/etc/sudoers":               "the sudoers privilege config",
        "/etc/hosts":                 "the hosts file",
        "/etc/crontab":               "the system crontab",
        "/etc/cron.d":                "a cron job directory",
        "/root/.bashrc":              "root's shell config (.bashrc)",
        "/root/.profile":             "root's shell profile",
        "/root/.ssh/authorized_keys": "root's SSH authorized_keys",
        "/etc/ssh/sshd_config":       "the SSH daemon config",
        "/etc/ld.so.preload":         "the LD_PRELOAD injection file (rootkit risk)",
        "/etc/ld.so.conf":            "the dynamic linker config",
    }

    for fpath in watch_files:
        if not os.path.exists(fpath):
            continue
        try:
            # Compute SHA256 of the file content
            h = hashlib.sha256()
            with open(fpath, "rb") as fh:
                for chunk in iter(lambda: fh.read(8192), b""):
                    h.update(chunk)
            current_hash = h.hexdigest()
        except Exception:
            continue

        if fpath in prev_hashes and prev_hashes[fpath] != current_hash:
            label   = _file_label.get(fpath, fpath)
            action  = f"modified {label} ({fpath})"
            context = _escalation_context(actor, how, action)
            facts: dict = {
                "File":          fpath,
                "What changed":  label,
                "Detection":     "SHA256 hash changed — content was altered",
                "Previous hash": prev_hashes[fpath][:16] + "...",
                "Current hash":  current_hash[:16] + "...",
            }
            if how:
                facts["Escalated via"] = how
            trigger_alert(
                "CRITICAL", "Critical File Modified", actor,
                context,
                env,
                extra_facts=facts,
            )
        prev_hashes[fpath] = current_hash

    ALERTS_SENT[state_key] = prev_hashes


# -----------------------------------------------------------------
# Check: LD_PRELOAD / history wipe in auth/syslog
# -----------------------------------------------------------------
def check_insider_evasion(env: dict):
    """
    Detect ONLY anti-forensic / evidence-destruction events from syslog/auth.log.
    Uses EVASION_PATTERNS (not DANGEROUS_PATTERNS) to avoid duplicating alerts
    that check_auditd_commands already raises with better attribution.

    Catches: history wipes, HISTFILE redirects, log truncation via shell
    redirect, shred of critical paths, LD_PRELOAD injection.
    """
    lines = get_cycle_lines(AUTH_LOGS + SYSLOG_LOGS)
    for line in lines:
        for pat, desc, severity in EVASION_PATTERNS:
            if re.search(pat, line, re.IGNORECASE):

                # Extract user -- try sudo format first (most reliable)
                # Then try "for user X" only in a session open context
                # Avoid the loose "for \S+" that matches any word after "for"
                m_sudo_user  = re.search(r"sudo:\s+(\S+)\s*:", line)
                m_sess_user  = re.search(r"session opened for user (\S+)", line)
                m_pam_user   = re.search(r"user=([A-Za-z0-9_.-]+)", line)
                if m_sudo_user:
                    user = re.sub(r'\(.*', '', m_sudo_user.group(1)).strip()
                elif m_sess_user:
                    user = re.sub(r'\(.*', '', m_sess_user.group(1)).strip()
                elif m_pam_user:
                    user = m_pam_user.group(1).strip()
                else:
                    user = "unknown"

                m_cmd       = re.search(r"COMMAND=(.+)$", line.strip())
                command_str = m_cmd.group(1).strip() if m_cmd else line.strip()[:200]

                if m_sudo_user and m_cmd:
                    detail = f"{user} ran a command that erases evidence: {command_str}"
                else:
                    detail = f"Evidence-destruction pattern detected — {desc}. Log: {line.strip()[:180]}"

                trigger_alert(
                    severity, f"Anti-Forensic Activity: {desc}", user,
                    detail,
                    env,
                    context_lines=[line.strip()],
                    extra_facts={
                        "Command": command_str,
                        "Risk":    "Someone is trying to erase traces of their activity",
                    }
                )
                break


# -----------------------------------------------------------------
# Check: processes running from suspicious paths (/tmp, /dev/shm)
# -----------------------------------------------------------------
def check_suspicious_exec_paths(env: dict):
    """
    Detect processes executing from /tmp, /dev/shm, /run/user, or other
    writable directories -- a classic malware/implant indicator.
    Legitimate software never runs from these locations.
    """
    try:
        for pid in os.listdir("/proc"):
            if not pid.isdigit():
                continue
            try:
                exe_path = os.readlink(f"/proc/{pid}/exe")
            except Exception:
                continue

            if re.match(r"^/(?:tmp|dev/shm|run/user|var/tmp)/", exe_path):
                try:
                    status = open(f"/proc/{pid}/status", errors="replace").read()
                    uid_m  = re.search(r"^Uid:\s+(\d+)", status, re.M)
                    uid    = uid_m.group(1) if uid_m else "?"
                    user   = uid_to_name(uid)
                except Exception:
                    user = "unknown"

                # Check lateral attribution
                real_actor, lateral_target = _get_lateral_actor(user)
                if lateral_target:
                    alert_user = real_actor
                    note = f"(originally executed as '{lateral_target}' by '{real_actor}' via su)"
                else:
                    alert_user = user
                    note = ""

                detail_msg = (
                    f"Process is running from a writable temporary directory: {exe_path}  "
                    f"(PID {pid}, account: {user}){(' — ' + note) if note else ''}. "
                    f"No legitimate software runs from /tmp or /dev/shm."
                )

                facts: dict = {
                    "PID": pid,
                    "Exe": exe_path,
                }
                if lateral_target:
                    facts["Actual actor"] = real_actor
                    facts["Account used"] = lateral_target

                trigger_alert(
                    "CRITICAL", "Process Running From Suspicious Path", alert_user,
                    detail_msg,
                    env,
                    extra_facts=facts,
                )
    except Exception:
        pass


# -----------------------------------------------------------------
# Check: data exfiltration patterns (scp, rsync, large curl/wget)
# -----------------------------------------------------------------
def check_data_exfiltration(env: dict):
    """
    Detect potential data exfiltration via:
    - scp / sftp outbound transfers
    - rsync to remote hosts
    - Large data piped to curl/wget
    - tar + curl/wget (pack and send)
    """
    if not os.path.exists(AUDIT_LOG):
        return

    _EXFIL_RE = re.compile(
        r"""(?x)
        \bscp\s+.*\s[\w@][\w.@-]+:  # scp to remote
        |\brsync\s+.*(?:-e\s+ssh|rsync://)  # rsync over ssh
        |\btar\s+.*\|\s*(?:curl|wget|nc\b|socat)  # tar piped to network
        |\bcurl\s+.*--data-binary\s+@  # curl uploading file
        |\bsftp\b                    # sftp session
        """, re.IGNORECASE
    )

    for rec in _build_audit_records(AUDIT_LOG):
        cmd = rec.get("cmd", "")
        if not _EXFIL_RE.search(cmd):
            continue

        uid  = rec.get("uid", "0")
        auid = rec.get("auid", "4294967295")
        try:
            if int(auid) >= 4294967294:
                continue
        except ValueError:
            pass

        user = _resolve_audit_user(rec)
        base_username = uid_to_name(uid)
        real_actor, lateral_target = _get_lateral_actor(base_username)
        alert_user = real_actor if lateral_target else user

        detail_msg = f"{alert_user} ran a command that transfers data to an external host: {cmd[:200]}"
        if lateral_target:
            detail_msg += f"  (acting as '{lateral_target}' — real actor: {real_actor})"

        facts: dict = {"Command": cmd[:300]}
        if lateral_target:
            facts["Actual actor"] = real_actor
            facts["Account used"] = lateral_target

        trigger_alert(
            "HIGH", "Potential Data Exfiltration", alert_user,
            detail_msg,
            env,
            extra_facts=facts,
        )


# -----------------------------------------------------------------
# Check: auditd sensitive file access (key=sensitive_files)
# -----------------------------------------------------------------
def check_auditd_sensitive_files(env: dict):
    """
    Parse auditd records with key=sensitive_files or key=ld_preload.
    These are written by the file watches in smart_monitor_auditd.rules:
    /etc/passwd, /etc/shadow, /etc/sudoers, sshd_config, authorized_keys, etc.
    """
    if not os.path.exists(AUDIT_LOG):
        return

    _SENSITIVE_KEYS = {"sensitive_files", "ld_preload", "cron_changes"}
    _SENSITIVE_LABELS = {
        "/etc/passwd":                "user account database",
        "/etc/shadow":                "password hash file",
        "/etc/sudoers":               "sudoers privilege config",
        "/etc/sudoers.d":             "sudoers.d privilege config",
        "/etc/ssh/sshd_config":       "SSH daemon config",
        "/root/.ssh":                 "root SSH keys",
        "/root/.bashrc":              "root shell config",
        "/etc/hosts":                 "hosts file",
        "/etc/ld.so.preload":         "LD_PRELOAD injection file",
        "/etc/crontab":               "system crontab",
        "/etc/cron.d":                "cron.d directory",
        "/var/spool/cron":            "user crontabs",
    }

    for rec in _build_audit_records(AUDIT_LOG):
        key_tag = rec.get("key", "")
        if key_tag not in _SENSITIVE_KEYS:
            continue

        uid  = rec.get("uid", "0")
        auid = rec.get("auid", "4294967295")
        try:
            auid_int = int(auid)
        except ValueError:
            auid_int = 4294967295

        # Skip pure kernel/system events
        if auid_int >= 4294967294 and int(uid) == 0:
            continue

        # Skip known system service accounts
        uname = uid_to_name(uid)
        if uname in DELETION_WHITELIST_USERS:
            continue

        user = _resolve_audit_user(rec)
        fpath = rec.get("name", rec.get("exe", "?"))

        # Find the best matching label
        label = fpath
        for path_prefix, desc in _SENSITIVE_LABELS.items():
            if fpath.startswith(path_prefix):
                label = f"{desc} ({fpath})"
                break

        # Determine operation type from syscall number
        # Use inode-based open flags where available, fallback to sensible label
        syscall = rec.get("syscall", "")
        # Common syscall numbers: open=2, read=0, write=1, openat=257, creat=85
        # For file watches, auditd fires on the permission bits (r/w/a)
        # The key_tag tells us why it fired — use that as primary signal
        if key_tag in ("ld_preload", "log_tampering"):
            op = "wrote to"
        elif key_tag == "cron_changes":
            op = "modified"
        else:
            # Fall back to syscall number — map common ones
            _op_map = {
                "0": "read", "1": "wrote to", "2": "opened",
                "3": "read", "4": "checked", "85": "created",
                "257": "opened", "256": "opened",
            }
            op = _op_map.get(syscall, "accessed")

        # Check lateral attribution
        base_username = uid_to_name(uid)
        real_actor, lateral_target = _get_lateral_actor(base_username)
        alert_user = real_actor if lateral_target else user

        # LD_PRELOAD is always CRITICAL
        severity = "CRITICAL" if key_tag == "ld_preload" else "HIGH"

        detail_msg = f"{alert_user} {op} {label}"
        if lateral_target:
            detail_msg += f" (acting as '{lateral_target}' — real actor: {real_actor})"

        facts: dict = {
            "File":      fpath,
            "Operation": op,
        }
        if lateral_target:
            facts["Actual actor"] = real_actor
            facts["Account used"] = lateral_target

        trigger_alert(
            severity, "Sensitive File Accessed/Modified", alert_user,
            detail_msg,
            env,
            extra_facts=facts,
        )


# -----------------------------------------------------------------
# Check: non-root SSH authorized_keys modification
# -----------------------------------------------------------------

# Track authorized_keys content hashes for all users to detect changes
_SSH_KEY_HASHES: dict = {}   # path -> sha256 hex

def check_user_ssh_keys(env: dict):
    """
    Detect when any user's ~/.ssh/authorized_keys is created, modified,
    or deleted. This catches SSH backdoor planting on normal accounts —
    an attacker who gains write access to /home/naveen/.ssh/ can add
    their own key to permanently re-enter as naveen.

    Strategy:
    - Scan /home/*/  .ssh/authorized_keys on every cycle
    - SHA256 hash each file; alert on first appearance, change, or deletion
    - Also check via auditd key=user_ssh_keys for immediate detection
    - Lateral attribution: if user1 su'd into user2 and modified user2's
      keys, blame user1
    """
    global _SSH_KEY_HASHES

    now   = datetime.now(IST)
    actor, how = _active_root_actor()

    # ── Hash-based detection: scan all users ────────────────────────
    try:
        home_base = "/home"
        if not os.path.isdir(home_base):
            return
        for username in os.listdir(home_base):
            key_path = os.path.join(home_base, username, ".ssh", "authorized_keys")

            # Deletion detection
            if key_path in _SSH_KEY_HASHES and not os.path.exists(key_path):
                real_actor, lateral_target = _get_lateral_actor(username)
                alert_user = real_actor if lateral_target else (actor if how else username)
                trigger_alert(
                    "HIGH", "SSH Authorized Keys Deleted", alert_user,
                    f"The authorized_keys file for '{username}' was deleted. "
                    f"This sometimes happens right after adding a backdoor key to cover tracks.",
                    env,
                    extra_facts={
                        "Account": username,
                        "File":    key_path,
                        **({"Actual actor": real_actor, "Account used": lateral_target}
                           if lateral_target else {}),
                    }
                )
                del _SSH_KEY_HASHES[key_path]
                continue

            if not os.path.exists(key_path):
                continue

            try:
                h = hashlib.sha256()
                with open(key_path, "rb") as fh:
                    for chunk in iter(lambda: fh.read(8192), b""):
                        h.update(chunk)
                current_hash = h.hexdigest()
            except Exception:
                continue

            prev_hash = _SSH_KEY_HASHES.get(key_path)

            if prev_hash is None:
                # First time seeing this file — just baseline it, no alert
                _SSH_KEY_HASHES[key_path] = current_hash
                continue

            if current_hash != prev_hash:
                # File changed — read the current keys for context
                try:
                    keys_content = open(key_path, errors="replace").read()
                    key_count    = len([l for l in keys_content.splitlines()
                                       if l.strip() and not l.startswith("#")])
                except Exception:
                    keys_content = ""
                    key_count    = 0

                real_actor, lateral_target = _get_lateral_actor(username)
                # If root has an active session, they're the most likely actor
                if how and not lateral_target:
                    alert_user = actor
                elif lateral_target:
                    alert_user = real_actor
                else:
                    alert_user = username

                trigger_alert(
                    "CRITICAL", "SSH Authorized Keys Modified", alert_user,
                    f"The authorized_keys file for '{username}' was modified — "
                    f"now contains {key_count} key(s). "
                    f"Someone may have added a persistent SSH backdoor to this account.",
                    env,
                    extra_facts={
                        "Account":   username,
                        "Key count": str(key_count),
                        **({"Actual actor": real_actor, "Account used": lateral_target}
                           if lateral_target else {}),
                        **({"Root session": how} if how and not lateral_target else {}),
                        "Prev hash": prev_hash[:16] + "...",
                        "New hash":  current_hash[:16] + "...",
                    }
                )
                _SSH_KEY_HASHES[key_path] = current_hash

    except Exception:
        pass

    # ── auditd key=user_ssh_keys (write to /home/) ──────────────────
    if not os.path.exists(AUDIT_LOG):
        return

    for rec in _build_audit_records(AUDIT_LOG):
        if rec.get("key", "") != "user_ssh_keys":
            continue

        uid  = rec.get("uid", "0")
        auid = rec.get("auid", "4294967295")
        try:
            auid_int = int(auid)
        except ValueError:
            auid_int = 4294967295

        if auid_int >= 4294967294 and int(uid) == 0:
            continue  # pure kernel/system

        uname = uid_to_name(uid)
        if uname in DELETION_WHITELIST_USERS:
            continue

        fpath = rec.get("name", "?")
        # Only care about .ssh/ paths
        if ".ssh" not in fpath:
            continue

        user = _resolve_audit_user(rec)
        base_username = uid_to_name(uid)

        # Figure out whose .ssh this is
        m_owner = re.search(r"/home/([^/]+)/", fpath)
        owner   = m_owner.group(1) if m_owner else "unknown"

        real_actor, lateral_target = _get_lateral_actor(base_username)
        alert_user = real_actor if lateral_target else user

        # If they're writing to their own .ssh, not suspicious from auditd
        # (hash-based detection above covers the actual content change)
        if owner == base_username:
            continue

        trigger_alert(
            "CRITICAL", "SSH Keys Written To Another User Account", alert_user,
            f"{alert_user} wrote to {owner}'s SSH directory: {fpath}. "
            f"This could be planting a backdoor key in another user's account.",
            env,
            extra_facts={
                "Target account": owner,
                "File":           fpath,
                **({"Actual actor": real_actor, "Account used": lateral_target}
                   if lateral_target else {}),
            }
        )


# -----------------------------------------------------------------
# Check: /proc/sysrq-trigger write
# -----------------------------------------------------------------
def check_sysrq(env: dict):
    """
    Detect writes to /proc/sysrq-trigger via auditd key=sysrq_trigger.

    /proc/sysrq-trigger is a kernel interface that accepts single-char
    commands with immediate, irreversible effects:
      'b' = immediate reboot (no sync, no unmount)
      'o' = immediate power off
      'f' = trigger OOM killer (kills processes)
      'i' = kill all processes except init
      'e' = send SIGTERM to all processes
      'k' = kill all processes on current terminal
      'c' = kernel crash / panic (triggers kdump)

    An attacker with root can use this to instantly destroy a server
    or cover tracks by forcing a reboot that clears memory.
    This is one of the most destructive single-commands on Linux.
    """
    if not os.path.exists(AUDIT_LOG):
        return

    _SYSRQ_EFFECTS = {
        "b": "IMMEDIATE REBOOT (no sync/unmount) — data loss likely",
        "o": "IMMEDIATE POWER OFF",
        "c": "KERNEL CRASH / PANIC (triggers kdump)",
        "f": "OOM killer triggered — may kill critical processes",
        "i": "SIGKILL sent to ALL processes except init",
        "e": "SIGTERM sent to ALL processes",
        "k": "Kill all processes on this terminal (SAK)",
        "m": "Dump memory info to console",
        "s": "Sync all filesystems",
        "u": "Remount all filesystems read-only",
        "9": "Raise oom_score_adj on all tasks",
    }

    for rec in _build_audit_records(AUDIT_LOG):
        if rec.get("key", "") != "sysrq_trigger":
            continue

        uid  = rec.get("uid", "0")
        auid = rec.get("auid", "4294967295")
        try:
            auid_int = int(auid)
        except ValueError:
            auid_int = 4294967295

        if auid_int >= 4294967294 and int(uid) == 0:
            continue

        user = _resolve_audit_user(rec)
        actor, how = _active_root_actor()
        base_username = uid_to_name(uid)
        real_actor, lateral_target = _get_lateral_actor(base_username)
        alert_user = real_actor if lateral_target else (actor if how else user)

        # Try to get the character written from the cmd/args
        cmd = rec.get("cmd", "")
        sysrq_char = ""
        m_char = re.search(r"(?:echo|printf)\s+['\"]?([a-z0-9])['\"]?", cmd, re.IGNORECASE)
        if m_char:
            sysrq_char = m_char.group(1).lower()
        effect = _SYSRQ_EFFECTS.get(sysrq_char, "Unknown sysrq command")

        trigger_alert(
            "CRITICAL", "SysRq Trigger Write Detected", alert_user,
            f"{alert_user} wrote to /proc/sysrq-trigger — "
            f"key '{sysrq_char or '?'}': {effect}",
            env,
            extra_facts={
                "SysRq key":  sysrq_char or "unknown",
                "Effect":     effect,
                "Command":    cmd[:200] if cmd else "unknown",
                **({"Escalated via": how} if how else {}),
                **({"Actual actor": real_actor, "Account used": lateral_target}
                   if lateral_target else {}),
            }
        )


# -----------------------------------------------------------------
# Check: su failures (wrong password on su to another user)
# -----------------------------------------------------------------

# Track per-target su failure counts: {actor -> {target -> [timestamps]}}
_SU_FAILURES: dict = defaultdict(lambda: defaultdict(list))

def check_su_failures(env: dict):
    """
    Detect repeated failed `su` attempts (wrong password) for local accounts.
    This is separate from sudo failures and SSH brute-force.

    Scenarios caught:
    - User trying to su to root without knowing the root password
    - User trying to su to another user account (brute force local pivot)
    - Attacker with a shell trying to escalate laterally

    auth.log patterns:
      su: FAILED su for root by naveen
      su: pam_unix(su:auth): authentication failure; ... user=naveen ruser=ubuntu
    """
    lines = get_cycle_lines(AUTH_LOGS)
    now   = datetime.now(IST)

    for line in lines:
        # Pattern 1: "FAILED su for <target> by <actor>"
        m1 = re.search(
            r"su:\s+FAILED su for (\S+) by (\S+)", line, re.IGNORECASE)
        # Pattern 2: PAM auth failure with ruser
        m2 = re.search(
            r"pam_unix\(su[^)]*\):.*authentication failure.*user=(\S+).*ruser=(\S+)",
            line, re.IGNORECASE)
        # Pattern 3: su authentication failure (Debian/Ubuntu format)
        m3 = re.search(
            r"su\[.*\]:.*authentication failure.*user=(\S+)", line, re.IGNORECASE)

        if m1:
            target, actor = m1.group(1), m1.group(2)
        elif m2:
            target, actor = m2.group(1), m2.group(2)
        elif m3:
            target = m3.group(1)
            actor  = "unknown"
        else:
            continue

        target = target.strip("()")
        actor  = actor.strip("()")

        _SU_FAILURES[actor][target].append(now)
        # Prune old entries
        _SU_FAILURES[actor][target] = [
            t for t in _SU_FAILURES[actor][target]
            if (now - t) <= BRUTE_FORCE_WINDOW
        ]

        count = len(_SU_FAILURES[actor][target])

        # Alert threshold: 3+ failures within the window
        if count >= 3:
            hour      = int(now.strftime("%H"))
            off_hours = hour < 6 or hour > 22
            severity  = "HIGH" if (target == "root" or off_hours) else "MEDIUM"
            trigger_alert(
                severity,
                "Repeated su Authentication Failures",
                actor,
                f"{actor} tried to switch to the '{target}' account {count} times "
                f"with the wrong password in {BRUTE_FORCE_WINDOW}. "
                f"This looks like a local brute-force or privilege escalation attempt.",
                env,
                extra_facts={
                    "Target account": target,
                    "Off-hours":      "Yes — outside business hours" if off_hours else "No",
                }
            )


# -----------------------------------------------------------------
# Check: home directory snooping (user reading another user's files)
# -----------------------------------------------------------------

# Track who accessed whose home dir this cycle: (actor, owner) -> count
_HOME_SNOOP_SEEN: dict = {}

def check_home_dir_snooping(env: dict):
    """
    Detect when a user accesses another user's home directory.

    The classic insider threat: an employee with a shell reads
    /home/finance_user/documents/ or /home/admin/.bash_history
    looking for credentials, sensitive data, or private info.

    Uses auditd key=home_dir_access (openat syscall on /home/).
    Only alerts when actor != file owner (reading your OWN dir is fine).
    Deduplicates: one alert per (actor, victim) pair per cooldown period.

    Whitelist: root/system processes are excluded. Only uid >= 1000.
    """
    if not os.path.exists(AUDIT_LOG):
        return

    now = datetime.now(IST)
    # Purge old seen entries (use 30-min TTL same as MEDIUM cooldown)
    snoop_ttl = timedelta(minutes=30)
    for key in list(_HOME_SNOOP_SEEN.keys()):
        if (now - _HOME_SNOOP_SEEN[key]["ts"]) > snoop_ttl:
            del _HOME_SNOOP_SEEN[key]

    for rec in _build_audit_records(AUDIT_LOG):
        if rec.get("key", "") != "home_dir_access":
            continue

        uid  = rec.get("uid", "0")
        auid = rec.get("auid", "4294967295")

        try:
            uid_int  = int(uid)
            auid_int = int(auid)
        except ValueError:
            continue

        # Only real logged-in users (uid >= 1000, auid set)
        if uid_int < 1000 or auid_int >= 4294967294:
            continue

        fpath = rec.get("name", "")
        if not fpath or "/home/" not in fpath:
            continue

        # Extract the home dir owner from the path
        m_owner = re.search(r"/home/([^/]+)/", fpath)
        if not m_owner:
            continue
        home_owner = m_owner.group(1)

        actor = uid_to_name(uid)

        # Skip if user is accessing their OWN home directory
        if actor == home_owner:
            continue

        # Skip system/service accounts
        if actor in DELETION_WHITELIST_USERS:
            continue

        # Check lateral attribution
        real_actor, lateral_target = _get_lateral_actor(actor)
        alert_user = real_actor if lateral_target else actor

        # Dedup: one alert per (actor, victim) pair per snoop_ttl
        snoop_key = f"{alert_user}:{home_owner}"
        if snoop_key in _HOME_SNOOP_SEEN:
            _HOME_SNOOP_SEEN[snoop_key]["count"] += 1
            continue
        _HOME_SNOOP_SEEN[snoop_key] = {"ts": now, "count": 1}

        hour      = int(now.strftime("%H"))
        off_hours = hour < 6 or hour > 22
        severity  = "HIGH" if off_hours else "MEDIUM"

        # Escalate if accessing sensitive sub-paths
        sensitive_paths = (".ssh", ".bash_history", ".gnupg", "password", "secret", "private")
        if any(sp in fpath.lower() for sp in sensitive_paths):
            severity = "HIGH"

        if lateral_target:
            who_line = f"{real_actor} (acting as '{lateral_target}' via su)"
        else:
            who_line = alert_user

        # Describe what kind of path was accessed
        sensitive_hit = next(
            (sp for sp in (".ssh", ".bash_history", ".gnupg", "password", "secret", "private")
             if sp in fpath.lower()), None)
        if sensitive_hit:
            path_note = f" — accessed sensitive path containing '{sensitive_hit}'"
        else:
            path_note = ""

        trigger_alert(
            severity, "Home Directory Snooping", alert_user,
            f"{who_line} read files inside {home_owner}'s home directory{path_note}: {fpath}",
            env,
            extra_facts={
                "Accessed account": home_owner,
                "File":             fpath,
                "Off-hours":        "Yes — outside business hours" if off_hours else "No",
                **({"Actual actor": real_actor, "Account used": lateral_target}
                   if lateral_target else {}),
            }
        )


# -----------------------------------------------------------------
# Main loop
# -----------------------------------------------------------------
def main():
    global HOSTNAME
    log("Smart Monitor v3.0 starting...")
    load_state()
    env = load_env(ENV_PATH)

    # Set HOSTNAME from .env SERVER_NAME — your human-friendly server label.
    # This name appears in every email subject, alert banner, and JSON record
    # so you can instantly tell which server fired the alert.
    HOSTNAME = env.get("SERVER_NAME", "").strip() or _AUTO_HOSTNAME
    log(f"[INFO] Server identity: {HOSTNAME}  (set SERVER_NAME in .env to customise)")

    cycle = 0
    while True:
        cycle += 1
        log(f"--- Cycle {cycle} ---")
        env = load_env(ENV_PATH)
        # Re-read SERVER_NAME every cycle so a rename takes effect without restart
        HOSTNAME = env.get("SERVER_NAME", "").strip() or _AUTO_HOSTNAME

        load_cycle_lines()

        check_log_tampering(env)
        check_su_sudo(env)
        check_su_failures(env)
        check_ssh_bruteforce(env)
        check_auditd_commands(env)
        check_auditd_deletions(env)
        check_auditd_sensitive_files(env)
        check_user_ssh_keys(env)
        check_user_group_changes(env)
        check_proc_scanner(env)
        check_suspicious_exec_paths(env)
        check_kernel_modules(env)
        check_network_connections(env)
        check_file_integrity(env)
        check_sysrq(env)
        check_insider_evasion(env)
        check_data_exfiltration(env)
        check_home_dir_snooping(env)
        check_dormant_accounts(env)
        check_threat_scores(env)

        save_state()
        time.sleep(60)


if __name__ == "__main__":
    main()
