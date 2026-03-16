"""Timeline Reconstruction Engine.

Parses timestamps from:
  - inode metadata (atime, mtime, ctime) for sensitive files — local mode only
  - /var/log/auth.log  (and /var/log/secure on RHEL-based systems)
  - /var/log/syslog    (and /var/log/messages)
  - per-user .bash_history  (including embedded HISTTIMEFORMAT timestamps)

Produces a list of TimelineEvent dicts sorted by timestamp, with unknown
timestamps pushed to the end.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .extractor import FilesystemAccessor

# ── Helpers ───────────────────────────────────────────────────────────────────

def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def _from_epoch(epoch: float) -> str:
    return _fmt(datetime.fromtimestamp(epoch, tz=timezone.utc).replace(tzinfo=None))


def _make_event(
    timestamp: Optional[str],
    source: str,
    event_type: str,
    detail: str,
    severity: str = "info",
    data: Optional[dict] = None,
) -> Dict:
    ev = {
        "timestamp": timestamp or "unknown",
        "source": source,
        "event_type": event_type,
        "detail": detail,
        "severity": severity,
    }
    if data is not None:
        ev["data"] = data
    return ev


# ── Suspicious bash command patterns ─────────────────────────────────────────
# Each entry: (compiled_regex, human_label, severity)
# severity: info | medium | high | critical

SUSPICIOUS_CMDS: List[tuple] = [
    # ── Network recon ────────────────────────────────────────────────────────
    (re.compile(r"\bnmap\b"),
     "Network scanner (nmap) executed", "medium"),
    (re.compile(r"\b(masscan|zmap|rustscan)\b"),
     "High-speed port scanner executed", "high"),
    (re.compile(r"\b(nikto|dirb|gobuster|ffuf|wfuzz|feroxbuster)\b"),
     "Web content/vulnerability scanner executed", "high"),
    (re.compile(r"\b(enum4linux|ldapsearch|snmpwalk|dnsenum|dnsrecon)\b"),
     "Service/domain enumeration tool executed", "high"),
    # ── Exploitation frameworks ──────────────────────────────────────────────
    (re.compile(r"\b(msfconsole|msfvenom|metasploit)\b"),
     "Metasploit tool executed", "high"),
    (re.compile(r"\bsqlmap\b"),
     "sqlmap SQL-injection tool executed", "high"),
    (re.compile(r"\b(searchsploit|exploitdb)\b"),
     "Exploit database search executed", "medium"),
    (re.compile(r"\bburpsuite\b|\bburp\b"),
     "Burp Suite executed", "medium"),
    # ── Credential attacks ──────────────────────────────────────────────────
    (re.compile(r"\bhydra\b"),
     "Hydra brute-force tool executed", "high"),
    (re.compile(r"\b(john|hashcat|medusa|crackmapexec)\b"),
     "Password cracker / credential spray executed", "high"),
    (re.compile(r"\b(mimikatz|secretsdump|hashdump)\b"),
     "Credential dumping tool executed", "critical"),
    (re.compile(r"cat\s+/etc/shadow"),
     "Shadow password file read directly", "high"),
    (re.compile(r"cat\s+.*[/\\](\.ssh[/\\]id_rsa|id_ed25519|\.pem|\.key)\b"),
     "Private key / certificate read via cat", "high"),
    (re.compile(r"\bsu\s+\S|\bsu\s*-\b"),
     "User switch (su) executed", "medium"),
    (re.compile(r"\bpasswd\s+\S"),
     "Password change command issued for another user", "medium"),
    (re.compile(r"\bchpasswd\b"),
     "Batch password change (chpasswd) executed", "high"),
    # ── Privilege escalation ─────────────────────────────────────────────────
    (re.compile(r"\bsudo\b"),
     "sudo executed", "info"),
    (re.compile(r"\b(linpeas|linenum|lse\.sh|pspy|pwnkit)\b"),
     "Privilege escalation enumeration script executed", "high"),
    (re.compile(r"\bchmod\b.+[+][xs]"),
     "Executable/SUID bit set via chmod", "high"),
    (re.compile(r"\bchmod\s+[0-7]*7[0-9][0-9]\b|\bchmod\s+777\b"),
     "World-writable permissions set", "high"),
    (re.compile(r"find\s+.+[-]perm\s+.*([-+/]4000|[-+/]2000|-u[+=]s|-g[+=]s)"),
     "SUID/SGID binary search (privilege escalation recon)", "high"),
    (re.compile(r"find\s+/\s+.*[-]writable\b|find\s+/\s+.*[-]perm\s+-[0-9]*2\b"),
     "World-writable file/directory search", "medium"),
    # ── Reverse shells ───────────────────────────────────────────────────────
    (re.compile(r"bash\s+-[ic]\s+.*/dev/tcp/"),
     "Bash /dev/tcp reverse shell", "critical"),
    (re.compile(r"bash\s+-[ic]\s.*>&.*\d+\.\d+|>\s*&\s*/dev/tcp/"),
     "Bash reverse shell redirect detected", "critical"),
    (re.compile(r"python[23]?\s+-c\s+.*socket.*connect|python[23]?\s+-c\s+.*subprocess.*Popen"),
     "Python reverse shell one-liner", "critical"),
    (re.compile(r"perl\s+-e.*socket.*connect|perl\s+-MSocket"),
     "Perl reverse shell one-liner", "critical"),
    (re.compile(r"ruby\s+-rsocket|php\s+-r.*fsockopen"),
     "Ruby/PHP reverse shell one-liner", "critical"),
    (re.compile(r"\bsocat\b.*exec|\bsocat\b.*EXEC"),
     "socat shell execution", "critical"),
    # ── Persistence / scheduled tasks ────────────────────────────────────────
    (re.compile(r"\bcrontab\b"),
     "Crontab accessed/modified", "medium"),
    (re.compile(r"\bsystemctl\s+enable\b"),
     "Systemd service enabled (persistence)", "medium"),
    (re.compile(r"\b(update-rc\.d|insserv)\b"),
     "SysV init service registration", "medium"),
    (re.compile(r"\bat\s+"),
     "at job scheduled", "medium"),
    # ── Exfiltration / data transfer ─────────────────────────────────────────
    (re.compile(r"\b(scp|sftp)\b"),
     "Secure copy / SFTP transfer executed", "medium"),
    (re.compile(r"\brsync\b"),
     "rsync transfer executed", "medium"),
    (re.compile(r"\b(wget|curl)\b.+https?://"),
     "Remote file download via wget/curl", "medium"),
    (re.compile(r"\bssh\b.+-[DRL]\b"),
     "SSH tunnel created (-D/-R/-L)", "high"),
    # ── Network capture / traffic analysis ───────────────────────────────────
    (re.compile(r"\b(wireshark|tcpdump|tshark)\b"),
     "Packet capture tool executed", "medium"),
    (re.compile(r"\b(aircrack-ng|airmon-ng|airodump-ng|aireplay-ng)\b"),
     "Wireless attack tool executed", "high"),
    # ── Log tampering / anti-forensics ───────────────────────────────────────
    (re.compile(r"\bhistory\s+-[caw]\b|unset\s+HISTFILE|HISTSIZE\s*=\s*0"),
     "History clear / disable attempted", "high"),
    (re.compile(r">\s*/var/log/\S+"),
     "Log file overwritten/truncated via shell redirect", "high"),
    (re.compile(r"\brm\s+-[rf]{1,2}\s+/var/log/"),
     "Log directory/file deleted", "high"),
    (re.compile(r"\bshred\b.*log"),
     "Log file shredded", "high"),
    (re.compile(r"\brm\s+-[rf]{1,2}\b"),
     "Forced recursive file removal", "medium"),
    # ── Anonymisation / evasion ───────────────────────────────────────────────
    (re.compile(r"\bproxychains\b"),
     "proxychains (traffic proxying) executed", "medium"),
    (re.compile(r"\btor\b"),
     "Tor anonymisation tool invoked", "medium"),
    # ── System utilities with forensic significance ───────────────────────────
    (re.compile(r"\b(nc|netcat)\b"),
     "netcat executed", "medium"),
    (re.compile(r"\bsocat\b"),
     "socat executed", "medium"),
    (re.compile(r"\bdd\b.+if="),
     "dd disk/file operation executed", "medium"),
]

# ── Command categorization ───────────────────────────────────────────────────
# Order matters: first match wins.
CATEGORY_PATTERNS: List[tuple] = [
    # ── Highest-priority: active attack TTPs ──────────────────────────────
    ("Anti-Forensics",       re.compile(
        r"history\s+-[caw]|unset\s+HISTFILE|HISTSIZE\s*=\s*0"
        r"|shred\b|wipe\b|dd\s+if=/dev/zero.+of=.*/var/log"
        r"|>\s*/var/log/\S+|truncate\s.*-s\s*0\s.*/var/log"
        r"|rm\s+-[rf]+\s+/var/log/"
    )),
    ("Reverse Shell",        re.compile(
        r"bash\s+-[ic]\s+['\"]?.*(/dev/tcp/|/dev/udp/|>&\s*\d+\.\d+)"
        r"|python3?\s+-c\s+.*socket\.connect"
        r"|perl\s+-[Mme]+.*socket.*connect"
        r"|ruby\s+-rsocket\s+-e"
        r"|php\s+.*fsockopen"
        r"|socat\s+.*EXEC"
        r"|nc\s+.*-e\s+/bin/(ba)?sh"
    )),
    ("Exploitation",         re.compile(
        r"\b(msfconsole|msfvenom|sqlmap|searchsploit|burpsuite)\b|\.\./exploit"
    )),
    ("Credential Access",    re.compile(
        r"\b(hydra|john|hashcat|medusa|crackmapexec|secretsdump|hashdump|mimikatz|chpasswd)\b"
        r"|cat\s+/etc/shadow|cat\s+/etc/passwd"
        r"|cat\s+\S*id_rsa|cat\s+\S*\.pem|cat\s+\S*\.key"
        r"|\bsu\b(\s|$)|\bsu\s+-|\bpasswd\b"
        r"|ssh\s+\S+@\S+"
    )),
    ("Privilege Escalation", re.compile(
        r"\b(linpeas|linenum|lse\.sh|pspy|pwnkit|pkexec)\b"
        r"|sudo\s+-[siu]|\bsudo\s+-l\b"
        r"|chmod\s+(777|[0-9]*[467][0-9]|[+]s)\b"
        r"|find\s+.*-perm\s+[-/][246]?[467][0-9][0-9]"
        r"|find\s+.*-perm\s+[-/]?u[+=]s"
        r"|find\s+.*-writable"
    )),
    ("Reconnaissance",       re.compile(
        r"\b(nmap|masscan|zmap|netstat|ss|arp|whois|dig|host|traceroute"
        r"|ping|ifconfig|enum4linux|ldapsearch|snmpwalk|nikto|dirb|gobuster"
        r"|ffuf|wfuzz|feroxbuster|rustscan|dnsenum|dnsrecon|smbclient|smbmap)\b"
        r"|ip\s+(addr|route|link|neigh|a)\b"
    )),
    ("Lateral Movement",     re.compile(
        r"\b(psexec|wmiexec|evil-winrm|xfreerdp|rdesktop)\b"
    )),
    ("Persistence",          re.compile(
        r"\b(crontab|update-rc\.d|insserv|rc\.local)\b"
        r"|systemctl\s+enable\b"
        r"|at\s+[0-9]"
        r"|\.bashrc|\.profile|\.bash_logout"
    )),
    ("Exfiltration",         re.compile(
        r"\b(scp|rsync|sftp|ftp)\b"           # any use of transfer tools
        r"|curl\s+.*-[dFT]\b|wget\s+.*--post"
        r"|nc\s+.*-[we]\s+\d"
        r"|ssh\s+.*-[DRL]\s+\d"               # SSH tunnels
    )),
    ("Data Collection",      re.compile(
        r"\b(find|locate|grep|cat)\b.*\b(passwd|shadow|id_rsa|\.key|\.pem|wallet|\.kdbx|secret|credentials)\b"
    )),
    ("Network Capture",      re.compile(
        r"\b(tcpdump|wireshark|tshark|airodump-ng|aircrack-ng|airmon-ng)\b"
    )),
    ("Download",             re.compile(
        r"\b(wget|curl)\b.+https?://"
    )),
    ("Permissions Change",   re.compile(
        r"\b(chmod|chown|chgrp)\b"
    )),
    ("Code Execution",       re.compile(
        r"\b(python3?|perl|ruby|bash|sh)\b\s+\S+\.(?:py|pl|rb|sh)\b|\.\./\S+|\./\S+"
    )),
    ("Shell Access",         re.compile(
        r"\b(ssh|telnet|nc|netcat|socat)\b"
    )),
    ("Process / System",     re.compile(
        r"\b(ps|top|htop|pstree|uname|env|set|export|iptables|ip6tables|sysctl)\b"
    )),
    ("Package Management",   re.compile(
        r"\b(apt|apt-get|dpkg|pip3?|pip\s|gem|yum|dnf|pacman)\b"
        r"|git\s+(clone|pull|fetch)\b"
    )),
    ("File Operations",      re.compile(
        r"\b(cp|mv|rm|mkdir|tar|zip|gzip|dd|ln)\b"
    )),
]


def _categorize_command(cmd: str) -> str:
    """Return the first matching behavioral category for a command."""
    for cat, pat in CATEGORY_PATTERNS:
        if pat.search(cmd):
            return cat
    return "General"


# ── Attack chain detection ────────────────────────────────────────────────────
# Each chain: (name, severity, [step_regex, ...])
# Steps must appear in order anywhere across the session commands.
ATTACK_CHAINS: List[tuple] = [
    (
        "Malware download → permission grant → execute",
        "critical",
        [
            re.compile(r"\b(wget|curl)\b.+https?://"),
            re.compile(r"chmod\s+[+]x|chmod\s+7"),
            re.compile(r"\.\./\S+|\./\S+|bash\s+\S+\.sh|sh\s+\S+\.sh"),
        ],
    ),
    (
        "Credential dump → offline crack",
        "critical",
        [
            re.compile(r"\b(hashdump|secretsdump|mimikatz)\b|cat\s+/etc/shadow"),
            re.compile(r"\b(john|hashcat|hydra)\b"),
        ],
    ),
    (
        "Reverse shell staging and catch",
        "critical",
        [
            re.compile(r"\b(msfvenom|msfconsole)\b"),
            re.compile(r"\bsessions\b|\b(nc|netcat)\s+.*-lv"),
        ],
    ),
    (
        "Bash /dev/tcp reverse shell",
        "critical",
        [
            re.compile(r"bash\s+-[ic]\s+['\"]?.*(/dev/tcp/|/dev/udp/|>&\s*\d+\.\d+)"),
        ],
    ),
    (
        "SUID search → SUID binary abuse",
        "high",
        [
            re.compile(r"find\s+.*-perm\s+[-/][246]?[467][0-9][0-9]|find\s+.*-perm\s+[-/]?u[+=]s"),
            re.compile(r"\b(sudo|pkexec)\b|\./\S+"),
        ],
    ),
    (
        "Network recon → credential attack → lateral movement",
        "high",
        [
            re.compile(r"\b(nmap|masscan|rustscan|ping|netstat)\b|ip\s+(addr|route|link)\b"),
            re.compile(r"\b(hydra|medusa|john|hashcat|crackmapexec)\b|\bsu\b|\bpasswd\b"),
            re.compile(r"\b(ssh|scp|evil-winrm|psexec|wmiexec)\b\s+\S+@\S+"),
        ],
    ),
    (
        "Persistence installation",
        "high",
        [
            re.compile(r"systemctl\s+enable\b|crontab\s+-[el]|update-rc\.d"),
            re.compile(r"\.bashrc|\.profile|\.bash_logout|/etc/cron"),
        ],
    ),
    (
        "Data staging → exfiltration",
        "high",
        [
            re.compile(r"\b(tar|zip|find)\b.*\.(?:sql|bak|kdbx|key|pem|csv|db|xlsx)"),
            re.compile(r"\b(scp|rsync|curl|sftp)\b"),
        ],
    ),
    (
        "Privilege escalation recon → exploit",
        "high",
        [
            re.compile(r"\b(linpeas|linenum|lse\.sh|id|sudo\s+-l|pspy)\b"),
            re.compile(r"\bsudo\b|\bsu\s+-\b|pkexec|\.\./exploit"),
        ],
    ),
    (
        "Intrusion then log tampering",
        "high",
        [
            re.compile(r"\b(ssh|nc|msfconsole|exploit|hydra)\b"),
            re.compile(r"history\s+-[caw]|>\s*/var/log/|unset\s+HISTFILE|rm\s+-[rf]+\s+/var/log"),
        ],
    ),
]

_FREQ_TOOLS = [
    "nmap", "masscan", "rustscan", "msfconsole", "msfvenom",
    "hydra", "medusa", "john", "hashcat", "crackmapexec",
    "sqlmap", "searchsploit", "linpeas", "linenum", "pspy",
    "ssh", "scp", "sftp", "rsync", "curl", "wget", "nc", "socat",
    "tcpdump", "wireshark", "tshark",
    "gobuster", "dirb", "ffuf", "nikto", "wfuzz", "enum4linux",
    "smbclient", "ldapsearch", "snmpwalk",
    "python3", "python", "perl", "ruby",
    "crontab", "systemctl",
]

_AF_INLINE: List[tuple] = [
    (re.compile(r"history\s+-[caw]"),             "History explicitly cleared/written"),
    (re.compile(r"unset\s+HISTFILE"),              "HISTFILE unset — session will not be logged"),
    (re.compile(r"HISTSIZE\s*=\s*0"),              "HISTSIZE set to 0 — history recording disabled"),
    (re.compile(r">\s*/var/log/\S+"),             "Log file truncated via shell redirect"),
    (re.compile(r"\bshred\b.*/var/log/"),         "Log file shredded"),
    (re.compile(r"rm\s+-[rf]+\s+/var/log/"),       "Log directory deleted"),
    (re.compile(r"dd\s+if=/dev/zero.+of=.*log"),  "Log overwritten with zeros via dd"),
]


def _detect_chains(commands: List[str]) -> List[tuple]:
    """Return (name, severity, [matched_step_cmd, ...]) for each detected chain."""
    found = []
    for name, severity, steps in ATTACK_CHAINS:
        step_matches: List[str] = []
        search_from = 0
        for step_re in steps:
            matched = None
            for i in range(search_from, len(commands)):
                if step_re.search(commands[i]):
                    matched = commands[i]
                    search_from = i + 1
                    break
            if matched is None:
                break
            step_matches.append(matched)
        else:
            found.append((name, severity, step_matches))
    return found


# ── Log parsing patterns ──────────────────────────────────────────────────────

AUTH_PATTERNS: List[tuple] = [
    (re.compile(r"Accepted (?:password|publickey) for (\S+) from (\S+)"),
     "SSH login success: user={1} from={2}", "medium"),
    (re.compile(r"Failed password for (?:invalid user )?(\S+) from (\S+)"),
     "SSH login failure: user={1} from={2}", "high"),
    (re.compile(r"sudo:\s+(\S+) .* COMMAND=(.+)"),
     "sudo: user={1} cmd={2}", "medium"),
    (re.compile(r"new user: name=(\S+)"),
     "User account created: {1}", "high"),
    (re.compile(r"useradd.* '(\S+)'"),
     "useradd: {1}", "high"),
    (re.compile(r"session opened for user (\S+) by"),
     "Session opened: {1}", "info"),
    (re.compile(r"session closed for user (\S+)"),
     "Session closed: {1}", "info"),
]

SYSLOG_PATTERNS: List[tuple] = [
    (re.compile(r"(tor|openvpn|wireguard|wg-quick)\["),
     "Network anonymizer service active: {1}", "medium"),
    (re.compile(r"Started\s+(.+?)\s*\.service"),
     "Service started: {1}", "info"),
    (re.compile(r"kernel:.*segfault at"),
     "Kernel segfault (possible exploit)", "high"),
    (re.compile(r"OUT=\S+ SRC=(\S+) DST=(\S+).*DPT=(\S+)"),
     "Firewall event: {1} → {2}:{3}", "info"),
    (re.compile(r"(msfconsole|metasploit|msfvenom)"),
     "Metasploit reference in syslog", "high"),
]


def _parse_log_timestamp(line: str) -> Optional[datetime]:
    """Try multiple common log timestamp formats."""
    # ISO-8601: 2026-02-12T10:21:00 or 2026-02-12 10:21:00
    m = re.match(r"(\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2})", line)
    if m:
        raw = m.group(1).replace("T", " ")
        try:
            return datetime.strptime(raw, "%Y-%m-%d %H:%M:%S")
        except ValueError:
            pass
    # classic syslog: Feb 12 10:21:00
    m = re.match(r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
    if m:
        try:
            year = datetime.now().year
            return datetime.strptime(f"{year} {m.group(1)}", "%Y %b %d %H:%M:%S")
        except ValueError:
            pass
    return None


def _apply_log_patterns(
    line: str, patterns: List[tuple], source: str
) -> Optional[Dict]:
    ts = _parse_log_timestamp(line)
    ts_str = _fmt(ts) if ts else None
    for pattern, label_tmpl, severity in patterns:
        m = pattern.search(line)
        if m:
            label = label_tmpl
            for i, g in enumerate(m.groups(), 1):
                label = label.replace(f"{{{i}}}", (g or "").strip()[:60])
            return _make_event(ts_str, source, "log_event", label, severity)
    return None


# ── Scanner functions ─────────────────────────────────────────────────────────

def scan_inode_metadata(fs: FilesystemAccessor) -> List[Dict]:
    """Collect mtime/atime for security-sensitive files (local mode only)."""
    if fs.mode != "local":
        return []

    candidates = [
        "/etc/passwd", "/etc/shadow", "/etc/sudoers",
        "/etc/crontab", "/etc/ssh/sshd_config",
        "/root/.bash_history", "/root/.bashrc",
        "/etc/hosts", "/etc/resolv.conf",
    ]

    events: List[Dict] = []

    for p in candidates:
        full = fs._local_full(p)
        try:
            s = os.stat(full)
            events.append(_make_event(
                _from_epoch(s.st_mtime), "inode", "file_modified",
                f"Modified: {p}", "info",
            ))
        except OSError:
            pass

    # per-user home dirs
    home_base = fs._local_full("/home")
    try:
        for user in os.listdir(home_base):
            hist = os.path.join(home_base, user, ".bash_history")
            try:
                s = os.stat(hist)
                events.append(_make_event(
                    _from_epoch(s.st_mtime), "inode", "file_modified",
                    f"Modified: /home/{user}/.bash_history", "info",
                ))
            except OSError:
                pass
    except OSError:
        pass

    return events


def scan_bash_history(fs: FilesystemAccessor) -> List[Dict]:  # noqa: C901
    """Multi-layer bash history forensic analysis.

    Per history file, six analysis passes are applied:
      1. Parse & timestamp reconstruction
           - HISTTIMEFORMAT (#epoch) lines used directly.
           - If none found, inode mtime anchors the last command and all
             timestamps are interpolated backwards at 30 s/cmd average.
             Reconstructed timestamps are marked as approximate in the event.
      2. Session grouping
           - Consecutive commands separated by > 10 minutes form a new session.
           - Each session emits a summary event (time range, duration, dominant
             activity categories).
      3. Per-command categorization + suspicious pattern flagging
           - Every command is labelled with a behavioral category
             (Reconnaissance, Exploitation, Credential Access, …).
           - SUSPICIOUS_CMDS patterns emit a flagged event with category tag.
      4. Attack chain detection
           - Known multi-step sequences (download→chmod→execute, etc.) are
             matched across the full command list in order.
           - Matched chains emit a single high/critical summary event.
      5. Frequency analysis
           - Tools executed ≥ 3 times emit a frequency summary event,
             indicating possible scripted or campaign-level use.
      6. Anti-forensics inline detection
           - `history -c`, `unset HISTFILE`, log truncation, etc. are
             flagged individually as they appear in the command stream.
    """
    history_files: List[tuple] = []

    if fs.exists("/root/.bash_history"):
        history_files.append(("/root/.bash_history", "root"))

    for user in fs.list_dir("/home"):
        p = f"/home/{user}/.bash_history"
        if fs.exists(p):
            history_files.append((p, user))

    events: List[Dict] = []

    for hist_path, user in history_files:
        content = fs.read_file(hist_path, max_bytes=2_000_000)
        if not content:
            continue

        raw = content.decode("utf-8", errors="ignore").strip()

        # ── Wiped history ────────────────────────────────────────────────────
        if len(raw) < 5:
            events.append(_make_event(
                None, "bash_history", "anti_forensics",
                f"[{user}] Bash history appears wiped (file is empty)", "high",
            ))
            continue

        # ── Pass 1: parse (epoch_or_None, command, line_no) pairs ─────────────
        raw_entries: List[tuple] = []   # (Optional[float], str, int)
        pending_epoch: Optional[float] = None
        has_any_timestamp = False
        raw_line_no = 0

        for line in raw.splitlines():
            raw_line_no += 1
            line = line.rstrip()
            if not line:
                continue
            if line.startswith("#") and line[1:].isdigit():
                try:
                    pending_epoch = float(line[1:])
                    has_any_timestamp = True
                except ValueError:
                    pass
                continue
            raw_entries.append((pending_epoch, line, raw_line_no))
            pending_epoch = None

        if not raw_entries:
            continue

        # ── Timestamp reconstruction (no HISTTIMEFORMAT) ─────────────────────
        if not has_any_timestamp:
            inode_mtime: Optional[float] = None
            if fs.mode == "local":
                try:
                    inode_mtime = os.stat(fs._local_full(hist_path)).st_mtime
                except OSError:
                    pass

            if inode_mtime is not None:
                n = len(raw_entries)
                AVG_INTERVAL = 30  # seconds between commands (heuristic)
                raw_entries = [
                    (inode_mtime - (n - 1 - i) * AVG_INTERVAL, cmd, ln)
                    for i, (_, cmd, ln) in enumerate(raw_entries)
                ]
                events.append(_make_event(
                    _from_epoch(inode_mtime),
                    "bash_history",
                    "timestamp_reconstruction",
                    (
                        f"[{user}] No HISTTIMEFORMAT detected in history file. "
                        f"All timestamps estimated via inode mtime "
                        f"({_from_epoch(inode_mtime)}) with 30 s/cmd back-interpolation. "
                        f"Treat as approximate — enable HISTTIMEFORMAT for exact timestamps."
                    ),
                    "info",
                ))

        # ── Pass 2: session grouping ─────────────────────────────────────────
        SESSION_GAP = 600  # 10 minutes
        sessions: List[List[tuple]] = []
        cur_session: List[tuple] = []

        for entry in raw_entries:
            epoch, _cmd, _ln = entry
            if not cur_session or epoch is None:
                cur_session.append(entry)
            else:
                prev_epoch = cur_session[-1][0]
                if prev_epoch is None or (epoch - prev_epoch) <= SESSION_GAP:
                    cur_session.append(entry)
                else:
                    sessions.append(cur_session)
                    cur_session = [entry]
        if cur_session:
            sessions.append(cur_session)

        for sess_idx, session in enumerate(sessions, 1):
            cmds = [c for _, c, _ in session]
            ts_vals = [e for e, _, _ in session if e is not None]

            if ts_vals:
                sess_start = _from_epoch(ts_vals[0])
                sess_end   = _from_epoch(ts_vals[-1])
                dur_s      = int(ts_vals[-1] - ts_vals[0])
                dur_str    = f"{dur_s // 60}m {dur_s % 60}s"
            else:
                sess_start = sess_end = "unknown"
                dur_str = "unknown"

            # Tally categories for this session
            cat_counts: Dict[str, int] = {}
            for c in cmds:
                cat = _categorize_command(c)
                cat_counts[cat] = cat_counts.get(cat, 0) + 1
            cat_counts.pop("General", None)
            dominant = sorted(cat_counts.items(), key=lambda x: -x[1])
            activity_str = (
                ", ".join(f"{cat} ×{n}" for cat, n in dominant[:5])
                if dominant else "General commands only"
            )

            events.append(_make_event(
                sess_start,
                "bash_history",
                "session_summary",
                (
                    f"[{user}] Session {sess_idx}/{len(sessions)} "
                    f"— {len(cmds)} cmd(s) "
                    f"| {sess_start} → {sess_end} ({dur_str}) "
                    f"| Activity: {activity_str}"
                ),
                "info",
            ))

        # ── Pass 3: per-command events (suspicious + category) ───────────────
        all_commands = [c for _, c, _ in raw_entries]

        for epoch, cmd, line_no in raw_entries:
            ts_str = _from_epoch(epoch) if epoch is not None else None
            cat    = _categorize_command(cmd)
            tag    = f"[{cat}] " if cat != "General" else ""

            flagged = False
            for pattern, label, severity in SUSPICIOUS_CMDS:
                if pattern.search(cmd):
                    events.append(_make_event(
                        ts_str, "bash_history", "suspicious_command",
                        f"[{user}] {tag}{label}: `{cmd[:120]}`", severity,
                        data={"user": user, "category": cat, "label": label, "command": cmd[:200], "line_no": line_no},
                    ))
                    flagged = True
                    break

            # Emit a plain categorized timeline event for meaningful non-suspicious cmds
            if not flagged and cat not in ("General", "File Operations"):
                events.append(_make_event(
                    ts_str, "bash_history",
                    f"cmd_{cat.lower().replace(' ', '_')}",
                    f"[{user}] [{cat}] {cmd[:120]}",
                    "info",
                ))

        # ── Pass 4: attack chain detection ───────────────────────────────────
        # Build first-occurrence line-number map for step lookups
        cmd_to_line: Dict[str, int] = {}
        for _, cmd, ln in raw_entries:
            if cmd not in cmd_to_line:
                cmd_to_line[cmd] = ln

        for chain_name, severity, steps in _detect_chains(all_commands):
            step_preview = " → ".join(f"`{s[:70]}`" for s in steps)
            step_line_nos = [cmd_to_line.get(s) for s in steps]
            events.append(_make_event(
                None,
                "bash_history",
                "attack_chain",
                f"[{user}] Attack chain detected: {chain_name} | Steps: {step_preview}",
                severity,
                data={"user": user, "chain": chain_name, "steps": [s[:200] for s in steps], "step_line_nos": step_line_nos},
            ))

        # ── Pass 5: frequency analysis ────────────────────────────────────────
        freq_hits = []
        for tool in _FREQ_TOOLS:
            count = sum(
                1 for c in all_commands
                if re.search(rf"\b{re.escape(tool)}\b", c)
            )
            if count >= 3:
                sev = "high" if count >= 10 else "medium"
                freq_hits.append({"tool": tool, "count": count, "severity": sev})
                events.append(_make_event(
                    None,
                    "bash_history",
                    "frequency_analysis",
                    f"[{user}] `{tool}` invoked {count}× — possible scripted or repeated campaign use",
                    sev,
                    data={"user": user, "tool": tool, "count": count},
                ))

        # ── Pass 6: anti-forensics inline scan ───────────────────────────────
        for epoch, cmd, _ln in raw_entries:
            ts_str = _from_epoch(epoch) if epoch is not None else None
            for af_pat, af_desc in _AF_INLINE:
                if af_pat.search(cmd):
                    events.append(_make_event(
                        ts_str, "bash_history", "anti_forensics",
                        f"[{user}] {af_desc}: `{cmd[:120]}`", "high",
                    ))

        # ── Pass 7: category-level activity profile narrative ─────────────────
        # Tally every command across all sessions by behavioral category and
        # produce a single structured summary event per user.
        _HIGH_RISK_CATS = {
            "Reverse Shell", "Exploitation", "Credential Access",
            "Privilege Escalation", "Anti-Forensics", "Exfiltration",
            "Lateral Movement", "Persistence",
        }
        cat_counts: Dict[str, int] = {}
        for _, cmd, _ in raw_entries:
            cat = _categorize_command(cmd)
            cat_counts[cat] = cat_counts.get(cat, 0) + 1

        if cat_counts:
            total = sum(cat_counts.values())
            # Build sorted table: high-risk categories first, then by count desc
            def _cat_sort(kv):
                cat, cnt = kv
                return (0 if cat in _HIGH_RISK_CATS else 1, -cnt)

            breakdown = "\n".join(
                f"  {cat:<22}  {cnt:>4}  ({100*cnt/total:5.1f}%)"
                for cat, cnt in sorted(cat_counts.items(), key=_cat_sort)
            )
            dominant = max(cat_counts, key=lambda c: cat_counts[c])
            high_risk_present = bool(_HIGH_RISK_CATS & cat_counts.keys())
            profile_sev = "high" if high_risk_present else "medium"
            dominant_note = (
                f"Dominant category: {dominant} ({cat_counts[dominant]} cmds)"
                f"{' — HIGH RISK' if dominant in _HIGH_RISK_CATS else ''}"
            )
            categories_data = [
                {
                    "name": cat,
                    "count": cnt,
                    "pct": round(100 * cnt / total, 1),
                    "high_risk": cat in _HIGH_RISK_CATS,
                }
                for cat, cnt in sorted(cat_counts.items(), key=_cat_sort)
            ]
            events.append(_make_event(
                None, "bash_history", "activity_profile",
                f"[{user}] Activity profile — {total} commands across "
                f"{len(cat_counts)} categories.\n{breakdown}\n{dominant_note}",
                profile_sev,
                data={
                    "user": user,
                    "total": total,
                    "dominant": dominant,
                    "high_risk_present": high_risk_present,
                    "categories": categories_data,
                },
            ))

        # ── Pass 8: raw history export ────────────────────────────────────────
        # Collect suspicious line numbers from Pass 3 events already appended.
        susp_lines = {
            e["data"]["line_no"]
            for e in events
            if e.get("event_type") == "suspicious_command"
            and e.get("data", {}).get("user") == user
            and e["data"].get("line_no") is not None
        }
        history_lines = [
            {
                "no": ln,
                "ts": _from_epoch(epoch) if epoch is not None else None,
                "cmd": cmd,
                "category": _categorize_command(cmd),
                "suspicious": ln in susp_lines,
            }
            for epoch, cmd, ln in raw_entries
        ]
        events.append(_make_event(
            None, "bash_history", "bash_history_raw",
            f"[{user}] Raw bash history — {len(history_lines)} commands",
            "info",
            data={"user": user, "path": hist_path, "lines": history_lines},
        ))

    return events


def scan_logs(fs: FilesystemAccessor) -> List[Dict]:
    """Parse system logs for authentication, service, and anomaly events."""
    log_targets = [
        ("/var/log/auth.log",  AUTH_PATTERNS,   "auth.log"),
        ("/var/log/secure",    AUTH_PATTERNS,   "secure"),
        ("/var/log/syslog",    SYSLOG_PATTERNS, "syslog"),
        ("/var/log/messages",  SYSLOG_PATTERNS, "messages"),
    ]

    events: List[Dict] = []

    for log_path, patterns, source in log_targets:
        content = fs.read_file(log_path, max_bytes=5_000_000)
        if not content:
            continue

        raw_len = len(content.strip())
        if raw_len < 64:
            events.append(_make_event(
                None, source, "anti_forensics",
                f"Log appears truncated or wiped: {log_path} ({raw_len} bytes)", "high",
            ))
            continue

        lines = content.decode("utf-8", errors="ignore").splitlines()
        # Analyse the most recent 10 000 lines to keep performance reasonable
        for line in lines[-10_000:]:
            ev = _apply_log_patterns(line, patterns, source)
            if ev:
                events.append(ev)

    return events


# ── Public entry point ────────────────────────────────────────────────────────

def build_timeline(fs: FilesystemAccessor) -> List[Dict]:
    """Build and return the sorted timeline for the given filesystem."""
    events: List[Dict] = []
    events.extend(scan_inode_metadata(fs))
    events.extend(scan_bash_history(fs))
    events.extend(scan_logs(fs))

    def sort_key(e: Dict) -> str:
        ts = e["timestamp"]
        return "9999-99-99 99:99:99" if ts == "unknown" else ts

    events.sort(key=sort_key)
    return events
