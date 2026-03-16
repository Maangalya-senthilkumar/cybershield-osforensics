"""Persistence Mechanism Scanner.

Detects common post-exploitation persistence techniques:

  - Suspicious crontab / cron.d entries
  - Unknown or payload-bearing systemd service units
  - Suspicious shell startup files (.bashrc, .profile, /etc/rc.local, …)
  - SSH authorized_keys abuse (especially for root)
"""
from __future__ import annotations

import re
from typing import Dict, List

from .extractor import FilesystemAccessor

# ── Cron suspicious patterns ──────────────────────────────────────────────────

_CRON_SUSPICIOUS = [
    re.compile(r"\b(wget|curl)\b.+http"),
    re.compile(r"\bbase64\b.+-d"),
    re.compile(r"/tmp/\S+"),
    re.compile(r"\bbash\b\s+-[ice]"),
    re.compile(r"\bnc\b\s+-"),
    re.compile(r"\bpython\b.*-c"),
    re.compile(r"\bperl\b.*-e"),
    re.compile(r"\bchmod\b.+[+][xs]"),
    re.compile(r"\|\s*bash"),
    re.compile(r"\b(msfconsole|msfvenom|metasploit)\b"),
    re.compile(r"\bnohup\b.+&\s*$"),
    re.compile(r"\bsocat\b"),
    re.compile(r">\s*/dev/null\s+2>&1.*&"),   # background silenced process
]

# ── Shell-startup suspicious patterns ────────────────────────────────────────

_STARTUP_SUSPICIOUS = [
    re.compile(r"\b(wget|curl)\b.+http"),
    re.compile(r"\bbase64\b.+-d"),
    re.compile(r"\bnc\b\s+-[el]"),
    re.compile(r"/tmp/\.\w+"),                 # hidden file in /tmp
    re.compile(r"bash\s+-i\s+>&"),             # classic reverse bash shell
    re.compile(r"\bpython\b.*socket"),
    re.compile(r"\bnohup\b.+&\s*$"),
    re.compile(r"\b(msfconsole|msfvenom)\b"),
    re.compile(r"\bsocat\b"),
    re.compile(r"export\s+HISTFILE=/dev/null"),
    re.compile(r"unset\s+HISTFILE"),
    re.compile(r"HISTSIZE\s*=\s*0"),
]

# ── Known-legitimate systemd service name pattern ─────────────────────────────
# Anything NOT matching this regex is flagged for investigation.

_KNOWN_SVC = re.compile(
    r"^("
    r"ssh(d)?|cron(d)?|atd|rsyslog|syslog(d)?|systemd[-_]|dbus"
    r"|network(ing)?|NetworkManager|avahi|bluetooth|cups|snapd"
    r"|ufw|firewald|iptables|nftables"
    r"|apt[-_]|dpkg|policykit|polkit|colord|accounts-daemon"
    r"|gdm|lightdm|sddm|xorg|pulseaudio|pipewire|alsa"
    r"|udev|getty|login|serial-getty|console-setup"
    r"|docker|containerd|lxc|lxd|libvirt|qemu[-_]|vmtoolsd|vboxadd[-_]"
    r"|nginx|apache2|httpd|mysql|mariadb|postgresql|redis|mongodb|memcached"
    r"|tor|openvpn|wg[-_]quick|unbound|bind9|named|dnsmasq"
    r"|ondemand|cloud[-_]init|unattended[-_]upgrades|update[-_]"
    r"|motd|fwupd|packagekit|udisks|upower|thermald|tlp"
    r"|kerneloops|apport|whoopsie|rtkit|acpid|irqbalance|cpupower"
    r"|postfix|exim|dovecot|sendmail|procmail"
    r"|clamav|freshclam|rkhunter|aide|auditd|apparmor"
    r"|multipathd|lvm2|mdadm|dm[-_]|iscsid|open-iscsi"
    r"|nfs|rpc|portmap|rpcbind|autofs"
    r"|cups|samba|winbind|krb5|sssd|ldap|pam"
    r")\S*\.service$",
    re.IGNORECASE,
)

# Payload keywords that immediately escalate to high severity
_PAYLOAD_KEYWORDS = [
    "/tmp/", "base64", "wget http", "curl http",
    "nc -", "bash -i", "python -c", "perl -e",
    "socat", "msfconsole", "msfvenom",
]


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_finding(
    source: str,
    category: str,
    detail: str,
    severity: str = "medium",
    snippet: str = "",
) -> Dict:
    return {
        "source": source,
        "category": category,
        "detail": detail,
        "severity": severity,
        "snippet": snippet,
    }


# ── Scanners ──────────────────────────────────────────────────────────────────

def scan_crontabs(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    candidate_paths: List[str] = ["/etc/crontab"]

    for entry in fs.list_dir("/etc/cron.d"):
        candidate_paths.append(f"/etc/cron.d/{entry}")

    for user in fs.list_dir("/var/spool/cron/crontabs"):
        candidate_paths.append(f"/var/spool/cron/crontabs/{user}")

    for user in fs.list_dir("/var/spool/cron"):
        p = f"/var/spool/cron/{user}"
        if p not in candidate_paths:
            candidate_paths.append(p)

    for path in candidate_paths:
        content = fs.read_file(path, max_bytes=500_000)
        if not content:
            continue
        for line in content.decode("utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pat in _CRON_SUSPICIOUS:
                if pat.search(stripped):
                    findings.append(_make_finding(
                        path, "crontab",
                        f"Suspicious cron entry in {path}",
                        "high", stripped[:250],
                    ))
                    break  # one finding per cron line

    return findings


def scan_systemd_services(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    service_dirs = [
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    ]

    seen: set = set()

    for svc_dir in service_dirs:
        for svc_name in fs.list_dir(svc_dir):
            if not svc_name.endswith(".service"):
                continue
            if svc_name in seen:
                continue
            seen.add(svc_name)

            if _KNOWN_SVC.match(svc_name):
                continue

            svc_path = f"{svc_dir}/{svc_name}"
            content = fs.read_file(svc_path, max_bytes=100_000)
            snippet = ""
            severity = "medium"
            detail = f"Unknown/unrecognised service unit: {svc_name}"

            if content:
                text = content.decode("utf-8", errors="ignore")
                snippet = text[:400]
                text_lower = text.lower()
                if any(kw in text_lower for kw in _PAYLOAD_KEYWORDS):
                    severity = "high"
                    detail = f"Suspicious service unit with shell payload: {svc_name}"

            findings.append(_make_finding(svc_path, "systemd_service", detail, severity, snippet))

    return findings


def scan_shell_startup(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    # (path, owner-label)
    candidates: List[tuple] = [
        ("/root/.bashrc",       "root"),
        ("/root/.bash_profile", "root"),
        ("/root/.profile",      "root"),
        ("/etc/profile",        "system"),
        ("/etc/bash.bashrc",    "system"),
        ("/etc/rc.local",       "system"),
        ("/etc/environment",    "system"),
    ]

    for user in fs.list_dir("/home"):
        for fname in (".bashrc", ".bash_profile", ".profile", ".bash_login"):
            candidates.append((f"/home/{user}/{fname}", user))

    for path, owner in candidates:
        content = fs.read_file(path, max_bytes=200_000)
        if not content:
            continue
        for line in content.decode("utf-8", errors="ignore").splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for pat in _STARTUP_SUSPICIOUS:
                if pat.search(stripped):
                    findings.append(_make_finding(
                        path, "shell_startup",
                        f"Suspicious startup entry [{owner}]: {path}",
                        "high", stripped[:250],
                    ))
                    break

    return findings


def scan_ssh_authorized_keys(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    users_to_check: List[tuple] = [("root", "/root")]
    for user in fs.list_dir("/home"):
        users_to_check.append((user, f"/home/{user}"))

    for user, home in users_to_check:
        auth_keys = f"{home}/.ssh/authorized_keys"
        content = fs.read_file(auth_keys, max_bytes=100_000)
        if not content:
            continue

        text = content.decode("utf-8", errors="ignore")
        keys = [ln.strip() for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        if not keys:
            continue

        severity = "high" if user == "root" else "medium"
        # Flag command= restricted keys as potentially backdoored
        forced_cmd = any('command="' in k for k in keys)
        detail = (
            f"SSH authorized_keys for '{user}': {len(keys)} key(s)"
            + (" (forced-command entry detected)" if forced_cmd else "")
        )
        findings.append(_make_finding(
            auth_keys, "ssh_authorized_keys", detail, severity,
            "\n".join(keys[:3]),   # show first 3 keys in snippet
        ))

    return findings


# ── Public entry point ────────────────────────────────────────────────────────

def detect_persistence(fs: FilesystemAccessor) -> List[Dict]:
    """Return all persistence findings: cron, systemd, shell-startup, SSH keys."""
    findings: List[Dict] = []
    findings.extend(scan_crontabs(fs))
    findings.extend(scan_systemd_services(fs))
    findings.extend(scan_shell_startup(fs))
    findings.extend(scan_ssh_authorized_keys(fs))
    return findings
