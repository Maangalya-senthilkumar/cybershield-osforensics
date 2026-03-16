"""Configuration File Analysis.

Reads and audits critical Linux configuration files for security misconfigurations,
weak settings, and forensically interesting artefacts.

Analysers:
  - SSH server (sshd_config)
  - sudo (sudoers + sudoers.d)
  - IPTables / nftables rules
  - PAM (pam.d common-auth, common-password, su, sudo)
  - Kernel parameters (sysctl.conf, sysctl.d)
  - Password / account policies (login.defs)
  - AppArmor / SELinux status files
  - /etc/hosts (rogue entries)
  - /etc/resolv.conf (rogue DNS)
  - Network interfaces / NM config
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional

from .extractor import FilesystemAccessor


# ─── Result models ────────────────────────────────────────────────────────────

def _finding(
    config: str,
    category: str,
    detail: str,
    severity: str = "info",
    snippet: str = "",
    recommendation: str = "",
) -> Dict:
    return {
        "config": config,
        "category": category,
        "detail": detail,
        "severity": severity,
        "snippet": snippet,
        "recommendation": recommendation,
    }


def _read(fs: FilesystemAccessor, path: str) -> Optional[str]:
    raw = fs.read_file(path, max_bytes=256_000)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


def _lines(text: str) -> List[str]:
    return [l for l in text.splitlines() if l.strip() and not l.strip().startswith("#")]


# ─── SSH Configuration ────────────────────────────────────────────────────────

_SSH_SECURE_CIPHERS = {
    "aes256-gcm@openssh.com", "aes128-gcm@openssh.com",
    "chacha20-poly1305@openssh.com", "aes256-ctr", "aes128-ctr",
}
_SSH_WEAK_CIPHERS = re.compile(
    r"\b(arcfour|3des-cbc|blowfish-cbc|cast128-cbc|aes128-cbc|aes192-cbc|aes256-cbc)\b",
    re.IGNORECASE,
)
_SSH_WEAK_MAC = re.compile(r"\bhmac-(?:md5|sha1)\b", re.IGNORECASE)


def _audit_sshd(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []
    text = _read(fs, "/etc/ssh/sshd_config")
    if text is None:
        findings.append(_finding("sshd_config", "file", "sshd_config not found — SSH server may not be installed", "info"))
        return findings

    cfg: Dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            cfg[parts[0].lower()] = parts[1].strip()

    checks = [
        # (key, bad_value, detail, severity, recommendation)
        ("permitrootlogin",     "yes",              "Root login is permitted",                          "high",   "Set PermitRootLogin to 'no' or 'prohibit-password'"),
        ("permitrootlogin",     "without-password",  "Root login allowed via public key (no password)", "medium", "Consider setting PermitRootLogin to 'no'"),
        ("passwordauthentication","yes",             "Password authentication is enabled",               "medium", "Disable PasswordAuthentication and use key-based auth"),
        ("permitemptypasswords","yes",               "Empty passwords are permitted",                    "critical","Set PermitEmptyPasswords to 'no' immediately"),
        ("x11forwarding",       "yes",               "X11 forwarding is enabled (attack surface)",      "medium", "Disable X11Forwarding unless required"),
        ("usedns",              "yes",               "DNS lookups enabled — may leak information",       "low",    "Set UseDNS to 'no' for performance and privacy"),
        ("gssapiauthentication","yes",               "GSSAPI authentication enabled",                   "low",    "Disable GSSAPI if Kerberos is not used"),
        ("usepam",              "no",                "PAM disabled for SSH — bypasses PAM controls",    "medium", "Enable UsePAM for centralized auth control"),
        ("protocol",            "1",                 "SSH protocol version 1 is active (insecure)",     "critical","Remove 'Protocol 1' — SSHv1 is broken"),
        ("ignorerhosts",        "no",                "~/.rhosts are NOT ignored",                        "high",   "Set IgnoreRhosts to 'yes'"),
        ("ignoreuserknownhosts","no",                "User known_hosts NOT ignored for HostbasedAuth",  "low",    "Set IgnoreUserKnownHosts to 'yes'"),
        ("hostbasedauthentication","yes",            "Host-based authentication enabled",               "high",   "Disable HostbasedAuthentication"),
        ("challengeresponseauthentication","yes",    "Challenge-response auth enabled (may bypass MFA)","medium","Disable if not needed"),
        ("kerberosauthentication","yes",             "Kerberos authentication active",                  "low",    "Disable if Kerberos is not used"),
        ("maxauthtries",        None,                None,                                              None,     None),   # handled separately
        ("clientaliveinterval", None,                None,                                              None,     None),
    ]

    for key, bad_val, detail, sev, rec in checks:
        if detail is None:
            continue
        val = cfg.get(key)
        if val is None:
            continue
        if bad_val is None or val.lower() == bad_val.lower():
            findings.append(_finding(
                "sshd_config", key, detail, sev,
                snippet=f"{key.capitalize()} {val}",
                recommendation=rec,
            ))

    # MaxAuthTries should be ≤ 4
    max_tries = cfg.get("maxauthtries")
    if max_tries:
        try:
            n = int(max_tries)
            if n > 4:
                findings.append(_finding("sshd_config", "maxauthtries",
                    f"MaxAuthTries is {n} (recommended ≤ 4)", "medium",
                    snippet=f"MaxAuthTries {n}",
                    recommendation="Set MaxAuthTries 3"))
        except ValueError:
            pass

    # Port
    port = cfg.get("port", "22")
    if port == "22":
        findings.append(_finding("sshd_config", "port",
            "SSH is running on default port 22 — easily discoverable", "low",
            snippet="Port 22", recommendation="Consider changing to a non-standard port"))

    # AllowUsers / AllowGroups
    if "allowusers" not in cfg and "allowgroups" not in cfg:
        findings.append(_finding("sshd_config", "access_control",
            "No AllowUsers or AllowGroups directive — all users may SSH in", "medium",
            recommendation="Restrict access with AllowUsers or AllowGroups"))

    # Ciphers
    ciphers_line = cfg.get("ciphers", "")
    if ciphers_line and _SSH_WEAK_CIPHERS.search(ciphers_line):
        findings.append(_finding("sshd_config", "ciphers",
            "Weak SSH ciphers configured", "high",
            snippet=f"Ciphers {ciphers_line}",
            recommendation="Use only AES-GCM / ChaCha20 ciphers"))

    # MACs
    macs_line = cfg.get("macs", "")
    if macs_line and _SSH_WEAK_MAC.search(macs_line):
        findings.append(_finding("sshd_config", "macs",
            "Weak SSH MACs configured (MD5/SHA1)", "high",
            snippet=f"MACs {macs_line}",
            recommendation="Remove hmac-md5 and hmac-sha1 from MACs list"))

    # ClientAliveInterval — session timeout
    if "clientaliveinterval" not in cfg:
        findings.append(_finding("sshd_config", "session_timeout",
            "ClientAliveInterval not set — idle sessions never time out", "low",
            recommendation="Set ClientAliveInterval 300 ClientAliveCountMax 2"))

    if not findings:
        findings.append(_finding("sshd_config", "summary",
            "No critical SSH misconfigurations found", "info"))
    return findings


# ─── Sudo Configuration ───────────────────────────────────────────────────────

_SUDO_NOPASSWD  = re.compile(r"NOPASSWD", re.IGNORECASE)
_SUDO_ALL_ALL   = re.compile(r"ALL\s*=\s*(?:\([^)]*\))?\s*ALL", re.IGNORECASE)
_SUDO_SHELL_ESC = re.compile(
    r"\b(vi|vim|nano|less|more|man|awk|find|python\d?|perl|ruby|lua|node|env|bash|sh|zsh|nmap|ftp|git|socat|nc|netcat)\b",
    re.IGNORECASE,
)


def _audit_sudoers(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    def _check_text(path: str, text: str) -> None:
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or line.startswith("Defaults"):
                continue

            # NOPASSWD combined with ALL
            if _SUDO_NOPASSWD.search(line) and _SUDO_ALL_ALL.search(line):
                findings.append(_finding(path, "nopasswd_all",
                    f"NOPASSWD ALL granted — full root without password",
                    "critical", snippet=line,
                    recommendation="Remove NOPASSWD or restrict to specific commands"))

            elif _SUDO_NOPASSWD.search(line):
                findings.append(_finding(path, "nopasswd",
                    "NOPASSWD entry — sudo without password for specific command",
                    "high", snippet=line,
                    recommendation="Audit whether this NOPASSWD grant is necessary"))

            # Shell-escape-prone commands
            m = _SUDO_SHELL_ESC.search(line)
            if m:
                findings.append(_finding(path, "shell_escape",
                    f"sudo allows '{m.group()}' — GTFOBins shell-escape risk",
                    "high", snippet=line,
                    recommendation=f"Remove {m.group()} from sudoers; see gtfobins.github.io"))

            # Wildcard arguments
            if re.search(r"\*", line) and not line.startswith("Host_Alias"):
                findings.append(_finding(path, "wildcard",
                    "Wildcard (*) in sudo rule — may allow argument injection",
                    "medium", snippet=line,
                    recommendation="Replace wildcards with explicit allowed arguments"))

    # Main sudoers
    main = _read(fs, "/etc/sudoers")
    if main is None:
        findings.append(_finding("sudoers", "file", "sudoers file not found", "info"))
    else:
        _check_text("/etc/sudoers", main)

    # Drop-in files
    dropins = fs.list_dir("/etc/sudoers.d")
    for name in dropins:
        path = f"/etc/sudoers.d/{name}"
        text = _read(fs, path)
        if text:
            _check_text(path, text)

    if not findings:
        findings.append(_finding("sudoers", "summary",
            "No critical sudo misconfigurations found", "info"))
    return findings


# ─── IPTables Rules ───────────────────────────────────────────────────────────

_IPTABLES_PATHS = [
    "/etc/iptables/rules.v4",
    "/etc/iptables/rules.v6",
    "/etc/sysconfig/iptables",         # RHEL / CentOS
    "/etc/sysconfig/ip6tables",
]

_IPTABLES_ACCEPT_ALL = re.compile(r"-P\s+(INPUT|FORWARD|OUTPUT)\s+ACCEPT", re.IGNORECASE)
_IPTABLES_OPEN_PORT  = re.compile(r"--dport\s+(\d+).*-j\s+ACCEPT", re.IGNORECASE)
_IPTABLES_WIDE_OPEN  = re.compile(r"-A\s+INPUT\s+-j\s+ACCEPT", re.IGNORECASE)
_DANGEROUS_PORTS = {
    21: "FTP", 23: "Telnet", 512: "rexec", 513: "rlogin", 514: "rsh",
    1099: "Java RMI", 3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis",
    27017: "MongoDB", 9200: "Elasticsearch", 5900: "VNC", 3389: "RDP",
}


def _audit_iptables(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []
    found_any = False

    for path in _IPTABLES_PATHS:
        text = _read(fs, path)
        if text is None:
            continue
        found_any = True

        # Default ACCEPT policies
        for m in _IPTABLES_ACCEPT_ALL.finditer(text):
            chain = m.group(1).upper()
            findings.append(_finding(path, "default_policy",
                f"Default policy for {chain} chain is ACCEPT — no implicit deny",
                "high" if chain == "INPUT" else "medium",
                snippet=m.group(0).strip(),
                recommendation=f"Set -P {chain} DROP and allow only required traffic"))

        # Fully open INPUT
        if _IPTABLES_WIDE_OPEN.search(text):
            findings.append(_finding(path, "wide_open",
                "INPUT chain has a blanket ACCEPT rule — all traffic allowed",
                "critical", snippet="-A INPUT -j ACCEPT",
                recommendation="Remove blanket ACCEPT and use specific allow rules"))

        # Open dangerous ports
        for m in _IPTABLES_OPEN_PORT.finditer(text):
            try:
                port = int(m.group(1))
            except ValueError:
                continue
            if port in _DANGEROUS_PORTS:
                svc = _DANGEROUS_PORTS[port]
                findings.append(_finding(path, "open_port",
                    f"Port {port} ({svc}) is open in firewall rules",
                    "high" if port in (23, 21, 512, 513, 514) else "medium",
                    snippet=m.group(0).strip(),
                    recommendation=f"Block port {port} if {svc} is not required"))

        # nftables fallback string in iptables files
        if "nftables" in text.lower():
            findings.append(_finding(path, "nftables_ref",
                "nftables reference found in iptables file — verify active firewall",
                "low", snippet="", recommendation="Confirm nftables is the active firewall"))

    if not found_any:
        # Check if ufw is installed/enabled
        ufw_rules = _read(fs, "/etc/ufw/user.rules")
        if ufw_rules:
            findings.append(_finding("ufw", "summary",
                "UFW rules found — iptables rules file absent but UFW manages the firewall", "info"))
        else:
            findings.append(_finding("iptables", "file",
                "No iptables or UFW rules found — firewall may be inactive", "high",
                recommendation="Install and configure a firewall (ufw, iptables, or nftables)"))

    return findings


# ─── PAM Configuration ────────────────────────────────────────────────────────

_PAM_NULLOK    = re.compile(r"\bnullok\b", re.IGNORECASE)
_PAM_NOFILE    = re.compile(r"\bnulls\b|\bnobody\b|\bno_root_squash\b", re.IGNORECASE)
_PAM_PWQUALITY = re.compile(r"pam_pwquality|pam_cracklib", re.IGNORECASE)
_PAM_FAILLOCK  = re.compile(r"pam_faillock|pam_tally2", re.IGNORECASE)
_PAM_MFA       = re.compile(r"pam_google_authenticator|pam_duo|pam_oath|pam_totp|pam_okta", re.IGNORECASE)


def _audit_pam(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    pam_files = {
        "/etc/pam.d/common-auth":     "auth stack",
        "/etc/pam.d/common-password": "password stack",
        "/etc/pam.d/su":              "su access",
        "/etc/pam.d/sudo":            "sudo pam",
        "/etc/pam.d/sshd":            "sshd pam",
        "/etc/pam.d/login":           "console login",
    }
    found_any = False
    has_pwquality = False
    has_faillock  = False
    has_mfa       = False

    for path, label in pam_files.items():
        text = _read(fs, path)
        if text is None:
            continue
        found_any = True

        if _PAM_PWQUALITY.search(text):
            has_pwquality = True
        if _PAM_FAILLOCK.search(text):
            has_faillock = True
        if _PAM_MFA.search(text):
            has_mfa = True

        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if _PAM_NULLOK.search(stripped):
                findings.append(_finding(path, "nullok",
                    f"nullok in {label} — allows login with empty password",
                    "high", snippet=stripped,
                    recommendation="Remove 'nullok' from PAM configuration"))

    if not found_any:
        findings.append(_finding("pam.d", "file",
            "No PAM configuration files found", "info"))
        return findings

    if not has_pwquality:
        findings.append(_finding("pam.d", "password_complexity",
            "No password complexity module (pam_pwquality/pam_cracklib) found",
            "medium", recommendation="Install pam_pwquality and configure minlen, complexity"))

    if not has_faillock:
        findings.append(_finding("pam.d", "lockout_policy",
            "No account lockout module (pam_faillock/pam_tally2) found — brute-force risk",
            "high", recommendation="Configure pam_faillock to lock accounts after failed attempts"))

    if has_mfa:
        findings.append(_finding("pam.d", "mfa",
            "Multi-factor authentication module detected in PAM", "info"))

    return findings


# ─── Kernel Parameters (sysctl) ───────────────────────────────────────────────

_SYSCTL_PATHS = [
    "/etc/sysctl.conf",
    "/etc/sysctl.d/99-sysctl.conf",
    "/etc/sysctl.d/10-network-security.conf",
]

_DESIRABLE_PARAMS = {
    "net.ipv4.ip_forward":                      ("0", "IP forwarding enabled — host may route traffic", "medium"),
    "net.ipv4.conf.all.send_redirects":         ("0", "ICMP redirects can be sent — potential MITM", "medium"),
    "net.ipv4.conf.default.send_redirects":     ("0", "ICMP redirects on default interface", "medium"),
    "net.ipv4.conf.all.accept_redirects":       ("0", "Accepting ICMP redirects (MITM risk)", "medium"),
    "net.ipv4.conf.all.secure_redirects":       ("0", "Accepting secure ICMP redirects", "low"),
    "net.ipv4.conf.all.log_martians":           ("1", "Martian packet logging disabled", "low"),
    "net.ipv4.icmp_echo_ignore_broadcasts":     ("1", "Responding to broadcast pings (Smurf risk)", "low"),
    "net.ipv4.tcp_syncookies":                  ("1", "SYN cookies disabled — SYN flood risk", "medium"),
    "kernel.randomize_va_space":                ("2", "ASLR disabled or weak (value != 2)", "high"),
    "kernel.dmesg_restrict":                    ("1", "dmesg unrestricted — kernel info leak", "medium"),
    "kernel.kptr_restrict":                     ("2", "Kernel pointers exposed in /proc", "medium"),
    "kernel.sysrq":                             ("0", "SysRq key enabled — privileged operations possible", "medium"),
    "net.ipv4.conf.all.rp_filter":              ("1", "Reverse path filtering disabled", "low"),
    "fs.suid_dumpable":                         ("0", "SUID core dumps enabled — credential leak risk", "medium"),
    "net.ipv4.conf.all.accept_source_route":    ("0", "Source routing accepted", "medium"),
    "kernel.core_uses_pid":                     ("1", "Core dumps don't include PID", "info"),
}


def _audit_sysctl(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []
    observed: Dict[str, str] = {}

    for path in _SYSCTL_PATHS:
        text = _read(fs, path)
        if text is None:
            continue
        for line in text.splitlines():
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            if "=" in stripped:
                k, _, v = stripped.partition("=")
                observed[k.strip().lower()] = v.strip()

    if not observed:
        findings.append(_finding("sysctl", "file",
            "No sysctl configuration files found — kernel hardening status unknown", "medium",
            recommendation="Create /etc/sysctl.d/99-hardening.conf with security parameters"))
        return findings

    for param, (desired, detail, sev) in _DESIRABLE_PARAMS.items():
        val = observed.get(param.lower())
        if val is None:
            continue
        if val != desired:
            findings.append(_finding("sysctl.conf", f"kernel_param",
                f"{param} = {val} (expected {desired}): {detail}",
                sev, snippet=f"{param} = {val}",
                recommendation=f"Set {param} = {desired}"))

    # net.ipv4.ip_forward: if set to 1, flag it
    if observed.get("net.ipv4.ip_forward") == "1":
        findings.append(_finding("sysctl.conf", "ip_forward",
            "IP forwarding is enabled — this host acts as a router", "medium",
            snippet="net.ipv4.ip_forward = 1",
            recommendation="Disable if not intentionally routing traffic"))

    if not findings:
        findings.append(_finding("sysctl.conf", "summary",
            "Kernel parameters appear acceptably hardened", "info"))
    return findings


# ─── Password Policy (/etc/login.defs) ───────────────────────────────────────

def _audit_login_defs(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []
    text = _read(fs, "/etc/login.defs")
    if text is None:
        findings.append(_finding("login.defs", "file",
            "/etc/login.defs not found", "info"))
        return findings

    cfg: Dict[str, str] = {}
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split(None, 1)
        if len(parts) == 2:
            cfg[parts[0].upper()] = parts[1].strip()

    checks = [
        # (key, threshold, direction, detail, severity, recommendation)
        ("PASS_MAX_DAYS",  90,  "gt", "Password max age is >90 days",      "medium", "Set PASS_MAX_DAYS 90"),
        ("PASS_MIN_DAYS",  1,   "lt", "Minimum password age is <1 day",     "low",    "Set PASS_MIN_DAYS 1"),
        ("PASS_MIN_LEN",   12,  "lt", "Minimum password length is <12",     "medium", "Set PASS_MIN_LEN 12"),
        ("PASS_WARN_AGE",  7,   "lt", "Password expiry warning <7 days",    "low",    "Set PASS_WARN_AGE 7"),
        ("LOGIN_RETRIES",  5,   "gt", "Login retries >5 before lockout",    "low",    "Set LOGIN_RETRIES 3"),
        ("LOGIN_TIMEOUT",  60,  "gt", "Login timeout >60 seconds",          "low",    "Set LOGIN_TIMEOUT 60"),
        ("DEFAULT_HOME",   None, None,"",                                   "info",   ""),
        ("CREATE_HOME",    None, None,"",                                   "info",   ""),
    ]

    for key, threshold, direction, detail, sev, rec in checks:
        if threshold is None:
            continue
        val_str = cfg.get(key)
        if val_str is None:
            continue
        try:
            val = int(val_str)
        except ValueError:
            continue
        flag = (direction == "gt" and val > threshold) or (direction == "lt" and val < threshold)
        if flag:
            findings.append(_finding("login.defs", key.lower(),
                f"{detail} (current: {val})", sev,
                snippet=f"{key} {val}",
                recommendation=rec))

    if not findings:
        findings.append(_finding("login.defs", "summary",
            "Password policy settings look adequate", "info"))
    return findings


# ─── /etc/hosts Anomalies ─────────────────────────────────────────────────────

_TRUSTED_HOSTS = re.compile(
    r"^(127\.|::1|0\.0\.0\.0|fe80:|ff02:|localhost|\s*#)",
)
_PRIVATE_RANGES = re.compile(
    r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)"
)


def _audit_hosts(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []
    text = _read(fs, "/etc/hosts")
    if text is None:
        findings.append(_finding("/etc/hosts", "file", "/etc/hosts not found", "info"))
        return findings

    seen_ips: Dict[str, List[str]] = {}

    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parts = stripped.split()
        if len(parts) < 2:
            continue
        ip = parts[0]
        names = parts[1:]

        # Track multiple entries for the same IP (possible poisoning)
        seen_ips.setdefault(ip, []).extend(names)

        # Any non-loopback / non-link-local IP pointing to a well-known name
        if not re.match(r"^(127\.|::1|0\.0\.0\.0|fe80:|ff02:)", ip):
            for name in names:
                if re.search(r"(google|microsoft|apple|github|amazon|facebook|update|security|antivirus|av\.|clamav|norton|sophos|mcafee)", name, re.IGNORECASE):
                    findings.append(_finding("/etc/hosts", "dns_hijack",
                        f"Suspicious redirect: '{name}' → {ip} (possible hosts poisoning)",
                        "critical", snippet=stripped,
                        recommendation="Verify this /etc/hosts entry is legitimate"))

        # Public IP for localhost names
        if re.match(r"(localhost|localhost\.localdomain|broadcasthost)$", " ".join(names), re.IGNORECASE) and not re.match(r"^(127\.|::1|0\.0\.0\.0)", ip):
            findings.append(_finding("/etc/hosts", "localhost_remap",
                f"'localhost' remapped to non-loopback IP {ip}", "high",
                snippet=stripped, recommendation="Restore localhost to 127.0.0.1"))

    # Extra entries beyond loopback
    public_entries = [
        (ip, names) for ip, names in seen_ips.items()
        if not re.match(r"^(127\.|::1|0\.0\.0\.0|fe80:|ff02:)", ip)
    ]
    if public_entries:
        findings.append(_finding("/etc/hosts", "custom_entries",
            f"{len(public_entries)} non-loopback host entr{'y' if len(public_entries)==1 else 'ies'} found — verify they are legitimate",
            "low",
            snippet="\n".join(f"{ip}  {' '.join(names)}" for ip, names in public_entries[:5]),
            recommendation="Review /etc/hosts for unexpected entries"))

    if not findings:
        findings.append(_finding("/etc/hosts", "summary",
            "/etc/hosts contains only standard entries", "info"))
    return findings


# ─── resolv.conf — rogue DNS ─────────────────────────────────────────────────

_KNOWN_PUBLIC_DNS = {
    "8.8.8.8", "8.8.4.4",       # Google
    "1.1.1.1", "1.0.0.1",       # Cloudflare
    "9.9.9.9", "149.112.112.112",# Quad9
    "208.67.222.222", "208.67.220.220",  # OpenDNS
    "4.2.2.1", "4.2.2.2",
}


def _audit_resolv(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []
    text = _read(fs, "/etc/resolv.conf")
    if text is None:
        findings.append(_finding("resolv.conf", "file",
            "/etc/resolv.conf not found", "info"))
        return findings

    nameservers = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.startswith("nameserver"):
            parts = stripped.split()
            if len(parts) >= 2:
                nameservers.append(parts[1])

    if not nameservers:
        findings.append(_finding("resolv.conf", "no_dns",
            "No nameservers configured in resolv.conf", "medium",
            recommendation="Configure at least one nameserver"))
        return findings

    for ns in nameservers:
        if re.match(r"^(127\.|::1)", ns):
            findings.append(_finding("resolv.conf", "local_dns",
                f"Local DNS resolver {ns} — verify dnsmasq/systemd-resolved config", "low",
                snippet=f"nameserver {ns}"))
        elif not _PRIVATE_RANGES.match(ns) and ns not in _KNOWN_PUBLIC_DNS:
            findings.append(_finding("resolv.conf", "unknown_dns",
                f"Unknown/unlisted DNS server: {ns} — possible DNS hijacking", "medium",
                snippet=f"nameserver {ns}",
                recommendation="Verify this DNS server is authorised"))

    if nameservers:
        findings.append(_finding("resolv.conf", "summary",
            f"Configured DNS servers: {', '.join(nameservers)}", "info",
            snippet="\n".join(f"nameserver {ns}" for ns in nameservers)))

    return findings


# ─── AppArmor / SELinux Status ────────────────────────────────────────────────

def _audit_mac(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    # AppArmor
    aa_status = _read(fs, "/sys/kernel/security/apparmor/profiles")
    or_status = _read(fs, "/etc/apparmor/parser.conf") or _read(fs, "/etc/default/grub")

    apparmor_enabled = fs.exists("/sys/kernel/security/apparmor/profiles") or fs.exists("/etc/apparmor.d")

    selinux_config = _read(fs, "/etc/selinux/config")
    selinux_enabled = selinux_config is not None

    if apparmor_enabled:
        findings.append(_finding("apparmor", "status",
            "AppArmor is present on this system", "info"))
        # Check for disabled/complain mode profiles
        aa_profiles = _read(fs, "/etc/apparmor.d")
        disabled = fs.list_dir("/etc/apparmor.d/disable") if fs.exists("/etc/apparmor.d/disable") else []
        if disabled:
            findings.append(_finding("apparmor", "disabled_profiles",
                f"{len(disabled)} AppArmor profile(s) explicitly disabled",
                "medium", snippet="\n".join(disabled[:10]),
                recommendation="Review and re-enable disabled AppArmor profiles"))

    if selinux_enabled and selinux_config:
        selinux_mode = None
        for line in selinux_config.splitlines():
            stripped = line.strip()
            if stripped.upper().startswith("SELINUX=") and not "TYPE" in stripped.upper():
                selinux_mode = stripped.split("=", 1)[1].strip().lower()
        if selinux_mode == "disabled":
            findings.append(_finding("selinux", "disabled",
                "SELinux is disabled", "medium",
                recommendation="Enable SELinux in enforcing mode"))
        elif selinux_mode == "permissive":
            findings.append(_finding("selinux", "permissive",
                "SELinux is in permissive mode — violations are logged but not blocked",
                "low", snippet=f"SELINUX={selinux_mode}",
                recommendation="Switch SELinux to enforcing mode"))
        elif selinux_mode == "enforcing":
            findings.append(_finding("selinux", "enforcing",
                "SELinux is enforcing — MAC controls active", "info"))

    if not apparmor_enabled and not selinux_enabled:
        findings.append(_finding("MAC", "absent",
            "Neither AppArmor nor SELinux is present — no mandatory access control",
            "medium", recommendation="Enable AppArmor or SELinux for defence-in-depth"))

    return findings


# ─── Network Interfaces ───────────────────────────────────────────────────────

def _audit_network(fs: FilesystemAccessor) -> List[Dict]:
    findings: List[Dict] = []

    interfaces_text = _read(fs, "/etc/network/interfaces")
    if interfaces_text:
        # Look for hard-coded credentials (passwords / pre-shared keys)
        if re.search(r"\bwpa-psk\b|\bpassword\b|\bpsk\b", interfaces_text, re.IGNORECASE):
            findings.append(_finding("/etc/network/interfaces", "credentials",
                "Possible credentials (PSK/password) embedded in network interfaces file",
                "high", recommendation="Remove credentials from interfaces file; use secrets manager"))

        # Promiscuous mode
        if re.search(r"\bpromisc\b", interfaces_text, re.IGNORECASE):
            findings.append(_finding("/etc/network/interfaces", "promisc",
                "Interface configured in promiscuous mode — packet capture active", "high",
                recommendation="Verify promiscuous mode is intentional and authorised"))

    # NetworkManager connections with plain-text credentials
    nm_dir = "/etc/NetworkManager/system-connections"
    nm_connections = fs.list_dir(nm_dir)
    for fname in nm_connections:
        nm_path = f"{nm_dir}/{fname}"
        nm_text = _read(fs, nm_path)
        if nm_text and re.search(r"^psk\s*=|^password\s*=|^password-flags\s*=\s*0", nm_text, re.IGNORECASE | re.MULTILINE):
            findings.append(_finding(nm_path, "nm_credential",
                f"NetworkManager connection '{fname}' contains plain-text credentials",
                "medium", recommendation="Use password-flags=1 (agent-managed) instead of stored credentials"))

    if not findings:
        findings.append(_finding("network", "summary",
            "No critical network configuration issues found", "info"))
    return findings


# ─── Aggregator ───────────────────────────────────────────────────────────────

def analyze_configs(fs: FilesystemAccessor) -> List[Dict]:
    """Run all configuration auditors and return a flat list of findings."""
    all_findings: List[Dict] = []
    all_findings.extend(_audit_sshd(fs))
    all_findings.extend(_audit_sudoers(fs))
    all_findings.extend(_audit_iptables(fs))
    all_findings.extend(_audit_pam(fs))
    all_findings.extend(_audit_sysctl(fs))
    all_findings.extend(_audit_login_defs(fs))
    all_findings.extend(_audit_hosts(fs))
    all_findings.extend(_audit_resolv(fs))
    all_findings.extend(_audit_mac(fs))
    all_findings.extend(_audit_network(fs))
    return all_findings
