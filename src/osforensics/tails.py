"""Tails OS focused forensic heuristics.

Tails is intentionally amnesic, so this module prioritizes indirect indicators,
runtime traces, and meta-evidence that an amnesic/privacy-oriented workflow was
used.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Sequence

from .extractor import FilesystemAccessor


_ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
_TS_RE = re.compile(r"\b([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\b")
_CMD_FRAGMENT_RE = re.compile(
    r"\b(?:nmap|sqlmap|hydra|scp|ssh|curl|wget|netcat|nc|python\s+-m\s+http\.server)\b[^\n\r]{0,140}",
    re.IGNORECASE,
)


def _read_text(fs: FilesystemAccessor, path: str, max_bytes: int = 1_200_000) -> str:
    raw = fs.read_file(path, max_bytes=max_bytes)
    if not raw:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _extract_onions(text: str, limit: int = 8) -> List[str]:
    out: List[str] = []
    for m in _ONION_RE.findall(text or ""):
        v = m.lower()
        if v not in out:
            out.append(v)
        if len(out) >= limit:
            break
    return out


def _first_lines_with(text: str, needles: Sequence[str], limit: int = 4) -> List[str]:
    needles_l = [n.lower() for n in needles]
    out: List[str] = []
    for line in (text or "").splitlines():
        ll = line.lower()
        if any(n in ll for n in needles_l):
            out.append(line.strip()[:220])
        if len(out) >= limit:
            break
    return out


def _home_dirs(fs: FilesystemAccessor) -> List[str]:
    homes = ["/home/amnesia"]
    for name in fs.list_dir("/home"):
        n = name.strip("/")
        if n and n not in (".", ".."):
            homes.append(f"/home/{n}")
    # Stable order + de-dup
    seen = set()
    out: List[str] = []
    for h in homes:
        if h not in seen:
            out.append(h)
            seen.add(h)
    return out


def _tails_paths(fs: FilesystemAccessor) -> List[str]:
    candidates = [
        "/etc/amnesia",
        "/live/persistence/TailsData_unlocked",
        "/live/persistence/TailsData",
        "/usr/share/live/config",
        "/lib/live/mount",
    ]
    return [p for p in candidates if fs.exists(p)]


def _classify_profile(indicators: List[str], score: int) -> str:
    if score >= 6:
        label = "High Risk"
    elif score >= 3:
        label = "Security Researcher / Advanced Operator"
    else:
        label = "Privacy User"
    return f"Operational profile: {label} (score={score}, indicators={', '.join(indicators) or 'none'})"


def _extract_persistence_modules(fs: FilesystemAccessor) -> Dict[str, object]:
    """Extract enabled persistence modules from persistence.conf."""
    modules = []
    pconf_path = "/live/persistence/TailsData_unlocked/persistence.conf"
    pconf = _read_text(fs, pconf_path, max_bytes=300_000)
    
    if not pconf:
        return {"enabled": [], "total": 0}
    
    current_source = None
    for line in pconf.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("/"):
            current_source = line
        elif "destination=" in line and current_source:
            dest = line.split("destination=", 1)[1].strip()
            modules.append({
                "source": current_source,
                "destination": dest,
                "type": _classify_module_type(dest),
                "risk_level": _assess_module_risk(dest),
            })
    
    return {
        "enabled": modules,
        "total": len(modules),
        "high_risk_count": sum(1 for m in modules if m.get("risk_level") == "high"),
    }


def _classify_module_type(dest: str) -> str:
    """Classify persistence module by destination path."""
    dest_l = dest.lower()
    if "gnupg" in dest_l:
        return "GPG Keys"
    elif "ssh" in dest_l:
        return "SSH Keys"
    elif "electrum" in dest_l:
        return "Cryptocurrency Wallet"
    elif "thunderbird" in dest_l:
        return "Email Client"
    elif "tor-browser" in dest_l or "mozilla" in dest_l:
        return "Tor Browser Data"
    elif "persistent" in dest_l:
        return "User Files"
    elif ".config" in dest_l:
        return "Configuration"
    else:
        return "Custom Data"


def _assess_module_risk(dest: str) -> str:
    """Assess operational risk of a persistence module."""
    dest_l = dest.lower()
    if any(k in dest_l for k in ("gnupg", "ssh", "electrum", "bitcoin")):
        return "high"
    elif any(k in dest_l for k in ("thunderbird", "tor-browser", "mozilla")):
        return "medium"
    else:
        return "low"


def _extract_crypto_wallets(fs: FilesystemAccessor) -> Dict[str, object]:
    """Extract cryptocurrency wallet evidence."""
    wallets = []
    for home in _home_dirs(fs):
        wallet_bases = [
            (f"{home}/.electrum", "Electrum"),
            (f"{home}/.bitcoin", "Bitcoin Core"),
            (f"{home}/.monero", "Monero"),
        ]
        for wallet_path, wallet_type in wallet_bases:
            if fs.exists(wallet_path):
                try:
                    entries = fs.list_dir(wallet_path)
                    for entry in entries:
                        if entry.lower().endswith((".dat", ".db", ".sqlite", ".json")):
                            wallets.append({
                                "type": wallet_type,
                                "path": f"{wallet_path}/{entry}",
                                "name": entry,
                            })
                except:
                    pass
    
    return {
        "wallets": wallets[:20],
        "total": len(wallets),
        "types": len(set(w["type"] for w in wallets)),
    }


def _extract_identity_keys(fs: FilesystemAccessor) -> Dict[str, object]:
    """Extract SSH and GPG identity indicators."""
    ssh_keys = []
    gpg_keys = []
    
    for home in _home_dirs(fs):
        # SSH keys
        ssh_dir = f"{home}/.ssh"
        if fs.exists(ssh_dir):
            try:
                for entry in fs.list_dir(ssh_dir):
                    if entry.lower() in ("id_rsa", "id_ed25519", "id_ecdsa", "id_dsa", "authorized_keys"):
                        ssh_keys.append({
                            "name": entry,
                            "path": f"{ssh_dir}/{entry}",
                        })
            except:
                pass
        
        # GPG keys
        gpg_dir = f"{home}/.gnupg"
        if fs.exists(gpg_dir):
            try:
                for entry in fs.list_dir(gpg_dir):
                    if entry.lower() in ("pubring.kbx", "trustdb.gpg", "secring.gpg"):
                        gpg_keys.append({
                            "name": entry,
                            "path": f"{gpg_dir}/{entry}",
                        })
            except:
                pass
    
    return {
        "ssh_keys": ssh_keys,
        "gpg_keys": gpg_keys,
        "total_identities": len(ssh_keys) + len(gpg_keys),
    }


def _extract_tor_browser_artifacts(fs: FilesystemAccessor) -> Dict[str, object]:
    """Extract Tor Browser artifacts (bookmarks, history, extensions)."""
    artifacts = {
        "bookmarks": [],
        "profiles": [],
        "extensions": [],
        "total": 0,
    }
    
    for home in _home_dirs(fs):
        for browser_dir_name in (".tor-browser", "Tor Browser", ".mozilla"):
            browser_base = f"{home}/{browser_dir_name}"
            if fs.exists(browser_base):
                artifacts["profiles"].append(browser_base)
                
                # Look for bookmarks and history
                try:
                    for entry in fs.list_dir(browser_base):
                        if "profile" in entry.lower():
                            profile_path = f"{browser_base}/{entry}"
                            try:
                                for subentry in fs.list_dir(profile_path):
                                    if subentry.lower() in ("bookmarks.html", "places.sqlite", "extensions.ini"):
                                        artifacts["bookmarks"].append({
                                            "type": subentry.lower(),
                                            "path": f"{profile_path}/{subentry}",
                                        })
                            except:
                                pass
                except:
                    pass
    
    artifacts["total"] = len(artifacts["bookmarks"]) + len(artifacts["profiles"]) + len(artifacts["extensions"])
    return artifacts


def _extract_user_files(fs: FilesystemAccessor) -> Dict[str, object]:
    """Extract user files from persistent storage."""
    user_files = []
    file_stats = {"total": 0, "by_type": {}}
    
    for home in _home_dirs(fs):
        persistent_path = f"{home}/Persistent"
        if fs.exists(persistent_path):
            try:
                for entry in fs.list_dir(persistent_path)[:50]:  # Limit to first 50
                    if entry not in (".", ".."):
                        entry_path = f"{persistent_path}/{entry}"
                        ext = entry.split(".")[-1].lower() if "." in entry else "no-ext"
                        file_type = _classify_file_type(ext)
                        user_files.append({
                            "name": entry,
                            "path": entry_path,
                            "type": file_type,
                            "extension": ext,
                        })
                        file_stats["by_type"][file_type] = file_stats["by_type"].get(file_type, 0) + 1
            except:
                pass
    
    file_stats["total"] = len(user_files)
    return {
        "files": user_files,
        "stats": file_stats,
    }


def _classify_file_type(ext: str) -> str:
    """Classify file by extension."""
    ext_l = ext.lower()
    if ext_l in ("txt", "md", "doc", "docx", "pdf"):
        return "Documents"
    elif ext_l in ("jpg", "jpeg", "png", "gif", "bmp"):
        return "Images"
    elif ext_l in ("mp4", "avi", "mkv", "mov"):
        return "Videos"
    elif ext_l in ("zip", "rar", "7z", "tar", "gz"):
        return "Archives"
    elif ext_l in ("py", "sh", "js", "rb", "go"):
        return "Scripts"
    elif ext_l in ("sqlite", "db", "dat"):
        return "Databases"
    else:
        return "Other"


def _extract_dotfiles_activity(fs: FilesystemAccessor) -> Dict[str, object]:
    """Extract shell history and dotfile indicators."""
    activity = {
        "bash_history": [],
        "zsh_history": [],
        "custom_execs": [],
        "suspicious_commands": [],
    }
    
    for home in _home_dirs(fs):
        # Bash history
        bash_hist = _read_text(fs, f"{home}/.bash_history", max_bytes=300_000)
        if bash_hist:
            for line in bash_hist.splitlines()[-20:]:  # Last 20 commands
                if line.strip():
                    activity["bash_history"].append(line.strip()[:200])
                    if any(cmd in line.lower() for cmd in ("nmap", "sqlmap", "hydra", "curl", "wget", "nc", "ssh")):
                        activity["suspicious_commands"].append(line.strip()[:200])
        
        # Zsh history
        zsh_hist = _read_text(fs, f"{home}/.zsh_history", max_bytes=300_000)
        if zsh_hist:
            for line in zsh_hist.splitlines()[-20:]:
                if line.strip() and ":" not in line[:2]:  # Skip zsh metadata
                    activity["zsh_history"].append(line.strip()[:200])
    
    return {
        "history_entries": len(activity["bash_history"]) + len(activity["zsh_history"]),
        "suspicious_count": len(activity["suspicious_commands"]),
        "bash_history": activity["bash_history"][:10],
        "suspicious_commands": activity["suspicious_commands"][:10],
    }


def _extract_network_indicators(fs: FilesystemAccessor) -> Dict[str, object]:
    """Extract Tor network and bridge configuration."""
    config = {
        "bridges": [],
        "custom_sentries": [],
        "proxy_config": [],
    }
    
    torrc = _read_text(fs, "/etc/tor/torrc", max_bytes=350_000)
    tor_defaults = _read_text(fs, "/etc/tor/tor-service-defaults-torrc", max_bytes=350_000)
    
    for line in (torrc + "\n" + tor_defaults).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        line_l = line.lower()
        if "bridge " in line_l:
            config["bridges"].append(line[:150])
        elif "entrynode" in line_l or "exitnode" in line_l:
            config["custom_sentries"].append(line[:150])
        elif any(p in line_l for p in ("socksport", "dnsport", "transport", "clientuseipv6")):
            config["proxy_config"].append(line[:150])
    
    return {
        "bridges": config["bridges"][:10],
        "bridges_count": len(config["bridges"]),
        "custom_config": len(config["custom_sentries"]) + len(config["proxy_config"]),
    }


def _calculate_anonymity_score(findings_list: List[Dict[str, object]]) -> Dict[str, object]:
    """Calculate anonymity leakage risk score based on artifacts."""
    score = 0
    leaks = []
    
    # Check for high-risk artifacts
    for finding in findings_list:
        cat = str(finding.get("category", "")).lower()
        
        if cat == "hidden_service":
            score += 25
            leaks.append("Hidden service operation detected")
        elif cat == "persistence" and "enabled modules" in str(finding.get("detail", "")).lower():
            score += 20
            leaks.append("Persistence storage enabled")
        elif cat == "crypto" or "wallet" in cat:
            score += 15
            leaks.append("Cryptocurrency wallet found")
        elif cat == "identity_keys":
            score += 15
            leaks.append("SSH/GPG identity keys present")
        elif cat == "tor" and "onion" in str(finding.get("detail", "")).lower():
            score += 10
            leaks.append("Onion addresses recovered")
        elif cat == "browser":
            score += 8
            leaks.append("Browser artifacts recovered")
        elif cat == "anti_forensics":
            score += 5
            leaks.append("Anti-forensics measures detected")
    
    # Cap at 100
    score = min(score, 100)
    risk_level = "critical" if score >= 80 else "high" if score >= 60 else "medium" if score >= 40 else "low"
    
    return {
        "score": score,
        "max": 100,
        "risk_level": risk_level,
        "primary_leaks": leaks[:5],
        "leak_count": len(leaks),
    }


def analyze_tails(fs: FilesystemAccessor, tool_findings: Optional[List[Dict[str, object]]] = None) -> Dict[str, object]:
    """Run comprehensive Tails-specific forensic analysis.

    Returns a structured dict with findings and organized artifact categories.
    """
    out: List[Dict[str, object]] = []

    def add(category: str, detail: str, severity: str = "info", source: str = "tails", evidence: Optional[List[str]] = None):
        out.append(
            {
                "source": source,
                "category": category,
                "detail": detail,
                "severity": severity,
                "evidence": evidence or [],
            }
        )

    # 1) Detect if system was running Tails
    osr = _read_text(fs, "/etc/os-release", max_bytes=200_000)
    cmdline = _read_text(fs, "/proc/cmdline", max_bytes=80_000)
    tails_markers = _tails_paths(fs)
    tails_vars = []
    for k in ("TAILS_PRODUCT_NAME", "TAILS_VERSION", "TAILS_CHANNEL"):
        if k in osr:
            tails_vars.append(k)
    boot_markers = [m for m in ("boot=live", "amnesia", "nopersistence") if m in cmdline]

    if tails_markers or tails_vars or ("tails" in osr.lower()):
        add(
            "environment",
            "Tails OS environment indicators detected.",
            severity="high",
            evidence=tails_markers + tails_vars + boot_markers,
        )
    elif boot_markers:
        add(
            "environment",
            "Live amnesic boot parameters found but explicit Tails markers are limited.",
            severity="medium",
            evidence=boot_markers,
        )

    # 2) Persistence usage and modules
    persistence_paths = [
        p for p in (
            "/live/persistence/TailsData_unlocked",
            "/live/persistence/TailsData",
            "/live/persistence/TailsData_unlocked/persistence.conf",
        )
        if fs.exists(p)
    ]
    mounts = _read_text(fs, "/proc/mounts", max_bytes=500_000)
    syslog = _read_text(fs, "/var/log/syslog", max_bytes=1_500_000)
    persist_lines = _first_lines_with(syslog + "\n" + mounts, ["TailsData", "persistence", "live/persistence"], limit=6)
    if persistence_paths or persist_lines:
        add(
            "persistence",
            "Persistent storage appears present or mounted in this session.",
            severity="medium",
            evidence=persistence_paths + persist_lines,
        )
        pconf = _read_text(fs, "/live/persistence/TailsData_unlocked/persistence.conf", max_bytes=300_000)
        enabled_modules = _first_lines_with(pconf, ["=", "source=", "destination="], limit=8)
        if enabled_modules:
            add(
                "persistence",
                "Persistence feature definitions recovered.",
                severity="info",
                evidence=enabled_modules,
            )

    # 3) Tor activity forensics
    tor_paths = [p for p in ("/var/lib/tor", "/run/tor", "/etc/tor/torrc") if fs.exists(p)]
    torrc = _read_text(fs, "/etc/tor/torrc", max_bytes=350_000)
    tor_log = _read_text(fs, "/var/log/tor/log", max_bytes=1_200_000)
    tor_lines = _first_lines_with(tor_log + "\n" + syslog, ["bootstrapped", "tor", "guard", "circuit"], limit=8)
    onions = _extract_onions(torrc + "\n" + tor_log + "\n" + syslog, limit=10)
    if tor_paths or tor_lines:
        add(
            "tor",
            "Tor runtime artifacts and activity traces detected.",
            severity="high",
            evidence=tor_paths + tor_lines[:4],
        )
    if onions:
        add(
            "tor",
            "Potential onion destinations or hidden-service identifiers recovered.",
            severity="high",
            evidence=onions,
        )

    # 4) Tor Browser artifacts
    browser_hits: List[str] = []
    for home in _home_dirs(fs):
        for rel in (".tor-browser", "Tor Browser", ".mozilla", ".cache/torbrowser"):
            p = f"{home}/{rel}"
            if fs.exists(p):
                browser_hits.append(p)
    if browser_hits:
        add(
            "browser",
            "Tor Browser profile/runtime paths found.",
            severity="medium",
            evidence=browser_hits[:10],
        )

    # 5) USB origin detection clues
    by_id_entries = fs.list_dir("/dev/disk/by-id")
    usb_ids = [f"/dev/disk/by-id/{n}" for n in by_id_entries if "usb" in n.lower()][:8]
    usb_lines = _first_lines_with(syslog, ["usb", "mass storage", "uas", "sd ", "scsi"], limit=6)
    if usb_ids or usb_lines:
        add(
            "usb_origin",
            "USB boot/media indicators detected from block-id links or logs.",
            severity="info",
            evidence=usb_ids + usb_lines,
        )

    # 6) RAM artifact opportunities (best effort via dump discovery)
    dump_candidates: List[str] = []
    for base in ("/tmp", "/var/tmp", "/var/crash", "/mnt"):
        for n in fs.list_dir(base):
            ln = n.lower()
            if ln.endswith((".mem", ".raw", ".dmp", ".lime", ".vmem")):
                dump_candidates.append(f"{base}/{n}")
    if dump_candidates:
        add(
            "memory",
            "Potential memory dumps detected for volatile artifact extraction.",
            severity="high",
            evidence=dump_candidates[:8],
        )

    cmd_fragments = []
    for m in _CMD_FRAGMENT_RE.findall(syslog):
        frag = m.strip()
        if frag and frag not in cmd_fragments:
            cmd_fragments.append(frag)
        if len(cmd_fragments) >= 6:
            break
    if cmd_fragments:
        add(
            "memory",
            "Command-like runtime fragments recovered (best effort).",
            severity="medium",
            evidence=cmd_fragments,
        )

    # 7) Hidden service detection
    hs_hits = []
    if fs.exists("/var/lib/tor/hidden_service"):
        hs_hits.append("/var/lib/tor/hidden_service")
    hs_lines = _first_lines_with(torrc, ["HiddenServiceDir", "HiddenServicePort"], limit=8)
    if hs_hits or hs_lines:
        add(
            "hidden_service",
            "Tor hidden service configuration indicators detected.",
            severity="high",
            evidence=hs_hits + hs_lines,
        )

    # 8) Anti-forensic behavior indicators
    anti_evidence: List[str] = []
    for line in mounts.splitlines():
        if " tmpfs " in line and any(p in line for p in ("/run", "/tmp", "/var/tmp")):
            anti_evidence.append(line.strip()[:180])
            if len(anti_evidence) >= 5:
                break
    journald_conf = _read_text(fs, "/etc/systemd/journald.conf", max_bytes=200_000)
    anti_evidence.extend(_first_lines_with(journald_conf, ["Storage=volatile", "Storage=none", "ForwardToSyslog=no"], limit=3))
    if anti_evidence:
        add(
            "anti_forensics",
            "Amnesic/low-retention logging behavior indicators present.",
            severity="medium",
            evidence=anti_evidence,
        )

    # 9) Session timeline reconstruction
    timeline_events: List[str] = []
    for line in syslog.splitlines():
        ll = line.lower()
        if not ("tor" in ll or "boot" in ll or "systemd" in ll or "ssh" in ll):
            continue
        m = _TS_RE.search(line)
        ts = m.group(1) if m else "unknown-time"
        timeline_events.append(f"{ts} | {line.strip()[:140]}")
        if len(timeline_events) >= 10:
            break
    if timeline_events:
        add(
            "timeline",
            "Partial Tails session timeline reconstructed from volatile/system logs.",
            severity="info",
            evidence=timeline_events,
        )

    # 10) Misconfiguration and operational profile
    miscfg: List[str] = []
    unsafe_paths = [
        "/usr/share/applications/unsafe-browser.desktop",
        "/etc/tor/tor-service-defaults-torrc",
    ]
    for p in unsafe_paths:
        if fs.exists(p):
            miscfg.append(p)
    miscfg.extend(_first_lines_with(torrc, ["SocksPort", "DNSPort", "TransPort", "ClientUseIPv6"], limit=6))
    if miscfg:
        add(
            "misconfiguration",
            "Potential anonymity-impacting configuration traces detected.",
            severity="medium",
            evidence=miscfg[:8],
        )

    tools = tool_findings or []
    tool_names = {str(t.get("tool", "")).lower() for t in tools}
    profile_indicators: List[str] = []
    score = 0
    if any(f["category"] == "hidden_service" for f in out):
        profile_indicators.append("hidden_service")
        score += 3
    if any(t in tool_names for t in ("metasploit", "sqlmap", "hydra")):
        profile_indicators.append("offensive_tools")
        score += 3
    if any(f["category"] == "tor" for f in out):
        profile_indicators.append("tor_activity")
        score += 1
    if any(f["category"] == "persistence" for f in out):
        profile_indicators.append("persistent_storage")
        score += 1
    if any(f["category"] == "anti_forensics" for f in out):
        profile_indicators.append("anti_forensics")
        score += 1

    add(
        "operational_profile",
        _classify_profile(profile_indicators, score),
        severity="high" if score >= 6 else "medium" if score >= 3 else "info",
        evidence=profile_indicators,
    )

    # Structured artifact extraction
    persistence_modules = _extract_persistence_modules(fs)
    crypto_wallets = _extract_crypto_wallets(fs)
    identity_keys = _extract_identity_keys(fs)
    tor_browser = _extract_tor_browser_artifacts(fs)
    user_files = _extract_user_files(fs)
    dotfiles_activity = _extract_dotfiles_activity(fs)
    network_config = _extract_network_indicators(fs)
    anonymity_score = _calculate_anonymity_score(out)

    return {
        "findings": out,
        "artifacts": {
            "persistence_modules": persistence_modules,
            "crypto_wallets": crypto_wallets,
            "identity_keys": identity_keys,
            "tor_browser_artifacts": tor_browser,
            "user_files": user_files,
            "dotfiles_and_activity": dotfiles_activity,
            "network_config": network_config,
            "anonymity_score": anonymity_score,
        },
    }



def _read_text(fs: FilesystemAccessor, path: str, max_bytes: int = 1_200_000) -> str:
    raw = fs.read_file(path, max_bytes=max_bytes)
    if not raw:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _extract_onions(text: str, limit: int = 8) -> List[str]:
    out: List[str] = []
    for m in _ONION_RE.findall(text or ""):
        v = m.lower()
        if v not in out:
            out.append(v)
        if len(out) >= limit:
            break
    return out


def _first_lines_with(text: str, needles: Sequence[str], limit: int = 4) -> List[str]:
    needles_l = [n.lower() for n in needles]
    out: List[str] = []
    for line in (text or "").splitlines():
        ll = line.lower()
        if any(n in ll for n in needles_l):
            out.append(line.strip()[:220])
        if len(out) >= limit:
            break
    return out


def _home_dirs(fs: FilesystemAccessor) -> List[str]:
    homes = ["/home/amnesia"]
    for name in fs.list_dir("/home"):
        n = name.strip("/")
        if n and n not in (".", ".."):
            homes.append(f"/home/{n}")
    # Stable order + de-dup
    seen = set()
    out: List[str] = []
    for h in homes:
        if h not in seen:
            out.append(h)
            seen.add(h)
    return out


def _tails_paths(fs: FilesystemAccessor) -> List[str]:
    candidates = [
        "/etc/amnesia",
        "/live/persistence/TailsData_unlocked",
        "/live/persistence/TailsData",
        "/usr/share/live/config",
        "/lib/live/mount",
    ]
    return [p for p in candidates if fs.exists(p)]


def _classify_profile(indicators: List[str], score: int) -> str:
    if score >= 6:
        label = "High Risk"
    elif score >= 3:
        label = "Security Researcher / Advanced Operator"
    else:
        label = "Privacy User"
    return f"Operational profile: {label} (score={score}, indicators={', '.join(indicators) or 'none'})"


def analyze_tails(fs: FilesystemAccessor, tool_findings: Optional[List[Dict[str, object]]] = None) -> List[Dict[str, object]]:
    """Run Tails-specific forensic checks.

    Returns a list of normalized findings:
    {source, category, detail, severity, evidence}
    """
    out: List[Dict[str, object]] = []

    def add(category: str, detail: str, severity: str = "info", source: str = "tails", evidence: Optional[List[str]] = None):
        out.append(
            {
                "source": source,
                "category": category,
                "detail": detail,
                "severity": severity,
                "evidence": evidence or [],
            }
        )

    # 1) Detect if system was running Tails
    osr = _read_text(fs, "/etc/os-release", max_bytes=200_000)
    cmdline = _read_text(fs, "/proc/cmdline", max_bytes=80_000)
    tails_markers = _tails_paths(fs)
    tails_vars = []
    for k in ("TAILS_PRODUCT_NAME", "TAILS_VERSION", "TAILS_CHANNEL"):
        if k in osr:
            tails_vars.append(k)
    boot_markers = [m for m in ("boot=live", "amnesia", "nopersistence") if m in cmdline]

    if tails_markers or tails_vars or ("tails" in osr.lower()):
        add(
            "environment",
            "Tails OS environment indicators detected.",
            severity="high",
            evidence=tails_markers + tails_vars + boot_markers,
        )
    elif boot_markers:
        add(
            "environment",
            "Live amnesic boot parameters found but explicit Tails markers are limited.",
            severity="medium",
            evidence=boot_markers,
        )

    # 2) Persistence usage
    persistence_paths = [
        p for p in (
            "/live/persistence/TailsData_unlocked",
            "/live/persistence/TailsData",
            "/live/persistence/TailsData_unlocked/persistence.conf",
        )
        if fs.exists(p)
    ]
    mounts = _read_text(fs, "/proc/mounts", max_bytes=500_000)
    syslog = _read_text(fs, "/var/log/syslog", max_bytes=1_500_000)
    persist_lines = _first_lines_with(syslog + "\n" + mounts, ["TailsData", "persistence", "live/persistence"], limit=6)
    if persistence_paths or persist_lines:
        add(
            "persistence",
            "Persistent storage appears present or mounted in this session.",
            severity="medium",
            evidence=persistence_paths + persist_lines,
        )
        pconf = _read_text(fs, "/live/persistence/TailsData_unlocked/persistence.conf", max_bytes=300_000)
        enabled_modules = _first_lines_with(pconf, ["=", "source=", "destination="], limit=8)
        if enabled_modules:
            add(
                "persistence",
                "Persistence feature definitions recovered.",
                severity="info",
                evidence=enabled_modules,
            )

    # 3) Tor activity forensics
    tor_paths = [p for p in ("/var/lib/tor", "/run/tor", "/etc/tor/torrc") if fs.exists(p)]
    torrc = _read_text(fs, "/etc/tor/torrc", max_bytes=350_000)
    tor_log = _read_text(fs, "/var/log/tor/log", max_bytes=1_200_000)
    tor_lines = _first_lines_with(tor_log + "\n" + syslog, ["bootstrapped", "tor", "guard", "circuit"], limit=8)
    onions = _extract_onions(torrc + "\n" + tor_log + "\n" + syslog, limit=10)
    if tor_paths or tor_lines:
        add(
            "tor",
            "Tor runtime artifacts and activity traces detected.",
            severity="high",
            evidence=tor_paths + tor_lines[:4],
        )
    if onions:
        add(
            "tor",
            "Potential onion destinations or hidden-service identifiers recovered.",
            severity="high",
            evidence=onions,
        )

    # 4) Tor Browser artifacts
    browser_hits: List[str] = []
    for home in _home_dirs(fs):
        for rel in (".tor-browser", "Tor Browser", ".mozilla", ".cache/torbrowser"):
            p = f"{home}/{rel}"
            if fs.exists(p):
                browser_hits.append(p)
    if browser_hits:
        add(
            "browser",
            "Tor Browser profile/runtime paths found.",
            severity="medium",
            evidence=browser_hits[:10],
        )

    # 5) USB origin detection clues
    by_id_entries = fs.list_dir("/dev/disk/by-id")
    usb_ids = [f"/dev/disk/by-id/{n}" for n in by_id_entries if "usb" in n.lower()][:8]
    usb_lines = _first_lines_with(syslog, ["usb", "mass storage", "uas", "sd ", "scsi"], limit=6)
    if usb_ids or usb_lines:
        add(
            "usb_origin",
            "USB boot/media indicators detected from block-id links or logs.",
            severity="info",
            evidence=usb_ids + usb_lines,
        )

    # 6) RAM artifact opportunities (best effort via dump discovery)
    dump_candidates: List[str] = []
    for base in ("/tmp", "/var/tmp", "/var/crash", "/mnt"):
        for n in fs.list_dir(base):
            ln = n.lower()
            if ln.endswith((".mem", ".raw", ".dmp", ".lime", ".vmem")):
                dump_candidates.append(f"{base}/{n}")
    if dump_candidates:
        add(
            "memory",
            "Potential memory dumps detected for volatile artifact extraction.",
            severity="high",
            evidence=dump_candidates[:8],
        )

    cmd_fragments = []
    for m in _CMD_FRAGMENT_RE.findall(syslog):
        frag = m.strip()
        if frag and frag not in cmd_fragments:
            cmd_fragments.append(frag)
        if len(cmd_fragments) >= 6:
            break
    if cmd_fragments:
        add(
            "memory",
            "Command-like runtime fragments recovered (best effort).",
            severity="medium",
            evidence=cmd_fragments,
        )

    # 7) Hidden service detection
    hs_hits = []
    if fs.exists("/var/lib/tor/hidden_service"):
        hs_hits.append("/var/lib/tor/hidden_service")
    hs_lines = _first_lines_with(torrc, ["HiddenServiceDir", "HiddenServicePort"], limit=8)
    if hs_hits or hs_lines:
        add(
            "hidden_service",
            "Tor hidden service configuration indicators detected.",
            severity="high",
            evidence=hs_hits + hs_lines,
        )

    # 8) Anti-forensic behavior indicators
    anti_evidence: List[str] = []
    for line in mounts.splitlines():
        if " tmpfs " in line and any(p in line for p in ("/run", "/tmp", "/var/tmp")):
            anti_evidence.append(line.strip()[:180])
            if len(anti_evidence) >= 5:
                break
    journald_conf = _read_text(fs, "/etc/systemd/journald.conf", max_bytes=200_000)
    anti_evidence.extend(_first_lines_with(journald_conf, ["Storage=volatile", "Storage=none", "ForwardToSyslog=no"], limit=3))
    if anti_evidence:
        add(
            "anti_forensics",
            "Amnesic/low-retention logging behavior indicators present.",
            severity="medium",
            evidence=anti_evidence,
        )

    # 9) Session timeline reconstruction
    timeline_events: List[str] = []
    for line in syslog.splitlines():
        ll = line.lower()
        if not ("tor" in ll or "boot" in ll or "systemd" in ll or "ssh" in ll):
            continue
        m = _TS_RE.search(line)
        ts = m.group(1) if m else "unknown-time"
        timeline_events.append(f"{ts} | {line.strip()[:140]}")
        if len(timeline_events) >= 10:
            break
    if timeline_events:
        add(
            "timeline",
            "Partial Tails session timeline reconstructed from volatile/system logs.",
            severity="info",
            evidence=timeline_events,
        )

    # 10) Misconfiguration and operational profile
    miscfg: List[str] = []
    unsafe_paths = [
        "/usr/share/applications/unsafe-browser.desktop",
        "/etc/tor/tor-service-defaults-torrc",
    ]
    for p in unsafe_paths:
        if fs.exists(p):
            miscfg.append(p)
    miscfg.extend(_first_lines_with(torrc, ["SocksPort", "DNSPort", "TransPort", "ClientUseIPv6"], limit=6))
    if miscfg:
        add(
            "misconfiguration",
            "Potential anonymity-impacting configuration traces detected.",
            severity="medium",
            evidence=miscfg[:8],
        )

    tools = tool_findings or []
    tool_names = {str(t.get("tool", "")).lower() for t in tools}
    profile_indicators: List[str] = []
    score = 0
    if any(f["category"] == "hidden_service" for f in out):
        profile_indicators.append("hidden_service")
        score += 3
    if any(t in tool_names for t in ("metasploit", "sqlmap", "hydra")):
        profile_indicators.append("offensive_tools")
        score += 3
    if any(f["category"] == "tor" for f in out):
        profile_indicators.append("tor_activity")
        score += 1
    if any(f["category"] == "persistence" for f in out):
        profile_indicators.append("persistent_storage")
        score += 1
    if any(f["category"] == "anti_forensics" for f in out):
        profile_indicators.append("anti_forensics")
        score += 1

    add(
        "operational_profile",
        _classify_profile(profile_indicators, score),
        severity="high" if score >= 6 else "medium" if score >= 3 else "info",
        evidence=profile_indicators,
    )

    return out
