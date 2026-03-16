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
