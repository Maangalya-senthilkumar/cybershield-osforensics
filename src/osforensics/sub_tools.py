"""Domain-specific tool registries for each forensic sub-agent.

Each registry is a plain dict:
    { "tool_name": {"name", "description", "params", "fn"} }

Tools are thin wrappers around the existing forensic modules so that
each sub-agent only sees the tools relevant to its domain.
"""
from __future__ import annotations

import subprocess
import traceback
from pathlib import Path
from typing import Any, Dict

# ── Shared registration helper ─────────────────────────────────────────────────

def _make_registry(*tool_defs) -> Dict[str, dict]:
    """Build a registry dict from (name, description, params, fn) tuples."""
    return {t[0]: {"name": t[0], "description": t[1], "params": t[2], "fn": t[3]}
            for t in tool_defs}


# ── Lazy module imports (each domain loads only what it needs) ─────────────────

def _fs(path: str):
    from .extractor import FilesystemAccessor
    return FilesystemAccessor(path)


# ══════════════════════════════════════════════════════════════════════════════
# BROWSER AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _browser_detect(path: str) -> dict:
    try:
        from .browser import detect_browsers
        profiles = detect_browsers(_fs(path))
        return {"profiles": [p.dict() if hasattr(p, "dict") else dict(p) for p in profiles],
                "count": len(profiles)}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


def _browser_history(path: str, browser: str = "") -> dict:
    """Return browsing history entries, optionally filtered by browser name."""
    try:
        from .browser import detect_browsers
        profiles = detect_browsers(_fs(path))
        results = []
        for p in profiles:
            d = p.dict() if hasattr(p, "dict") else dict(p)
            if browser and browser.lower() not in d.get("browser", "").lower():
                continue
            results.append({
                "browser":      d["browser"],
                "user":         d["user"],
                "profile":      d["profile"],
                "history":      d.get("history", [])[:50],
                "downloads":    d.get("downloads", [])[:20],
                "search_terms": d.get("search_terms", [])[:20],
            })
        return {"profiles": results}
    except Exception as e:
        return {"error": str(e)}


def _browser_extensions(path: str) -> dict:
    """List all installed browser extensions and flag suspicious ones."""
    try:
        from .browser import detect_browsers
        profiles = detect_browsers(_fs(path))
        all_ext = []
        for p in profiles:
            d = p.dict() if hasattr(p, "dict") else dict(p)
            for ext in d.get("extensions", []):
                ext["browser"] = d["browser"]
                ext["user"]    = d["user"]
                all_ext.append(ext)
        return {"extension_count": len(all_ext), "extensions": all_ext}
    except Exception as e:
        return {"error": str(e)}


def _browser_credentials(path: str) -> dict:
    """Extract saved logins/passwords from browser profiles."""
    try:
        from .browser import detect_browsers
        profiles = detect_browsers(_fs(path))
        logins = []
        for p in profiles:
            d = p.dict() if hasattr(p, "dict") else dict(p)
            for l in d.get("logins", []):
                l["browser"] = d["browser"]
                l["user"]    = d["user"]
                logins.append(l)
        return {"login_count": len(logins), "logins": logins}
    except Exception as e:
        return {"error": str(e)}


BROWSER_TOOLS = _make_registry(
    (
        "list_browser_profiles",
        "Enumerate all browser profiles found on the system (Chrome, Firefox, Brave, Tor Browser).",
        {"path": "str: absolute filesystem path"},
        _browser_detect,
    ),
    (
        "get_browser_history",
        "Extract browsing history, downloads, and search terms. Optionally filter by browser name.",
        {"path": "str: absolute filesystem path", "browser": "str: optional browser name filter (chrome/firefox/brave/tor)"},
        _browser_history,
    ),
    (
        "get_browser_extensions",
        "List all installed browser extensions. Flags unusual or potentially malicious ones.",
        {"path": "str: absolute filesystem path"},
        _browser_extensions,
    ),
    (
        "get_saved_credentials",
        "Extract saved login entries (URLs, usernames) from browser credential stores.",
        {"path": "str: absolute filesystem path"},
        _browser_credentials,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# MEMORY AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _mem_full(dump_path: str) -> dict:
    try:
        from .memory import analyze_memory
        r = analyze_memory(dump_path)
        if r.needs_symbols:
            return {"error": f"Volatility3 symbol table missing for kernel: {r.kernel_version}",
                    "needs_symbols": True, "kernel_version": r.kernel_version}
        ext_conns = [c.dict() for c in r.connections
                     if c.raddr and not c.raddr.startswith(("127.", "0.0.0.0", "::"))]
        return {
            "kernel_version":       r.kernel_version,
            "process_count":        len(r.processes),
            "hidden_process_count": len(r.hidden_processes),
            "connection_count":     len(r.connections),
            "external_connections": ext_conns,
            "malware_indicators":   len(r.malfind),
            "processes":            [p.dict() for p in r.processes[:25]],
            "hidden_processes":     [p.dict() for p in r.hidden_processes],
        }
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


def _mem_processes(dump_path: str) -> dict:
    """Focus on process list, hidden processes, and suspicious command lines."""
    try:
        from .memory import analyze_memory
        r = analyze_memory(dump_path)
        procs  = [p.dict() for p in r.processes]
        hidden = [p.dict() for p in r.hidden_processes]
        suspicious = [p for p in procs if any(kw in (p.get("cmdline") or "").lower()
                                               for kw in ("bash -i", "nc ", "wget ", "curl ", "python -c", "/tmp/"))]
        return {"total": len(procs), "hidden": len(hidden),
                "suspicious_cmdline": suspicious,
                "processes": procs[:30], "hidden_processes": hidden}
    except Exception as e:
        return {"error": str(e)}


def _mem_network(dump_path: str) -> dict:
    """Focus on network connections from the memory dump."""
    try:
        from .memory import analyze_memory
        r = analyze_memory(dump_path)
        conns = [c.dict() for c in r.connections]
        external = [c for c in conns if c.get("raddr") and
                    not c["raddr"].startswith(("127.", "0.0.0.0", "::"))]
        return {"total_connections": len(conns), "external": len(external),
                "external_connections": external, "all_connections": conns[:40]}
    except Exception as e:
        return {"error": str(e)}


def _mem_malfind(dump_path: str) -> dict:
    """Run malfind: detect injected code / suspicious memory regions."""
    try:
        from .memory import analyze_memory
        r = analyze_memory(dump_path)
        return {"indicator_count": len(r.malfind),
                "indicators": [m.dict() for m in r.malfind]}
    except Exception as e:
        return {"error": str(e)}


def _mem_bash_history(dump_path: str) -> dict:
    """Extract bash command history from the memory dump."""
    try:
        from .memory import analyze_memory
        r = analyze_memory(dump_path)
        return {"command_count": len(r.bash_history),
                "history": [b.dict() for b in r.bash_history]}
    except Exception as e:
        return {"error": str(e)}


MEMORY_TOOLS = _make_registry(
    (
        "full_memory_analysis",
        "Run complete Volatility3 analysis: processes, connections, modules, malfind.",
        {"dump_path": "str: path to memory dump (.raw/.mem/.lime/.dmp/.vmem)"},
        _mem_full,
    ),
    (
        "list_processes",
        "Extract process list and hidden processes. Flags suspicious command lines.",
        {"dump_path": "str: path to memory dump"},
        _mem_processes,
    ),
    (
        "list_network_connections",
        "Extract all network connections from memory, highlighting external ones.",
        {"dump_path": "str: path to memory dump"},
        _mem_network,
    ),
    (
        "run_malfind",
        "Detect injected code and suspicious memory-mapped regions (shellcode, PE headers).",
        {"dump_path": "str: path to memory dump"},
        _mem_malfind,
    ),
    (
        "get_bash_history",
        "Recover bash command history from volatile memory.",
        {"dump_path": "str: path to memory dump"},
        _mem_bash_history,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# PERSISTENCE AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _persist_all(path: str) -> dict:
    try:
        from .persistence import detect_persistence
        items = [p.dict() for p in detect_persistence(_fs(path))]
        high  = [i for i in items if i["severity"] in ("critical", "high")]
        cats  = {}
        for i in items:
            cats[i["category"]] = cats.get(i["category"], 0) + 1
        return {"total": len(items), "high_severity": len(high),
                "by_category": cats, "high_items": high[:20], "all_items": items[:40]}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


def _persist_cron(path: str) -> dict:
    try:
        from .persistence import scan_crontabs
        items = scan_crontabs(_fs(path))
        return {"total": len(items), "items": items}
    except Exception as e:
        return {"error": str(e)}


def _persist_systemd(path: str) -> dict:
    try:
        from .persistence import scan_systemd_services
        items = scan_systemd_services(_fs(path))
        high  = [i for i in items if i["severity"] in ("critical", "high")]
        return {"total": len(items), "high": len(high),
                "high_items": high, "all_items": items[:30]}
    except Exception as e:
        return {"error": str(e)}


def _persist_startup(path: str) -> dict:
    try:
        from .persistence import scan_shell_startup
        items = scan_shell_startup(_fs(path))
        return {"total": len(items), "items": items}
    except Exception as e:
        return {"error": str(e)}


def _persist_ssh_keys(path: str) -> dict:
    try:
        from .persistence import scan_ssh_authorized_keys
        items = scan_ssh_authorized_keys(_fs(path))
        return {"total": len(items), "items": items}
    except Exception as e:
        return {"error": str(e)}


PERSISTENCE_TOOLS = _make_registry(
    (
        "detect_all_persistence",
        "Scan all persistence vectors: cron, systemd, shell startup, SSH keys.",
        {"path": "str: absolute filesystem path"},
        _persist_all,
    ),
    (
        "scan_crontabs",
        "Inspect cron.d, user crontabs, and /etc/crontab for suspicious entries.",
        {"path": "str: absolute filesystem path"},
        _persist_cron,
    ),
    (
        "scan_systemd_units",
        "Find unrecognised or payload-bearing systemd service units.",
        {"path": "str: absolute filesystem path"},
        _persist_systemd,
    ),
    (
        "scan_shell_startup",
        "Check .bashrc, .profile, /etc/rc.local, etc. for injected commands.",
        {"path": "str: absolute filesystem path"},
        _persist_startup,
    ),
    (
        "scan_ssh_authorized_keys",
        "Enumerate SSH authorized_keys for all users and flag forced-command entries.",
        {"path": "str: absolute filesystem path"},
        _persist_ssh_keys,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# FILESYSTEM AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _fs_detect_os(path: str) -> dict:
    try:
        from .detector import detect_os
        return detect_os(_fs(path))
    except Exception as e:
        return {"error": str(e)}


def _fs_detect_tools(path: str) -> dict:
    try:
        from .detector import detect_tools
        from .classifier import classify_findings
        findings   = detect_tools(_fs(path))
        classified = classify_findings(findings)
        return {"tool_count": len(classified), "findings": classified}
    except Exception as e:
        return {"error": str(e)}


def _fs_timeline(path: str, limit: int = 50) -> dict:
    try:
        from .timeline import build_timeline
        events = [e.dict() for e in build_timeline(_fs(path))]
        high   = [e for e in events if e["severity"] in ("critical", "high")]
        return {"total": len(events), "high": len(high),
                "high_events": high[:20], "recent": events[:limit]}
    except Exception as e:
        return {"error": str(e)}


def _fs_deleted(path: str) -> dict:
    try:
        from .deleted import detect_deleted
        items       = [d.dict() for d in detect_deleted(_fs(path))]
        suspicious  = [i for i in items if i["severity"] in ("critical", "high")]
        return {"total": len(items), "suspicious": len(suspicious),
                "suspicious_items": suspicious[:20], "all": items[:40]}
    except Exception as e:
        return {"error": str(e)}


def _fs_search(path: str, pattern: str) -> dict:
    p = Path(path).resolve()
    if not p.exists():
        return {"error": f"Path does not exist: {path}"}
    try:
        exts = ["*.txt","*.log","*.conf","*.cfg","*.sh","*.py","*.json",
                "*.yaml","*.env","*.ini","*.xml","*.csv"]
        grep_args = ["grep", "-ril"] + [a for e in exts for a in ("--include="+e,)] + ["--", pattern, str(p)]
        list_proc = subprocess.run(grep_args, capture_output=True, text=True, timeout=30)
        files = [l.strip() for l in list_proc.stdout.splitlines() if l.strip()]
        matches = []
        for f in files[:10]:
            r2 = subprocess.run(["grep", "-in", "--", pattern, f],
                                capture_output=True, text=True, timeout=10)
            for line in r2.stdout.splitlines()[:3]:
                matches.append({"file": f, "match": line.strip()})
        return {"files_matched": len(files), "file_list": files[:20], "samples": matches[:30]}
    except subprocess.TimeoutExpired:
        return {"error": "Search timed out"}
    except Exception as e:
        return {"error": str(e)}


FILESYSTEM_TOOLS = _make_registry(
    (
        "detect_os",
        "Identify the operating system and distribution from /etc/os-release and filesystem heuristics.",
        {"path": "str: absolute filesystem path"},
        _fs_detect_os,
    ),
    (
        "detect_installed_tools",
        "Find offensive/privacy/security tools installed on the system (nmap, metasploit, tor, etc.).",
        {"path": "str: absolute filesystem path"},
        _fs_detect_tools,
    ),
    (
        "build_timeline",
        "Reconstruct chronological filesystem activity from file timestamps and logs.",
        {"path": "str: absolute filesystem path", "limit": "int: max events to return (default 50)"},
        _fs_timeline,
    ),
    (
        "find_deleted_files",
        "Discover recently deleted or tampered files using filesystem metadata.",
        {"path": "str: absolute filesystem path"},
        _fs_deleted,
    ),
    (
        "search_content",
        "Search for a text/regex pattern across files. Finds credentials, C2 domains, IOCs.",
        {"path": "str: absolute filesystem path", "pattern": "str: text or regex pattern"},
        _fs_search,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# SERVICES AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _svc_all(path: str) -> dict:
    try:
        from .services import detect_services
        items = [s.dict() if hasattr(s, "dict") else dict(s) for s in detect_services(_fs(path))]
        suspicious = [i for i in items if i.get("severity") in ("critical", "high")]
        enabled    = [i for i in items if i.get("state") == "enabled"]
        by_cat: Dict[str, int] = {}
        for i in items:
            by_cat[i.get("category","unknown")] = by_cat.get(i.get("category","unknown"), 0) + 1
        return {"total": len(items), "enabled": len(enabled),
                "suspicious": len(suspicious), "by_category": by_cat,
                "suspicious_items": suspicious[:20], "all": items[:40]}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


def _svc_filter(path: str, category: str = "", severity: str = "") -> dict:
    try:
        from .services import detect_services
        items = [s.dict() if hasattr(s, "dict") else dict(s) for s in detect_services(_fs(path))]
        if category:
            items = [i for i in items if i.get("category", "").lower() == category.lower()]
        if severity:
            items = [i for i in items if i.get("severity", "").lower() == severity.lower()]
        return {"count": len(items), "services": items[:30]}
    except Exception as e:
        return {"error": str(e)}


SERVICES_TOOLS = _make_registry(
    (
        "list_all_services",
        "Enumerate all system services; flags unknown/suspicious ones that may be backdoors.",
        {"path": "str: absolute filesystem path"},
        _svc_all,
    ),
    (
        "filter_services",
        "Return services matching a specific category or severity (e.g. high, critical).",
        {"path": "str: absolute filesystem path",
         "category": "str: optional category filter",
         "severity": "str: optional severity filter (info/medium/high/critical)"},
        _svc_filter,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# CONFIG AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _cfg_all(path: str) -> dict:
    try:
        from .config import analyze_configs
        findings = analyze_configs(_fs(path))
        critical = [f for f in findings if f.get("severity") == "critical"]
        high     = [f for f in findings if f.get("severity") == "high"]
        by_cat: Dict[str, int] = {}
        for f in findings:
            by_cat[f.get("category","unknown")] = by_cat.get(f.get("category","unknown"), 0) + 1
        return {"total": len(findings), "critical": len(critical), "high": len(high),
                "by_category": by_cat, "top": findings[:25]}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


def _cfg_ssh(path: str) -> dict:
    try:
        from .config import analyze_configs
        findings = [f for f in analyze_configs(_fs(path)) if "ssh" in f.get("category","").lower()]
        return {"count": len(findings), "findings": findings}
    except Exception as e:
        return {"error": str(e)}


def _cfg_sudo(path: str) -> dict:
    try:
        from .config import analyze_configs
        findings = [f for f in analyze_configs(_fs(path)) if "sudo" in f.get("category","").lower()]
        return {"count": len(findings), "findings": findings}
    except Exception as e:
        return {"error": str(e)}


CONFIG_TOOLS = _make_registry(
    (
        "audit_all_configs",
        "Full security configuration audit: SSH, sudo, firewall, PAM, sysctl.",
        {"path": "str: absolute filesystem path"},
        _cfg_all,
    ),
    (
        "audit_ssh_config",
        "Audit SSH daemon and client configuration for weak settings or backdoors.",
        {"path": "str: absolute filesystem path"},
        _cfg_ssh,
    ),
    (
        "audit_sudo_rules",
        "Review sudoers rules for dangerous NOPASSWD, ALL privileges, or rogue entries.",
        {"path": "str: absolute filesystem path"},
        _cfg_sudo,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# MULTIMEDIA AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _mm_all(path: str) -> dict:
    try:
        from .multimedia import analyze_multimedia
        findings = analyze_multimedia(_fs(path))
        findings_l = [f if isinstance(f, dict) else (f.dict() if hasattr(f, "dict") else dict(f)) for f in findings]
        gps_files  = [f for f in findings_l if f.get("gps")]
        high       = [f for f in findings_l if f.get("severity") in ("high","critical")]
        return {"total": len(findings_l), "gps_files": len(gps_files),
                "suspicious": len(high), "samples": findings_l[:15],
                "high_risk": high[:10]}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


def _mm_gps(path: str) -> dict:
    try:
        from .multimedia import analyze_multimedia
        findings = analyze_multimedia(_fs(path))
        gps_files = []
        for f in findings:
            d = f if isinstance(f, dict) else (f.dict() if hasattr(f, "dict") else dict(f))
            if d.get("gps"):
                gps_files.append({"path": d["path"], "name": d.get("name",""),
                                   "gps": d["gps"], "metadata": d.get("metadata",{})})
        return {"files_with_gps": len(gps_files), "locations": gps_files}
    except Exception as e:
        return {"error": str(e)}


def _mm_steg(path: str) -> dict:
    try:
        from .multimedia import analyze_multimedia
        findings = analyze_multimedia(_fs(path))
        suspicious = []
        for f in findings:
            d = f if isinstance(f, dict) else (f.dict() if hasattr(f, "dict") else dict(f))
            flags = d.get("flags", [])
            if any("steg" in str(flag).lower() or "hidden" in str(flag).lower() for flag in flags):
                suspicious.append(d)
        return {"steganography_suspects": len(suspicious), "suspects": suspicious[:15]}
    except Exception as e:
        return {"error": str(e)}


MULTIMEDIA_TOOLS = _make_registry(
    (
        "scan_all_media",
        "Discover and analyse all media files: images, video, audio. Returns metadata and risk flags.",
        {"path": "str: absolute filesystem path"},
        _mm_all,
    ),
    (
        "extract_gps_locations",
        "Extract GPS coordinates embedded in image/video EXIF metadata.",
        {"path": "str: absolute filesystem path"},
        _mm_gps,
    ),
    (
        "detect_steganography",
        "Flag media files with statistical anomalies suggesting hidden steganographic data.",
        {"path": "str: absolute filesystem path"},
        _mm_steg,
    ),
)


# ══════════════════════════════════════════════════════════════════════════════
# TAILS AGENT TOOLS
# ══════════════════════════════════════════════════════════════════════════════

def _tails_full(path: str) -> dict:
    try:
        from .tails import analyze_tails
        findings = analyze_tails(_fs(path))
        detected = any(f.get("category") == "environment" and f.get("severity") == "high"
                       for f in findings)
        return {"tails_detected": detected, "findings": findings}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


def _tails_tor(path: str) -> dict:
    try:
        from .tails import analyze_tails
        findings = [f for f in analyze_tails(_fs(path))
                    if f.get("category") in ("tor", "hidden_service")]
        return {"tor_findings": len(findings), "findings": findings}
    except Exception as e:
        return {"error": str(e)}


def _tails_persistence(path: str) -> dict:
    try:
        from .tails import analyze_tails
        findings = [f for f in analyze_tails(_fs(path))
                    if f.get("category") == "persistence"]
        return {"persistence_findings": len(findings), "findings": findings}
    except Exception as e:
        return {"error": str(e)}


def _tails_profile(path: str) -> dict:
    try:
        from .tails import analyze_tails
        findings = [f for f in analyze_tails(_fs(path))
                    if f.get("category") == "operational_profile"]
        return {"profile": findings[0] if findings else {}}
    except Exception as e:
        return {"error": str(e)}


TAILS_TOOLS = _make_registry(
    (
        "full_tails_analysis",
        "Run all Tails OS and amnesic system forensic checks in one call.",
        {"path": "str: absolute filesystem path"},
        _tails_full,
    ),
    (
        "analyze_tor_activity",
        "Inspect Tor runtime artifacts: torrc, logs, onion addresses, hidden service config.",
        {"path": "str: absolute filesystem path"},
        _tails_tor,
    ),
    (
        "check_tails_persistence",
        "Detect if Tails persistent storage was enabled/mounted and what was persisted.",
        {"path": "str: absolute filesystem path"},
        _tails_persistence,
    ),
    (
        "get_operational_profile",
        "Classify the operator's risk profile based on combined Tails and tool indicators.",
        {"path": "str: absolute filesystem path"},
        _tails_profile,
    ),
)
