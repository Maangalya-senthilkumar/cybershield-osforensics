"""Forensic tool registry for the investigation agent.

Each function wraps an existing osforensics analysis module and is registered
with a name, description, and parameter schema the LLM can use.
"""
from __future__ import annotations

import subprocess
import traceback
from pathlib import Path
from typing import Any, Dict

from .browser import detect_browsers
from .classifier import classify_findings
from .config import analyze_configs
from .deleted import detect_deleted, carve_files
from .detector import detect_os, detect_tools
from .extractor import FilesystemAccessor
from .memory import analyze_memory
from .multimedia import analyze_multimedia
from .persistence import detect_persistence
from .report import build_report
from .services import detect_services
from .tails import analyze_tails
from .timeline import build_timeline

# ── Tool registry ──────────────────────────────────────────────────────────────

TOOL_REGISTRY: Dict[str, dict] = {}


def _tool(name: str, description: str, params: Dict[str, str]):
    """Decorator: register a function as an agent-callable tool."""
    def decorator(fn):
        TOOL_REGISTRY[name] = {
            "name": name,
            "description": description,
            "params": params,
            "fn": fn,
        }
        return fn
    return decorator


# ── Tool definitions───────────────────────────────────────────────────────────

@_tool(
    "analyze_filesystem",
    (
        "Run a full forensic analysis on a filesystem path or disk image. "
        "Returns OS info, suspicious tools found, severity breakdown, timeline "
        "summary, deleted files count, persistence count, and the top findings."
    ),
    {"path": "str: absolute path to a mounted filesystem directory or disk image file"},
)
def analyze_filesystem(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        os_info     = detect_os(fs)
        findings    = detect_tools(fs)
        classified  = classify_findings(findings)
        timeline    = build_timeline(fs)
        deleted     = detect_deleted(fs)
        persistence = detect_persistence(fs)
        services    = detect_services(fs)
        browsers    = detect_browsers(fs)
        report = build_report(
            os_info, classified,
            timeline=timeline, deleted=deleted,
            persistence=persistence, services=services, browsers=browsers,
        )
        return {
            "os": report.os_info.dict() if report.os_info else {},
            "total_findings": len(report.findings),
            # ToolFinding uses .risk (high/dual-use/…), not .severity
            "high_risk":  sum(1 for f in report.findings if f.risk == "high"),
            "dual_use":   sum(1 for f in report.findings if f.risk == "dual-use"),
            "timeline_events": len(report.timeline),
            "deleted_files":   len(report.deleted),
            "persistence_items": len(report.persistence),
            "services_count":  len(report.services),
            "summary": report.summary,
            "top_findings": [f.dict() for f in report.findings[:15]],
        }
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}


@_tool(
    "get_timeline",
    (
        "Extract chronological filesystem activity events (file access, "
        "modification, creation). Useful for reconstructing what happened and when."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
)
def get_timeline(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        tl = build_timeline(fs)
        # build_timeline returns List[Dict] — no .dict() call needed
        events   = [e if isinstance(e, dict) else e.dict() for e in tl]
        critical = [e for e in events if e.get("severity") == "critical"]
        high     = [e for e in events if e.get("severity") == "high"]
        return {
            "total_events":    len(events),
            "critical_events": len(critical),
            "high_events":     len(high),
            "recent":          events[:30],
            "critical":        critical[:10],
        }
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "get_deleted_files",
    (
        "Discover deleted and recently removed files. Can reveal data destruction, "
        "log tampering, or attempt to hide evidence."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
)
def get_deleted_files(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        deleted = detect_deleted(fs)
        # detect_deleted returns List[Dict] — normalise defensively
        items = [f if isinstance(f, dict) else f.dict() for f in deleted]
        suspicious = [i for i in items if i.get("severity") in ("critical", "high")]
        return {
            "total_deleted":    len(items),
            "suspicious_count": len(suspicious),
            "suspicious":       suspicious,
            "all_files":        items[:40],
        }
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "get_persistence_mechanisms",
    (
        "Identify persistence mechanisms: cron jobs, systemd services, shell rc "
        "files, SUID binaries, authorized_keys, startup scripts, etc."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
)
def get_persistence_mechanisms(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        pers = detect_persistence(fs)
        # detect_persistence returns plain dicts — no .dict() needed
        items = [p if isinstance(p, dict) else p.dict() for p in pers]
        high_sev = [i for i in items if i["severity"] in ("critical", "high")]
        categories: Dict[str, int] = {}
        for i in items:
            categories[i["category"]] = categories.get(i["category"], 0) + 1
        return {
            "total":          len(items),
            "high_severity":  len(high_sev),
            "by_category":    categories,
            "critical_items": high_sev[:20],
            "all_items":      items[:30],
        }
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "get_browser_artifacts",
    (
        "Extract browser forensics (history, downloads, cookies, extensions) from "
        "user profiles. Path MUST be a specific directory (e.g. /home/user or /), "
        "NOT a wildcard like /home/user/* or a specific file like cookies.sqlite. "
        "The tool automatically scans for browser profiles within the given root."
    ),
    {"path": "str: absolute path to a mounted filesystem directory (root or home)"},
)
def get_browser_artifacts(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        browsers = detect_browsers(fs)
        result = [b.dict() if hasattr(b, "dict") else dict(b) for b in browsers]
        return {"browser_count": len(result), "browsers": result}
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "get_services",
    (
        "Enumerate installed system services and daemons. Identify unusual or "
        "suspicious services that could be backdoors or malware persistence."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
)
def get_services(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        svcs = detect_services(fs)
        items = [s.dict() if hasattr(s, "dict") else dict(s) for s in svcs]
        return {"total": len(items), "services": items[:30]}
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "analyze_memory_dump",
    (
        "Analyze a memory dump with Volatility3. Extracts running processes, "
        "network connections, bash history, loaded kernel modules, and malware "
        "indicators (suspicious memory-mapped regions via malfind)."
    ),
    {"dump_path": "str: absolute path to memory dump file (.raw, .mem, .lime, .dmp, .vmem)"},
)
def analyze_memory_dump(dump_path: str) -> dict:
    try:
        report = analyze_memory(dump_path)
        if report.needs_symbols:
            return {
                "error": (
                    f"Volatility3 symbol table missing for kernel: "
                    f"{report.kernel_version or 'unknown'}. "
                    "Install ISF symbols before memory analysis."
                ),
                "needs_symbols": True,
                "kernel_version": report.kernel_version,
            }
        ext = [
            c.dict() for c in report.connections
            if c.raddr and not c.raddr.startswith(("127.", "0.0.0.0", "::"))
        ]
        return {
            "kernel_version":        report.kernel_version,
            "process_count":         len(report.processes),
            "hidden_process_count":  len(report.hidden_processes),
            "connection_count":      len(report.connections),
            "external_connections":  ext,
            "malware_indicators":    len(report.malfind),
            "kernel_modules":        len(report.modules),
            "processes":             [p.dict() for p in report.processes[:25]],
            "hidden_processes":      [p.dict() for p in report.hidden_processes],
            "malfind":               [m.dict() for m in report.malfind],
            "bash_history":          [b.dict() for b in report.bash_history[:20]],
        }
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "search_file_content",
    (
        "Search for a text pattern inside files at a given path. "
        "Path must be a specific directory or file (NO wildcards like *). "
        "Useful for finding credentials, c2 domains, or specific strings."
    ),
    {
        "path":    "str: absolute path to directory or file to search",
        "pattern": "str: text/regex pattern to search for (case-insensitive)",
    },
)
def search_file_content(path: str, pattern: str) -> dict:
    if "*" in path:
        return {"error": f"Wildcards (*) are not supported in path: {path}. Please provide a specific directory or file path."}
    p = Path(path).resolve()
    if not p.exists():
        return {"error": f"Path does not exist: {path}"}
    try:
        # Step 1: list matching files (limit to text-like extensions)
        list_proc = subprocess.run(
            [
                "grep", "-ril",
                "--include=*.txt", "--include=*.log", "--include=*.conf",
                "--include=*.cfg", "--include=*.sh",  "--include=*.py",
                "--include=*.json","--include=*.yaml","--include=*.env",
                "--include=*.ini", "--include=*.xml", "--include=*.csv",
                "--", pattern, str(p),
            ],
            capture_output=True, text=True, timeout=30,
        )
        files = [l.strip() for l in list_proc.stdout.splitlines() if l.strip()]
        # Step 2: collect sample matches from first 10 files
        matches = []
        for f in files[:10]:
            r2 = subprocess.run(
                ["grep", "-in", "--", pattern, f],
                capture_output=True, text=True, timeout=10,
            )
            for line in r2.stdout.splitlines()[:3]:
                matches.append({"file": f, "match": line.strip()})
        return {
            "files_with_match": len(files),
            "file_list":        files[:20],
            "sample_matches":   matches[:30],
        }
    except subprocess.TimeoutExpired:
        return {"error": "Search timed out — directory may be too large"}
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "analyze_multimedia",
    (
        "Discover and analyze multimedia files (images, video, audio) for metadata, "
        "GPS locations, and steganography indicators (hidden data)."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
)
def analyze_multimedia_tool(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        findings = analyze_multimedia(fs)
        # Summarize for the agent
        critical = [f for f in findings if f.get("severity") == "critical"]
        high     = [f for f in findings if f.get("severity") == "high"]
        gps_files = [f for f in findings if f.get("gps")]
        return {
            "total_media_found": len(findings),
            "critical_issues":   len(critical),
            "high_issues":       len(high),
            "files_with_gps":    len(gps_files),
            "samples":           findings[:15],
            "critical":          critical[:10],
        }
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "analyze_tails_os",
    (
        "Run specialized forensic checks for Tails OS indicators, persistence "
        "usage, Tor activity, and amnesic runtime traces."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
)
def analyze_tails_tool(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        # We can pass existing findings if we had them, but for a standalone call, None is fine
        tails_findings = analyze_tails(fs)
        return {
            "tails_detected": any(f["category"] == "environment" and f["severity"] == "high" for f in tails_findings),
            "findings": tails_findings,
        }
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "audit_security_configs",
    (
        "Audit critical system configurations (SSH, sudo, firewall, PAM, sysctl) "
        "for security weaknesses, misconfigurations, and rogue entries."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
)
def audit_security_configs_tool(path: str) -> dict:
    try:
        fs = FilesystemAccessor(path)
        findings = analyze_configs(fs)
        critical = [f for f in findings if f.get("severity") == "critical"]
        high     = [f for f in findings if f.get("severity") == "high"]
        # Group by category
        by_cat = {}
        for f in findings:
            cat = f.get("category", "general")
            by_cat[cat] = by_cat.get(cat, 0) + 1

        return {
            "total_findings": len(findings),
            "critical": len(critical),
            "high": len(high),
            "by_category": by_cat,
            "top_findings": findings[:20],
        }
    except Exception as e:
        return {"error": str(e)}


@_tool(
    "carve_deleted_files",
    (
        "Attempt to carve deleted files from a raw disk image using file signatures. "
        "This is a slow, deep-scan operation that works even if the filesystem is damaged."
    ),
    {
        "image_path": "str: absolute path to the raw disk image file",
        "groups": "list: optional list of file groups to carve (image, document, executable, database, archive, video, audio, text)",
    },
)
def carve_deleted_files_tool(image_path: str, groups: list = None) -> dict:
    try:
        fs = FilesystemAccessor(image_path)
        # Use a standardized recovery directory
        out_dir = "/tmp/osforensics_carved"
        findings = carve_files(fs, out_dir, sig_groups=groups, max_files=50)
        return {
            "total_carved": len([f for f in findings if f.get("type") == "carved"]),
            "output_directory": out_dir,
            "findings": findings,
        }
    except Exception as e:
        return {"error": str(e)}


# ── Dispatcher ────────────────────────────────────────────────────────────────

def execute_tool(name: str, args: dict) -> Any:
    """Execute a registered tool by name with the given arguments."""
    if name not in TOOL_REGISTRY:
        return {"error": f"Unknown tool '{name}'. Available: {list(TOOL_REGISTRY.keys())}"}
    try:
        return TOOL_REGISTRY[name]["fn"](**args)
    except TypeError as e:
        return {"error": f"Invalid arguments for '{name}': {e}"}
    except Exception as e:
        return {"error": str(e), "trace": traceback.format_exc()}
