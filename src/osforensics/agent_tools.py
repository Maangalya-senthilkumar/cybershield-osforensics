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
from .deleted import detect_deleted
from .detector import detect_os, detect_tools
from .extractor import FilesystemAccessor
from .memory import analyze_memory
from .persistence import detect_persistence
from .report import build_report
from .services import detect_services
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
            "critical": sum(1 for f in report.findings if f.severity == "critical"),
            "high":     sum(1 for f in report.findings if f.severity == "high"),
            "medium":   sum(1 for f in report.findings if f.severity == "medium"),
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
        events = [e.dict() for e in tl]
        critical = [e for e in events if e["severity"] == "critical"]
        high     = [e for e in events if e["severity"] == "high"]
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
        items = [f.dict() for f in deleted]
        suspicious = [i for i in items if i["severity"] in ("critical", "high")]
        return {
            "total_deleted":   len(items),
            "suspicious_count": len(suspicious),
            "suspicious":      suspicious,
            "all_files":       items[:40],
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
        items = [p.dict() for p in pers]
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
        "Extract browser forensics: browsing history, bookmarks, cookies, "
        "download records, and installed extensions from Chrome, Firefox, etc."
    ),
    {"path": "str: absolute path to a mounted filesystem directory"},
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
        "Search for a text pattern inside files at a given path. Useful for "
        "finding credentials, c2 domains, config values, or specific strings "
        "without running a full analysis."
    ),
    {
        "path":    "str: absolute path to directory or file to search",
        "pattern": "str: text/regex pattern to search for (case-insensitive)",
    },
)
def search_file_content(path: str, pattern: str) -> dict:
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
