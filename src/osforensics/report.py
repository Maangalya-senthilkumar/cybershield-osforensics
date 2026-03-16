"""Reporting models and helpers to build structured forensic output.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional
from pydantic import BaseModel


# ── Tool detection models ─────────────────────────────────────────────────────

class ToolFinding(BaseModel):
    tool: str
    risk: str
    evidence: List[str]


class OSInfo(BaseModel):
    name: Optional[str] = None
    id: Optional[str] = None
    variant_tags: List[str] = []
    notes: List[str] = []


# ── Timeline models ───────────────────────────────────────────────────────────

class TimelineEvent(BaseModel):
    timestamp: str
    source: str
    event_type: str
    detail: str
    severity: str = "info"
    data: Optional[Dict[str, Any]] = None


# ── Deleted file models ───────────────────────────────────────────────────────

class DeletedFinding(BaseModel):
    path: str
    type: str
    detail: str
    severity: str = "medium"
    # Extended forensic fields
    inode: Optional[int] = None
    size: Optional[int] = None
    mtime: Optional[str] = None
    atime: Optional[str] = None
    ctime: Optional[str] = None
    deleted_at: Optional[str] = None
    recoverable: bool = False
    recovery_hint: str = ""
    recovery_id: str = ""
    user: Optional[str] = None
    command: Optional[str] = None


# ── Persistence models ────────────────────────────────────────────────────────

class PersistenceFinding(BaseModel):
    source: str
    category: str
    detail: str
    severity: str = "medium"
    snippet: str = ""


# ── Configuration analysis models ─────────────────────────────────────────────

class ConfigFinding(BaseModel):
    config: str
    category: str
    detail: str
    severity: str = "info"
    snippet: str = ""
    recommendation: str = ""


# ── Browser forensics models ─────────────────────────────────────────────────

class BrowserProfile(BaseModel):
    browser: str
    browser_label: str
    user: str
    profile: str
    profile_path: str
    severity: str = "info"
    flags: List[str] = []
    history: List[Dict[str, Any]] = []
    downloads: List[Dict[str, Any]] = []
    bookmarks: List[Dict[str, Any]] = []
    cookies: List[Dict[str, Any]] = []
    extensions: List[Dict[str, Any]] = []
    logins: List[Dict[str, Any]] = []
    search_terms: List[Dict[str, Any]] = []
    autofill: List[Dict[str, Any]] = []


# ── Service detection models ──────────────────────────────────────────────────

class ServiceFinding(BaseModel):
    name: str
    display_name: str
    description: str = ""
    category: str
    state: str
    exec_start: str = ""
    run_user: str = "root"
    severity: str = "info"
    source: str = "systemd"
    flags: List[str] = []
    unit_path: str = ""


# ── Multimedia analysis models ────────────────────────────────────────────────

class MediaFinding(BaseModel):
    path: str
    name: str = ""
    media_type: str                       # "image" | "video" | "audio"
    ext: str = ""
    size: Optional[int] = None
    severity: str = "info"
    flags: List[str] = []
    findings: List[str] = []
    metadata: Dict[str, Any] = {}
    streams: List[Dict[str, Any]] = []
    gps: Dict[str, Any] = {}
    thumbnail: Optional[Dict[str, Any]] = None


# ── Tails OS models ──────────────────────────────────────────────────────────

class TailsFinding(BaseModel):
    source: str
    category: str
    detail: str
    severity: str = "info"
    evidence: List[str] = []


# ── Memory forensics models ───────────────────────────────────────────────────

class MemoryProcess(BaseModel):
    pid: int = 0
    ppid: int = 0
    name: str = ""
    offset: str = ""
    threads: int = 0
    create_time: Optional[str] = None
    cmdline: Optional[str] = None
    hidden: bool = False


class MemoryConnection(BaseModel):
    pid: int = 0
    process: str = ""
    proto: str = ""
    laddr: str = ""
    lport: int = 0
    raddr: str = ""
    rport: int = 0
    state: str = ""


class MemoryBashEntry(BaseModel):
    pid: int = 0
    process: str = ""
    command: str = ""


class MemoryMalfind(BaseModel):
    pid: int = 0
    process: str = ""
    address: str = ""
    protection: str = ""
    hex_dump: str = ""
    disassembly: str = ""


class MemoryModule(BaseModel):
    name: str = ""
    size: int = 0
    offset: str = ""


class MemoryReport(BaseModel):
    dump_path: str = ""
    volatility_available: bool = False
    volatility_error: Optional[str] = None
    needs_symbols: bool = False
    kernel_version: Optional[str] = None
    symbol_errors: List[str] = []
    processes: List[MemoryProcess] = []
    hidden_processes: List[MemoryProcess] = []
    connections: List[MemoryConnection] = []
    bash_history: List[MemoryBashEntry] = []
    malfind: List[MemoryMalfind] = []
    modules: List[MemoryModule] = []
    summary: Dict[str, Any] = {}


# ── Top-level report ──────────────────────────────────────────────────────────

class ForensicReport(BaseModel):
    os_info: OSInfo
    findings: List[ToolFinding]
    summary: Dict[str, Any] = {}
    timeline: List[TimelineEvent] = []
    deleted: List[DeletedFinding] = []
    persistence: List[PersistenceFinding] = []
    config: List[ConfigFinding] = []
    services: List[ServiceFinding] = []
    browsers: List[BrowserProfile] = []
    multimedia: List[MediaFinding] = []
    tails: List[TailsFinding] = []


def build_report(
    os_info: Dict[str, object],
    classified_findings: List[Dict[str, object]],
    timeline: Optional[List[Dict]] = None,
    deleted: Optional[List[Dict]] = None,
    persistence: Optional[List[Dict]] = None,
    config: Optional[List[Dict]] = None,
    services: Optional[List[Dict]] = None,
    browsers: Optional[List[Dict]] = None,
    multimedia: Optional[List[Dict]] = None,
    tails: Optional[List[Dict]] = None,
) -> ForensicReport:
    os_model = OSInfo(
        name=os_info.get("name"),
        id=os_info.get("id"),
        variant_tags=os_info.get("variant_tags", []),
        notes=os_info.get("notes", []),
    )

    tool_findings = [
        ToolFinding(tool=f["tool"], risk=f.get("risk", "unknown"), evidence=f.get("evidence", []))
        for f in classified_findings
    ]

    timeline_events = [
        TimelineEvent(**e) for e in (timeline or [])
    ]

    deleted_findings = [
        DeletedFinding(**d) for d in (deleted or [])
    ]

    persistence_findings = [
        PersistenceFinding(**p) for p in (persistence or [])
    ]

    config_findings = [
        ConfigFinding(**c) for c in (config or [])
    ]

    service_findings = [
        ServiceFinding(**s) for s in (services or [])
    ]

    browser_profiles = [
        BrowserProfile(**b) for b in (browsers or [])
    ]

    media_findings = [
        MediaFinding(**m) for m in (multimedia or [])
    ]

    tails_findings = [
        TailsFinding(**t) for t in (tails or [])
    ]

    high_timeline  = sum(1 for e in timeline_events  if e.severity == "high")
    high_deleted   = sum(1 for d in deleted_findings  if d.severity == "high")
    high_persist   = sum(1 for p in persistence_findings if p.severity == "high")
    high_config    = sum(1 for c in config_findings if c.severity in ("high", "critical"))
    high_services  = sum(1 for s in service_findings if s.severity in ("high", "critical"))
    high_multimedia = sum(1 for m in media_findings if m.severity in ("high", "critical"))
    high_tails = sum(1 for t in tails_findings if t.severity in ("high", "critical"))

    summary = {
        "total_tools":         len(tool_findings),
        "high_risk_tools":     sum(1 for f in tool_findings if f.risk == "high"),
        # keep legacy key so the existing status bar still works
        "high_risk":           sum(1 for f in tool_findings if f.risk == "high"),
        "timeline_events":     len(timeline_events),
        "high_timeline":       high_timeline,
        "deleted_findings":    len(deleted_findings),
        "high_deleted":        high_deleted,
        "persistence_findings": len(persistence_findings),
        "high_persistence":    high_persist,
        "config_findings":     len(config_findings),
        "high_config":         high_config,
        "service_count":       len(service_findings),
        "high_services":       high_services,
        "enabled_services":    sum(1 for s in service_findings if s.state == "enabled"),
        "browser_count":       len(browser_profiles),
        "high_browsers":       sum(1 for b in browser_profiles if b.severity in ("high", "critical")),
        "multimedia_count":    len(media_findings),
        "high_multimedia":     high_multimedia,
        "tails_findings":      len(tails_findings),
        "high_tails":          high_tails,
        "total_high":          sum(1 for f in tool_findings if f.risk == "high") + high_timeline + high_deleted + high_persist + high_config + high_services + sum(1 for b in browser_profiles if b.severity in ("high", "critical")) + high_multimedia + high_tails,
    }

    return ForensicReport(
        os_info=os_model,
        findings=tool_findings,
        summary=summary,
        timeline=timeline_events,
        deleted=deleted_findings,
        persistence=persistence_findings,
        config=config_findings,
        services=service_findings,
        browsers=browser_profiles,
        multimedia=media_findings,
        tails=tails_findings,
    )
