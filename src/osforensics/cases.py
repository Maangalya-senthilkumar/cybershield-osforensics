"""Case Management — stores forensic investigation cases on the host.

Case storage layout:
    ~/.osforensics/cases/<uuid>/case.json

Each case.json contains:
    {
      "id":           "uuid",
      "name":         "Incident Response 2026-03",
      "number":       "CASE-2026-001",
      "examiner":     "Jane Forensics",
      "description":  "...",
      "created_at":   "2026-03-07T12:00:00+00:00",
      "updated_at":   "2026-03-07T14:00:00+00:00",
      "data_sources": [
        {
          "id":       "uuid",
          "path":     "/path/to/image",
          "label":    "Primary Disk",
          "added_at": "...",
          "report":   { ... full ForensicReport JSON ... }
        }
      ]
    }
"""
from __future__ import annotations

import json
import os
import shutil
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

_CASES_DIR = os.path.join(os.path.expanduser("~"), ".osforensics", "cases")


# ── Internal helpers ──────────────────────────────────────────────────────────

def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _case_dir(case_id: str) -> str:
    # Guard against directory traversal
    safe = os.path.basename(case_id)
    if safe != case_id or not safe:
        raise ValueError(f"Invalid case id: {case_id!r}")
    return os.path.join(_CASES_DIR, safe)


def _case_path(case_id: str) -> str:
    return os.path.join(_case_dir(case_id), "case.json")


def _load(case_id: str) -> Dict:
    p = _case_path(case_id)
    if not os.path.exists(p):
        raise FileNotFoundError(f"Case not found: {case_id!r}")
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _save(case: Dict) -> None:
    d = _case_dir(case["id"])
    os.makedirs(d, exist_ok=True)
    p = os.path.join(d, "case.json")
    tmp = p + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(case, f, indent=2, ensure_ascii=False)
    os.replace(tmp, p)   # atomic on POSIX


def _ensure_legal_sections(case: Dict) -> None:
    """Backfill legal/audit sections for older case.json files."""
    if "chain_of_custody" not in case or not isinstance(case.get("chain_of_custody"), list):
        case["chain_of_custody"] = []
    if "audit_log" not in case or not isinstance(case.get("audit_log"), list):
        case["audit_log"] = []


def _next_evidence_id(case: Dict) -> str:
    """Generate a stable, human-readable evidence id like EV-001."""
    idx = len(case.get("data_sources", [])) + 1
    return f"EV-{idx:03d}"


def _append_audit_event(case: Dict, action: str, actor: str = "system", details: Optional[Dict[str, Any]] = None) -> None:
    case.setdefault("audit_log", []).append({
        "timestamp": _now(),
        "actor": actor,
        "action": action,
        "details": details or {},
    })


def _append_custody_event(
    case: Dict,
    evidence_id: str,
    action: str,
    collected_by: str,
    verified_by: Optional[str] = None,
    notes: str = "",
    details: Optional[Dict[str, Any]] = None,
) -> None:
    case.setdefault("chain_of_custody", []).append({
        "timestamp": _now(),
        "evidence_id": evidence_id,
        "action": action,
        "collected_by": collected_by,
        "verified_by": verified_by or "",
        "notes": notes,
        "details": details or {},
    })


# ── Public API ────────────────────────────────────────────────────────────────

def list_cases() -> List[Dict]:
    """Return lightweight case summaries sorted by updated_at descending."""
    os.makedirs(_CASES_DIR, exist_ok=True)
    cases: List[Dict] = []
    for entry in os.scandir(_CASES_DIR):
        if not entry.is_dir():
            continue
        p = os.path.join(entry.path, "case.json")
        if not os.path.exists(p):
            continue
        try:
            with open(p, "r", encoding="utf-8") as f:
                data = json.load(f)
            cases.append({
                "id":           data["id"],
                "name":         data.get("name", "Untitled"),
                "number":       data.get("number", ""),
                "examiner":     data.get("examiner", ""),
                "description":  data.get("description", ""),
                "created_at":   data.get("created_at", ""),
                "updated_at":   data.get("updated_at", ""),
                "source_count": len(data.get("data_sources", [])),
            })
        except Exception:
            pass
    return sorted(cases, key=lambda c: c.get("updated_at", ""), reverse=True)


def create_case(
    name: str,
    number: str = "",
    examiner: str = "",
    description: str = "",
) -> Dict:
    """Create a new case and return its full data."""
    case_id = str(uuid.uuid4())
    now = _now()
    case: Dict = {
        "id":           case_id,
        "name":         name.strip(),
        "number":       number.strip(),
        "examiner":     examiner.strip(),
        "description":  description.strip(),
        "created_at":   now,
        "updated_at":   now,
        "data_sources": [],
        "chain_of_custody": [],
        "audit_log": [],
    }
    _append_audit_event(case, "case_created", actor=(examiner.strip() or "system"), details={"name": name.strip(), "number": number.strip()})
    _save(case)
    return case


def get_case(case_id: str) -> Dict:
    case = _load(case_id)
    _ensure_legal_sections(case)
    return case


def update_case(
    case_id: str,
    name: Optional[str] = None,
    number: Optional[str] = None,
    examiner: Optional[str] = None,
    description: Optional[str] = None,
) -> Dict:
    case = _load(case_id)
    _ensure_legal_sections(case)
    if name        is not None: case["name"]        = name.strip()
    if number      is not None: case["number"]      = number.strip()
    if examiner    is not None: case["examiner"]    = examiner.strip()
    if description is not None: case["description"] = description.strip()
    _append_audit_event(case, "case_updated", actor="system", details={
        "name_changed": name is not None,
        "number_changed": number is not None,
        "examiner_changed": examiner is not None,
        "description_changed": description is not None,
    })
    case["updated_at"] = _now()
    _save(case)
    return case


def delete_case(case_id: str) -> None:
    d = _case_dir(case_id)
    if not os.path.isdir(d):
        raise FileNotFoundError(f"Case not found: {case_id!r}")
    shutil.rmtree(d)


def add_data_source(
    case_id: str,
    path: str,
    label: str,
    report: Dict[str, Any],
    evidence: Optional[Dict[str, Any]] = None,
    provenance: Optional[Dict[str, Any]] = None,
    actor: str = "system",
    verified_by: Optional[str] = None,
) -> Dict:
    """Attach a data source with its analysis report to the given case."""
    case = _load(case_id)
    _ensure_legal_sections(case)
    evidence_meta = evidence or {}
    evidence_id = evidence_meta.get("evidence_id") or _next_evidence_id(case)
    source: Dict = {
        "id":       str(uuid.uuid4()),
        "path":     path,
        "label":    (label.strip() or os.path.basename(path)) or path,
        "added_at": _now(),
        "report":   report,
        "evidence": {
            "evidence_id": evidence_id,
            "acquisition_time": evidence_meta.get("acquisition_time") or _now(),
            "hashes": evidence_meta.get("hashes") or {},
        },
        "provenance": provenance or {
            "source": path,
            "extraction_method": "filesystem_accessor",
            "original_path": path,
        },
    }
    case["data_sources"].append(source)

    _append_custody_event(
        case,
        evidence_id=evidence_id,
        action="uploaded_to_forensic_system",
        collected_by=actor,
        verified_by=verified_by,
        notes="Evidence ingested and analyzed",
        details={"source_id": source["id"], "path": path, "label": source["label"]},
    )
    _append_audit_event(case, "source_added", actor=actor, details={"source_id": source["id"], "path": path, "label": source["label"], "evidence_id": evidence_id})

    case["updated_at"] = _now()
    _save(case)
    return source


def remove_data_source(case_id: str, source_id: str) -> None:
    case = _load(case_id)
    _ensure_legal_sections(case)
    removed = None
    kept = []
    for s in case["data_sources"]:
        if s.get("id") == source_id and removed is None:
            removed = s
            continue
        kept.append(s)
    before = len(case["data_sources"])
    case["data_sources"] = kept
    if len(case["data_sources"]) == before:
        raise FileNotFoundError(f"Source {source_id!r} not found in case {case_id!r}")
    if removed:
        ev = ((removed.get("evidence") or {}).get("evidence_id") or "")
        if ev:
            _append_custody_event(
                case,
                evidence_id=ev,
                action="removed_from_case",
                collected_by="system",
                notes="Evidence source removed from case",
                details={"source_id": source_id, "path": removed.get("path", "")},
            )
        _append_audit_event(case, "source_removed", actor="system", details={"source_id": source_id, "path": removed.get("path", ""), "evidence_id": ev})
    case["updated_at"] = _now()
    _save(case)


def append_case_audit(case_id: str, action: str, actor: str = "system", details: Optional[Dict[str, Any]] = None) -> Dict:
    """Append a generic audit event to a case and return the event."""
    case = _load(case_id)
    _ensure_legal_sections(case)
    ev = {
        "timestamp": _now(),
        "actor": actor,
        "action": action,
        "details": details or {},
    }
    case["audit_log"].append(ev)
    case["updated_at"] = _now()
    _save(case)
    return ev
