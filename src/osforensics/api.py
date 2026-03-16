"""FastAPI application exposing analysis endpoints.

The endpoint /analyze accepts JSON with an `image_path` pointing to either
an on-disk mounted directory (for development) or a disk image file (dd, etc.).

Extended endpoints:
  POST /analyze           – full analysis (tools + timeline + deleted + persistence + config + services + browsers + multimedia)
    POST /analyze/ssh       – remote live analysis via SSH snapshot acquisition
  POST /upload            – upload a disk image, analyse, then delete temporary file
  POST /timeline          – timeline-only scan for a given path
  POST /deleted           – deleted-file scan for a given path
  POST /deleted/recover   – recover a single file by recovery_id
  POST /deleted/carve     – signature-based file carving from a raw disk image
  POST /persistence       – persistence-mechanism scan for a given path
  POST /config            – configuration-file audit for a given path
  POST /services          – service detection and enumeration for a given path
  POST /browsers          – browser forensics (history, bookmarks, cookies, extensions …)
  POST /multimedia        – multimedia forensics (EXIF, GPS, steganography, tampering …)
    POST /analyze/tails     – full analysis with dedicated Tails OS heuristics
    POST /cases/{id}/analyze/ssh   – remote live analysis saved as a case source
    POST /cases/{id}/analyze/tails – same as above but saved under a case source

Explorer endpoints (Autopsy-style navigation):
  POST /explore/tree      – static artifact category tree
  POST /explore/browse    – list directory children with metadata
  POST /explore/stat      – full inode metadata for a single path
  POST /explore/read      – read file content (text or hex preview)
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import traceback
from typing import Optional

from fastapi import FastAPI, HTTPException, UploadFile, File, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, Response
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

from . import agent_memory
from .agent_core import get_agent

from .browser import detect_browsers
from .cases import (
    list_cases, create_case, get_case, update_case, delete_case,
    add_data_source, remove_data_source, append_case_audit,
)
from .classifier import classify_findings
from .config import analyze_configs
from .container import analyze_containers
from .deleted import detect_deleted, recover_file, carve_files, CARVE_GROUPS, SAFE_RECOVERY_DIR
from .detector import detect_os, detect_tools
from .explorer import ARTIFACT_TREE, browse, stat_file, read_text
from .extractor import FilesystemAccessor
from .multimedia import analyze_multimedia, ALL_MEDIA_EXTS, EXT_TO_MIME
from .persistence import detect_persistence
from .remote import collect_remote_snapshot, collect_remote_host_info, RemoteSnapshotError
from .report import build_report
from .reporting import render_report_html, render_report_pdf
from .services import detect_services
from .tails import analyze_tails
from .timeline import build_timeline
from .ai_timeline import analyze_timeline_ai
from .live_memory import get_live_ram_info, get_top_memory_processes, generate_memory_ai_insight, generate_dump_ai_insight
from .memory import analyze_memory
from .antiforensics import detect_antiforensics


class AnalyzeRequest(BaseModel):
    image_path: str


class TailsDeepScanRequest(BaseModel):
    image_path: str
    collect_dir: Optional[str] = None
    max_copy_bytes: int = 25 * 1024 * 1024
    no_collect: bool = False


class ExploreRequest(BaseModel):
    image_path: str
    path: str
    limit: Optional[int] = 200_000


class RecoverRequest(BaseModel):
    image_path: str
    recovery_id: str
    output_dir: Optional[str] = None


class CarveRequest(BaseModel):
    image_path: str
    output_dir: Optional[str] = None
    sig_groups: Optional[list] = None   # None = all groups
    max_files: int = 200
    max_scan_gb: float = 2.0            # scan ceiling in GB


class AIAnalyzeTimelineRequest(BaseModel):
    events: list[dict]

class ReportExportRequest(BaseModel):
    report: dict
    report_title: Optional[str] = "OS Forensics Comprehensive Report"
    case_name: Optional[str] = None
    source_path: Optional[str] = None
    generated_by: Optional[str] = "OSForensics"
    case_data: Optional[dict] = None
    intro_text: Optional[str] = None
    report_variant: Optional[str] = "comprehensive"
    include_raw_json: Optional[bool] = True


app = FastAPI(title="OS Forensics API")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    """Return an empty favicon response to avoid browser 404 noise."""
    return Response(status_code=204)

# Allow the UI dev server to call this API during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
        "http://localhost:3000",
        "http://127.0.0.1:3000",
        "http://localhost:8000",
        "http://127.0.0.1:8000",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"],
    max_age=3600,
)


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _compute_file_hashes(path: str) -> dict:
    """Return cryptographic fingerprints for regular files."""
    if not path or not os.path.isfile(path):
        return {}
    sha256 = hashlib.sha256()
    sha1 = hashlib.sha1()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            if not chunk:
                break
            sha256.update(chunk)
            sha1.update(chunk)
    return {
        "sha256": sha256.hexdigest(),
        "sha1": sha1.hexdigest(),
        "size_bytes": os.path.getsize(path),
    }


def _legal_disclaimer() -> dict:
    return {
        "forensic_safe_environment": True,
        "original_evidence_unmodified": True,
        "notes": [
            "Analysis performed in a forensic-safe, read-focused environment.",
            "Original evidence should remain unmodified and preserved separately.",
            "Findings should be corroborated with additional investigative methods.",
        ],
    }


def _safe_filename(value: str, default: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return default
    cleaned = "".join(ch if ch.isalnum() or ch in ("-", "_", ".") else "_" for ch in raw)
    cleaned = cleaned.strip("._")
    return cleaned or default


def _attach_legal_context(
    out: dict,
    *,
    evidence_file: str,
    extraction_method: str,
    integrity_hashes: Optional[dict] = None,
) -> dict:
    """Attach legal-awareness metadata to analysis output."""
    hashes = integrity_hashes or {}
    out["evidence_integrity"] = {
        "evidence_file": evidence_file,
        "hashes": hashes,
        "acquisition_time": _utc_now(),
    }
    out["evidence_provenance"] = [
        {
            "artifact": evidence_file,
            "source": evidence_file,
            "extraction_method": extraction_method,
        }
    ]
    out["audit_log"] = out.get("audit_log") or []
    out["audit_log"].append({
        "timestamp": _utc_now(),
        "actor": "osforensics",
        "action": "analysis_executed",
        "details": {"evidence_file": evidence_file, "extraction_method": extraction_method},
    })
    out["legal_disclaimer"] = _legal_disclaimer()
    return out


def _is_tails_os(os_info: Optional[dict]) -> bool:
    """Return True when OS metadata strongly indicates Tails OS."""
    if not os_info:
        return False

    # Only treat explicit Tails identifiers as a match.
    # Generic live/privacy tags should not trigger Tails heuristics.
    direct_values = [
        str(os_info.get("name") or "").lower(),
        str(os_info.get("id") or "").lower(),
    ]
    if any("tails" in value for value in direct_values):
        return True

    for tag in os_info.get("variant_tags", []) or []:
        if "tails" in str(tag).lower():
            return True

    return False


def _extract_tails_analysis(tails_result: dict | list) -> tuple[list, dict]:
    """
    Extract findings and artifacts from analyze_tails result.
    Returns (findings_list, artifacts_dict) tuple.
    Handles both new dict format and legacy list format for backward compatibility.
    """
    if isinstance(tails_result, dict):
        # New format: dict with 'findings' and 'artifacts' keys
        return (tails_result.get("findings", []), tails_result.get("artifacts", {}))
    else:
        # Legacy format: list of findings
        return (tails_result, {})


def _run_tails_deep_scan(req: TailsDeepScanRequest) -> dict:
    """Execute standalone tails_volume_deep_scan.py and return parsed JSON report."""
    repo_root = Path(__file__).resolve().parents[2]
    scanner = repo_root / "tails_volume_deep_scan.py"
    if not scanner.exists():
        raise RuntimeError(f"Deep scanner script not found: {scanner}")

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    output_path = Path(tempfile.gettempdir()) / f"tails_deep_api_{ts}.json"

    cmd = [
        sys.executable,
        str(scanner),
        "--mount",
        req.image_path,
        "--output",
        str(output_path),
        "--pretty",
        "--summary-only",
    ]
    if req.no_collect:
        cmd.append("--no-collect")
    else:
        if req.collect_dir:
            cmd.extend(["--collect-dir", req.collect_dir])
        cmd.extend(["--max-copy-bytes", str(max(1, int(req.max_copy_bytes)))])

    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
    if proc.returncode != 0:
        raise RuntimeError(
            "Deep scan command failed"
            f"\nexit={proc.returncode}"
            f"\nstdout={proc.stdout[-4000:]}"
            f"\nstderr={proc.stderr[-4000:]}"
        )

    if not output_path.exists():
        raise RuntimeError("Deep scan completed but output JSON file was not produced")

    with output_path.open("r", encoding="utf-8") as f:
        deep = json.load(f)
    deep.setdefault("meta", {})
    deep["meta"]["api_wrapper"] = {
        "command": " ".join(cmd),
        "stdout_tail": proc.stdout[-2000:],
        "stderr_tail": proc.stderr[-2000:],
    }
    return deep


# ── Shared helper ─────────────────────────────────────────────────────────────

def _full_analysis(fs: FilesystemAccessor, tails_focus: bool = False) -> dict:
    os_info    = detect_os(fs)
    findings   = detect_tools(fs)
    classified = classify_findings(findings)
    timeline   = build_timeline(fs)
    deleted    = detect_deleted(fs)
    persistence = detect_persistence(fs)
    config     = analyze_configs(fs)
    services   = detect_services(fs)
    browsers   = detect_browsers(fs)
    multimedia = analyze_multimedia(fs)
    tails_result = analyze_tails(fs, tool_findings=classified) if (tails_focus or _is_tails_os(os_info)) else {}
    tails, tails_artifacts = _extract_tails_analysis(tails_result)
    antiforensics = detect_antiforensics(fs)
    containers = analyze_containers(fs)
    report = build_report(os_info, classified, timeline=timeline, deleted=deleted,
                          persistence=persistence, config=config, services=services,
                          browsers=browsers, multimedia=multimedia, tails=tails,
                          tails_artifacts=tails_artifacts,
                          antiforensics=antiforensics, containers=containers)
    out = report.dict()
    if tails_focus:
        out.setdefault("summary", {})["analysis_mode"] = "tails_os"
    return out


def _live_analysis(req: "LiveScanRequest") -> dict:
    """Run analysis against the current live host with scan-type flags."""
    fs = FilesystemAccessor("/")
    os_info    = detect_os(fs)
    findings   = detect_tools(fs)
    classified = classify_findings(findings)
    timeline    = build_timeline(fs)       if req.timeline    else []
    deleted     = detect_deleted(fs)       if req.deleted     else []
    persistence = detect_persistence(fs)   if req.persistence else []
    config      = analyze_configs(fs)      if req.config      else []
    services    = detect_services(fs)      if req.services    else []
    browsers    = detect_browsers(fs)      if req.browsers    else []
    multimedia  = analyze_multimedia(fs)   if req.multimedia  else []
    tails_result = analyze_tails(fs, tool_findings=classified) if _is_tails_os(os_info) else {}
    tails, tails_artifacts = _extract_tails_analysis(tails_result)
    antiforensics = detect_antiforensics(fs)
    containers  = analyze_containers(fs)
    report = build_report(os_info, classified, timeline=timeline, deleted=deleted,
                          persistence=persistence, config=config, services=services,
                          browsers=browsers, multimedia=multimedia, tails=tails,
                          tails_artifacts=tails_artifacts,
                          antiforensics=antiforensics, containers=containers)
    out = report.dict()
    out.setdefault("summary", {})["analysis_mode"] = "live_system"
    return _attach_legal_context(
        out,
        evidence_file="/",
        extraction_method="live_host_filesystem_scan",
        integrity_hashes={},
    )


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """Full forensic analysis: OS, tools, timeline, deleted files, persistence."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        out = _full_analysis(fs)
        hashes = _compute_file_hashes(req.image_path)
        return _attach_legal_context(
            out,
            evidence_file=req.image_path,
            extraction_method="filesystem_accessor_full_analysis",
            integrity_hashes=hashes,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/analyze/tails")
def analyze_tails_os(req: AnalyzeRequest):
    """Run full analysis with explicit Tails-focused heuristics enabled."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        out = _full_analysis(fs, tails_focus=True)
        hashes = _compute_file_hashes(req.image_path)
        return _attach_legal_context(
            out,
            evidence_file=req.image_path,
            extraction_method="filesystem_accessor_tails_analysis",
            integrity_hashes=hashes,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/analyze/tails/deep")
def analyze_tails_deep(req: TailsDeepScanRequest):
    """Run full Tails analysis and attach standalone deep scan artifacts."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        out = _full_analysis(fs, tails_focus=True)
        deep = _run_tails_deep_scan(req)
        out.setdefault("tails_artifacts", {})["deep_scan"] = deep
        # Expose key deep artifacts at top-level tails_artifacts for convenience in UI.
        for k, v in (deep.get("artifacts") or {}).items():
            out.setdefault("tails_artifacts", {}).setdefault(k, v)

        hashes = _compute_file_hashes(req.image_path)
        return _attach_legal_context(
            out,
            evidence_file=req.image_path,
            extraction_method="filesystem_accessor_tails_deep_analysis",
            integrity_hashes=hashes,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/upload")
def upload_image(file: UploadFile = File(...)):
    """Accept an uploaded image, analyse it, then remove the temporary file."""
    tmp_dir = tempfile.mkdtemp(prefix="osforensics_upload_")
    try:
        tmp_path = os.path.join(tmp_dir, file.filename)
        with open(tmp_path, "wb") as out_f:
            shutil.copyfileobj(file.file, out_f)
        fs = FilesystemAccessor(tmp_path)
        out = _full_analysis(fs)
        hashes = _compute_file_hashes(tmp_path)
        return _attach_legal_context(
            out,
            evidence_file=file.filename or tmp_path,
            extraction_method="uploaded_image_tempfile_analysis",
            integrity_hashes=hashes,
        )
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})
    finally:
        try:
            file.file.close()
        except Exception:
            pass
        try:
            shutil.rmtree(tmp_dir)
        except Exception:
            pass


@app.post("/timeline")
def timeline_scan(req: AnalyzeRequest):
    """Return only the timeline events for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"timeline": build_timeline(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/timeline/ai-analysis")
def timeline_ai_analysis(req: AIAnalyzeTimelineRequest):
    """Deep AI analysis of timeline events for attack sequences and predictions."""
    try:
        return analyze_timeline_ai(req.events)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/deleted")
def deleted_scan(req: AnalyzeRequest):
    """Return only the deleted-file findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"deleted": detect_deleted(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.get("/deleted/carve/groups")
def carve_groups():
    """Return available carving signature groups and their descriptions."""
    return {"groups": CARVE_GROUPS}


@app.post("/deleted/carve")
def deleted_carve(req: CarveRequest):
    """Signature-based file carving from a raw disk image.

    Scans the raw bytes of the image looking for known file-type magic bytes
    (JPEG, PNG, PDF, ZIP, ELF, SQLite, …) and extracts matching data to
    output_dir.  Works even when all inode / partition metadata is wiped.
    Only applicable to disk images (not live mounted directories).
    """
    if not os.path.isfile(req.image_path):
        raise HTTPException(
            status_code=400,
            detail="File carving requires a disk image file path, not a directory.",
        )
    # Validate / derive output directory
    _BLOCKED = ("/", "/etc", "/bin", "/sbin", "/usr", "/lib",
                "/boot", "/proc", "/sys", "/dev", "/root")
    if req.output_dir is not None:
        out_dir = os.path.abspath(req.output_dir)
        if out_dir in _BLOCKED:
            raise HTTPException(status_code=400, detail="Unsafe output directory.")
    else:
        out_dir = os.path.join(SAFE_RECOVERY_DIR, "carved")

    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        results = carve_files(
            fs,
            out_dir,
            sig_groups=req.sig_groups or None,
            max_files=min(req.max_files, 500),
            max_scan_bytes=int(req.max_scan_gb * 1024 ** 3),
        )
        carved_count = sum(1 for r in results if r["type"] == "carved")
        return {"carved": results, "output_dir": out_dir, "carved_count": carved_count}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/deleted/recover")
def deleted_recover(req: RecoverRequest):
    """Attempt to recover a single deleted file identified by recovery_id."""
    # Validate output_dir if provided (prevent path traversal to system dirs)
    if req.output_dir is not None:
        out_dir = os.path.abspath(req.output_dir)
        blocked = ("/", "/etc", "/bin", "/sbin", "/usr", "/lib",
                   "/boot", "/proc", "/sys", "/dev", "/root")
        if out_dir in blocked:
            raise HTTPException(status_code=400, detail="Unsafe output directory")
    else:
        out_dir = SAFE_RECOVERY_DIR
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return recover_file(fs, req.recovery_id, out_dir)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/persistence")
def persistence_scan(req: AnalyzeRequest):
    """Return only the persistence-mechanism findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"persistence": detect_persistence(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/config")
def config_scan(req: AnalyzeRequest):
    """Return configuration-file audit findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"config": analyze_configs(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/services")
def services_scan(req: AnalyzeRequest):
    """Return service detection findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"services": detect_services(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/browsers")
def browser_scan(req: AnalyzeRequest):
    """Return browser forensics findings for the given path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"browsers": detect_browsers(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/multimedia")
def multimedia_scan(req: AnalyzeRequest):
    """Return multimedia forensics findings (EXIF, GPS, steganography indicators, tampering …)."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return {"multimedia": analyze_multimedia(fs)}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/report/export/html")
def export_report_html(req: ReportExportRequest):
    """Render a structured, comprehensive forensic report as downloadable HTML."""
    try:
        html_doc = render_report_html(
            req.report,
            report_title=req.report_title or "OS Forensics Comprehensive Report",
            case_name=req.case_name or "",
            source_path=req.source_path or "",
            generated_by=req.generated_by or "OSForensics",
            case_data=req.case_data or None,
            intro_text=req.intro_text or "",
            report_variant=req.report_variant or "comprehensive",
            include_raw_json=req.include_raw_json if req.include_raw_json is not None else True,
        )
        filename = _safe_filename(req.case_name or req.report_title or "forensics_report", "forensics_report") + ".html"
        headers = {"Content-Disposition": f"attachment; filename={filename}"}
        return Response(content=html_doc, media_type="text/html; charset=utf-8", headers=headers)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/report/export/pdf")
def export_report_pdf(req: ReportExportRequest):
    """Render a comprehensive forensic report as downloadable PDF."""
    try:
        pdf_bytes = render_report_pdf(
            req.report,
            report_title=req.report_title or "OS Forensics Comprehensive Report",
            case_name=req.case_name or "",
            source_path=req.source_path or "",
            generated_by=req.generated_by or "OSForensics",
            case_data=req.case_data or None,
            intro_text=req.intro_text or "",
            report_variant=req.report_variant or "comprehensive",
        )
        filename = _safe_filename(req.case_name or req.report_title or "forensics_report", "forensics_report") + ".pdf"
        headers = {"Content-Disposition": f"attachment; filename={filename}"}
        return Response(content=pdf_bytes, media_type="application/pdf", headers=headers)
    except RuntimeError as e:
        raise HTTPException(status_code=501, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.get("/multimedia/view")
def multimedia_view(
    image_path: str = Query(..., description="Path to disk image or mounted directory"),
    file_path:  str = Query(..., description="Path to the media file within the filesystem"),
):
    """Serve a single media file for inline browser viewing.

    Security controls:
    - Only media file extensions (image/video/audio) are accepted.
    - In local mode the resolved path must stay within the accessor root.
    - File size capped at 200 MB.
    """
    ext = os.path.splitext(file_path)[1].lower()
    if ext not in ALL_MEDIA_EXTS:
        raise HTTPException(status_code=400, detail=f"Extension {ext!r} is not a recognised media type.")

    # Normalize: must be an absolute path within the image/directory
    safe_path = "/" + file_path.lstrip("/")

    try:
        fs = FilesystemAccessor(image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    mime = EXT_TO_MIME.get(ext, "application/octet-stream")

    if fs.mode == "local":
        # For live/mounted mode serve directly — FileResponse handles range
        # requests so video seeking works properly.
        local_p = os.path.realpath(os.path.join(fs.path, safe_path.lstrip("/")))
        root_p  = os.path.realpath(fs.path)
        # Path-traversal guard (relaxed for root '/' which is the live-system scan)
        if root_p != "/" and not local_p.startswith(root_p + os.sep) and local_p != root_p:
            raise HTTPException(status_code=403, detail="Path traversal detected.")
        if not os.path.isfile(local_p):
            raise HTTPException(status_code=404, detail="File not found.")
        return FileResponse(local_p, media_type=mime, headers={"Accept-Ranges": "bytes"})
    else:
        # TSK / disk-image mode: extract bytes via pytsk3
        raw = fs.read_file(safe_path, max_bytes=200 * 1024 * 1024)
        if raw is None:
            raise HTTPException(status_code=404, detail="File not found in image.")
        return Response(content=raw, media_type=mime)


@app.get("/live/info")
def live_info():
    """Return runtime information about the currently running host system."""
    import socket
    import subprocess

    def _read(path: str, default: str = "") -> str:
        try:
            with open(path) as f:
                return f.read().strip()
        except Exception:
            return default

    # Kernel version (third token of /proc/version)
    version_line = _read("/proc/version")
    kernel = version_line.split()[2] if version_line else "unknown"

    # Uptime
    uptime_raw = _read("/proc/uptime", "0").split()[0]
    try:
        uptime_secs = float(uptime_raw)
    except Exception:
        uptime_secs = 0.0
    uptime_h = int(uptime_secs // 3600)
    uptime_m = int((uptime_secs % 3600) // 60)
    uptime_str = f"{uptime_h}h {uptime_m}m" if uptime_h else f"{uptime_m}m"

    # Load averages
    load_avg = _read("/proc/loadavg", "").split()[:3]

    # Memory (values are in kB)
    meminfo: dict[str, int] = {}
    for line in _read("/proc/meminfo").splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            try:
                meminfo[k.strip()] = int(v.strip().split()[0])
            except Exception:
                pass
    mem_total = meminfo.get("MemTotal", 0)
    mem_avail = meminfo.get("MemAvailable", 0)
    used_pct  = round((1 - mem_avail / mem_total) * 100, 1) if mem_total else 0

    # OS release
    os_release: dict[str, str] = {}
    for line in _read("/etc/os-release").splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            os_release[k.strip()] = v.strip().strip('"')

    # Network interfaces (exclude loopback)
    try:
        ifaces = [i for i in os.listdir("/sys/class/net/") if i != "lo"]
    except Exception:
        ifaces = []

    # Running process count from /proc
    try:
        process_count = sum(1 for d in os.listdir("/proc") if d.isdigit())
    except Exception:
        process_count = 0

    # Logged-in users via `who` (best-effort)
    users: list[str] = []
    try:
        result = subprocess.run(
            ["who"], capture_output=True, text=True, timeout=3
        )
        if result.returncode == 0:
            for line in result.stdout.strip().splitlines():
                parts = line.split()
                if parts:
                    users.append(parts[0])
    except Exception:
        pass

    return {
        "hostname":      socket.gethostname(),
        "os_name":       os_release.get("PRETTY_NAME") or os_release.get("NAME", "Linux"),
        "os_id":         os_release.get("ID", "linux"),
        "kernel":        kernel,
        "uptime_seconds": uptime_secs,
        "uptime_str":    uptime_str,
        "load_avg":      load_avg,
        "memory": {
            "total_kb":     mem_total,
            "available_kb": mem_avail,
            "used_pct":     used_pct,
        },
        "interfaces":    ifaces,
        "process_count": process_count,
        "users":         list(set(users)),
    }


class LiveScanRequest(BaseModel):
    timeline:    bool = True
    deleted:     bool = True
    persistence: bool = True
    config:      bool = True
    services:    bool = True
    browsers:    bool = True
    # Enable multimedia analysis by default so the Multimedia tab
    # is populated on a standard live scan without requiring a
    # separate rescan from the UI.
    multimedia:  bool = True


class SSHAnalyzeRequest(BaseModel):
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None

    # Optional path scope. Defaults to a curated high-value set when omitted.
    include_paths: Optional[list[str]] = None

    # Acquisition limits to keep remote collection bounded.
    connect_timeout: int = 15
    # banner_timeout: how long to wait for the server SSH banner (sshd UseDNS
    # reverse-DNS can hold this up by 30+ s on some hosts).
    banner_timeout: int = 120
    # auth_timeout: how long to wait for the authentication exchange to finish.
    auth_timeout: int = 120
    max_total_mb: int = 1024
    max_file_mb: int = 32
    max_files: int = 25_000

    # Scan toggles aligned with local live scan.
    timeline:    bool = True
    deleted:     bool = True
    persistence: bool = True
    config:      bool = True
    services:    bool = True
    browsers:    bool = True
    multimedia:  bool = True


class SSHFSMountAnalyzeRequest(BaseModel):
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None

    # Remote directory to mount for analysis.
    remote_path: str = "/"
    connect_timeout: int = 15
    banner_timeout: int = 120
    auth_timeout: int = 120

    # Scan toggles aligned with local live scan.
    timeline:    bool = True
    deleted:     bool = True
    persistence: bool = True
    config:      bool = True
    services:    bool = True
    browsers:    bool = True
    multimedia:  bool = True


def _ssh_analysis(req: SSHAnalyzeRequest) -> dict:
    """Acquire a bounded remote snapshot over SSH, then analyze it locally."""
    tmp_dir = tempfile.mkdtemp(prefix="osforensics_ssh_")
    try:
        snapshot = collect_remote_snapshot(
            host=req.host,
            username=req.username,
            port=req.port,
            password=req.password,
            key_path=req.key_path,
            key_passphrase=req.key_passphrase,
            include_paths=req.include_paths,
            out_dir=tmp_dir,
            connect_timeout=max(2, req.connect_timeout),
            banner_timeout=max(5, req.banner_timeout),
            auth_timeout=max(5, req.auth_timeout),
            max_total_bytes=max(1, req.max_total_mb) * 1024 * 1024,
            max_file_bytes=max(1, req.max_file_mb) * 1024 * 1024,
            max_files=max(100, req.max_files),
        )

        fs = FilesystemAccessor(snapshot.local_root)
        os_info    = detect_os(fs)
        findings   = detect_tools(fs)
        classified = classify_findings(findings)
        timeline    = build_timeline(fs)      if req.timeline    else []
        deleted     = detect_deleted(fs)      if req.deleted     else []
        persistence = detect_persistence(fs)  if req.persistence else []
        config      = analyze_configs(fs)     if req.config      else []
        services    = detect_services(fs)     if req.services    else []
        browsers    = detect_browsers(fs)     if req.browsers    else []
        multimedia  = analyze_multimedia(fs)  if req.multimedia  else []
        tails_result = analyze_tails(fs, tool_findings=classified) if _is_tails_os(os_info) else {}
        tails, tails_artifacts = _extract_tails_analysis(tails_result)
        containers  = analyze_containers(fs)
        report = build_report(
            os_info,
            classified,
            timeline=timeline,
            deleted=deleted,
            persistence=persistence,
            config=config,
            services=services,
            browsers=browsers,
            multimedia=multimedia,
            tails=tails,
            tails_artifacts=tails_artifacts,
            containers=containers,
        )
        out = report.dict()
        out.setdefault("summary", {})["analysis_mode"] = "remote_ssh_live"
        out["remote_target"] = {
            "host": req.host,
            "port": req.port,
            "username": req.username,
            "scheme": "ssh",
        }
        out["live_info"] = snapshot.live_info if snapshot.live_info else {
            "hostname": req.host,
            "os_name":  out.get("os_info", {}).get("name") or "Linux",
            "kernel":   "unknown",
            "uptime_str": "-",
            "load_avg": [],
            "memory":   {"total_kb": 0, "available_kb": 0, "used_pct": 0},
            "interfaces": [],
            "process_count": 0,
            "users": [req.username],
            "scheme": "remote_ssh",
        }
        out["acquisition"] = snapshot.to_dict()
        return _attach_legal_context(
            out,
            evidence_file=f"ssh://{req.username}@{req.host}:{req.port}",
            extraction_method="ssh_snapshot_via_sftp_then_local_analysis",
            integrity_hashes={},
        )
    finally:
        shutil.rmtree(tmp_dir, ignore_errors=True)


def _try_unmount(path: str) -> Optional[str]:
    """Best-effort unmount helper for FUSE mounts."""
    attempts = [
        ["fusermount", "-u", path],
        ["umount", path],
    ]
    errors = []
    for cmd in attempts:
        bin_name = cmd[0]
        if shutil.which(bin_name) is None:
            continue
        try:
            subprocess.run(cmd, check=True, capture_output=True, text=True, timeout=10)
            return None
        except Exception as e:
            errors.append(f"{' '.join(cmd)}: {e}")
    if not errors:
        return "No unmount tool found (fusermount/umount)"
    return "; ".join(errors)


def _sshfs_analysis(req: SSHFSMountAnalyzeRequest) -> dict:
    """Mount a remote path via SSHFS, analyze it, then unmount."""
    if shutil.which("sshfs") is None:
        raise RemoteSnapshotError("sshfs is not installed on the backend host")

    using_password = bool((req.password or "").strip())

    mount_dir = tempfile.mkdtemp(prefix="osforensics_sshfs_")
    mounted = False
    unmount_warning = None

    try:
        remote_path = (req.remote_path or "/").strip() or "/"
        if not remote_path.startswith("/"):
            remote_path = f"/{remote_path}"

        remote_spec = f"{req.username}@{req.host}:{remote_path}"
        mount_cmd = [
            "sshfs",
            remote_spec,
            mount_dir,
            "-p", str(req.port),
            "-o", "ro",
            "-o", f"ConnectTimeout={max(2, req.connect_timeout)}",
            "-o", "ServerAliveInterval=15",
            "-o", "ServerAliveCountMax=3",
            "-o", "StrictHostKeyChecking=accept-new",
        ]

        key_path = (req.key_path or "").strip()
        if key_path:
            expanded_key = os.path.expanduser(key_path)
            mount_cmd += ["-o", f"IdentityFile={expanded_key}", "-o", "BatchMode=yes"]

        timeout = max(15, req.banner_timeout + req.auth_timeout + req.connect_timeout)
        if using_password:
            # Prefer native sshfs password input to avoid requiring sshpass.
            pwd_cmd = mount_cmd + ["-o", "password_stdin"]
            result = subprocess.run(
                pwd_cmd,
                input=(req.password or "") + "\n",
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "sshfs mount failed").strip()
                # Some sshfs builds may not support password_stdin.
                if "password_stdin" in err.lower() and shutil.which("sshpass") is not None:
                    result = subprocess.run(
                        ["sshpass", "-p", req.password] + mount_cmd,
                        capture_output=True,
                        text=True,
                        timeout=timeout,
                    )
                    if result.returncode != 0:
                        err = (result.stderr or result.stdout or "sshfs mount failed").strip()
                        raise RemoteSnapshotError(err)
                elif "password_stdin" in err.lower() and shutil.which("sshpass") is None:
                    raise RemoteSnapshotError(
                        "This sshfs build does not support password_stdin. "
                        "Install sshpass on backend host or use key-based auth."
                    )
                else:
                    raise RemoteSnapshotError(err)
        else:
            result = subprocess.run(
                mount_cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            if result.returncode != 0:
                err = (result.stderr or result.stdout or "sshfs mount failed").strip()
                raise RemoteSnapshotError(err)
        mounted = True

        fs = FilesystemAccessor(mount_dir)
        os_info    = detect_os(fs)
        findings   = detect_tools(fs)
        classified = classify_findings(findings)
        timeline    = build_timeline(fs)      if req.timeline    else []
        deleted     = detect_deleted(fs)      if req.deleted     else []
        persistence = detect_persistence(fs)  if req.persistence else []
        config      = analyze_configs(fs)     if req.config      else []
        services    = detect_services(fs)     if req.services    else []
        browsers    = detect_browsers(fs)     if req.browsers    else []
        multimedia  = analyze_multimedia(fs)  if req.multimedia  else []
        tails_result = analyze_tails(fs, tool_findings=classified) if _is_tails_os(os_info) else {}
        tails, tails_artifacts = _extract_tails_analysis(tails_result)
        containers  = analyze_containers(fs)
        report = build_report(
            os_info,
            classified,
            timeline=timeline,
            deleted=deleted,
            persistence=persistence,
            config=config,
            services=services,
            browsers=browsers,
            multimedia=multimedia,
            tails=tails,
            tails_artifacts=tails_artifacts,
            containers=containers,
        )
        out = report.dict()
        out.setdefault("summary", {})["analysis_mode"] = "remote_sshfs_mount"
        out["remote_target"] = {
            "host": req.host,
            "port": req.port,
            "username": req.username,
            "scheme": "sshfs",
            "remote_path": remote_path,
        }
        try:
            info = collect_remote_host_info(
                host=req.host,
                username=req.username,
                port=req.port,
                password=req.password,
                key_path=req.key_path,
                key_passphrase=req.key_passphrase,
                connect_timeout=max(2, req.connect_timeout),
                banner_timeout=max(5, req.banner_timeout),
                auth_timeout=max(5, req.auth_timeout),
            )
            out["live_info"] = info
        except Exception:
            out["live_info"] = {
                "hostname": req.host,
                "os_name": out.get("os_info", {}).get("name") or "Linux",
                "kernel": "unknown",
                "uptime_str": "-",
                "load_avg": [],
                "memory": {"total_kb": 0, "available_kb": 0, "used_pct": 0},
                "interfaces": [],
                "process_count": 0,
                "users": [req.username],
                "scheme": "remote_ssh",
            }
        out["acquisition"] = {
            "mode": "sshfs_mount",
            "mountpoint": mount_dir,
            "remote_path": remote_path,
            "readonly": True,
        }
        return _attach_legal_context(
            out,
            evidence_file=f"sshfs://{req.username}@{req.host}:{req.port}{remote_path}",
            extraction_method="sshfs_readonly_mount_then_local_analysis",
            integrity_hashes={},
        )
    finally:
        if mounted:
            unmount_warning = _try_unmount(mount_dir)
        if unmount_warning:
            print(f"[osforensics] WARNING: failed to unmount {mount_dir}: {unmount_warning}")
        shutil.rmtree(mount_dir, ignore_errors=True)


@app.post("/analyze/live")
def analyze_live(req: LiveScanRequest = None):
    """Forensic analysis of the running host system. Accepts optional scan-type flags."""
    if req is None:
        req = LiveScanRequest()
    try:
        return _live_analysis(req)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.get("/memory/live")
def memory_live():
    """Real-time RAM and top process statistics."""
    try:
        return {
            "ram": get_live_ram_info(),
            "top_processes": get_top_memory_processes()
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})


@app.post("/memory/ai-analysis")
def memory_ai_analysis():
    """Generate AI insights based on the current live memory state."""
    try:
        ram = get_live_ram_info()
        procs = get_top_memory_processes()
        insight = generate_memory_ai_insight(ram, procs)
        return {"insight": insight}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})


@app.post("/memory/upload")
def upload_memory_dump(file: UploadFile = File(...)):
    """Accept an uploaded memory dump, analyze via Volatility 3, then remove the file."""
    tmp_dir = tempfile.mkdtemp(prefix="osforensics_memdump_")
    try:
        tmp_path = os.path.join(tmp_dir, file.filename)
        with open(tmp_path, "wb") as out_f:
            shutil.copyfileobj(file.file, out_f)
        
        # Run Volatility 3 analysis
        report = analyze_memory(tmp_path)
        return report.dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})
    finally:
        try:
            file.file.close()
            shutil.rmtree(tmp_dir)
        except Exception:
            pass


class MemoryDumpAIRequest(BaseModel):
    report_data: dict


@app.post("/memory/analyze-dump/ai")
def memory_dump_ai_analysis(req: MemoryDumpAIRequest):
    """Generate specialized AI forensic insights based on a Volatility 3 MemoryReport."""
    try:
        insight = generate_dump_ai_insight(req.report_data)
        return {"insight": insight}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e)})

@app.post("/analyze/ssh")
def analyze_ssh(req: SSHAnalyzeRequest):
    """Run remote live forensics by acquiring a bounded SSH snapshot first."""
    try:
        return _ssh_analysis(req)
    except RemoteSnapshotError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/analyze/sshfs")
def analyze_sshfs(req: SSHFSMountAnalyzeRequest):
    """Run remote live forensics by auto-mounting the remote path via SSHFS."""
    try:
        return _sshfs_analysis(req)
    except RemoteSnapshotError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


class SSHInfoRequest(BaseModel):
    host: str
    username: str
    port: int = 22
    password: Optional[str] = None
    key_path: Optional[str] = None
    key_passphrase: Optional[str] = None
    connect_timeout: int = 15
    banner_timeout: int = 120
    auth_timeout: int = 120


@app.post("/analyze/ssh/info")
def analyze_ssh_info(req: SSHInfoRequest):
    """Quick SSH connect to fetch live system metadata without a full snapshot.

    Returns hostname, OS, kernel, uptime, memory, interfaces, users, etc.
    Useful for verifying credentials and previewing remote host details before
    starting a full analysis.
    """
    try:
        info = collect_remote_host_info(
            host=req.host,
            username=req.username,
            port=req.port,
            password=req.password,
            key_path=req.key_path,
            key_passphrase=req.key_passphrase,
            connect_timeout=max(2, req.connect_timeout),
            banner_timeout=max(5, req.banner_timeout),
            auth_timeout=max(5, req.auth_timeout),
        )
        return info
    except RemoteSnapshotError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


# ── Explorer endpoints (Autopsy-style navigation) ─────────────────────────────

@app.get("/explore/tree")
def artifact_tree():
    """Return the static artifact category tree (no image_path needed)."""
    return {"tree": ARTIFACT_TREE}


@app.post("/explore/browse")
def explore_browse(req: ExploreRequest):
    """List a directory with per-entry inode metadata."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return browse(fs, req.path)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/explore/stat")
def explore_stat(req: ExploreRequest):
    """Return full inode metadata for a single path."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return stat_file(fs, req.path)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/explore/read")
def explore_read(req: ExploreRequest):
    """Read file content (UTF-8 text or hex preview for binary files)."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return read_text(fs, req.path, limit=req.limit or 200_000)
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


# ── Host filesystem browser (for the file-picker dialog) ─────────────────────

class FsBrowseRequest(BaseModel):
    path: str = "/"


@app.post("/fs/browse")
def fs_browse(req: FsBrowseRequest):
    """List the host filesystem directory for the GUI file-picker.

    Returns the normalized path and a list of children:
      { name, path, is_dir, size, mtime }
    Silently skips entries that cannot be stat'd.
    """
    import stat as _stat
    path = os.path.normpath(req.path or "/")
    if not os.path.isdir(path):
        raise HTTPException(status_code=400, detail=f"Not a directory: {path}")
    try:
        raw = os.listdir(path)
    except PermissionError:
        raise HTTPException(status_code=403, detail=f"Permission denied: {path}")

    children = []
    for name in sorted(raw, key=lambda n: (not os.path.isdir(os.path.join(path, n)), n.lower())):
        full = os.path.join(path, name)
        try:
            st = os.lstat(full)
            is_dir = _stat.S_ISDIR(st.st_mode)
            children.append({
                "name":   name,
                "path":   full,
                "is_dir": is_dir,
                "size":   st.st_size if not is_dir else None,
                "mtime":  st.st_mtime,
            })
        except OSError:
            pass

    # Build breadcrumb from the current path
    parts = [p for p in path.split("/") if p]
    crumbs = [{"label": "/", "path": "/"}]
    for i, part in enumerate(parts):
        crumbs.append({"label": part, "path": "/" + "/".join(parts[:i + 1])})

    return {"path": path, "children": children, "breadcrumbs": crumbs}


@app.get("/fs/usb/sources")
def fs_usb_sources():
    """Return USB block device candidates, prioritizing Tails-like media.

    Each candidate includes:
      - device_path (/dev/sdX1)
      - mountpoint (if mounted)
      - use_path (mountpoint when available, else device path)
      - tails_score / tails_markers (best-effort local checks)
    """
    try:
        res = subprocess.run(
            ["lsblk", "-J", "-o", "NAME,PATH,RM,TYPE,MOUNTPOINT,FSTYPE,SIZE,MODEL,VENDOR,TRAN,LABEL"],
            capture_output=True,
            text=True,
            timeout=4,
        )
        if res.returncode != 0:
            raise RuntimeError(res.stderr.strip() or "lsblk failed")
        data = json.loads(res.stdout or "{}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Failed to enumerate USB sources: {e}")

    items = []

    def _score_mount(mountpoint: Optional[str]) -> tuple[int, list[str]]:
        if not mountpoint or not os.path.isdir(mountpoint):
            return 0, []
        markers = []
        checks = [
            ("live", os.path.join(mountpoint, "live")),
            ("tails_amnesia", os.path.join(mountpoint, "etc", "amnesia")),
            ("tails_persistence", os.path.join(mountpoint, "live", "persistence")),
            ("squashfs", os.path.join(mountpoint, "live", "filesystem.squashfs")),
            ("boot_live", os.path.join(mountpoint, "boot")),
        ]
        score = 0
        for label, p in checks:
            if os.path.exists(p):
                markers.append(label)
                score += 1
        return score, markers

    def _walk(node: dict, parent_usb: bool = False):
        dev_path = node.get("path") or ""
        rm = int(node.get("rm") or 0)
        tran = str(node.get("tran") or "").lower()
        typ = str(node.get("type") or "")
        is_usb = parent_usb or tran == "usb" or rm == 1

        mountpoint = node.get("mountpoint") or ""
        model = (node.get("model") or "").strip()
        vendor = (node.get("vendor") or "").strip()
        label = (node.get("label") or "").strip()

        if is_usb and typ in ("disk", "part") and dev_path.startswith("/dev/"):
            tails_score, tails_markers = _score_mount(mountpoint if mountpoint else None)
            items.append(
                {
                    "device_name": node.get("name") or "",
                    "device_path": dev_path,
                    "mountpoint": mountpoint or None,
                    "use_path": mountpoint or dev_path,
                    "type": typ,
                    "size": node.get("size") or "",
                    "fstype": node.get("fstype") or "",
                    "vendor": vendor,
                    "model": model,
                    "label": label,
                    "transport": tran,
                    "tails_score": tails_score,
                    "tails_markers": tails_markers,
                    "tails_likely": tails_score >= 2,
                }
            )

        for ch in node.get("children") or []:
            _walk(ch, parent_usb=is_usb)

    for n in data.get("blockdevices") or []:
        _walk(n)

    # Prefer mounted partitions and likely-Tails sources first.
    items.sort(
        key=lambda x: (
            0 if x.get("mountpoint") else 1,
            -(x.get("tails_score") or 0),
            x.get("device_path") or "",
        )
    )
    return {"sources": items}


# ── Case management models ────────────────────────────────────────────────────

class CaseCreate(BaseModel):
    name: str
    number: str = ""
    examiner: str = ""
    description: str = ""


class CaseUpdate(BaseModel):
    name: Optional[str] = None
    number: Optional[str] = None
    examiner: Optional[str] = None
    description: Optional[str] = None


class CaseAnalyzeRequest(BaseModel):
    image_path: str


class CaseAnalyzeTailsDeepRequest(BaseModel):
    image_path: str
    collect_dir: Optional[str] = None
    max_copy_bytes: int = 25 * 1024 * 1024
    no_collect: bool = False


# ── Case management endpoints ─────────────────────────────────────────────────

@app.get("/cases")
def cases_list():
    """Return a lightweight summary list of all cases."""
    return {"cases": list_cases()}


@app.post("/cases")
def cases_create(req: CaseCreate):
    """Create a new case and return its full data."""
    if not req.name.strip():
        raise HTTPException(status_code=400, detail="Case name is required")
    return create_case(req.name, req.number, req.examiner, req.description)


@app.get("/cases/{case_id}")
def cases_get(case_id: str):
    """Return the full case data including all data sources and reports."""
    try:
        return get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.put("/cases/{case_id}")
def cases_update(case_id: str, req: CaseUpdate):
    """Update case metadata (name, number, examiner, description)."""
    try:
        return update_case(case_id, req.name, req.number, req.examiner, req.description)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.delete("/cases/{case_id}")
def cases_delete(case_id: str):
    """Permanently delete a case and all its stored data."""
    try:
        delete_case(case_id)
        return {"ok": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/cases/{case_id}/analyze")
def cases_analyze(case_id: str, req: CaseAnalyzeRequest):
    """Run a full forensic analysis and save the result as a data source in the case."""
    try:
        get_case(case_id)   # verify exists before expensive analysis
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = _full_analysis(fs)
        hashes = _compute_file_hashes(req.image_path)
        report = _attach_legal_context(
            report,
            evidence_file=req.image_path,
            extraction_method="filesystem_accessor_full_analysis",
            integrity_hashes=hashes,
        )
        label  = os.path.basename(req.image_path.rstrip("/")) or req.image_path
        case_obj = get_case(case_id)
        actor = case_obj.get("examiner") or "system"
        source = add_data_source(
            case_id,
            req.image_path,
            label,
            report,
            evidence={"acquisition_time": _utc_now(), "hashes": hashes},
            provenance={
                "source": req.image_path,
                "extraction_method": "filesystem_accessor_full_analysis",
                "original_path": req.image_path,
            },
            actor=actor,
            verified_by=actor,
        )
        append_case_audit(case_id, "analysis_module_executed", actor="osforensics", details={"module": "full_analysis", "source_id": source.get("id")})
        return {"source": source, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/cases/{case_id}/analyze/tails")
def cases_analyze_tails(case_id: str, req: CaseAnalyzeRequest):
    """Run Tails-focused analysis and save the result as a data source in the case."""
    try:
        get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = _full_analysis(fs, tails_focus=True)
        hashes = _compute_file_hashes(req.image_path)
        report = _attach_legal_context(
            report,
            evidence_file=req.image_path,
            extraction_method="filesystem_accessor_tails_analysis",
            integrity_hashes=hashes,
        )
        label_base = os.path.basename(req.image_path.rstrip("/")) or req.image_path
        label = f"{label_base} (TailsOS)"
        case_obj = get_case(case_id)
        actor = case_obj.get("examiner") or "system"
        source = add_data_source(
            case_id,
            req.image_path,
            label,
            report,
            evidence={"acquisition_time": _utc_now(), "hashes": hashes},
            provenance={
                "source": req.image_path,
                "extraction_method": "filesystem_accessor_tails_analysis",
                "original_path": req.image_path,
            },
            actor=actor,
            verified_by=actor,
        )
        append_case_audit(case_id, "analysis_module_executed", actor="osforensics", details={"module": "tails_analysis", "source_id": source.get("id")})
        return {"source": source, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/cases/{case_id}/analyze/tails/deep")
def cases_analyze_tails_deep(case_id: str, req: CaseAnalyzeTailsDeepRequest):
    """Run deep Tails-focused analysis and save result as a case data source."""
    try:
        get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = _full_analysis(fs, tails_focus=True)
        deep_req = TailsDeepScanRequest(
            image_path=req.image_path,
            collect_dir=req.collect_dir,
            max_copy_bytes=req.max_copy_bytes,
            no_collect=req.no_collect,
        )
        deep = _run_tails_deep_scan(deep_req)
        report.setdefault("tails_artifacts", {})["deep_scan"] = deep
        for k, v in (deep.get("artifacts") or {}).items():
            report.setdefault("tails_artifacts", {}).setdefault(k, v)

        hashes = _compute_file_hashes(req.image_path)
        report = _attach_legal_context(
            report,
            evidence_file=req.image_path,
            extraction_method="filesystem_accessor_tails_deep_analysis",
            integrity_hashes=hashes,
        )
        label_base = os.path.basename(req.image_path.rstrip("/")) or req.image_path
        label = f"{label_base} (TailsOS Deep)"
        case_obj = get_case(case_id)
        actor = case_obj.get("examiner") or "system"
        source = add_data_source(
            case_id,
            req.image_path,
            label,
            report,
            evidence={"acquisition_time": _utc_now(), "hashes": hashes},
            provenance={
                "source": req.image_path,
                "extraction_method": "filesystem_accessor_tails_deep_analysis",
                "original_path": req.image_path,
            },
            actor=actor,
            verified_by=actor,
        )
        append_case_audit(case_id, "analysis_module_executed", actor="osforensics", details={"module": "tails_deep_analysis", "source_id": source.get("id")})
        return {"source": source, "report": report}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/cases/{case_id}/analyze/live")
def cases_analyze_live(case_id: str, req: LiveScanRequest = None):
    """Run live-system scan and save results under the selected case."""
    if req is None:
        req = LiveScanRequest()
    try:
        get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = _live_analysis(req)
        info = live_info()
        host = info.get("hostname") or "live-host"
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        label = f"Live System ({host}) [{ts}]"
        case_obj = get_case(case_id)
        actor = case_obj.get("examiner") or "system"
        source = add_data_source(
            case_id,
            "/",
            label,
            report,
            evidence={"acquisition_time": _utc_now(), "hashes": {}},
            provenance={
                "source": "/",
                "extraction_method": "live_host_filesystem_scan",
                "original_path": "/",
            },
            actor=actor,
            verified_by=actor,
        )
        append_case_audit(case_id, "analysis_module_executed", actor="osforensics", details={"module": "live_analysis", "source_id": source.get("id")})
        return {"source": source, "report": report, "live_info": info}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/cases/{case_id}/analyze/ssh")
def cases_analyze_ssh(case_id: str, req: SSHAnalyzeRequest):
    """Run remote SSH live-system scan and save results under the selected case."""
    try:
        get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = _ssh_analysis(req)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        label = f"Remote SSH ({req.username}@{req.host}:{req.port}) [{ts}]"
        source_path = f"ssh://{req.username}@{req.host}:{req.port}"
        case_obj = get_case(case_id)
        actor = case_obj.get("examiner") or "system"
        source = add_data_source(
            case_id,
            source_path,
            label,
            report,
            evidence={"acquisition_time": _utc_now(), "hashes": {}},
            provenance={
                "source": source_path,
                "extraction_method": "ssh_snapshot_via_sftp_then_local_analysis",
                "original_path": source_path,
            },
            actor=actor,
            verified_by=actor,
        )
        append_case_audit(case_id, "analysis_module_executed", actor="osforensics", details={"module": "remote_ssh_analysis", "source_id": source.get("id")})
        return {"source": source, "report": report}
    except RemoteSnapshotError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/cases/{case_id}/analyze/sshfs")
def cases_analyze_sshfs(case_id: str, req: SSHFSMountAnalyzeRequest):
    """Run remote SSHFS-mounted scan and save results under the selected case."""
    try:
        get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = _sshfs_analysis(req)
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ")
        remote_path = (req.remote_path or "/").strip() or "/"
        if not remote_path.startswith("/"):
            remote_path = f"/{remote_path}"
        label = f"Remote SSHFS ({req.username}@{req.host}:{req.port}{remote_path}) [{ts}]"
        source_path = f"sshfs://{req.username}@{req.host}:{req.port}{remote_path}"
        case_obj = get_case(case_id)
        actor = case_obj.get("examiner") or "system"
        source = add_data_source(
            case_id,
            source_path,
            label,
            report,
            evidence={"acquisition_time": _utc_now(), "hashes": {}},
            provenance={
                "source": source_path,
                "extraction_method": "sshfs_readonly_mount_then_local_analysis",
                "original_path": source_path,
            },
            actor=actor,
            verified_by=actor,
        )
        append_case_audit(case_id, "analysis_module_executed", actor="osforensics", details={"module": "remote_sshfs_analysis", "source_id": source.get("id")})
        return {"source": source, "report": report}
    except RemoteSnapshotError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.delete("/cases/{case_id}/sources/{source_id}")
def cases_remove_source(case_id: str, source_id: str):
    """Remove a data source from a case."""
    try:
        remove_data_source(case_id, source_id)
        return {"ok": True}
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


# ── Agent endpoints ───────────────────────────────────────────────────────────

class AgentChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    model: Optional[str] = None


@app.get("/agent/status")
def agent_status():
    """Check whether Ollama is reachable and return available model info."""
    ag = get_agent()
    available, msg = ag.check_ollama()
    return {
        "available": available,
        "message":   msg,
        "model":     ag.model if available else None,
        "models":    ag.list_models(),
    }


@app.post("/agent/chat/stream")
def agent_chat_stream(req: AgentChatRequest):
    """Stream investigation steps as SSE (text/event-stream).

    Each SSE line is: `data: <json>\\n\\n`
    The stream ends with `data: [DONE]\\n\\n`.
    """
    ag = get_agent()
    if req.model:
        ag.model = req.model

    def generate():
        try:
            for event in ag.run(req.message, req.session_id):
                yield f"data: {json.dumps(event)}\n\n"
        except Exception as e:
            yield f"data: {json.dumps({'type': 'error', 'message': str(e)})}\n\n"
        finally:
            yield "data: [DONE]\n\n"

    return StreamingResponse(
        generate(),
        media_type="text/event-stream",
        headers={
            "Cache-Control":    "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@app.post("/agent/chat")
def agent_chat(req: AgentChatRequest):
    """Non-streaming version: collect all steps, return when investigation completes."""
    ag = get_agent()
    if req.model:
        ag.model = req.model

    steps: list = []
    final_answer = None
    session_id: Optional[str] = req.session_id
    error: Optional[str] = None

    for event in ag.run(req.message, req.session_id):
        t = event["type"]
        if t == "session":
            session_id = event["session_id"]
        elif t == "step":
            steps.append(event)
        elif t == "answer":
            final_answer = event
            session_id   = event.get("session_id", session_id)
        elif t == "error":
            error = event["message"]
            break

    return {
        "session_id":  session_id,
        "steps":       steps,
        "answer":      final_answer["text"] if final_answer else None,
        "total_steps": final_answer.get("steps", len(steps)) if final_answer else len(steps),
        "error":       error,
    }


@app.get("/agent/history/{session_id}")
def agent_history(session_id: str):
    """Return all episodes and evidence for a past investigation session."""
    return {
        "episodes": agent_memory.get_episodes(session_id),
        "evidence": agent_memory.get_evidence(session_id),
    }


@app.get("/agent/sessions")
def agent_sessions():
    """List recent investigation sessions."""
    return {"sessions": agent_memory.get_sessions()}


@app.post("/agent/reset/{session_id}")
def agent_reset(session_id: str):
    """Clear episodes and evidence for a session (soft delete)."""
    agent_memory.clear_session(session_id)
    return {"ok": True}

