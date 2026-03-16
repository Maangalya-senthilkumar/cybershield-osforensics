"""FastAPI application exposing analysis endpoints.

The endpoint /analyze accepts JSON with an `image_path` pointing to either
an on-disk mounted directory (for development) or a disk image file (dd, etc.).

Extended endpoints:
  POST /analyze           – full analysis (tools + timeline + deleted + persistence + config + services + browsers + multimedia)
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
    POST /cases/{id}/analyze/tails – same as above but saved under a case source

Explorer endpoints (Autopsy-style navigation):
  POST /explore/tree      – static artifact category tree
  POST /explore/browse    – list directory children with metadata
  POST /explore/stat      – full inode metadata for a single path
  POST /explore/read      – read file content (text or hex preview)
"""
from __future__ import annotations

from datetime import datetime, timezone
import json
import os
import shutil
import subprocess
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
    add_data_source, remove_data_source,
)
from .classifier import classify_findings
from .config import analyze_configs
from .deleted import detect_deleted, recover_file, carve_files, CARVE_GROUPS, SAFE_RECOVERY_DIR
from .detector import detect_os, detect_tools
from .explorer import ARTIFACT_TREE, browse, stat_file, read_text
from .extractor import FilesystemAccessor
from .memory import analyze_memory
from .multimedia import analyze_multimedia, ALL_MEDIA_EXTS, EXT_TO_MIME
from .persistence import detect_persistence
from .report import build_report
from .services import detect_services
from .tails import analyze_tails
from .timeline import build_timeline


class AnalyzeRequest(BaseModel):
    image_path: str


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


app = FastAPI(title="OS Forensics API")

# Allow the UI dev server to call this API during development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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
    tails      = analyze_tails(fs, tool_findings=classified)
    report = build_report(os_info, classified, timeline=timeline, deleted=deleted,
                          persistence=persistence, config=config, services=services,
                          browsers=browsers, multimedia=multimedia, tails=tails)
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
    tails       = analyze_tails(fs, tool_findings=classified)
    report = build_report(os_info, classified, timeline=timeline, deleted=deleted,
                          persistence=persistence, config=config, services=services,
                          browsers=browsers, multimedia=multimedia, tails=tails)
    out = report.dict()
    out.setdefault("summary", {})["analysis_mode"] = "live_system"
    return out


# ── Endpoints ─────────────────────────────────────────────────────────────────

@app.post("/analyze")
def analyze(req: AnalyzeRequest):
    """Full forensic analysis: OS, tools, timeline, deleted files, persistence."""
    try:
        fs = FilesystemAccessor(req.image_path)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))
    try:
        return _full_analysis(fs)
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
        return _full_analysis(fs, tails_focus=True)
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
        return _full_analysis(fs)
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


@app.post("/memory")
def analyze_memory_dump(req: AnalyzeRequest):
    """Analyze a memory dump file with Volatility3."""
    try:
        report = analyze_memory(req.image_path)
        return report.dict()
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


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
    multimedia:  bool = False


@app.post("/analyze/live")
def analyze_live(req: LiveScanRequest = None):
    """Forensic analysis of the running host system. Accepts optional scan-type flags."""
    if req is None:
        req = LiveScanRequest()
    try:
        return _live_analysis(req)
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
        label  = os.path.basename(req.image_path.rstrip("/")) or req.image_path
        source = add_data_source(case_id, req.image_path, label, report)
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
        label_base = os.path.basename(req.image_path.rstrip("/")) or req.image_path
        label = f"{label_base} (TailsOS)"
        source = add_data_source(case_id, req.image_path, label, report)
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
        source = add_data_source(case_id, "/", label, report)
        return {"source": source, "report": report, "live_info": info}
    except Exception as e:
        raise HTTPException(status_code=500, detail={"error": str(e), "trace": traceback.format_exc()})


@app.post("/cases/{case_id}/analyze/memory")
def cases_analyze_memory(case_id: str, req: CaseAnalyzeRequest):
    """Run memory dump analysis and save the result as a data source in the case."""
    try:
        get_case(case_id)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    try:
        report = analyze_memory(req.image_path)
        label_base = os.path.basename(req.image_path) or req.image_path
        label = f"{label_base} (Memory Dump)"
        source = add_data_source(case_id, req.image_path, label, report.dict())
        return {"source": source, "report": report.dict()}
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

