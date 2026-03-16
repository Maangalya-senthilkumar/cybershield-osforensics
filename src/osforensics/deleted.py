"""Deleted file detection and recovery (forensic-grade).

Four complementary strategies:

1.  pytsk3 / TSK scan  (disk-image mode only)
    Walks the full inode table, collects UNALLOC entries.
    Records size, MAC timestamps, inode number.
    Probes data blocks to assess recoverability.

2.  Trash / recycle-bin scan  (both modes)
    Reads freedesktop Trash (info/*.trashinfo + files/) per user.
    These files are immediately recoverable and can be restored on demand.

3.  Deleted-but-open file detection  (local mode only)
    Iterates /proc/<pid>/fd/ for symlinks ending in " (deleted)".
    Content is accessible through /proc/<pid>/fd/<n> while process runs.

4.  Anti-forensics indicator scan  (both modes)
    Parses shell history files (.bash_history, .zsh_history) and
    auditd logs for rm/shred/wipe/srm commands targeting high-value
    forensic artefacts.  These indicate intentional evidence destruction.
"""
from __future__ import annotations

import os
import re
from datetime import datetime, timezone
from typing import Dict, List, Optional

from .extractor import FilesystemAccessor

try:
    import pytsk3 as _tsk
    _HAS_PYTSK3 = True
    _UNALLOC_FLAG = 0x02
    _META_TYPE_DIR = _tsk.TSK_FS_META_TYPE_DIR
    _META_TYPE_REG = _tsk.TSK_FS_META_TYPE_REG
except Exception:
    _tsk = None                    # type: ignore
    _HAS_PYTSK3 = False
    _UNALLOC_FLAG = 0x02
    _META_TYPE_DIR = 2
    _META_TYPE_REG = 1

_MAX_INODE_FINDINGS = 1000
_MAX_DEPTH = 8

# Names that raise severity if deleted
_HIGH_VALUE = frozenset([
    "bash_history", "auth.log", "syslog", "secure", "messages",
    "passwd", "shadow", "group", "kern.log", "audit.log",
    "dmesg", "wtmp", "btmp", "lastlog", "faillog",
])

# Data-wiping commands
_WIPE_RE = re.compile(
    r"\b(shred|srm|wipe|secure-delete|bleachbit|scrub)\b"
    r"|dd\s+if=/dev/(zero|urandom)"
    r"|truncate\s+-s\s+0",
    re.IGNORECASE,
)

_RM_RE = re.compile(r"\brm\b", re.IGNORECASE)

_HIGHVAL_PATH_RE = re.compile(
    r"(auth\.log|syslog|messages|kern\.log|audit\.log|dmesg|wtmp|btmp"
    r"|lastlog|faillog|\.bash_history|\.zsh_history|/var/log"
    r"|shadow|(?<!\w)passwd(?!\w))",
    re.IGNORECASE,
)

SAFE_RECOVERY_DIR = "/tmp/osforensics_recovery"


# ── Helpers ───────────────────────────────────────────────────────────────────

def _ts(unix_val) -> Optional[str]:
    if unix_val is None or unix_val == 0:
        return None
    try:
        return datetime.fromtimestamp(float(unix_val), tz=timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    except Exception:
        return None


def _sev(name: str) -> str:
    return "high" if any(h in name.lower() for h in _HIGH_VALUE) else "medium"


def _fmt_size(n: int) -> str:
    if n < 1024:
        return f"{n} B"
    elif n < 1024 ** 2:
        return f"{n / 1024:.1f} KB"
    elif n < 1024 ** 3:
        return f"{n / 1024 ** 2:.1f} MB"
    return f"{n / 1024 ** 3:.1f} GB"


def _base_finding(path: str, ftype: str, detail: str, severity: str) -> Dict:
    """Return a finding dict with all optional fields at safe defaults."""
    return {
        "path": path,
        "type": ftype,
        "detail": detail,
        "severity": severity,
        "inode": None,
        "size": None,
        "mtime": None,
        "atime": None,
        "ctime": None,
        "deleted_at": None,
        "recoverable": False,
        "recovery_hint": "",
        "recovery_id": "",
        "user": None,
        "command": None,
    }


# ── Strategy 1: pytsk3 TSK inode scan ─────────────────────────────────────────

def _probe_tsk_inode(fs_obj, inode: int, size: int):
    """Try to read the first block of a deleted inode to assess recoverability."""
    if size <= 0:
        return False, "zero-length file"
    try:
        f = fs_obj.open_meta(inode=inode)
        probe = min(512, size)
        data = f.read_random(0, probe)
        if data and any(b != 0 for b in data):
            return True, "data blocks appear intact"
        return False, "data blocks zeroed or overwritten"
    except Exception as exc:
        return False, f"unreadable ({exc})"


def _tsk_recurse(dir_obj, path: str, findings: list, depth: int, fs_obj) -> None:
    if depth > _MAX_DEPTH or len(findings) >= _MAX_INODE_FINDINGS:
        return
    for entry in dir_obj:
        if len(findings) >= _MAX_INODE_FINDINGS:
            break
        if not hasattr(entry, "info") or entry.info is None:
            continue
        if entry.info.name is None:
            continue
        try:
            name = entry.info.name.name.decode("utf-8", errors="ignore")
        except Exception:
            continue
        if name in (".", ".."):
            continue
        meta = entry.info.meta
        if meta is None:
            continue

        full = f"{path.rstrip('/')}/{name}"
        is_del = bool(meta.flags & _UNALLOC_FLAG)

        if is_del:
            inode_n = int(meta.addr) if meta.addr else None
            size = int(meta.size) if meta.size else 0
            mtime = _ts(meta.mtime) if meta.mtime else None
            atime = _ts(meta.atime) if meta.atime else None
            ctime = (
                _ts(meta.crtime)
                if hasattr(meta, "crtime") and meta.crtime
                else _ts(meta.ctime) if meta.ctime else None
            )
            size_str = _fmt_size(size) if size else "0 B"

            if inode_n and 0 < size <= 100 * 1024 * 1024:
                recoverable, hint = _probe_tsk_inode(fs_obj, inode_n, size)
            elif size > 100 * 1024 * 1024:
                recoverable, hint = False, "file too large to probe"
            else:
                recoverable, hint = False, "no inode number available"

            finding = _base_finding(
                full, "deleted_inode",
                f"Deleted inode {inode_n}: {full} ({size_str})",
                _sev(name),
            )
            finding.update({
                "inode": inode_n,
                "size": size,
                "mtime": mtime,
                "atime": atime,
                "ctime": ctime,
                "recoverable": recoverable,
                "recovery_hint": hint,
                "recovery_id": f"tsk:{inode_n}" if inode_n else "",
            })
            findings.append(finding)

        # Recurse into live directories only
        if not is_del and depth < _MAX_DEPTH:
            try:
                if int(meta.type) == _META_TYPE_DIR:
                    _tsk_recurse(entry.as_directory(), full, findings, depth + 1, fs_obj)
            except Exception:
                pass


def scan_deleted_tsk(fs: FilesystemAccessor) -> List[Dict]:
    """Recover deleted inodes from a pytsk3 disk image."""
    if not (_HAS_PYTSK3 and fs.mode == "tsk"):
        return []
    findings: list = []
    try:
        _tsk_recurse(fs.fs.open_dir("/"), "/", findings, 0, fs.fs)
    except Exception as exc:
        findings.append(_base_finding("/", "scan_error", f"TSK scan error: {exc}", "info"))
    return findings


# ── Strategy 2: Trash / recycle-bin scan ──────────────────────────────────────

def _parse_trashinfo(raw: bytes) -> Dict:
    out: Dict = {}
    for line in raw.decode("utf-8", errors="ignore").splitlines():
        if line.startswith("Path="):
            out["path"] = line[5:].strip()
        elif line.startswith("DeletionDate="):
            out["deleted_at"] = line[13:].strip()
    return out


def _scan_trash_dir(fs: FilesystemAccessor, trash_root: str, user: str) -> List[Dict]:
    info_dir = f"{trash_root}/info"
    files_dir = f"{trash_root}/files"
    if not fs.exists(info_dir):
        return []
    findings: list = []
    for entry in fs.list_dir(info_dir):
        if not entry.endswith(".trashinfo"):
            continue
        info_raw = fs.read_file(f"{info_dir}/{entry}", max_bytes=4096)
        if not info_raw:
            continue
        meta = _parse_trashinfo(info_raw)
        orig_path = meta.get("path") or f"/{entry[:-10]}"
        deleted_at = meta.get("deleted_at")
        base = entry[:-10]   # strip .trashinfo suffix
        trash_file = f"{files_dir}/{base}"

        size: Optional[int] = None
        if fs.mode == "local":
            try:
                local_p = os.path.join(fs.path, trash_file.lstrip("/"))
                if os.path.isfile(local_p):
                    size = os.path.getsize(local_p)
            except Exception:
                pass

        is_recoverable = fs.exists(trash_file)
        finding = _base_finding(
            orig_path, "trash",
            f"In {user}'s Trash as '{base}', deleted {deleted_at or 'at unknown time'}",
            _sev(os.path.basename(orig_path)),
        )
        finding.update({
            "size": size,
            "deleted_at": deleted_at,
            "recoverable": is_recoverable,
            "recovery_hint": (
                f"File is in Trash at {trash_file}" if is_recoverable
                else "Trash entry exists but the file itself is missing"
            ),
            "recovery_id": f"trash:{trash_file}" if is_recoverable else "",
            "user": user,
        })
        findings.append(finding)
    return findings


def scan_trash(fs: FilesystemAccessor) -> List[Dict]:
    """Scan freedesktop Trash directories for all users."""
    findings: list = []
    candidates = [
        ("/root/.local/share/Trash", "root"),
        ("/root/.Trash", "root"),
    ]
    try:
        for user in fs.list_dir("/home"):
            candidates.append((f"/home/{user}/.local/share/Trash", user))
            candidates.append((f"/home/{user}/.Trash-0", user))
            candidates.append((f"/home/{user}/.Trash-1000", user))
    except Exception:
        pass
    for trash_root, user in candidates:
        if fs.exists(trash_root):
            findings.extend(_scan_trash_dir(fs, trash_root, user))
    return findings


# ── Strategy 3: Deleted-but-open file detection ────────────────────────────────

def scan_open_deleted(fs: FilesystemAccessor) -> List[Dict]:
    """Find files unlinked from disk but still held open by running processes."""
    if fs.mode != "local":
        return []
    findings: list = []
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except Exception:
        return []

    seen: set = set()
    for pid in pids[:512]:
        fd_dir = f"/proc/{pid}/fd"
        try:
            fds = os.listdir(fd_dir)
        except (PermissionError, FileNotFoundError):
            continue
        except Exception:
            continue
        for fd in fds:
            fd_path = f"{fd_dir}/{fd}"
            try:
                target = os.readlink(fd_path)
            except Exception:
                continue
            if " (deleted)" not in target:
                continue
            real_path = target.replace(" (deleted)", "").strip()
            key = (pid, real_path)
            if key in seen:
                continue
            seen.add(key)

            try:
                with open(f"/proc/{pid}/comm") as f:
                    proc_name = f.read().strip()
            except Exception:
                proc_name = "unknown"

            size: Optional[int] = None
            try:
                size = os.stat(fd_path).st_size
            except Exception:
                pass

            finding = _base_finding(
                real_path, "open_deleted",
                f"Deleted on disk, still open by PID {pid} ({proc_name})",
                _sev(os.path.basename(real_path)),
            )
            finding.update({
                "size": size,
                "recoverable": True,
                "recovery_hint": (
                    f"Read from /proc/{pid}/fd/{fd} while PID {pid} ({proc_name}) is running"
                ),
                "recovery_id": f"proc:{pid}:{fd}",
            })
            findings.append(finding)
    return findings


# ── Strategy 4: Anti-forensics indicator scan ──────────────────────────────────

def _parse_history(raw: bytes, user: str, filepath: str) -> List[Dict]:
    findings: list = []
    for lineno, line in enumerate(raw.decode("utf-8", errors="ignore").splitlines(), 1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or stripped.startswith(":"):
            continue
        is_wipe = bool(_WIPE_RE.search(stripped))
        is_rm   = bool(_RM_RE.search(stripped))
        targets_hv = bool(_HIGHVAL_PATH_RE.search(stripped))
        if not (is_wipe or (is_rm and targets_hv)):
            continue
        sev = "high" if (is_wipe or targets_hv) else "medium"
        label = "data wiping command" if is_wipe else "deletion of forensic artefact"
        tokens = stripped.split()
        path_tokens = [t for t in tokens[1:] if not t.startswith("-") and ("/" in t or "." in t)]
        target = path_tokens[0] if path_tokens else filepath
        finding = _base_finding(
            target, "anti_forensics",
            f"Shell history ({filepath}, line {lineno}): {label}: {stripped[:120]}",
            sev,
        )
        finding.update({
            "recoverable": False,
            "recovery_hint": "Evidence of intentional evidence destruction; data may be unrecoverable",
            "user": user,
            "command": stripped[:300],
        })
        findings.append(finding)
    return findings


def scan_anti_forensics(fs: FilesystemAccessor) -> List[Dict]:
    """Detect intentional deletion / data destruction in shell histories and audit logs."""
    findings: list = []
    history_paths = [
        ("/root/.bash_history", "root"),
        ("/root/.zsh_history", "root"),
    ]
    try:
        for user in fs.list_dir("/home"):
            history_paths.append((f"/home/{user}/.bash_history", user))
            history_paths.append((f"/home/{user}/.zsh_history", user))
    except Exception:
        pass

    for hist_path, user in history_paths:
        raw = fs.read_file(hist_path, max_bytes=512 * 1024)
        if raw:
            findings.extend(_parse_history(raw, user, hist_path))

    # auditd log: look for SYSCALL records from deletion-related executables
    audit_raw = fs.read_file("/var/log/audit/audit.log", max_bytes=2 * 1024 * 1024)
    if audit_raw:
        for line in audit_raw.decode("utf-8", errors="ignore").splitlines():
            if "type=SYSCALL" not in line:
                continue
            comm_m = re.search(r'comm="([^"]+)"', line)
            if not comm_m:
                continue
            comm = comm_m.group(1)
            if comm not in ("rm", "shred", "wipe", "srm", "secure-delete", "unlink", "truncate"):
                continue
            exe_m = re.search(r'exe="([^"]+)"', line)
            exe = exe_m.group(1) if exe_m else comm
            uid_m = re.search(r"\buid=(\d+)", line)
            uid = uid_m.group(1) if uid_m else "unknown"
            is_wipe_cmd = comm in ("shred", "wipe", "srm", "secure-delete")
            finding = _base_finding(
                exe, "anti_forensics",
                f"auditd: {comm} called by uid={uid}",
                "high" if is_wipe_cmd else "medium",
            )
            finding.update({
                "recoverable": False,
                "recovery_hint": "Recorded in auditd log only; file contents likely destroyed",
                "user": uid,
                "command": line[:200],
            })
            findings.append(finding)
    return findings


# ── File recovery ──────────────────────────────────────────────────────────────

def recover_file(
    fs: FilesystemAccessor,
    recovery_id: str,
    output_dir: str,
) -> Dict:
    """Attempt to recover a deleted file.

    Returns {success: bool, path: str, size: int, error: str}.
    """
    os.makedirs(output_dir, exist_ok=True)
    if recovery_id.startswith("tsk:"):
        return _rec_tsk(fs, recovery_id[4:], output_dir)
    if recovery_id.startswith("trash:"):
        return _rec_trash(fs, recovery_id[6:], output_dir)
    if recovery_id.startswith("proc:"):
        parts = recovery_id.split(":", 2)
        if len(parts) == 3:
            return _rec_proc(parts[1], parts[2], output_dir)
    return {"success": False, "path": "", "size": 0, "error": f"Unknown recovery scheme: {recovery_id}"}


def _rec_tsk(fs: FilesystemAccessor, inode_str: str, output_dir: str) -> Dict:
    if not (_HAS_PYTSK3 and fs.mode == "tsk"):
        return {"success": False, "path": "", "size": 0, "error": "pytsk3 not available or not in TSK mode"}
    if not re.fullmatch(r"\d+", inode_str):
        return {"success": False, "path": "", "size": 0, "error": "Invalid inode number"}
    try:
        inode = int(inode_str)
        f = fs.fs.open_meta(inode=inode)
        size = int(f.info.meta.size)
        if size <= 0:
            return {"success": False, "path": "", "size": 0, "error": "File has zero length"}
        cap = min(size, 200 * 1024 * 1024)
        data = f.read_random(0, cap)
        out_path = os.path.join(output_dir, f"recovered_inode_{inode}.bin")
        with open(out_path, "wb") as fout:
            fout.write(data)
        return {"success": True, "path": out_path, "size": len(data), "error": ""}
    except Exception as exc:
        return {"success": False, "path": "", "size": 0, "error": str(exc)}


def _rec_trash(fs: FilesystemAccessor, trash_path: str, output_dir: str) -> Dict:
    # Security: validate source is genuinely within a Trash directory
    if "/Trash/" not in trash_path and "/.Trash" not in trash_path:
        return {"success": False, "path": "", "size": 0, "error": "Not a valid Trash path"}

    import shutil

    if fs.mode != "local":
        raw = fs.read_file(trash_path, max_bytes=200 * 1024 * 1024)
        if raw is None:
            return {"success": False, "path": "", "size": 0, "error": "Could not read file from image"}
        base = os.path.basename(trash_path)
        out_path = os.path.join(output_dir, f"recovered_{base}")
        with open(out_path, "wb") as fout:
            fout.write(raw)
        return {"success": True, "path": out_path, "size": len(raw), "error": ""}

    # Local mode: copy the actual file
    try:
        src = trash_path if os.path.isabs(trash_path) else os.path.join(fs.path, trash_path.lstrip("/"))
        base = os.path.basename(src)
        out_path = os.path.join(output_dir, f"recovered_{base}")
        if os.path.isdir(src):
            shutil.copytree(src, out_path, dirs_exist_ok=True)
            size = sum(
                os.path.getsize(os.path.join(r, fn))
                for r, _, files in os.walk(out_path)
                for fn in files
            )
        else:
            shutil.copy2(src, out_path)
            size = os.path.getsize(out_path)
        return {"success": True, "path": out_path, "size": size, "error": ""}
    except Exception as exc:
        return {"success": False, "path": "", "size": 0, "error": str(exc)}


def _rec_proc(pid: str, fd: str, output_dir: str) -> Dict:
    """Recover a deleted-but-still-open file via /proc/PID/fd/FD."""
    if not re.fullmatch(r"\d+", pid) or not re.fullmatch(r"\d+", fd):
        return {"success": False, "path": "", "size": 0, "error": "Invalid PID or FD number"}
    fd_path = f"/proc/{pid}/fd/{fd}"
    try:
        with open(fd_path, "rb") as src:
            data = src.read(200 * 1024 * 1024)
        try:
            comm = open(f"/proc/{pid}/comm").read().strip()
        except Exception:
            comm = "proc"
        out_path = os.path.join(output_dir, f"recovered_{comm}_pid{pid}_fd{fd}.bin")
        with open(out_path, "wb") as fout:
            fout.write(data)
        return {"success": True, "path": out_path, "size": len(data), "error": ""}
    except Exception as exc:
        return {"success": False, "path": "", "size": 0, "error": str(exc)}


# ── Public entry point ─────────────────────────────────────────────────────────

def detect_deleted(fs: FilesystemAccessor) -> List[Dict]:
    """Run all deleted-file detection strategies and return combined results."""
    findings: list = []
    findings.extend(scan_deleted_tsk(fs))
    findings.extend(scan_trash(fs))
    findings.extend(scan_open_deleted(fs))
    findings.extend(scan_anti_forensics(fs))
    return findings


# ── File Carving (signature-based recovery) ────────────────────────────────────
#
# Scans the raw bytes of a disk image for known file-type magic bytes ("headers")
# and optionally their corresponding terminating byte sequences ("footers").
# Works even when the inode table has been wiped — the technique used by tools
# like Foremost, Scalpel, and PhotoRec.
#
# Only applicable to disk-image (TSK) mode; mounting a live directory gives no
# raw unallocated blocks to scan.

_CARVE_CHUNK = 4 * 1024 * 1024   # 4 MB read window

_MB = 1024 * 1024

# Each entry: (type_name, file_ext, header_bytes, footer_bytes_or_None, max_size, group)
CARVE_SIGNATURES = [
    # ── images ─────────────────────────────────────────────────────────────────
    ("JPEG",         "jpg",   b"\xff\xd8\xff",                  b"\xff\xd9",               30 * _MB,  "image"),
    ("PNG",          "png",   b"\x89PNG\r\n\x1a\n",             b"IEND\xaeB`\x82",         25 * _MB,  "image"),
    ("GIF87a",       "gif",   b"GIF87a",                        b"\x00\x3b",               10 * _MB,  "image"),
    ("GIF89a",       "gif",   b"GIF89a",                        b"\x00\x3b",               10 * _MB,  "image"),
    ("BMP",          "bmp",   b"BM",                            None,                       5 * _MB,  "image"),
    ("TIFF-LE",      "tif",   b"II\x2a\x00",                   None,                      50 * _MB,  "image"),
    ("TIFF-BE",      "tif",   b"MM\x00\x2a",                   None,                      50 * _MB,  "image"),
    ("WEBP",         "webp",  b"RIFF",                          None,                      10 * _MB,  "image"),   # RIFF….WEBP
    # ── documents ──────────────────────────────────────────────────────────────
    ("PDF",          "pdf",   b"%PDF",                          b"%%EOF",                 100 * _MB,  "document"),
    ("ZIP/DOCX/XLSX","zip",   b"PK\x03\x04",                   b"PK\x05\x06",            200 * _MB,  "document"),
    ("OLE2",         "doc",   b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", None,                100 * _MB,  "document"),  # Word/Excel/PPT
    ("RTF",          "rtf",   b"{\\rtf",                        b"}",                     20 * _MB,  "document"),
    # ── executables / binaries ─────────────────────────────────────────────────
    ("ELF",          "elf",   b"\x7fELF",                       None,                     50 * _MB,  "executable"),
    ("Mach-O",       "macho", b"\xce\xfa\xed\xfe",              None,                     50 * _MB,  "executable"),  # 32-bit little-endian
    ("Mach-O-64",    "macho", b"\xcf\xfa\xed\xfe",              None,                     50 * _MB,  "executable"),
    # ── databases ──────────────────────────────────────────────────────────────
    ("SQLite",       "db",    b"SQLite format 3\x00",           None,                    200 * _MB,  "database"),
    # ── archives ───────────────────────────────────────────────────────────────
    ("GZIP",         "gz",    b"\x1f\x8b\x08",                  None,                   100 * _MB,  "archive"),
    ("BZIP2",        "bz2",   b"BZh",                            None,                   100 * _MB,  "archive"),
    ("7-Zip",        "7z",    b"7z\xbc\xaf\x27\x1c",            None,                   500 * _MB,  "archive"),
    ("XZ",           "xz",    b"\xfd7zXZ\x00",                  b"\x59\x5a",            100 * _MB,  "archive"),
    # ── email / forensic artefacts ─────────────────────────────────────────────
    ("PST/OST",      "pst",   b"\x21\x42\x44\x4e",              None,                   500 * _MB,  "email"),
    ("mbox",         "mbox",  b"From ",                          None,                    10 * _MB,  "email"),
    # ── video ──────────────────────────────────────────────────────────────────
    ("MP4/ISO",      "mp4",   b"\x00\x00\x00\x18ftypMP42",      None,                   500 * _MB,  "video"),
    ("MP4-isom",     "mp4",   b"\x00\x00\x00\x20ftypisom",      None,                   500 * _MB,  "video"),
    ("AVI",          "avi",   b"RIFF",                           None,                   500 * _MB,  "video"),
    # ── audio ──────────────────────────────────────────────────────────────────
    ("MP3-ID3",      "mp3",   b"ID3",                            None,                    20 * _MB,  "audio"),
    ("WAV",          "wav",   b"RIFF",                           None,                    50 * _MB,  "audio"),
    # ── scripts / text ─────────────────────────────────────────────────────────
    ("UTF8-BOM",     "txt",   b"\xef\xbb\xbf",                  None,                     1 * _MB,  "text"),
    ("XML-decl",     "xml",   b"<?xml version",                 b"</",                    5 * _MB,  "text"),
    ("Shell-script", "sh",    b"#!/bin/sh",                     None,                     1 * _MB,  "text"),
    ("Bash-script",  "sh",    b"#!/bin/bash",                   None,                     1 * _MB,  "text"),
    ("Python-script","py",    b"#!/usr/bin/python",             None,                     1 * _MB,  "text"),
    ("Bash-history", "txt",   b": 1",                           None,                     10 * _MB, "text"),
]

# Human-readable groups shown in the UI
CARVE_GROUPS = {
    "image":      "Images (JPEG, PNG, GIF, BMP, TIFF, WEBP)",
    "document":   "Documents (PDF, DOCX, XLSX, DOC, RTF)",
    "executable": "Executables (ELF, Mach-O)",
    "database":   "Databases (SQLite)",
    "archive":    "Archives (ZIP, GZIP, 7z, BZIP2, XZ)",
    "email":      "Email & Outlook (PST, mbox)",
    "video":      "Video (MP4, AVI)",
    "audio":      "Audio (MP3, WAV)",
    "text":       "Scripts & Text (shell, Python, XML)",
}


def _scan_for_signature(raw_path: str, header: bytes, max_count: int) -> List[int]:
    """Return sorted list of absolute byte offsets where `header` starts in the raw file."""
    h_len = len(header)
    overlap = h_len - 1
    offsets: List[int] = []
    file_pos = 0   # absolute file position of chunk[0] in the current iteration
    tail = b""

    with open(raw_path, "rb") as fh:
        while len(offsets) < max_count:
            chunk = fh.read(_CARVE_CHUNK)
            if not chunk:
                break

            window = tail + chunk
            # window[i] is at absolute file position: (file_pos - len(tail)) + i
            win_base = file_pos - len(tail)

            p = 0
            while True:
                i = window.find(header, p)
                if i < 0:
                    break
                abs_off = win_base + i
                # Deduplicate: only record strictly new offsets (handles overlap re-detection)
                if not offsets or abs_off > offsets[-1]:
                    offsets.append(abs_off)
                    if len(offsets) >= max_count:
                        break
                p = i + 1

            file_pos += len(chunk)
            tail = chunk[-overlap:] if overlap > 0 else b""

    return offsets


def _carve_one(raw_path: str, offset: int, sig_tuple: tuple, out_path: str) -> int:
    """Extract one carved artefact starting at `offset`.  Returns bytes written."""
    _name, _ext, header, footer, max_size, _group = sig_tuple
    with open(raw_path, "rb") as fh:
        fh.seek(offset)
        data = fh.read(max_size)

    if footer and len(data) > len(footer):
        end = data.find(footer)
        if end != -1:
            data = data[:end + len(footer)]

    # Sanity: must start with the header we expected
    if not data.startswith(header):
        raise ValueError("extracted data does not start with expected header")

    with open(out_path, "wb") as fout:
        fout.write(data)
    return len(data)


def carve_files(
    fs: "FilesystemAccessor",
    output_dir: str,
    sig_groups: Optional[List[str]] = None,
    max_files: int = 200,
    max_scan_bytes: int = 2 * 1024 * 1024 * 1024,  # 2 GB scan ceiling
) -> List[Dict]:
    """Signature-based file carving from a raw disk image.

    Scans raw bytes looking for file magic bytes regardless of whether
    any inode metadata exists.  Works even on totally wiped partition tables.

    Args:
        fs:            FilesystemAccessor in TSK mode.
        output_dir:    Directory to write carved files into.
        sig_groups:    Optional list of group keys to restrict scanning
                       (e.g. ["image", "document"]).  None = all groups.
        max_files:     Hard cap on total carved files.
        max_scan_bytes: Stop scanning after this many image bytes (safety cap).

    Returns:
        List of finding dicts compatible with DeletedFinding.
    """
    if fs.mode != "tsk":
        return [_base_finding("", "carve_skip",
                              "File carving requires a disk image (TSK mode); "
                              "not applicable to a live mounted directory.", "info")]

    os.makedirs(output_dir, exist_ok=True)
    raw_path = fs.path

    # Check image size so we can warn if truncating
    try:
        img_size = os.path.getsize(raw_path)
    except Exception:
        img_size = 0
    scanning_truncated = img_size > max_scan_bytes

    # Filter signatures to requested groups
    active_sigs = [
        s for s in CARVE_SIGNATURES
        if sig_groups is None or s[5] in sig_groups
    ]
    if not active_sigs:
        return [_base_finding("", "carve_error", "No signatures selected.", "info")]

    findings: list = []
    counter = 0
    seen_offsets: set = set()   # avoid extracting RIFF-based types twice at same offset

    for sig in active_sigs:
        if counter >= max_files:
            break

        name, ext, header, footer, max_size, group = sig
        per_sig_limit = min(50, max_files - counter)

        try:
            offsets = _scan_for_signature(raw_path, header, per_sig_limit)
        except Exception as exc:
            findings.append(_base_finding(
                raw_path, "carve_error",
                f"Scan error for {name}: {exc}", "info",
            ))
            continue

        for off in offsets:
            if counter >= max_files:
                break
            if scanning_truncated and off >= max_scan_bytes:
                break

            # Some headers (e.g. RIFF) are shared by WEBP/WAV/AVI — skip dupes
            if off in seen_offsets:
                continue
            seen_offsets.add(off)

            fname = f"carved_{group}_{name.lower().replace('/', '-')}_{counter:04d}.{ext}"
            out_path = os.path.join(output_dir, fname)

            try:
                size = _carve_one(raw_path, off, sig, out_path)
            except Exception as exc:
                findings.append(_base_finding(
                    out_path, "carve_error",
                    f"Failed to carve {name} at offset {off:#010x}: {exc}", "info",
                ))
                continue

            finding = _base_finding(
                out_path, "carved",
                f"Carved {name} at disk offset {off:#010x} ({_fmt_size(size)})",
                "medium",
            )
            finding.update({
                "size": size,
                "recoverable": True,
                "recovery_hint": f"Carved from offset {off:#010x} in image",
                "recovery_id": f"carved:{out_path}",
                # Re-use inode field for the raw disk offset (useful for analysts)
                "inode": off,
            })
            findings.append(finding)
            counter += 1

    if scanning_truncated:
        findings.append(_base_finding(
            raw_path, "carve_info",
            f"Scan capped at {_fmt_size(max_scan_bytes)} of "
            f"{_fmt_size(img_size)} image; increase limit for full coverage.",
            "info",
        ))

    if not any(f["type"] == "carved" for f in findings):
        findings.append(_base_finding(
            output_dir, "carve_info",
            "No matching file signatures found in scanned region.", "info",
        ))

    return findings
