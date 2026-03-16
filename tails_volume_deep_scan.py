#!/usr/bin/env python3
"""Standalone deep forensic scan for a mounted Tails volume.

Usage:
  python tails_volume_deep_scan.py --mount /home/aparichit/TailsData
  python tails_volume_deep_scan.py --mount /home/aparichit/TailsData --output tails_report.json
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import sys
import time
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Tuple

MAX_TEXT_READ = 2_000_000
MAX_FILE_SNIPPET = 80_000
MAX_WALK_FILES = 250_000
MAX_LARGEST_FILES = 120
MAX_TIMELINE_EVENTS = 200
MAX_SUSPICIOUS_LINES = 120
DEFAULT_MAX_COPY_BYTES = 25 * 1024 * 1024

ONION_RE = re.compile(r"\b[a-z2-7]{16,56}\.onion\b", re.IGNORECASE)
BTC_RE = re.compile(r"\b(?:bc1|[13])[a-zA-HJ-NP-Z0-9]{20,90}\b")
ETH_RE = re.compile(r"\b0x[a-fA-F0-9]{40}\b")
XMR_RE = re.compile(r"\b4[0-9AB][1-9A-HJ-NP-Za-km-z]{93}\b")
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")

SUSPICIOUS_CMD_RE = re.compile(
    r"\b(?:nmap|sqlmap|hydra|john|hashcat|aircrack|netcat|nc|proxychains|msfconsole|metasploit|"
    r"curl|wget|scp|ssh|torsocks|bitcoin-cli|monero-wallet-cli|gpg|shred|wipe|dd\s+if=|"
    r"python\s+-m\s+http\.server)\b",
    re.IGNORECASE,
)

TEXT_EXTENSIONS = {
    ".txt", ".md", ".log", ".conf", ".cfg", ".ini", ".json", ".yaml", ".yml",
    ".xml", ".csv", ".list", ".service", ".desktop", ".sh", ".zsh", ".bash",
    ".py", ".js", ".ts", ".sql", ".asc", ".pem", ".pub",
}

WALLET_PATH_HINTS = [
    ".electrum",
    ".bitcoin",
    ".monero",
    "wallet",
    "wallets",
    "electrum",
    "wasabi",
    "sparrow",
]

KEY_PATH_HINTS = [
    ".ssh",
    ".gnupg",
    "key",
    "keys",
    "id_rsa",
    "id_ed25519",
    "authorized_keys",
]

TOR_HINTS = ["tor", "onion", "bridges", "obfs4", "snowflake", "meek", "hiddenservice"]


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_read_text(path: Path, max_bytes: int = MAX_TEXT_READ) -> str:
    try:
        with path.open("rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def safe_lstat(path: Path):
    try:
        return path.lstat()
    except Exception:
        return None


def file_sha256(path: Path, max_bytes: int = 8_000_000) -> Optional[str]:
    try:
        h = hashlib.sha256()
        with path.open("rb") as f:
            remaining = max_bytes
            while remaining > 0:
                chunk = f.read(min(1_048_576, remaining))
                if not chunk:
                    break
                h.update(chunk)
                remaining -= len(chunk)
        return h.hexdigest()
    except Exception:
        return None


def classify_ext(ext: str) -> str:
    ext = ext.lower()
    if ext in {".txt", ".md", ".doc", ".docx", ".pdf", ".odt", ".rtf"}:
        return "documents"
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".svg", ".webp"}:
        return "images"
    if ext in {".mp4", ".mkv", ".avi", ".mov", ".webm", ".mp3", ".wav", ".flac"}:
        return "media"
    if ext in {".zip", ".rar", ".7z", ".tar", ".gz", ".bz2", ".xz"}:
        return "archives"
    if ext in {".sqlite", ".db", ".dat", ".ldb"}:
        return "databases"
    if ext in {".py", ".sh", ".js", ".ts", ".rb", ".go", ".pl", ".ps1"}:
        return "scripts"
    if ext in {".pem", ".key", ".pub", ".asc", ".gpg", ".kbx"}:
        return "keys"
    return "other"


def is_probably_text(path: Path) -> bool:
    if path.suffix.lower() in TEXT_EXTENSIONS:
        return True
    try:
        with path.open("rb") as f:
            sample = f.read(4096)
        if not sample:
            return True
        if b"\x00" in sample:
            return False
        sample.decode("utf-8")
        return True
    except Exception:
        return False


def parse_mount_info(mount_path: Path) -> Dict[str, object]:
    info: Dict[str, object] = {
        "mount_path": str(mount_path),
        "exists": mount_path.exists(),
        "is_dir": mount_path.is_dir(),
        "device": None,
        "fstype": None,
        "mount_opts": None,
        "statvfs": {},
    }
    if not mount_path.exists():
        return info

    mounts = safe_read_text(Path("/proc/mounts"), max_bytes=1_000_000)
    best = None
    best_mnt_len = -1
    for line in mounts.splitlines():
        parts = line.split()
        if len(parts) < 4:
            continue
        dev, mnt, fstype, opts = parts[0], parts[1], parts[2], parts[3]
        if mnt == str(mount_path):
            best = (dev, fstype, opts)
            break
        if str(mount_path).startswith(mnt.rstrip("/") + "/"):
            if best is None or len(mnt) > best_mnt_len:
                best = (dev, fstype, opts)
                best_mnt_len = len(mnt)

    if best:
        info["device"] = best[0]
        info["fstype"] = best[1]
        info["mount_opts"] = best[2]

    try:
        v = os.statvfs(mount_path)
        total = v.f_frsize * v.f_blocks
        free = v.f_frsize * v.f_bfree
        avail = v.f_frsize * v.f_bavail
        used = total - free
        info["statvfs"] = {
            "total_bytes": total,
            "used_bytes": used,
            "free_bytes": free,
            "available_bytes": avail,
        }
    except Exception:
        pass

    return info


def gather_filesystem_inventory(mount_path: Path) -> Dict[str, object]:
    ext_counter: Counter = Counter()
    type_counter: Counter = Counter()
    top_dirs: Counter = Counter()
    largest: List[Tuple[int, str]] = []
    recent_events: List[Tuple[float, str, str, int]] = []

    counts = {
        "files": 0,
        "dirs": 0,
        "symlinks": 0,
        "other": 0,
        "errors": 0,
        "scanned_entries": 0,
        "truncated": False,
    }

    for root, dirs, files in os.walk(mount_path, topdown=True, onerror=lambda _e: None, followlinks=False):
        root_path = Path(root)
        counts["dirs"] += 1
        counts["scanned_entries"] += len(dirs) + len(files)

        rel_root = str(root_path.relative_to(mount_path)) if root_path != mount_path else "."
        first_segment = rel_root.split(os.sep, 1)[0] if rel_root != "." else "."
        top_dirs[first_segment] += len(files)

        for name in files:
            if counts["files"] >= MAX_WALK_FILES:
                counts["truncated"] = True
                break

            p = root_path / name
            st = safe_lstat(p)
            if st is None:
                counts["errors"] += 1
                continue

            mode = st.st_mode
            rel = str(p.relative_to(mount_path))
            if stat.S_ISLNK(mode):
                counts["symlinks"] += 1
                continue
            if not stat.S_ISREG(mode):
                counts["other"] += 1
                continue

            counts["files"] += 1
            ext = p.suffix.lower() or "<no_ext>"
            ext_counter[ext] += 1
            type_counter[classify_ext(ext)] += 1

            size = int(st.st_size)
            largest.append((size, rel))
            if len(largest) > MAX_LARGEST_FILES * 2:
                largest.sort(reverse=True)
                largest = largest[:MAX_LARGEST_FILES]

            mtime = float(st.st_mtime)
            recent_events.append((mtime, "modified", rel, size))
            if len(recent_events) > MAX_TIMELINE_EVENTS * 3:
                recent_events.sort(reverse=True)
                recent_events = recent_events[: MAX_TIMELINE_EVENTS * 2]

        if counts["truncated"]:
            break

    largest.sort(reverse=True)
    largest_out = [{"size": s, "path": p} for s, p in largest[:MAX_LARGEST_FILES]]

    recent_events.sort(reverse=True)
    timeline = []
    for ts, evt, path, size in recent_events[:MAX_TIMELINE_EVENTS]:
        timeline.append(
            {
                "ts": datetime.fromtimestamp(ts, tz=timezone.utc).isoformat(),
                "event": evt,
                "path": path,
                "size": size,
            }
        )

    return {
        "counts": counts,
        "top_extensions": ext_counter.most_common(60),
        "file_types": dict(type_counter),
        "top_dirs_by_file_count": top_dirs.most_common(40),
        "largest_files": largest_out,
        "timeline": timeline,
    }


def parse_persistence_conf(mount_path: Path) -> Dict[str, object]:
    candidates = [
        mount_path / "persistence.conf",
        mount_path / "live/persistence/TailsData_unlocked/persistence.conf",
        mount_path / "TailsData_unlocked/persistence.conf",
    ]
    found = next((p for p in candidates if p.exists()), None)
    if not found:
        return {"found": False, "path": None, "modules": [], "raw_preview": []}

    text = safe_read_text(found, max_bytes=400_000)
    modules = []
    current_source = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("/"):
            current_source = line
        elif "destination=" in line and current_source:
            destination = line.split("destination=", 1)[1].strip()
            modules.append({"source": current_source, "destination": destination})

    preview = [l[:240] for l in text.splitlines()[:120]]
    return {
        "found": True,
        "path": str(found),
        "modules": modules,
        "raw_preview": preview,
    }


def find_interesting_paths(mount_path: Path) -> Dict[str, List[str]]:
    hits: Dict[str, List[str]] = defaultdict(list)

    path_checks = {
        "tails_markers": [
            "amnesia",
            "live",
            "persistence.conf",
            "Tor Browser",
            ".tor-browser",
            ".amnesia",
        ],
        "wallet_paths": WALLET_PATH_HINTS,
        "key_paths": KEY_PATH_HINTS,
        "tor_paths": TOR_HINTS,
        "history_paths": ["history", "bash_history", "zsh_history", "fish_history"],
        "logs": ["log", "journal", "syslog", "auth.log"],
    }

    for root, dirs, files in os.walk(mount_path, topdown=True, onerror=lambda _e: None, followlinks=False):
        rel_root = os.path.relpath(root, mount_path)
        rel_root = "." if rel_root == "." else rel_root

        names = list(dirs) + list(files)
        for name in names:
            rel = name if rel_root == "." else f"{rel_root}/{name}"
            rel_l = rel.lower()
            for bucket, needles in path_checks.items():
                if any(n.lower() in rel_l for n in needles):
                    if len(hits[bucket]) < 300:
                        hits[bucket].append(rel)

    return dict(hits)


def scan_textual_artifacts(mount_path: Path) -> Dict[str, object]:
    onions = set()
    btc = set()
    eth = set()
    xmr = set()
    ips = set()
    suspicious_lines: List[Dict[str, str]] = []
    bridge_lines: List[Dict[str, str]] = []
    hidden_service_lines: List[Dict[str, str]] = []

    scanned_text_files = 0

    for root, _dirs, files in os.walk(mount_path, topdown=True, onerror=lambda _e: None, followlinks=False):
        for name in files:
            p = Path(root) / name
            if not p.exists() or not p.is_file():
                continue
            if not is_probably_text(p):
                continue

            scanned_text_files += 1
            text = safe_read_text(p, max_bytes=MAX_FILE_SNIPPET)
            if not text:
                continue

            rel = str(p.relative_to(mount_path))
            for hit in ONION_RE.findall(text):
                if len(onions) < 400:
                    onions.add(hit.lower())
            for hit in BTC_RE.findall(text):
                if len(btc) < 200:
                    btc.add(hit)
            for hit in ETH_RE.findall(text):
                if len(eth) < 200:
                    eth.add(hit)
            for hit in XMR_RE.findall(text):
                if len(xmr) < 200:
                    xmr.add(hit)
            for hit in IP_RE.findall(text):
                if len(ips) < 500:
                    ips.add(hit)

            for line in text.splitlines()[:6000]:
                line_strip = line.strip()
                if not line_strip:
                    continue
                ll = line_strip.lower()

                if SUSPICIOUS_CMD_RE.search(line_strip) and len(suspicious_lines) < MAX_SUSPICIOUS_LINES:
                    suspicious_lines.append({"path": rel, "line": line_strip[:320]})

                if ("bridge" in ll or "obfs4" in ll or "snowflake" in ll or "meek" in ll) and len(bridge_lines) < 120:
                    bridge_lines.append({"path": rel, "line": line_strip[:320]})

                if ("hiddenservicedir" in ll or "hiddenserviceport" in ll) and len(hidden_service_lines) < 120:
                    hidden_service_lines.append({"path": rel, "line": line_strip[:320]})

    return {
        "text_files_scanned": scanned_text_files,
        "onion_addresses": sorted(onions)[:250],
        "btc_like_strings": sorted(btc)[:120],
        "eth_like_strings": sorted(eth)[:120],
        "xmr_like_strings": sorted(xmr)[:120],
        "ip_addresses": sorted(ips)[:250],
        "suspicious_lines": suspicious_lines,
        "bridge_related_lines": bridge_lines,
        "hidden_service_lines": hidden_service_lines,
    }


def find_key_wallet_browser_artifacts(mount_path: Path) -> Dict[str, object]:
    key_files = []
    wallet_files = []
    browser_files = []

    key_name_markers = {"id_rsa", "id_ed25519", "id_ecdsa", "authorized_keys", "pubring.kbx", "trustdb.gpg", "secring.gpg"}
    wallet_name_markers = {"wallet.dat", "default_wallet", "electrum.dat", "keys", "seed"}

    for root, _dirs, files in os.walk(mount_path, topdown=True, onerror=lambda _e: None, followlinks=False):
        for name in files:
            p = Path(root) / name
            rel = str(p.relative_to(mount_path)).lower()
            rel_orig = str(p.relative_to(mount_path))

            if any(k in rel for k in (".ssh/", ".gnupg/", "key", "keys")) or name.lower() in key_name_markers:
                st = safe_lstat(p)
                key_files.append({"path": rel_orig, "size": int(st.st_size) if st else None})

            if any(k in rel for k in WALLET_PATH_HINTS) or name.lower() in wallet_name_markers:
                st = safe_lstat(p)
                wallet_files.append({"path": rel_orig, "size": int(st.st_size) if st else None})

            if any(k in rel for k in ("tor browser", ".tor-browser", "places.sqlite", "bookmarks", "extensions", "prefs.js")):
                st = safe_lstat(p)
                browser_files.append({"path": rel_orig, "size": int(st.st_size) if st else None})

    return {
        "key_files": key_files[:600],
        "wallet_files": wallet_files[:600],
        "browser_files": browser_files[:800],
    }


def summarize_risk(artifacts: Dict[str, object]) -> Dict[str, object]:
    score = 0
    reasons: List[str] = []

    persistence = artifacts.get("persistence", {})
    modules = persistence.get("modules", []) if isinstance(persistence, dict) else []
    if modules:
        score += 15
        reasons.append("Persistence modules configured")

    text_scan = artifacts.get("text_scan", {}) if isinstance(artifacts.get("text_scan"), dict) else {}
    onions = text_scan.get("onion_addresses", [])
    bridges = text_scan.get("bridge_related_lines", [])
    hidden = text_scan.get("hidden_service_lines", [])
    susp = text_scan.get("suspicious_lines", [])
    wallets_btc = text_scan.get("btc_like_strings", [])
    wallets_eth = text_scan.get("eth_like_strings", [])
    wallets_xmr = text_scan.get("xmr_like_strings", [])

    if onions:
        score += 20
        reasons.append(f"Onion addresses detected ({len(onions)})")
    if bridges:
        score += 10
        reasons.append("Tor bridge configuration traces found")
    if hidden:
        score += 20
        reasons.append("Hidden service configuration traces found")
    if susp:
        score += 10
        reasons.append(f"Suspicious command lines found ({len(susp)})")

    key_wallet_browser = artifacts.get("key_wallet_browser", {}) if isinstance(artifacts.get("key_wallet_browser"), dict) else {}
    key_files = key_wallet_browser.get("key_files", [])
    wallet_files = key_wallet_browser.get("wallet_files", [])
    browser_files = key_wallet_browser.get("browser_files", [])

    if key_files:
        score += 10
        reasons.append(f"Identity/key artifacts found ({len(key_files)})")
    if wallet_files or wallets_btc or wallets_eth or wallets_xmr:
        score += 15
        reasons.append("Cryptocurrency wallet indicators found")
    if browser_files:
        score += 8
        reasons.append(f"Tor Browser artifacts found ({len(browser_files)})")

    score = min(score, 100)
    if score >= 75:
        level = "critical"
    elif score >= 50:
        level = "high"
    elif score >= 25:
        level = "medium"
    else:
        level = "low"

    return {"score": score, "max": 100, "risk_level": level, "reasons": reasons}


def _path_under_mount(mount_path: Path, target: Path) -> bool:
    try:
        target.resolve().relative_to(mount_path.resolve())
        return True
    except Exception:
        return False


def _add_rel_if_exists(mount_path: Path, rel: str, out: set) -> None:
    clean = rel.lstrip("/")
    p = mount_path / clean
    if p.exists() and p.is_file():
        out.add(clean)


def _collect_from_dir(mount_path: Path, rel_dir: str, out: set, limit_files: int = 4000) -> None:
    base = mount_path / rel_dir
    if not base.exists() or not base.is_dir():
        return
    count = 0
    for root, _dirs, files in os.walk(base, topdown=True, onerror=lambda _e: None, followlinks=False):
        for name in files:
            p = Path(root) / name
            if not p.exists() or not p.is_file() or not _path_under_mount(mount_path, p):
                continue
            rel = str(p.resolve().relative_to(mount_path.resolve()))
            out.add(rel)
            count += 1
            if count >= limit_files:
                return


def collect_evidence_files(report: Dict[str, object], mount_path: Path, collect_dir: Path, max_copy_bytes: int) -> Dict[str, object]:
    """Collect discovered high-signal artifact files into a local evidence folder."""
    collect_dir.mkdir(parents=True, exist_ok=True)

    candidates: set = set()
    artifacts = report.get("artifacts", {}) if isinstance(report.get("artifacts"), dict) else {}

    # Start with explicit artifact path hits.
    key_wallet_browser = artifacts.get("key_wallet_browser", {}) if isinstance(artifacts.get("key_wallet_browser"), dict) else {}
    for section in ("key_files", "wallet_files", "browser_files"):
        for entry in key_wallet_browser.get(section, []):
            if isinstance(entry, dict) and entry.get("path"):
                _add_rel_if_exists(mount_path, str(entry["path"]), candidates)

    text_scan = artifacts.get("text_scan", {}) if isinstance(artifacts.get("text_scan"), dict) else {}
    for section in ("suspicious_lines", "bridge_related_lines", "hidden_service_lines"):
        for entry in text_scan.get(section, []):
            if isinstance(entry, dict) and entry.get("path"):
                _add_rel_if_exists(mount_path, str(entry["path"]), candidates)

    persistence = artifacts.get("persistence", {}) if isinstance(artifacts.get("persistence"), dict) else {}
    p_path = persistence.get("path")
    if isinstance(p_path, str) and p_path:
        p_abs = Path(p_path)
        if p_abs.exists() and p_abs.is_file() and _path_under_mount(mount_path, p_abs):
            candidates.add(str(p_abs.resolve().relative_to(mount_path.resolve())))

    for section in ("interesting_paths",):
        sec_data = artifacts.get(section, {}) if isinstance(artifacts.get(section), dict) else {}
        for _bucket, rels in sec_data.items():
            if not isinstance(rels, list):
                continue
            for rel in rels:
                if isinstance(rel, str):
                    _add_rel_if_exists(mount_path, rel, candidates)

    # Include common high-value dirs so we "grab all those files" consistently.
    high_value_dirs = [
        "Persistent",
        "home/amnesia/.ssh",
        "home/amnesia/.gnupg",
        "home/amnesia/.electrum",
        "home/amnesia/.bitcoin",
        "home/amnesia/.monero",
        "home/amnesia/.tor-browser",
        "etc/tor",
        "var/log",
        "var/lib/tor",
        "live/persistence/TailsData_unlocked",
    ]
    for rel_dir in high_value_dirs:
        _collect_from_dir(mount_path, rel_dir, candidates)

    evidence_root = collect_dir / "collected_files"
    manifest = {
        "collection_utc": now_iso(),
        "mount_path": str(mount_path),
        "collect_dir": str(collect_dir),
        "max_copy_bytes": max_copy_bytes,
        "candidate_count": len(candidates),
        "copied": [],
        "skipped": [],
    }

    copied_bytes = 0
    for rel in sorted(candidates):
        src = mount_path / rel
        if not src.exists() or not src.is_file():
            manifest["skipped"].append({"path": rel, "reason": "not_a_file_or_missing"})
            continue

        st = safe_lstat(src)
        if st is None:
            manifest["skipped"].append({"path": rel, "reason": "lstat_failed"})
            continue

        size = int(st.st_size)
        if size > max_copy_bytes:
            manifest["skipped"].append({"path": rel, "reason": "size_limit", "size": size})
            continue

        dest = evidence_root / rel
        dest.parent.mkdir(parents=True, exist_ok=True)
        try:
            shutil.copy2(src, dest)
            sha = file_sha256(src, max_bytes=max(size, 1))
            manifest["copied"].append({"path": rel, "size": size, "sha256": sha})
            copied_bytes += size
        except Exception as e:
            manifest["skipped"].append({"path": rel, "reason": f"copy_failed: {e}"})

    manifest["copied_count"] = len(manifest["copied"])
    manifest["skipped_count"] = len(manifest["skipped"])
    manifest["copied_bytes"] = copied_bytes
    manifest_path = collect_dir / "collection_manifest.json"
    with manifest_path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2, ensure_ascii=True)

    return {
        "enabled": True,
        "collect_dir": str(collect_dir),
        "manifest_path": str(manifest_path),
        "collected_files_root": str(evidence_root),
        "copied_count": manifest["copied_count"],
        "skipped_count": manifest["skipped_count"],
        "copied_bytes": copied_bytes,
        "max_copy_bytes": max_copy_bytes,
    }


def build_report(mount_path: Path, collect_dir: Optional[Path] = None, max_copy_bytes: int = DEFAULT_MAX_COPY_BYTES) -> Dict[str, object]:
    started = time.time()

    report: Dict[str, object] = {
        "meta": {
            "tool": "tails_volume_deep_scan",
            "version": "1.0",
            "generated_utc": now_iso(),
            "host": os.uname().nodename if hasattr(os, "uname") else None,
        },
        "input": {
            "mount_path": str(mount_path),
        },
        "mount": parse_mount_info(mount_path),
        "artifacts": {},
        "summary": {},
    }

    if not mount_path.exists() or not mount_path.is_dir():
        report["summary"] = {
            "status": "error",
            "message": f"Mount path does not exist or is not a directory: {mount_path}",
        }
        report["meta"]["duration_seconds"] = round(time.time() - started, 3)
        return report

    report["artifacts"]["filesystem_inventory"] = gather_filesystem_inventory(mount_path)
    report["artifacts"]["persistence"] = parse_persistence_conf(mount_path)
    report["artifacts"]["interesting_paths"] = find_interesting_paths(mount_path)
    report["artifacts"]["text_scan"] = scan_textual_artifacts(mount_path)
    report["artifacts"]["key_wallet_browser"] = find_key_wallet_browser_artifacts(mount_path)
    report["artifacts"]["mount_root_listing"] = sorted([p.name for p in mount_path.iterdir()])[:1000]

    report["summary"] = {
        "status": "ok",
        "risk": summarize_risk(report["artifacts"]),
    }

    if collect_dir is not None:
        report["artifacts"]["evidence_collection"] = collect_evidence_files(
            report=report,
            mount_path=mount_path,
            collect_dir=collect_dir,
            max_copy_bytes=max_copy_bytes,
        )

    report["meta"]["duration_seconds"] = round(time.time() - started, 3)

    # Add optional sample hashes for top files to support quick triage.
    largest = report["artifacts"].get("filesystem_inventory", {}).get("largest_files", [])
    hash_samples = []
    for item in largest[:20]:
        rel = item.get("path")
        if not rel:
            continue
        abs_path = mount_path / rel
        hash_samples.append(
            {
                "path": rel,
                "sha256_first_bytes": file_sha256(abs_path),
            }
        )
    report["artifacts"]["largest_file_hash_samples"] = hash_samples

    return report


def print_console_summary(report: Dict[str, object]) -> None:
    print("=" * 72)
    print("Tails Volume Deep Scan")
    print("=" * 72)

    summary = report.get("summary", {})
    if summary.get("status") != "ok":
        print(f"Status: {summary.get('status')}")
        print(f"Error: {summary.get('message')}")
        return

    mount = report.get("mount", {})
    risk = summary.get("risk", {})
    fs = report.get("artifacts", {}).get("filesystem_inventory", {})
    counts = fs.get("counts", {})
    text_scan = report.get("artifacts", {}).get("text_scan", {})
    key_wallet_browser = report.get("artifacts", {}).get("key_wallet_browser", {})
    persistence = report.get("artifacts", {}).get("persistence", {})
    collection = report.get("artifacts", {}).get("evidence_collection", {})

    print(f"Mount Path: {report.get('input', {}).get('mount_path')}")
    print(f"Device/FSType: {mount.get('device')} / {mount.get('fstype')}")
    print(f"Files Scanned: {counts.get('files')} (dirs: {counts.get('dirs')}, symlinks: {counts.get('symlinks')})")
    if counts.get("truncated"):
        print("Scan Notice: file traversal reached safety limit and was truncated.")

    print("-" * 72)
    print(f"Risk Score: {risk.get('score')}/{risk.get('max')} ({risk.get('risk_level')})")
    for reason in risk.get("reasons", []):
        print(f"  - {reason}")

    print("-" * 72)
    print(f"Persistence.conf found: {persistence.get('found')} | modules: {len(persistence.get('modules', []))}")
    print(f"Onion addresses: {len(text_scan.get('onion_addresses', []))}")
    print(f"Bridge lines: {len(text_scan.get('bridge_related_lines', []))}")
    print(f"Hidden service lines: {len(text_scan.get('hidden_service_lines', []))}")
    print(f"Suspicious command lines: {len(text_scan.get('suspicious_lines', []))}")
    print(f"Wallet-like files: {len(key_wallet_browser.get('wallet_files', []))}")
    print(f"Identity/key files: {len(key_wallet_browser.get('key_files', []))}")
    print(f"Browser artifacts: {len(key_wallet_browser.get('browser_files', []))}")

    if isinstance(collection, dict) and collection.get("enabled"):
        print("-" * 72)
        print("Evidence collection:")
        print(f"  - Copied files: {collection.get('copied_count')}")
        print(f"  - Skipped files: {collection.get('skipped_count')}")
        print(f"  - Copied bytes: {collection.get('copied_bytes')}")
        print(f"  - Collection dir: {collection.get('collect_dir')}")
        print(f"  - Manifest: {collection.get('manifest_path')}")

    print("-" * 72)
    print("Top 10 largest files:")
    for item in fs.get("largest_files", [])[:10]:
        size_mb = (item.get("size", 0) or 0) / (1024 * 1024)
        print(f"  - {size_mb:9.2f} MB  {item.get('path')}")


def _print_list(title: str, values: List[str], limit: int) -> None:
    print("-" * 72)
    print(f"{title}: {len(values)}")
    if not values:
        print("  (none)")
        return
    shown = values[:limit]
    for v in shown:
        print(f"  - {v}")
    if len(values) > limit:
        print(f"  ... truncated {len(values) - limit} entries (increase --detail-limit)")


def _print_dict_line_list(title: str, values: List[Dict[str, str]], limit: int) -> None:
    print("-" * 72)
    print(f"{title}: {len(values)}")
    if not values:
        print("  (none)")
        return
    shown = values[:limit]
    for item in shown:
        path = str(item.get("path", ""))
        line = str(item.get("line", ""))
        print(f"  - {path}: {line}")
    if len(values) > limit:
        print(f"  ... truncated {len(values) - limit} entries (increase --detail-limit)")


def _print_entry_paths(title: str, entries: List[Dict[str, object]], limit: int) -> None:
    print("-" * 72)
    print(f"{title}: {len(entries)}")
    if not entries:
        print("  (none)")
        return
    shown = entries[:limit]
    for item in shown:
        p = str(item.get("path", ""))
        size = item.get("size")
        if isinstance(size, int):
            print(f"  - {p} (size={size})")
        else:
            print(f"  - {p}")
    if len(entries) > limit:
        print(f"  ... truncated {len(entries) - limit} entries (increase --detail-limit)")


def print_console_details(report: Dict[str, object], detail_limit: int) -> None:
    artifacts = report.get("artifacts", {}) if isinstance(report.get("artifacts"), dict) else {}
    text_scan = artifacts.get("text_scan", {}) if isinstance(artifacts.get("text_scan"), dict) else {}
    persistence = artifacts.get("persistence", {}) if isinstance(artifacts.get("persistence"), dict) else {}
    key_wallet_browser = artifacts.get("key_wallet_browser", {}) if isinstance(artifacts.get("key_wallet_browser"), dict) else {}
    collection = artifacts.get("evidence_collection", {}) if isinstance(artifacts.get("evidence_collection"), dict) else {}

    modules = persistence.get("modules", []) if isinstance(persistence.get("modules"), list) else []
    print("-" * 72)
    print(f"Persistence modules: {len(modules)}")
    if modules:
        for m in modules[:detail_limit]:
            src = str(m.get("source", ""))
            dst = str(m.get("destination", ""))
            print(f"  - source={src} destination={dst}")
        if len(modules) > detail_limit:
            print(f"  ... truncated {len(modules) - detail_limit} entries (increase --detail-limit)")
    else:
        print("  (none)")

    _print_list("Onion addresses", list(text_scan.get("onion_addresses", [])), detail_limit)
    _print_list("BTC-like strings", list(text_scan.get("btc_like_strings", [])), detail_limit)
    _print_list("ETH-like strings", list(text_scan.get("eth_like_strings", [])), detail_limit)
    _print_list("XMR-like strings", list(text_scan.get("xmr_like_strings", [])), detail_limit)
    _print_list("IP addresses", list(text_scan.get("ip_addresses", [])), detail_limit)
    _print_dict_line_list("Bridge related lines", list(text_scan.get("bridge_related_lines", [])), detail_limit)
    _print_dict_line_list("Hidden service lines", list(text_scan.get("hidden_service_lines", [])), detail_limit)
    _print_dict_line_list("Suspicious command lines", list(text_scan.get("suspicious_lines", [])), detail_limit)

    _print_entry_paths("Identity/key files", list(key_wallet_browser.get("key_files", [])), detail_limit)
    _print_entry_paths("Wallet files", list(key_wallet_browser.get("wallet_files", [])), detail_limit)
    _print_entry_paths("Browser artifact files", list(key_wallet_browser.get("browser_files", [])), detail_limit)

    if collection.get("manifest_path"):
        print("-" * 72)
        print(f"Collection manifest: {collection.get('manifest_path')}")


def parse_args(argv: Optional[Iterable[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Deep standalone forensic scan for a mounted Tails volume")
    parser.add_argument(
        "--mount",
        default="/home/aparichit/TailsData",
        help="Path to mounted Tails volume (default: /home/aparichit/TailsData)",
    )
    parser.add_argument(
        "--output",
        default=None,
        help="Output JSON file path (default: tails_deep_report_<timestamp>.json in current dir)",
    )
    parser.add_argument(
        "--pretty",
        action="store_true",
        help="Pretty-print JSON output",
    )
    parser.add_argument(
        "--collect-dir",
        default=None,
        help="Directory to copy discovered artifact files into (default: <output_parent>/tails_collected_<timestamp>)",
    )
    parser.add_argument(
        "--max-copy-bytes",
        type=int,
        default=DEFAULT_MAX_COPY_BYTES,
        help=f"Maximum file size to copy during evidence collection (default: {DEFAULT_MAX_COPY_BYTES})",
    )
    parser.add_argument(
        "--no-collect",
        action="store_true",
        help="Disable copying discovered files (scan/report only)",
    )
    parser.add_argument(
        "--summary-only",
        action="store_true",
        help="Show only high-level summary in terminal output",
    )
    parser.add_argument(
        "--detail-limit",
        type=int,
        default=500,
        help="Maximum entries to print per detailed section (default: 500)",
    )
    return parser.parse_args(argv)


def main(argv: Optional[Iterable[str]] = None) -> int:
    args = parse_args(argv)
    mount_path = Path(args.mount).expanduser().resolve()

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%SZ")
    out_path = Path(args.output) if args.output else Path.cwd() / f"tails_deep_report_{ts}.json"
    collect_dir: Optional[Path]
    if args.no_collect:
        collect_dir = None
    else:
        collect_dir = Path(args.collect_dir) if args.collect_dir else out_path.parent / f"tails_collected_{ts}"

    report = build_report(mount_path, collect_dir=collect_dir, max_copy_bytes=args.max_copy_bytes)

    try:
        with out_path.open("w", encoding="utf-8") as f:
            if args.pretty:
                json.dump(report, f, indent=2, ensure_ascii=True)
            else:
                json.dump(report, f, separators=(",", ":"), ensure_ascii=True)
        print_console_summary(report)
        if not args.summary_only:
            print_console_details(report, detail_limit=max(1, int(args.detail_limit)))
        print("-" * 72)
        print(f"JSON report written to: {out_path}")
        return 0 if report.get("summary", {}).get("status") == "ok" else 2
    except Exception as e:
        print_console_summary(report)
        print(f"Failed to write output file: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
