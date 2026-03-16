"""Browser Forensics Analysis.

Detects installed browsers and extracts forensic artefacts from each user
profile found on the filesystem image:

  - Visited history (URL, title, visit count, last visit time)
  - Downloads (URL, target path, MIME type, danger type, timestamps)
  - Bookmarks (title, URL, folder, date added)
  - Cookies (host, name, flags, expiry — highlighting sensitive/long-lived ones)
  - Extensions / Add-ons (name, version, permissions — flagging suspicious ones)
  - Saved logins / passwords (origin URL + username, always flagged high)
  - Search terms (extracted from history and keyword_search_terms tables)
  - Autofill / form data (field names + values)

Supported browsers
------------------
  Chromium-family : Google Chrome, Chromium, Brave, Microsoft Edge,
                    Opera, Vivaldi, Yandex Browser, Samsung Internet
  Gecko-family    : Firefox, Waterfox, LibreWolf, GNU IceCat, Tor Browser

Detection strategy
------------------
  1. Enumerate user home directories (``/home/*`` + ``/root``)
  2. For each user, probe known browser base-dirs
  3. Within each base-dir enumerate profiles (Default / Profile N / *.default*)
  4. Read SQLite artefact files via a temp-file approach (works with pytsk3 images
     as well as mounted local directories)
  5. Read JSON artefact files (Bookmarks, extensions.json, logins.json …)
"""
from __future__ import annotations

import json
import os
import re
import sqlite3
import tempfile
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from .extractor import FilesystemAccessor


# ─── Timestamp helpers ─────────────────────────────────────────────────────────

_CHROME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)


def _chrome_ts(microseconds: int) -> str:
    """Convert Chrome/WebKit timestamp (µs since 1601-01-01) → ISO string."""
    try:
        if not microseconds:
            return ""
        dt = _CHROME_EPOCH + timedelta(microseconds=int(microseconds))
        return dt.isoformat(timespec="seconds")
    except Exception:
        return ""


def _ff_ts(microseconds: int) -> str:
    """Convert Firefox timestamp (µs since Unix epoch) → ISO string."""
    try:
        if not microseconds:
            return ""
        dt = datetime.fromtimestamp(int(microseconds) / 1_000_000, tz=timezone.utc)
        return dt.isoformat(timespec="seconds")
    except Exception:
        return ""


def _epoch_ts(seconds: int) -> str:
    """Convert Unix epoch seconds → ISO string."""
    try:
        if not seconds:
            return ""
        dt = datetime.fromtimestamp(int(seconds), tz=timezone.utc)
        return dt.isoformat(timespec="seconds")
    except Exception:
        return ""


# ─── SQLite helper ─────────────────────────────────────────────────────────────

def _query_sqlite(
    raw_bytes: bytes,
    query: str,
    params: tuple = (),
    row_limit: int = 1000,
) -> List[Dict[str, Any]]:
    """Write ``raw_bytes`` to a temp file, run ``query``, return rows as dicts."""
    fd, tmp = tempfile.mkstemp(suffix=".sqlite3")
    try:
        os.write(fd, raw_bytes)
        os.close(fd)
        conn = sqlite3.connect(tmp)
        conn.row_factory = sqlite3.Row
        try:
            cur = conn.execute(query, params)
            rows = cur.fetchmany(row_limit)
            return [dict(r) for r in rows]
        except sqlite3.Error:
            return []
        finally:
            conn.close()
    except Exception:
        return []
    finally:
        try:
            os.unlink(tmp)
        except Exception:
            pass


def _read_bytes(fs: FilesystemAccessor, path: str, max_mb: int = 64) -> Optional[bytes]:
    return fs.read_file(path, max_bytes=max_mb * 1_048_576)


def _read_json(fs: FilesystemAccessor, path: str) -> Any:
    raw = fs.read_file(path, max_bytes=4 * 1_048_576)
    if raw is None:
        return None
    try:
        return json.loads(raw.decode("utf-8", errors="replace"))
    except Exception:
        return None


# ─── Severity / flag constants ─────────────────────────────────────────────────

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 4) <= _SEV_ORDER.get(b, 4) else b


# Extensions permissions that indicate elevated risk
_DANGEROUS_PERMS = {
    "<all_urls>": "high", "*://*/*": "high", "http://*/*": "medium", "https://*/*": "medium",
    "webRequest": "medium", "webRequestBlocking": "high",
    "cookies": "medium", "tabs": "low", "history": "medium",
    "downloads": "low", "proxy": "high", "privacy": "high",
    "nativeMessaging": "high", "debugger": "high",
    "management": "high", "contentSettings": "medium",
    "clipboardRead": "medium", "clipboardWrite": "low",
    "geolocation": "medium",
}

# Download file extensions that are executable / potentially dangerous
_EXEC_EXTS = {
    ".exe", ".msi", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf",
    ".jar", ".py", ".rb", ".sh", ".bash", ".zsh", ".apk", ".deb",
    ".rpm", ".dmg", ".pkg", ".elf", ".bin", ".run", ".com",
}

# Suspicious URL / domain patterns in history
_SUSPICIOUS_HISTORY = re.compile(
    r"(\.onion|pastebin\.com|paste\.ee|hastebin|raw\.githubusercontent\."
    r"com|transfer\.sh|file\.io|anonfiles|gofile\.io|ngrok\.io|serveo\.net"
    r"|burpcollaborator|requestbin|webhook\.site|canarytokens)",
    re.IGNORECASE,
)

# Search terms that may indicate malicious activity (broad — for flagging only)
_SUSPICIOUS_SEARCH = re.compile(
    r"\b(metasploit|msfconsole|msfvenom|cobalt.?strike|mimikatz|bloodhound"
    r"|sharphound|powersploit|empire|crackmapexec|impacket|responder|hashcat"
    r"|hydra|john.?the.?ripper|sqlmap|nikto|nessus|openvas|burp.?suite"
    r"|kali.?linux|parrot.?os|exploit|payload|reverse.?shell|bind.?shell"
    r"|privilege.?escal|lateral.?movement|credential.?dump|pass.?the.?hash"
    r"|golden.?ticket|silver.?ticket|kerberoast|dcom|wmi.?exec|psexec)\b",
    re.IGNORECASE,
)


# ─── Browser definitions ───────────────────────────────────────────────────────

# Each entry: (browser_id, browser_label, engine, relative_base_path_in_home)
_BROWSER_DEFS: List[Tuple[str, str, str, str]] = [
    ("chrome",         "Google Chrome",      "chromium", ".config/google-chrome"),
    ("chromium",       "Chromium",            "chromium", ".config/chromium"),
    ("brave",          "Brave Browser",       "chromium", ".config/BraveSoftware/Brave-Browser"),
    ("edge",           "Microsoft Edge",      "chromium", ".config/microsoft-edge"),
    ("opera",          "Opera",               "chromium", ".config/opera"),
    ("vivaldi",        "Vivaldi",             "chromium", ".config/vivaldi"),
    ("yandex",         "Yandex Browser",      "chromium", ".config/yandex-browser-stable"),
    ("firefox",        "Firefox",             "gecko",    ".mozilla/firefox"),
    ("waterfox",       "Waterfox",            "gecko",    ".waterfox"),
    ("librewolf",      "LibreWolf",           "gecko",    ".librewolf"),
    ("icecat",         "GNU IceCat",          "gecko",    ".icecat"),
    ("tor",            "Tor Browser",         "gecko",    ".tor-browser/app/Browser/TorBrowser/Data/Browser"),
]

# Additional absolute paths checked regardless of user (system-wide installs)
_SYSTEM_BROWSER_PATHS: List[Tuple[str, str, str, str]] = [
    ("chrome", "Google Chrome", "chromium", "/root/.config/google-chrome"),
    ("firefox", "Firefox",      "gecko",    "/root/.mozilla/firefox"),
]


# ─── User discovery ────────────────────────────────────────────────────────────

def _get_users(fs: FilesystemAccessor) -> List[Tuple[str, str]]:
    """Return list of (username, home_dir) pairs."""
    users: List[Tuple[str, str]] = []
    # Parse /etc/passwd for home dirs
    passwd_raw = fs.read_file("/etc/passwd", max_bytes=256_000)
    if passwd_raw:
        for line in passwd_raw.decode("utf-8", errors="replace").splitlines():
            parts = line.split(":")
            if len(parts) < 7:
                continue
            username, _, uid, _, _, home, shell = parts[:7]
            try:
                uid_n = int(uid)
            except ValueError:
                continue
            # Only real users (uid ≥ 1000 or root) with real shells
            if (uid_n == 0 or uid_n >= 1000) and shell.strip() not in ("", "/usr/sbin/nologin", "/sbin/nologin", "/bin/false"):
                if home and home.startswith("/"):
                    users.append((username, home))
    if not users:
        # Fallback: list /home dirs + /root
        for name in fs.list_dir("/home"):
            users.append((name, f"/home/{name}"))
        if fs.exists("/root"):
            users.append(("root", "/root"))
    return users


# ─── Chromium-family artefact extractors ──────────────────────────────────────

def _chrome_history(fs: FilesystemAccessor, profile_path: str) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    """Returns (history_entries, download_entries, search_terms)."""
    history: List[Dict] = []
    downloads: List[Dict] = []
    searches: List[Dict] = []

    raw = _read_bytes(fs, f"{profile_path}/History")
    if raw is None:
        return history, downloads, searches

    # ── URLs / History ──
    rows = _query_sqlite(
        raw,
        "SELECT url, title, visit_count, last_visit_time FROM urls ORDER BY last_visit_time DESC LIMIT 500",
    )
    for r in rows:
        url = r.get("url", "") or ""
        flags: List[str] = []
        sev = "info"
        if _SUSPICIOUS_HISTORY.search(url):
            flags.append("suspicious-url")
            sev = "medium"
        history.append({
            "url": url,
            "title": r.get("title", "") or "",
            "visit_count": r.get("visit_count", 0),
            "last_visit": _chrome_ts(r.get("last_visit_time", 0)),
            "severity": sev,
            "flags": flags,
        })

    # ── Downloads ──
    dl_rows = _query_sqlite(
        raw,
        "SELECT tab_url, target_path, start_time, end_time, mime_type, danger_type, state, total_bytes "
        "FROM downloads ORDER BY start_time DESC LIMIT 200",
    )
    for r in dl_rows:
        target = r.get("target_path", "") or ""
        ext = os.path.splitext(target)[1].lower()
        flags = []
        sev = "info"
        if ext in _EXEC_EXTS:
            flags.append("executable")
            sev = "medium"
        danger = r.get("danger_type", 0)
        if danger and danger > 0:
            flags.append(f"danger-type-{danger}")
            sev = _max_sev(sev, "high")
        downloads.append({
            "url": r.get("tab_url", "") or "",
            "target_path": target,
            "start_time": _chrome_ts(r.get("start_time", 0)),
            "end_time": _chrome_ts(r.get("end_time", 0)),
            "mime_type": r.get("mime_type", "") or "",
            "state": r.get("state", ""),
            "total_bytes": r.get("total_bytes", 0),
            "severity": sev,
            "flags": flags,
        })

    # ── Search terms ──
    kw_rows = _query_sqlite(
        raw,
        "SELECT lower_term FROM keyword_search_terms ORDER BY url_id DESC LIMIT 200",
    )
    for r in kw_rows:
        term = r.get("lower_term", "") or ""
        sev = "high" if _SUSPICIOUS_SEARCH.search(term) else "info"
        searches.append({
            "term": term,
            "engine": "search engine",
            "timestamp": "",
            "severity": sev,
            "flags": ["suspicious-search"] if sev == "high" else [],
        })

    return history, downloads, searches


def _chrome_bookmarks(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    data = _read_json(fs, f"{profile_path}/Bookmarks")
    if not data:
        return []
    bookmarks: List[Dict] = []

    def _walk(node, folder=""):
        t = node.get("type", "")
        name = node.get("name", "")
        if t == "url":
            url = node.get("url", "")
            date_added = node.get("date_added", "")
            # date_added is Chrome timestamp
            try:
                ts = _chrome_ts(int(date_added)) if date_added else ""
            except Exception:
                ts = ""
            bookmarks.append({
                "title": name,
                "url": url,
                "folder": folder,
                "date_added": ts,
                "severity": "info",
                "flags": [],
            })
        elif t == "folder":
            for child in node.get("children", []):
                _walk(child, folder=name if not folder else f"{folder}/{name}")

    roots = data.get("roots", {})
    for root_name, root_node in roots.items():
        _walk(root_node, folder=root_name)

    return bookmarks[:500]


def _chrome_cookies(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    raw = _read_bytes(fs, f"{profile_path}/Cookies")
    if raw is None:
        return []
    rows = _query_sqlite(
        raw,
        "SELECT host_key, name, path, is_secure, is_httponly, expires_utc, has_expires "
        "FROM cookies ORDER BY expires_utc DESC LIMIT 300",
    )
    result: List[Dict] = []
    for r in rows:
        host = r.get("host_key", "") or ""
        sev = "info"
        flags: List[str] = []
        if not r.get("is_secure", 1):
            flags.append("not-secure")
            sev = "low"
        if not r.get("is_httponly", 1):
            flags.append("not-httponly")
            sev = _max_sev(sev, "low")
        expires = r.get("expires_utc", 0)
        if expires:
            ts = _chrome_ts(expires)
        else:
            ts = ""
        result.append({
            "host": host,
            "name": r.get("name", "") or "",
            "path": r.get("path", "") or "",
            "is_secure": bool(r.get("is_secure", 0)),
            "is_httponly": bool(r.get("is_httponly", 0)),
            "expires": ts,
            "severity": sev,
            "flags": flags,
        })
    return result


def _chrome_logins(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    raw = _read_bytes(fs, f"{profile_path}/Login Data")
    if raw is None:
        return []
    rows = _query_sqlite(
        raw,
        "SELECT origin_url, username_value, date_created, times_used "
        "FROM logins ORDER BY date_created DESC LIMIT 200",
    )
    result: List[Dict] = []
    for r in rows:
        result.append({
            "origin": r.get("origin_url", "") or "",
            "username": r.get("username_value", "") or "",
            "date_created": _chrome_ts(r.get("date_created", 0)),
            "times_used": r.get("times_used", 0),
            "severity": "high",
            "flags": ["saved-credentials"],
        })
    return result


def _chrome_extensions(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    ext_dir = f"{profile_path}/Extensions"
    result: List[Dict] = []
    seen: set = set()

    for ext_id in fs.list_dir(ext_dir):
        if len(ext_id) != 32 or not ext_id.isalpha():
            continue
        ext_base = f"{ext_dir}/{ext_id}"
        # find the version subdir
        versions = fs.list_dir(ext_base)
        if not versions:
            continue
        ver_dir = f"{ext_base}/{sorted(versions)[-1]}"
        manifest = _read_json(fs, f"{ver_dir}/manifest.json")
        if not manifest:
            continue

        name = manifest.get("name", ext_id)
        version = manifest.get("version", "")
        desc = manifest.get("description", "")[:160]
        # collect all permissions
        perms = list(manifest.get("permissions", []))
        perms += list(manifest.get("host_permissions", []))
        perms += list((manifest.get("optional_permissions") or []))

        flags: List[str] = []
        sev = "info"
        for p in perms:
            p_sev = _DANGEROUS_PERMS.get(p, "info")
            if p_sev != "info":
                flags.append(f"perm:{p}")
                sev = _max_sev(sev, p_sev)

        # Translate Chrome Web Store message keys to something readable
        if name.startswith("__MSG_"):
            name = ext_id

        key = f"{ext_id}"
        if key in seen:
            continue
        seen.add(key)

        result.append({
            "id": ext_id,
            "name": name,
            "version": version,
            "description": desc,
            "permissions": perms[:20],
            "severity": sev,
            "flags": flags,
        })
    return result


def _chrome_autofill(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    raw = _read_bytes(fs, f"{profile_path}/Web Data")
    if raw is None:
        return []
    rows = _query_sqlite(
        raw,
        "SELECT name, value, count, date_last_used FROM autofill ORDER BY count DESC LIMIT 100",
    )
    return [
        {
            "field": r.get("name", "") or "",
            "value": r.get("value", "") or "",
            "count": r.get("count", 0),
            "last_used": _epoch_ts(r.get("date_last_used", 0)),
            "severity": "info",
            "flags": [],
        }
        for r in rows
        if r.get("value", "")
    ]


def _extract_chrome_profile(
    fs: FilesystemAccessor,
    browser_id: str,
    browser_label: str,
    user: str,
    profile_name: str,
    profile_path: str,
) -> Dict:
    history, downloads, searches = _chrome_history(fs, profile_path)
    bookmarks = _chrome_bookmarks(fs, profile_path)
    cookies = _chrome_cookies(fs, profile_path)
    logins = _chrome_logins(fs, profile_path)
    extensions = _chrome_extensions(fs, profile_path)
    autofill = _chrome_autofill(fs, profile_path)

    flags: List[str] = []
    sev = "info"

    if logins:
        flags.append("saved-passwords")
        sev = _max_sev(sev, "high")
    if any(d["flags"] for d in downloads):
        flags.append("suspicious-downloads")
        sev = _max_sev(sev, "medium")
    if any(h.get("severity") == "medium" for h in history):
        flags.append("suspicious-history")
        sev = _max_sev(sev, "medium")
    if any(e.get("severity") in ("high", "critical") for e in extensions):
        flags.append("suspicious-extensions")
        sev = _max_sev(sev, "high")
    if any(s.get("severity") == "high" for s in searches):
        flags.append("suspicious-searches")
        sev = _max_sev(sev, "high")
    # Wiped history indicator
    if fs.exists(f"{profile_path}/History") and not history:
        flags.append("wiped-history")
        sev = _max_sev(sev, "medium")

    return {
        "browser": browser_id,
        "browser_label": browser_label,
        "user": user,
        "profile": profile_name,
        "profile_path": profile_path,
        "severity": sev,
        "flags": flags,
        "history": history,
        "downloads": downloads,
        "bookmarks": bookmarks,
        "cookies": cookies,
        "extensions": extensions,
        "logins": logins,
        "search_terms": searches,
        "autofill": autofill,
    }


# ─── Firefox / Gecko-family artefact extractors ────────────────────────────────

def _ff_history_and_bookmarks(
    fs: FilesystemAccessor, profile_path: str
) -> Tuple[List[Dict], List[Dict], List[Dict]]:
    raw = _read_bytes(fs, f"{profile_path}/places.sqlite")
    if raw is None:
        return [], [], []

    history: List[Dict] = []
    bookmarks: List[Dict] = []
    searches: List[Dict] = []

    # History
    hist_rows = _query_sqlite(
        raw,
        "SELECT url, title, visit_count, last_visit_date FROM moz_places "
        "WHERE visit_count > 0 ORDER BY last_visit_date DESC LIMIT 500",
    )
    for r in hist_rows:
        url = r.get("url", "") or ""
        flags = []
        sev = "info"
        if _SUSPICIOUS_HISTORY.search(url):
            flags.append("suspicious-url")
            sev = "medium"
        history.append({
            "url": url,
            "title": r.get("title", "") or "",
            "visit_count": r.get("visit_count", 0),
            "last_visit": _ff_ts(r.get("last_visit_date", 0)),
            "severity": sev,
            "flags": flags,
        })

    # Bookmarks (moz_bookmarks JOIN moz_places)
    bm_rows = _query_sqlite(
        raw,
        "SELECT b.title, p.url, b.dateAdded, b.fk FROM moz_bookmarks b "
        "JOIN moz_places p ON p.id = b.fk WHERE b.type = 1 LIMIT 500",
    )
    for r in bm_rows:
        bookmarks.append({
            "title": r.get("title", "") or "",
            "url": r.get("url", "") or "",
            "folder": "",
            "date_added": _ff_ts(r.get("dateAdded", 0)),
            "severity": "info",
            "flags": [],
        })

    # Search history (moz_inputhistory or keyword search terms)
    search_rows = _query_sqlite(
        raw,
        "SELECT input, use_count FROM moz_inputhistory ORDER BY use_count DESC LIMIT 200",
    )
    for r in search_rows:
        term = r.get("input", "") or ""
        sev = "high" if _SUSPICIOUS_SEARCH.search(term) else "info"
        searches.append({
            "term": term,
            "engine": "address-bar",
            "timestamp": "",
            "severity": sev,
            "flags": ["suspicious-search"] if sev == "high" else [],
        })

    return history, bookmarks, searches


def _ff_downloads(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    # Modern Firefox stores downloads in places.sqlite under moz_annos
    raw = _read_bytes(fs, f"{profile_path}/places.sqlite")
    if raw is None:
        return []
    rows = _query_sqlite(
        raw,
        "SELECT p.url, a.content, a.dateAdded FROM moz_annos a "
        "JOIN moz_places p ON p.id = a.place_id "
        "WHERE a.anno_attribute_id IN (SELECT id FROM moz_anno_attributes WHERE name='downloads/destinationFileURI') "
        "ORDER BY a.dateAdded DESC LIMIT 200",
    )
    result: List[Dict] = []
    for r in rows:
        target = r.get("content", "") or ""
        if target.startswith("file://"):
            target = target[7:]
        ext = os.path.splitext(target)[1].lower()
        sev = "medium" if ext in _EXEC_EXTS else "info"
        flags = ["executable"] if ext in _EXEC_EXTS else []
        result.append({
            "url": r.get("url", "") or "",
            "target_path": target,
            "start_time": _ff_ts(r.get("dateAdded", 0)),
            "end_time": "",
            "mime_type": "",
            "state": "complete",
            "total_bytes": 0,
            "severity": sev,
            "flags": flags,
        })
    return result


def _ff_cookies(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    raw = _read_bytes(fs, f"{profile_path}/cookies.sqlite")
    if raw is None:
        return []
    rows = _query_sqlite(
        raw,
        "SELECT host, name, path, isSecure, isHttpOnly, expiry FROM moz_cookies "
        "ORDER BY expiry DESC LIMIT 300",
    )
    result: List[Dict] = []
    for r in rows:
        flags = []
        sev = "info"
        if not r.get("isSecure", 1):
            flags.append("not-secure")
            sev = "low"
        if not r.get("isHttpOnly", 1):
            flags.append("not-httponly")
            sev = _max_sev(sev, "low")
        result.append({
            "host": r.get("host", "") or "",
            "name": r.get("name", "") or "",
            "path": r.get("path", "") or "",
            "is_secure": bool(r.get("isSecure", 0)),
            "is_httponly": bool(r.get("isHttpOnly", 0)),
            "expires": _epoch_ts(r.get("expiry", 0)),
            "severity": sev,
            "flags": flags,
        })
    return result


def _ff_logins(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    data = _read_json(fs, f"{profile_path}/logins.json")
    if not data:
        return []
    result: List[Dict] = []
    for entry in data.get("logins", [])[:200]:
        result.append({
            "origin": entry.get("hostname", "") or entry.get("formSubmitURL", "") or "",
            "username": entry.get("encryptedUsername", "<encrypted>"),
            "date_created": _epoch_ts((entry.get("timeCreated", 0) or 0) // 1000),
            "times_used": entry.get("timesUsed", 0),
            "severity": "high",
            "flags": ["saved-credentials", "encrypted"],
        })
    return result


def _ff_extensions(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    data = _read_json(fs, f"{profile_path}/extensions.json")
    if not data:
        return []
    result: List[Dict] = []
    for addon in data.get("addons", [])[:100]:
        if addon.get("type") not in ("extension", None):
            continue
        # Permissions are stored differently for WebExtensions
        perms = []
        for perm_block in (addon.get("userPermissions") or {}, addon.get("optionalPermissions") or {}):
            if isinstance(perm_block, dict):
                perms += perm_block.get("permissions", [])
                perms += perm_block.get("origins", [])

        flags = []
        sev = "info"
        for p in perms:
            p_sev = _DANGEROUS_PERMS.get(p, "info")
            if p_sev != "info":
                flags.append(f"perm:{p}")
                sev = _max_sev(sev, p_sev)

        if addon.get("signedState", 2) < 0:
            flags.append("unsigned")
            sev = _max_sev(sev, "medium")

        result.append({
            "id": addon.get("id", ""),
            "name": addon.get("name", addon.get("id", "")),
            "version": addon.get("version", ""),
            "description": (addon.get("description") or "")[:160],
            "permissions": perms[:20],
            "severity": sev,
            "flags": flags,
        })
    return result


def _ff_autofill(fs: FilesystemAccessor, profile_path: str) -> List[Dict]:
    raw = _read_bytes(fs, f"{profile_path}/formhistory.sqlite")
    if raw is None:
        return []
    rows = _query_sqlite(
        raw,
        "SELECT fieldname, value, timesUsed FROM moz_formhistory "
        "ORDER BY timesUsed DESC LIMIT 100",
    )
    return [
        {
            "field": r.get("fieldname", "") or "",
            "value": r.get("value", "") or "",
            "count": r.get("timesUsed", 0),
            "last_used": "",
            "severity": "info",
            "flags": [],
        }
        for r in rows
        if r.get("value", "")
    ]


def _extract_firefox_profile(
    fs: FilesystemAccessor,
    browser_id: str,
    browser_label: str,
    user: str,
    profile_name: str,
    profile_path: str,
) -> Dict:
    history, bookmarks, searches = _ff_history_and_bookmarks(fs, profile_path)
    downloads = _ff_downloads(fs, profile_path)
    cookies = _ff_cookies(fs, profile_path)
    logins = _ff_logins(fs, profile_path)
    extensions = _ff_extensions(fs, profile_path)
    autofill = _ff_autofill(fs, profile_path)

    flags: List[str] = []
    sev = "info"

    if logins:
        flags.append("saved-passwords")
        sev = _max_sev(sev, "high")
    if any(d["flags"] for d in downloads):
        flags.append("suspicious-downloads")
        sev = _max_sev(sev, "medium")
    if any(h.get("severity") == "medium" for h in history):
        flags.append("suspicious-history")
        sev = _max_sev(sev, "medium")
    if any(e.get("severity") in ("high", "critical") for e in extensions):
        flags.append("suspicious-extensions")
        sev = _max_sev(sev, "high")
    if any(s.get("severity") == "high" for s in searches):
        flags.append("suspicious-searches")
        sev = _max_sev(sev, "high")
    if fs.exists(f"{profile_path}/places.sqlite") and not history:
        flags.append("wiped-history")
        sev = _max_sev(sev, "medium")
    # key4.db presence = master password / saved credentials store
    if fs.exists(f"{profile_path}/key4.db"):
        if not any(f == "saved-passwords" for f in flags):
            flags.append("credential-store")
            sev = _max_sev(sev, "medium")

    return {
        "browser": browser_id,
        "browser_label": browser_label,
        "user": user,
        "profile": profile_name,
        "profile_path": profile_path,
        "severity": sev,
        "flags": flags,
        "history": history,
        "downloads": downloads,
        "bookmarks": bookmarks,
        "cookies": cookies,
        "extensions": extensions,
        "logins": logins,
        "search_terms": searches,
        "autofill": autofill,
    }


# ─── Profile discovery ─────────────────────────────────────────────────────────

def _chrome_profiles(fs: FilesystemAccessor, base_path: str) -> List[str]:
    """Return list of profile sub-directory names for a Chromium browser."""
    profiles: List[str] = []
    for name in fs.list_dir(base_path):
        if name in ("Default", "Guest Profile", "System Profile") or re.match(r"Profile \d+", name):
            if fs.exists(f"{base_path}/{name}/History") or fs.exists(f"{base_path}/{name}/Bookmarks"):
                profiles.append(name)
    return profiles or ["Default"]


def _firefox_profiles(fs: FilesystemAccessor, base_path: str) -> List[str]:
    """Return list of profile directory names for a Gecko browser."""
    profiles: List[str] = []
    # Try profiles.ini first
    ini_raw = fs.read_file(f"{base_path}/profiles.ini", max_bytes=32_000)
    if ini_raw:
        for line in ini_raw.decode("utf-8", errors="replace").splitlines():
            m = re.match(r"Path\s*=\s*(.*)", line, re.IGNORECASE)
            if m:
                rel = m.group(1).strip()
                # relative path within base_path
                if not rel.startswith("/"):
                    actual = f"{base_path}/{rel}"
                else:
                    actual = rel
                dirname = rel.split("/")[-1] if "/" in rel else rel
                if fs.exists(f"{actual}/places.sqlite") or fs.exists(f"{actual}/cookies.sqlite"):
                    profiles.append(dirname if not rel.startswith("/") else actual)
    if profiles:
        return profiles
    # Fallback: scan for *.default* directories
    for name in fs.list_dir(base_path):
        if re.search(r"default", name, re.IGNORECASE) or re.search(r"\.[a-z0-9]{8}$", name):
            if fs.exists(f"{base_path}/{name}/places.sqlite"):
                profiles.append(name)
    return profiles


# ─── Main entry point ──────────────────────────────────────────────────────────

def detect_browsers(fs: FilesystemAccessor) -> List[Dict]:
    """Enumerate all browser profiles and extract forensic artefacts.

    Returns a list of profile dicts, one per discovered browser profile.
    """
    results: List[Dict] = []
    users = _get_users(fs)

    for username, home_dir in users:
        for b_id, b_label, engine, rel_path in _BROWSER_DEFS:
            base = f"{home_dir}/{rel_path}"
            if not fs.exists(base):
                continue

            if engine == "chromium":
                for profile_name in _chrome_profiles(fs, base):
                    profile_path = f"{base}/{profile_name}"
                    if not fs.exists(profile_path):
                        continue
                    try:
                        rec = _extract_chrome_profile(
                            fs, b_id, b_label, username, profile_name, profile_path
                        )
                        results.append(rec)
                    except Exception:
                        pass

            elif engine == "gecko":
                for profile_dir in _firefox_profiles(fs, base):
                    # profile_dir may be a full path (from profiles.ini with absolute) or relative name
                    if profile_dir.startswith("/"):
                        profile_path = profile_dir
                        profile_name = os.path.basename(profile_dir)
                    else:
                        profile_path = f"{base}/{profile_dir}"
                        profile_name = profile_dir
                    if not fs.exists(profile_path):
                        continue
                    try:
                        rec = _extract_firefox_profile(
                            fs, b_id, b_label, username, profile_name, profile_path
                        )
                        results.append(rec)
                    except Exception:
                        pass

    # Sort: most severe profiles first
    _sev_key = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    results.sort(key=lambda p: (_sev_key.get(p.get("severity", "info"), 4), p.get("browser", ""), p.get("user", "")))
    return results
