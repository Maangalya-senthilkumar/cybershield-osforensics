"""Filesystem Explorer — Autopsy-style artifact navigation.

Provides the backend for the interactive explorer sidebar:
  - browse(fs, path)   → list directory children with type / size / timestamps
  - stat_file(fs, path) → full inode metadata for a single path
  - read_text(fs, path) → first N bytes decoded as UTF-8 for the viewer pane
  - artifact_tree()    → fixed tree of forensically relevant artifact categories
"""
from __future__ import annotations

import os
import stat
import datetime
from typing import Dict, List, Optional

from .extractor import FilesystemAccessor


# ── Artifact category tree ────────────────────────────────────────────────────
# Each node: { id, label, icon, path|children }
# `path` nodes are browsable filesystem paths.
# `virtual` nodes are grouping nodes that expand into sub-categories.

ARTIFACT_TREE: List[Dict] = [
    {
        "id": "os",
        "label": "Operating System",
        "icon": "HardDrive",
        "children": [
            {"id": "os_release", "label": "OS Release",       "icon": "FileText", "path": "/etc/os-release"},
            {"id": "hostname",   "label": "Hostname",          "icon": "Server",   "path": "/etc/hostname"},
            {"id": "hosts",      "label": "Hosts File",        "icon": "Globe",    "path": "/etc/hosts"},
            {"id": "resolv",     "label": "DNS Config",        "icon": "Globe",    "path": "/etc/resolv.conf"},
            {"id": "fstab",      "label": "Mount Table",       "icon": "Database", "path": "/etc/fstab"},
            {"id": "timezone",   "label": "Timezone",          "icon": "Clock",    "path": "/etc/timezone"},
        ],
    },
    {
        "id": "users",
        "label": "Users & Accounts",
        "icon": "Users",
        "children": [
            {"id": "passwd",     "label": "passwd",            "icon": "FileText", "path": "/etc/passwd"},
            {"id": "group",      "label": "group",             "icon": "FileText", "path": "/etc/group"},
            {"id": "sudoers",    "label": "sudoers",           "icon": "Shield",   "path": "/etc/sudoers"},
            {"id": "shadow",     "label": "shadow",            "icon": "Lock",     "path": "/etc/shadow"},
            {"id": "lastlog",    "label": "lastlog (binary)",  "icon": "Activity", "path": "/var/log/lastlog"},
            {"id": "homes_dir",  "label": "/home Browse",      "icon": "Folder",   "path": "/home"},
        ],
    },
    {
        "id": "logs",
        "label": "System Logs",
        "icon": "List",
        "children": [
            {"id": "auth_log",   "label": "auth.log",          "icon": "Lock",     "path": "/var/log/auth.log"},
            {"id": "syslog",     "label": "syslog",            "icon": "Server",   "path": "/var/log/syslog"},
            {"id": "kern_log",   "label": "kern.log",          "icon": "Cpu",      "path": "/var/log/kern.log"},
            {"id": "dmesg_log",  "label": "dmesg",             "icon": "Cpu",      "path": "/var/log/dmesg"},
            {"id": "dpkg_log",   "label": "dpkg.log",          "icon": "Package",  "path": "/var/log/dpkg.log"},
            {"id": "apt_log",    "label": "apt/history.log",   "icon": "Package",  "path": "/var/log/apt/history.log"},
            {"id": "wtmp",       "label": "wtmp (binary)",     "icon": "Activity", "path": "/var/log/wtmp"},
            {"id": "btmp",       "label": "btmp (binary)",     "icon": "AlertTriangle", "path": "/var/log/btmp"},
            {"id": "faillog",    "label": "faillog (binary)",  "icon": "AlertTriangle", "path": "/var/log/faillog"},
            {"id": "secure_log", "label": "secure (RHEL)",     "icon": "Lock",     "path": "/var/log/secure"},
            {"id": "messages_log","label": "messages (RHEL)",  "icon": "Server",   "path": "/var/log/messages"},
            {"id": "journal_dir","label": "systemd journal",   "icon": "Folder",   "path": "/var/log/journal"},
            {"id": "log_dir",    "label": "/var/log Browse",   "icon": "Folder",   "path": "/var/log"},
        ],
    },
    {
        "id": "shell_history",
        "label": "Shell History",
        "icon": "Terminal",
        "children": [
            {"id": "root_hist",  "label": "root .bash_history","icon": "Terminal", "path": "/root/.bash_history"},
            {"id": "root_zsh",   "label": "root .zsh_history", "icon": "Terminal", "path": "/root/.zsh_history"},
            {"id": "root_fish",  "label": "root fish history", "icon": "Terminal", "path": "/root/.local/share/fish/fish_history"},
            {"id": "homes_hist", "label": "/home Browse",      "icon": "Folder",   "path": "/home"},
        ],
    },
    {
        "id": "network",
        "label": "Network Artifacts",
        "icon": "Wifi",
        "children": [
            {"id": "interfaces", "label": "interfaces",        "icon": "Wifi",     "path": "/etc/network/interfaces"},
            {"id": "NetworkManager_conf","label": "NetworkManager.conf","icon": "Wifi","path": "/etc/NetworkManager/NetworkManager.conf"},
            {"id": "ssh_config", "label": "sshd_config",       "icon": "Key",      "path": "/etc/ssh/sshd_config"},
            {"id": "ssh_known",  "label": "known_hosts (root)","icon": "Key",      "path": "/root/.ssh/known_hosts"},
            {"id": "ssh_auth",   "label": "authorized_keys (root)","icon": "Key",  "path": "/root/.ssh/authorized_keys"},
            {"id": "iptables_rules","label": "iptables rules", "icon": "Shield",   "path": "/etc/iptables/rules.v4"},
            {"id": "ufw_log",    "label": "ufw.log",           "icon": "Shield",   "path": "/var/log/ufw.log"},
            {"id": "hosts_deny", "label": "hosts.deny",        "icon": "Shield",   "path": "/etc/hosts.deny"},
            {"id": "hosts_allow","label": "hosts.allow",       "icon": "Shield",   "path": "/etc/hosts.allow"},
        ],
    },
    {
        "id": "persistence",
        "label": "Persistence Locations",
        "icon": "Shield",
        "children": [
            {"id": "crontab_root","label": "root crontab",     "icon": "Clock",    "path": "/var/spool/cron/crontabs/root"},
            {"id": "etc_crontab","label": "/etc/crontab",      "icon": "Clock",    "path": "/etc/crontab"},
            {"id": "cron_d",     "label": "/etc/cron.d",       "icon": "Folder",   "path": "/etc/cron.d"},
            {"id": "cron_daily", "label": "/etc/cron.daily",   "icon": "Folder",   "path": "/etc/cron.daily"},
            {"id": "cron_weekly","label": "/etc/cron.weekly",  "icon": "Folder",   "path": "/etc/cron.weekly"},
            {"id": "systemd_sys","label": "systemd system units","icon": "Server", "path": "/etc/systemd/system"},
            {"id": "rc_local",   "label": "rc.local",          "icon": "Terminal", "path": "/etc/rc.local"},
            {"id": "init_d",     "label": "/etc/init.d",       "icon": "Folder",   "path": "/etc/init.d"},
            {"id": "root_bashrc","label": "root .bashrc",      "icon": "Terminal", "path": "/root/.bashrc"},
            {"id": "root_profile","label": "root .profile",    "icon": "Terminal", "path": "/root/.profile"},
            {"id": "profile_d",  "label": "/etc/profile.d",    "icon": "Folder",   "path": "/etc/profile.d"},
        ],
    },
    {
        "id": "software",
        "label": "Installed Software",
        "icon": "Package",
        "children": [
            {"id": "dpkg_status","label": "dpkg status",       "icon": "Package",  "path": "/var/lib/dpkg/status"},
            {"id": "dpkg_info",  "label": "/var/lib/dpkg/info","icon": "Folder",   "path": "/var/lib/dpkg/info"},
            {"id": "rpm_db",     "label": "RPM DB",            "icon": "Package",  "path": "/var/lib/rpm"},
            {"id": "apt_sources","label": "apt sources.list",  "icon": "FileText", "path": "/etc/apt/sources.list"},
            {"id": "apt_sources_d","label": "apt sources.list.d","icon": "Folder", "path": "/etc/apt/sources.list.d"},
            {"id": "snap_dir",   "label": "snap packages",     "icon": "Package",  "path": "/snap"},
        ],
    },
    {
        "id": "processes",
        "label": "Running Processes",
        "icon": "Activity",
        "children": [
            {"id": "proc_dir",   "label": "/proc Browse",      "icon": "Folder",   "path": "/proc"},
            {"id": "proc_net",   "label": "net/tcp",           "icon": "Wifi",     "path": "/proc/net/tcp"},
            {"id": "proc_net6",  "label": "net/tcp6",          "icon": "Wifi",     "path": "/proc/net/tcp6"},
            {"id": "proc_netudp","label": "net/udp",           "icon": "Wifi",     "path": "/proc/net/udp"},
            {"id": "cmdline",    "label": "cmdline",           "icon": "Terminal", "path": "/proc/cmdline"},
            {"id": "cpuinfo",    "label": "cpuinfo",           "icon": "Cpu",      "path": "/proc/cpuinfo"},
            {"id": "meminfo",    "label": "meminfo",           "icon": "Database", "path": "/proc/meminfo"},
            {"id": "mounts",     "label": "mounts",            "icon": "Database", "path": "/proc/mounts"},
            {"id": "modules",    "label": "modules (lsmod)",   "icon": "Cpu",      "path": "/proc/modules"},
        ],
    },
    {
        "id": "filesystem",
        "label": "Filesystem",
        "icon": "Folder",
        "children": [
            {"id": "fs_root",    "label": "/ (root)",          "icon": "Folder",   "path": "/"},
            {"id": "fs_etc",     "label": "/etc",              "icon": "Folder",   "path": "/etc"},
            {"id": "fs_var",     "label": "/var",              "icon": "Folder",   "path": "/var"},
            {"id": "fs_tmp",     "label": "/tmp",              "icon": "Folder",   "path": "/tmp"},
            {"id": "fs_dev",     "label": "/dev",              "icon": "Folder",   "path": "/dev"},
            {"id": "fs_usr",     "label": "/usr",              "icon": "Folder",   "path": "/usr"},
            {"id": "fs_opt",     "label": "/opt",              "icon": "Folder",   "path": "/opt"},
            {"id": "fs_srv",     "label": "/srv",              "icon": "Folder",   "path": "/srv"},
            {"id": "fs_home",    "label": "/home",             "icon": "Folder",   "path": "/home"},
            {"id": "fs_root_home","label": "/root (home)",     "icon": "Folder",   "path": "/root"},
        ],
    },
    {
        "id": "docker",
        "label": "Container Artifacts",
        "icon": "Box",
        "children": [
            {"id": "docker_dir",  "label": "/var/lib/docker",  "icon": "Folder",   "path": "/var/lib/docker"},
            {"id": "lxc_dir",     "label": "/var/lib/lxc",     "icon": "Folder",   "path": "/var/lib/lxc"},
            {"id": "docker_env",  "label": "/.dockerenv",      "icon": "FileText", "path": "/.dockerenv"},
            {"id": "docker_cfg",  "label": "/etc/docker/daemon.json","icon": "FileText","path": "/etc/docker/daemon.json"},
        ],
    },
]


# ── Stat helpers ──────────────────────────────────────────────────────────────

def _epoch_str(ts: float) -> str:
    """Convert epoch float to ISO-ish string."""
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _humansize(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.0f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"


def _file_type(st_mode: int) -> str:
    if stat.S_ISREG(st_mode):   return "regular"
    if stat.S_ISDIR(st_mode):   return "directory"
    if stat.S_ISLNK(st_mode):   return "symlink"
    if stat.S_ISFIFO(st_mode):  return "pipe"
    if stat.S_ISSOCK(st_mode):  return "socket"
    if stat.S_ISBLK(st_mode):   return "block_device"
    if stat.S_ISCHR(st_mode):   return "char_device"
    return "unknown"


def _perm_str(st_mode: int) -> str:
    return stat.filemode(st_mode)


# ── Public API ────────────────────────────────────────────────────────────────

def browse(fs: FilesystemAccessor, path: str) -> Dict:
    """List a directory. Returns metadata for each child entry."""
    children = []

    if fs.mode == "local":
        names = fs.list_dir(path)
        for name in sorted(names):
            child_path = path.rstrip("/") + "/" + name
            entry: Dict = {"name": name, "path": child_path}
            full = fs._local_full(child_path)
            try:
                st = os.lstat(full)
                ftype = _file_type(st.st_mode)
                entry.update({
                    "type":  ftype,
                    "size":  st.st_size,
                    "size_human": _humansize(st.st_size),
                    "mtime": _epoch_str(st.st_mtime),
                    "atime": _epoch_str(st.st_atime),
                    "ctime": _epoch_str(st.st_ctime),
                    "mode":  _perm_str(st.st_mode),
                    "uid":   st.st_uid,
                    "gid":   st.st_gid,
                    "inode": st.st_ino,
                    "is_dir": ftype == "directory",
                })
                if ftype == "symlink":
                    try:
                        entry["symlink_target"] = os.readlink(full)
                    except OSError:
                        pass
            except OSError:
                entry.update({"type": "unknown", "is_dir": False})
            children.append(entry)
    else:
        # TSK mode — iterate the directory via pytsk3 to collect metadata in one pass
        try:
            import pytsk3 as _pytsk3
            dir_obj = fs.fs.open_dir(path)
            for direntry in dir_obj:
                if not hasattr(direntry, "info") or direntry.info is None:
                    continue
                name_info = getattr(direntry.info, "name", None)
                if name_info is None:
                    continue
                name = name_info.name
                if isinstance(name, bytes):
                    name = name.decode("utf-8", errors="replace")
                if name in (".", ".."):
                    continue
                child_path = path.rstrip("/") + "/" + name
                entry: Dict = {"name": name, "path": child_path}
                meta_info = getattr(direntry.info, "meta", None)
                if meta_info is not None:
                    is_dir = (meta_info.type == _pytsk3.TSK_FS_META_TYPE_DIR)
                    ftype = "directory" if is_dir else "regular"
                    size = int(meta_info.size) if meta_info.size else 0
                    entry.update({
                        "type":       ftype,
                        "size":       size,
                        "size_human": _humansize(size),
                        "is_dir":     is_dir,
                        "uid":        int(meta_info.uid) if meta_info.uid is not None else None,
                        "gid":        int(meta_info.gid) if meta_info.gid is not None else None,
                        "inode":      int(meta_info.addr) if hasattr(meta_info, "addr") else None,
                    })
                    for ts_attr in ("mtime", "atime", "ctime"):
                        ts_val = getattr(meta_info, ts_attr, None)
                        if ts_val:
                            try:
                                entry[ts_attr] = _epoch_str(float(ts_val))
                            except Exception:
                                pass
                else:
                    entry.update({"type": "unknown", "is_dir": False, "size": 0})
                children.append(entry)
        except ImportError:
            pass
        except Exception:
            names = fs.list_dir(path)
            for name in names:
                child_path = path.rstrip("/") + "/" + name
                children.append({"name": name, "path": child_path,
                                  "type": "unknown", "is_dir": False, "size": 0})

    # Directories first, then files, both alpha-sorted
    children.sort(key=lambda e: (0 if e.get("is_dir") else 1, e["name"].lower()))
    return {"path": path, "children": children}


def stat_file(fs: FilesystemAccessor, path: str) -> Dict:
    """Return full inode metadata for a single path."""
    result: Dict = {"path": path, "exists": False}
    if fs.mode == "local":
        full = fs._local_full(path)
        try:
            st = os.lstat(full)
            ftype = _file_type(st.st_mode)
            result.update({
                "exists":    True,
                "type":      ftype,
                "size":      st.st_size,
                "size_human": _humansize(st.st_size),
                "mtime":     _epoch_str(st.st_mtime),
                "atime":     _epoch_str(st.st_atime),
                "ctime":     _epoch_str(st.st_ctime),
                "mode":      _perm_str(st.st_mode),
                "mode_octal": oct(stat.S_IMODE(st.st_mode)),
                "uid":       st.st_uid,
                "gid":       st.st_gid,
                "inode":     st.st_ino,
                "nlinks":    st.st_nlink,
                "device":    st.st_dev,
                "is_dir":    ftype == "directory",
                "is_suid":   bool(st.st_mode & stat.S_ISUID),
                "is_sgid":   bool(st.st_mode & stat.S_ISGID),
                "is_sticky": bool(st.st_mode & stat.S_ISVTX),
            })
            if ftype == "symlink":
                try:
                    result["symlink_target"] = os.readlink(full)
                except OSError:
                    pass
        except OSError as e:
            result["error"] = str(e)
    else:
        # TSK mode — use pytsk3 metadata when available
        try:
            import pytsk3 as _pytsk3
            f = fs.fs.open(path)
            meta_info = f.info.meta
            if meta_info is not None:
                is_dir = (meta_info.type == _pytsk3.TSK_FS_META_TYPE_DIR)
                ftype = "directory" if is_dir else "regular"
                size = int(meta_info.size) if meta_info.size else 0
                result.update({
                    "exists":     True,
                    "type":       ftype,
                    "size":       size,
                    "size_human": _humansize(size),
                    "is_dir":     is_dir,
                    "uid":        int(meta_info.uid) if meta_info.uid is not None else None,
                    "gid":        int(meta_info.gid) if meta_info.gid is not None else None,
                    "inode":      int(meta_info.addr) if hasattr(meta_info, "addr") else None,
                    "mode":       oct(int(meta_info.mode)) if meta_info.mode else None,
                })
                for ts_attr in ("mtime", "atime", "ctime"):
                    ts_val = getattr(meta_info, ts_attr, None)
                    if ts_val:
                        try:
                            result[ts_attr] = _epoch_str(float(ts_val))
                        except Exception:
                            pass
            else:
                result.update({"exists": True, "type": "unknown", "is_dir": False,
                               "size": 0, "size_human": "0 B"})
        except ImportError:
            result["error"] = "pytsk3 not available"
        except Exception as e:
            result["error"] = str(e)
    return result


_TEXT_LIMIT = 200_000   # 200 KB max for viewer


def read_text(fs: FilesystemAccessor, path: str, limit: int = _TEXT_LIMIT) -> Dict:
    """Read up to `limit` bytes of a file and decode as UTF-8 for display."""
    meta = stat_file(fs, path)

    if fs.mode == "local":
        # In local mode, rely on stat to verify existence
        if not meta.get("exists"):
            return {"path": path, "exists": False, "content": None, "truncated": False,
                    "size": 0, "encoding": "utf-8", "error": meta.get("error", "File not found")}
        if meta.get("is_dir"):
            return {"path": path, "exists": True, "is_dir": True, "content": None,
                    "truncated": False, "size": 0, "encoding": "utf-8"}
    else:
        # TSK mode: stat may be incomplete — check for directory, but still
        # attempt to read even if stat reports the file as non-existent.
        if meta.get("exists") and meta.get("is_dir"):
            return {"path": path, "exists": True, "is_dir": True, "content": None,
                    "truncated": False, "size": 0, "encoding": "utf-8"}
        if not meta.get("exists"):
            meta = {}   # stat unavailable; proceed to direct read attempt

    raw = fs.read_file(path, max_bytes=limit + 1)
    if raw is None:
        return {"path": path, "exists": False, "content": None, "truncated": False,
                "size": 0, "encoding": "utf-8", "error": "File not found or not readable"}

    truncated = len(raw) > limit
    raw = raw[:limit]
    sz = meta.get("size", len(raw))

    # Detect binary: look for null bytes in first 8 KB
    is_binary = b"\x00" in raw[:8192]
    if is_binary:
        preview = raw[:512].hex(" ", 1)  # hex preview
        return {"path": path, "exists": True, "content": preview, "truncated": truncated,
                "size": sz, "encoding": "hex", "is_binary": True, **meta}

    content = raw.decode("utf-8", errors="replace")
    return {
        "path": path, "exists": True, "content": content, "truncated": truncated,
        "size": sz, "encoding": "utf-8", "is_binary": False, **meta,
    }
