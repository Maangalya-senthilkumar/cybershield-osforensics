"""Remote SSH snapshot acquisition utilities.

This module collects a bounded forensic snapshot from a remote Linux host via
SSH/SFTP into a local temporary directory.  The snapshot is then consumable by
the existing local FilesystemAccessor-based analysis pipeline without any
changes to the analysers.

Public API
----------
collect_remote_snapshot(...)  – download a bounded filesystem snapshot over SFTP
collect_remote_host_info(...) – quick SSH connect to fetch live system metadata
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, field
import os
import posixpath
import stat
import tempfile
from typing import Optional

try:
    import paramiko
except Exception:  # pragma: no cover
    paramiko = None  # type: ignore


# ── Default paths to capture ──────────────────────────────────────────────────

DEFAULT_SSH_PATHS = [
    "/etc",
    "/var/log",
    "/home",
    "/root",
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/opt",
    "/etc/systemd",
    "/lib/systemd",
    "/var/lib/systemd",
    "/var/spool/cron",
]


# ── Exceptions ────────────────────────────────────────────────────────────────

class RemoteSnapshotError(RuntimeError):
    """Raised when SSH snapshot acquisition or connection fails."""


# ── Data classes ──────────────────────────────────────────────────────────────

@dataclass
class SSHSnapshotStats:
    files_downloaded: int = 0
    dirs_created: int = 0
    bytes_downloaded: int = 0
    files_truncated: int = 0
    skipped_items: int = 0
    errors: list[str] = field(default_factory=list)


@dataclass
class SSHSnapshot:
    local_root: str
    host: str
    username: str
    port: int
    include_paths: list[str]
    stats: SSHSnapshotStats
    live_info: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        out = asdict(self)
        out["stats"]["errors"] = out["stats"]["errors"][:100]
        return out


# ── Internal SSH helpers ──────────────────────────────────────────────────────

def _run_cmd(client, cmd: str, timeout: int = 30) -> str:
    """Execute *cmd* on an open SSH client and return decoded stdout."""
    try:
        _, stdout, _ = client.exec_command(cmd, timeout=timeout)
        return stdout.read().decode("utf-8", errors="replace").strip()
    except Exception:
        return ""


def _collect_live_info(client) -> dict:
    """Collect basic live-system info from an already-connected SSH client."""
    hostname   = _run_cmd(client, "hostname") or "unknown"
    kernel     = _run_cmd(client, "uname -r") or "unknown"
    os_raw     = _run_cmd(client, "cat /etc/os-release 2>/dev/null || echo ''")
    uptime_raw = _run_cmd(client, "cat /proc/uptime 2>/dev/null || echo '0'")
    lavg_raw   = _run_cmd(client, "cat /proc/loadavg 2>/dev/null || echo ''")
    mem_raw    = _run_cmd(client, "cat /proc/meminfo 2>/dev/null || echo ''")
    who_raw    = _run_cmd(client, "who 2>/dev/null || echo ''")
    ifaces_raw = _run_cmd(client, "ls /sys/class/net/ 2>/dev/null || echo ''")
    procs_raw  = _run_cmd(
        client,
        "ls /proc 2>/dev/null | grep -cE '^[0-9]+$' 2>/dev/null || echo '0'",
    )

    os_name, os_id = "Linux", "linux"
    for line in os_raw.splitlines():
        if "=" in line:
            k, _, v = line.partition("=")
            v = v.strip().strip('"')
            if k.strip() == "PRETTY_NAME":
                os_name = v
            elif k.strip() == "ID":
                os_id = v

    uptime_secs = 0.0
    try:
        uptime_secs = float(uptime_raw.split()[0])
    except Exception:
        pass
    uh, um = int(uptime_secs // 3600), int((uptime_secs % 3600) // 60)
    uptime_str = f"{uh}h {um}m" if uh else f"{um}m"

    load_avg = lavg_raw.split()[:3]

    meminfo: dict = {}
    for line in mem_raw.splitlines():
        if ":" in line:
            k, _, v = line.partition(":")
            try:
                meminfo[k.strip()] = int(v.strip().split()[0])
            except Exception:
                pass
    mem_total = meminfo.get("MemTotal", 0)
    mem_avail = meminfo.get("MemAvailable", 0)
    used_pct  = round((1 - mem_avail / mem_total) * 100, 1) if mem_total else 0

    ifaces = [i for i in ifaces_raw.splitlines() if i.strip() and i.strip() != "lo"]

    process_count = 0
    try:
        process_count = int(procs_raw.strip())
    except Exception:
        pass

    users: list[str] = []
    for line in who_raw.splitlines():
        parts = line.split()
        if parts:
            users.append(parts[0])

    return {
        "hostname":       hostname,
        "os_name":        os_name,
        "os_id":          os_id,
        "kernel":         kernel,
        "uptime_seconds": uptime_secs,
        "uptime_str":     uptime_str,
        "load_avg":       load_avg,
        "memory": {
            "total_kb":     mem_total,
            "available_kb": mem_avail,
            "used_pct":     used_pct,
        },
        "interfaces":    ifaces,
        "process_count": process_count,
        "users":         list(set(users)),
        "scheme":        "remote_ssh",
    }


# ── Path safety ───────────────────────────────────────────────────────────────

def _norm_remote(path: str) -> str:
    if not path:
        return "/"
    p = posixpath.normpath(path)
    if not p.startswith("/"):
        p = "/" + p
    return p


def _safe_local_path(root: str, remote_path: str) -> str:
    """Map a remote absolute path to a local path under *root*, guard against traversal."""
    rel = remote_path.lstrip("/")
    local = os.path.realpath(os.path.join(root, rel))
    root_real = os.path.realpath(root)
    if not (local == root_real or local.startswith(root_real + os.sep)):
        raise RemoteSnapshotError(f"Unsafe path mapping for remote path: {remote_path}")
    return local


# ── File downloader ───────────────────────────────────────────────────────────

def _download_regular_file(
    sftp,
    remote_path: str,
    local_path: str,
    st_mode: int,
    max_file_bytes: int,
    max_total_bytes: int,
    stats: SSHSnapshotStats,
    max_files: int,
) -> None:
    if stats.files_downloaded >= max_files:
        return
    if stats.bytes_downloaded >= max_total_bytes:
        return
    if not stat.S_ISREG(st_mode):
        stats.skipped_items += 1
        return

    os.makedirs(os.path.dirname(local_path), exist_ok=True)

    file_budget = min(max_file_bytes, max_total_bytes - stats.bytes_downloaded)
    if file_budget <= 0:
        return

    try:
        with sftp.open(remote_path, "rb") as rf, open(local_path, "wb") as lf:
            remaining = file_budget
            while remaining > 0:
                chunk = rf.read(min(1_048_576, remaining))
                if not chunk:
                    break
                lf.write(chunk)
                remaining -= len(chunk)
                stats.bytes_downloaded += len(chunk)
            truncated = remaining == 0 and bool(rf.read(1))

        stats.files_downloaded += 1
        if truncated:
            stats.files_truncated += 1
    except Exception as e:
        stats.errors.append(f"{remote_path}: {e}")


# ── Public functions ──────────────────────────────────────────────────────────

def collect_remote_host_info(
    host: str,
    username: str,
    *,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    key_passphrase: Optional[str] = None,
    connect_timeout: int = 15,
    banner_timeout: int = 120,
    auth_timeout: int = 120,
) -> dict:
    """Quick SSH connect to retrieve live system metadata (no SFTP download).

    connect_timeout  – TCP socket connect timeout (seconds).
    banner_timeout   – How long to wait for the server's SSH banner.  Increase
                       this when the remote sshd has UseDNS yes and DNS is slow.
    auth_timeout     – How long to wait for authentication to complete.
    """
    if paramiko is None:
        raise RemoteSnapshotError("paramiko is required for SSH analysis but is not installed")
    if not host.strip() or not username.strip():
        raise RemoteSnapshotError("host and username are required")

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=key_path,
            passphrase=key_passphrase,
            timeout=connect_timeout,
            allow_agent=True,
            look_for_keys=True,
            banner_timeout=banner_timeout,
            auth_timeout=auth_timeout,
        )
    except Exception as e:
        raise RemoteSnapshotError(f"SSH connection failed: {e}")

    try:
        return _collect_live_info(client)
    finally:
        client.close()


def collect_remote_snapshot(
    host: str,
    username: str,
    *,
    port: int = 22,
    password: Optional[str] = None,
    key_path: Optional[str] = None,
    key_passphrase: Optional[str] = None,
    include_paths: Optional[list[str]] = None,
    out_dir: Optional[str] = None,
    connect_timeout: int = 15,
    banner_timeout: int = 120,
    auth_timeout: int = 120,
    max_total_bytes: int = 1_024 * 1024 * 1024,
    max_file_bytes: int = 32 * 1024 * 1024,
    max_files: int = 25_000,
) -> SSHSnapshot:
    """Collect a bounded filesystem snapshot from a remote host over SSH/SFTP."""
    if paramiko is None:
        raise RemoteSnapshotError("paramiko is required for SSH analysis but is not installed")

    if not host.strip() or not username.strip():
        raise RemoteSnapshotError("host and username are required for SSH analysis")

    selected = include_paths[:] if include_paths else DEFAULT_SSH_PATHS[:]
    selected = [_norm_remote(p) for p in selected if p and p.strip()]
    if not selected:
        selected = DEFAULT_SSH_PATHS[:]

    if out_dir is None:
        out_dir = tempfile.mkdtemp(prefix="osforensics_ssh_snapshot_")
    os.makedirs(out_dir, exist_ok=True)

    stats = SSHSnapshotStats()

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            hostname=host,
            port=port,
            username=username,
            password=password,
            key_filename=key_path,
            passphrase=key_passphrase,
            timeout=connect_timeout,
            allow_agent=True,
            look_for_keys=True,
            banner_timeout=banner_timeout,
            auth_timeout=auth_timeout,
        )
    except Exception as e:
        raise RemoteSnapshotError(f"SSH connection failed: {e}")

    live_info: dict = {}
    try:
        sftp = client.open_sftp()
        queue: list[str] = []

        for p in selected:
            try:
                st = sftp.stat(p)
            except Exception as e:
                stats.errors.append(f"{p}: {e}")
                continue

            if stat.S_ISDIR(st.st_mode):
                ldir = _safe_local_path(out_dir, p)
                os.makedirs(ldir, exist_ok=True)
                stats.dirs_created += 1
                queue.append(p)
            else:
                lfile = _safe_local_path(out_dir, p)
                _download_regular_file(
                    sftp, p, lfile, st.st_mode,
                    max_file_bytes, max_total_bytes, stats, max_files,
                )

        while (
            queue
            and stats.files_downloaded < max_files
            and stats.bytes_downloaded < max_total_bytes
        ):
            cur = queue.pop(0)
            try:
                entries = sftp.listdir_attr(cur)
            except Exception as e:
                stats.errors.append(f"{cur}: {e}")
                continue

            for ent in entries:
                if (
                    stats.files_downloaded >= max_files
                    or stats.bytes_downloaded >= max_total_bytes
                ):
                    break

                name = ent.filename
                if name in (".", ".."):
                    continue

                remote_child = posixpath.join(cur, name)
                try:
                    local_child = _safe_local_path(out_dir, remote_child)
                except Exception as e:
                    stats.errors.append(str(e))
                    continue

                mode = ent.st_mode
                if stat.S_ISLNK(mode):
                    stats.skipped_items += 1
                    continue
                if stat.S_ISDIR(mode):
                    try:
                        os.makedirs(local_child, exist_ok=True)
                        stats.dirs_created += 1
                        queue.append(remote_child)
                    except Exception as e:
                        stats.errors.append(f"{remote_child}: {e}")
                    continue

                _download_regular_file(
                    sftp, remote_child, local_child, mode,
                    max_file_bytes, max_total_bytes, stats, max_files,
                )

        sftp.close()

        # Collect live host info while the SSH session is still open.
        try:
            live_info = _collect_live_info(client)
        except Exception:
            pass

    finally:
        client.close()

    return SSHSnapshot(
        local_root=out_dir,
        host=host,
        username=username,
        port=port,
        include_paths=selected,
        stats=stats,
        live_info=live_info,
    )
