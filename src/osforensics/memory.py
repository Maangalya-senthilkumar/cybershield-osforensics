"""Memory forensics module — Volatility3 CLI wrapper.

Runs Volatility3 plugins against a memory dump and returns a structured
MemoryReport.  Volatility3 is invoked via subprocess so it does NOT need
to be importable; only the `vol` (or `vol3`) binary must be on PATH.

Supported dump formats  : .raw, .mem, .lime (LiME), .dmp, .vmem
Key plugins executed    :
  linux.pslist.PsList   – full process list from kernel linked list
  linux.psscan.PsScan   – scan memory for EPROCESS / task_struct blocks
  linux.netstat.NetStat – open sockets / network connections
  linux.bash.Bash       – bash command history recovered from memory
  linux.malfind.Malfind – regions with suspicious memory protection
  linux.lsmod.Lsmod     – loaded kernel modules
  linux.cmdline.CmdLine – per-process command lines
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from typing import Any, Dict, List, Optional

from .report import (
    MemoryBashEntry,
    MemoryConnection,
    MemoryMalfind,
    MemoryModule,
    MemoryProcess,
    MemoryReport,
)


# ── Volatility3 detection ─────────────────────────────────────────────────────

def _find_vol() -> Optional[str]:
    """Return the first volatility3 binary found on PATH, or None."""
    for name in ("vol", "vol3", "volatility3", "volatility"):
        path = shutil.which(name)
        if path:
            return path
    return None


# ── Plugin runner ─────────────────────────────────────────────────────────────

def _run_plugin(
    vol_bin: str,
    dump_path: str,
    plugin: str,
    extra_args: Optional[List[str]] = None,
    timeout: int = 180,
) -> Dict[str, Any]:
    """Run one Volatility3 plugin and return parsed output.

    Returns a dict with either:
      { "columns": [...], "rows": [[...], ...] }   – success
      { "error": "...", "raw": "..." }              – failure
    """
    cmd = [vol_bin, "-q", "-f", dump_path, "-r", "json", plugin]
    if extra_args:
        cmd.extend(extra_args)

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return {"error": f"Plugin timed out after {timeout}s: {plugin}"}
    except Exception as exc:
        return {"error": f"Subprocess error: {exc}"}

    stdout = result.stdout.strip()

    # Volatility3 --output-format json prints the JSON object directly.
    # Sometimes info/warning lines precede it; skip to the first '{' line.
    for i, line in enumerate(stdout.splitlines()):
        stripped = line.strip()
        if stripped.startswith("{"):
            try:
                data = json.loads("\n".join(stdout.splitlines()[i:]))
                return data
            except json.JSONDecodeError:
                break

    # Fallback: treat raw output as text for debugging
    return {
        "error": result.stderr[:1000].strip() if result.returncode != 0 else None,
        "raw": stdout[:2000],
    }


def _rows(plugin_result: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Convert Volatility3 JSON plugin output to a list of row dicts."""
    columns = plugin_result.get("columns") or plugin_result.get("header") or []
    rows = plugin_result.get("rows") or []
    if not columns or not rows:
        return []
    result = []
    for row in rows:
        if isinstance(row, dict):
            result.append(row)
        elif isinstance(row, (list, tuple)):
            result.append(dict(zip(columns, row)))
    return result


def _str(val: Any) -> str:
    return "" if val is None else str(val).strip()


def _int(val: Any, default: int = 0) -> int:
    try:
        return int(val)
    except (TypeError, ValueError):
        return default


# ── Process list ─────────────────────────────────────────────────────────────

def _parse_pslist(data: Dict[str, Any]) -> List[MemoryProcess]:
    procs: List[MemoryProcess] = []
    for r in _rows(data):
        # Volatility3 PsList columns (linux):
        # OFFSET (V), PID, TID, PPID, COMM, UID, GID, ...
        pid  = _int(r.get("PID")  or r.get("Pid")  or r.get("pid"))
        ppid = _int(r.get("PPID") or r.get("PPid") or r.get("ppid"))
        name = _str(r.get("COMM") or r.get("ImageFileName") or r.get("Name") or r.get("name") or "")
        procs.append(MemoryProcess(
            pid=pid,
            ppid=ppid,
            name=name,
            offset=_str(r.get("OFFSET (V)") or r.get("offset") or r.get("Offset") or ""),
            threads=_int(r.get("Threads") or r.get("threads") or 0),
            create_time=_str(r.get("CreateTime") or r.get("create_time") or ""),
        ))
    return procs


def _parse_psscan(data: Dict[str, Any]) -> List[MemoryProcess]:
    procs: List[MemoryProcess] = []
    for r in _rows(data):
        pid  = _int(r.get("PID")  or r.get("Pid")  or r.get("pid"))
        ppid = _int(r.get("PPID") or r.get("PPid") or r.get("ppid"))
        name = _str(r.get("COMM") or r.get("ImageFileName") or r.get("Name") or r.get("name") or "")
        procs.append(MemoryProcess(
            pid=pid,
            ppid=ppid,
            name=name,
            offset=_str(r.get("OFFSET (P)") or r.get("OFFSET (V)") or r.get("Offset") or ""),
        ))
    return procs


# ── Network connections ───────────────────────────────────────────────────────

def _parse_netstat(data: Dict[str, Any]) -> List[MemoryConnection]:
    conns: List[MemoryConnection] = []
    for r in _rows(data):
        # linux.sockstat.Sockstat columns:
        # NetNS, Pid, FD, Sock Addr, Domain, Type, Protocol,
        # Source Addr, Source Port, Dest Addr, Dest Port, State, Filter
        pid   = _int(r.get("Pid")  or r.get("PID")  or r.get("pid"))
        proto = _str(r.get("Protocol") or r.get("Proto") or r.get("protocol") or "")
        laddr = _str(r.get("Source Addr") or r.get("LocalAddr")  or r.get("local_addr")  or "")
        lport = _int(r.get("Source Port") or r.get("lport") or 0)
        raddr = _str(r.get("Dest Addr")   or r.get("RemoteAddr") or r.get("remote_addr") or "")
        rport = _int(r.get("Dest Port")   or r.get("rport") or 0)
        state = _str(r.get("State") or r.get("state") or "")
        proc  = _str(r.get("Process") or r.get("COMM") or r.get("name") or "")

        conns.append(MemoryConnection(
            pid=pid,
            process=proc,
            proto=proto,
            laddr=laddr,
            lport=lport,
            raddr=raddr,
            rport=rport,
            state=state,
        ))
    return conns


# ── Bash history ──────────────────────────────────────────────────────────────

def _parse_bash(data: Dict[str, Any]) -> List[MemoryBashEntry]:
    entries: List[MemoryBashEntry] = []
    for r in _rows(data):
        pid  = _int(r.get("Pid")  or r.get("PID")  or r.get("pid"))
        proc = _str(r.get("Process") or r.get("COMM") or r.get("name") or "bash")
        cmd  = _str(r.get("CommandLineHistory") or r.get("History") or r.get("command") or r.get("Command") or "")
        if cmd:
            entries.append(MemoryBashEntry(pid=pid, process=proc, command=cmd))
    return entries


# ── Malfind ───────────────────────────────────────────────────────────────────

def _parse_malfind(data: Dict[str, Any]) -> List[MemoryMalfind]:
    findings: List[MemoryMalfind] = []
    for r in _rows(data):
        pid  = _int(r.get("PID") or r.get("Pid") or r.get("pid"))
        proc = _str(r.get("Process") or r.get("COMM") or r.get("name") or "")
        addr = _str(r.get("Address") or r.get("address") or r.get("Start VPN") or "")
        prot = _str(r.get("Protection") or r.get("protection") or "")
        hexd = _str(r.get("Hexdump") or r.get("hexdump") or r.get("Hex") or "")
        disasm = _str(r.get("Disasm") or r.get("disasm") or r.get("Disassembly") or "")
        findings.append(MemoryMalfind(
            pid=pid,
            process=proc,
            address=addr,
            protection=prot,
            hex_dump=hexd[:512],
            disassembly=disasm[:512],
        ))
    return findings


# ── Modules ───────────────────────────────────────────────────────────────────

def _parse_lsmod(data: Dict[str, Any]) -> List[MemoryModule]:
    modules: List[MemoryModule] = []
    for r in _rows(data):
        name = _str(r.get("Name") or r.get("name") or r.get("Module") or "")
        size = _int(r.get("Size") or r.get("size") or r.get("Core size") or 0)
        offset = _str(r.get("Offset") or r.get("offset") or r.get("Address") or "")
        if name:
            modules.append(MemoryModule(name=name, size=size, offset=offset))
    return modules


# ── Cmdline ───────────────────────────────────────────────────────────────────

def _apply_cmdlines(
    processes: List[MemoryProcess],
    data: Dict[str, Any],
) -> None:
    """Fill in `cmdline` on existing MemoryProcess objects from PsAux output.

    linux.psaux.PsAux columns: PID, PPID, COMM, ARGS
    """
    by_pid: Dict[int, str] = {}
    for r in _rows(data):
        pid = _int(r.get("PID") or r.get("Pid") or r.get("pid"))
        # PsAux uses "ARGS"; older/alternate plugins used "Args" or "CommandLine"
        cmd = _str(
            r.get("ARGS") or r.get("Args") or
            r.get("CommandLine") or r.get("cmdline") or ""
        )
        if pid and cmd:
            by_pid[pid] = cmd
    for proc in processes:
        if proc.pid in by_pid:
            proc.cmdline = by_pid[proc.pid]


# ── Main analyser ─────────────────────────────────────────────────────────────

def analyze_memory(dump_path: str) -> MemoryReport:
    """Run all supported Volatility3 plugins and return a MemoryReport.

    If Volatility3 is not installed, a minimal report with
    ``volatility_available=False`` is returned immediately.
    """
    vol = _find_vol()

    if not vol:
        return MemoryReport(
            dump_path=dump_path,
            volatility_available=False,
            volatility_error=(
                "Volatility3 not found on PATH. "
                "Install it with: pip install volatility3"
            ),
        )

    if not os.path.isfile(dump_path):
        return MemoryReport(
            dump_path=dump_path,
            volatility_available=True,
            volatility_error=f"Dump file not found: {dump_path}",
        )

    errors: List[str] = []
    symbol_errors: List[str] = []

    # ── banners (detect kernel version without symbols) ───────────
    kernel_version: Optional[str] = None
    banners_data = _run_plugin(vol, dump_path, "banners.Banners")
    for r in _rows(banners_data):
        banner = _str(r.get("Banner") or r.get("banner") or "")
        if "Linux version" in banner:
            kernel_version = banner.split("\x00")[0].strip()
            break

    def _check_sym(name: str, data: Dict[str, Any]) -> bool:
        """Return True if the output indicates a missing symbol table."""
        raw = data.get("raw") or data.get("error") or ""
        return "Unable to validate" in raw or "symbol_table_name" in raw

    # ── pslist ────────────────────────────────────────────────────
    pslist_data = _run_plugin(vol, dump_path, "linux.pslist.PsList")
    if _check_sym("pslist", pslist_data):
        symbol_errors.append("pslist")
    elif pslist_data.get("error"):
        errors.append(f"pslist: {pslist_data['error']}")
    processes = _parse_pslist(pslist_data)

    # ── psscan (for hidden process detection) ─────────────────────
    psscan_data = _run_plugin(vol, dump_path, "linux.psscan.PsScan")
    if _check_sym("psscan", psscan_data):
        symbol_errors.append("psscan")
    elif psscan_data.get("error"):
        errors.append(f"psscan: {psscan_data['error']}")
    scanned = _parse_psscan(psscan_data)

    # hidden = in psscan but not in pslist (by PID)
    visible_pids = {p.pid for p in processes}
    hidden_processes = [p for p in scanned if p.pid not in visible_pids and p.pid > 0]
    # mark hidden flag
    for p in hidden_processes:
        p.hidden = True

    # ── cmdline (via psaux) ───────────────────────────────────────
    cmdline_data = _run_plugin(vol, dump_path, "linux.psaux.PsAux")
    if _check_sym("cmdline", cmdline_data):
        symbol_errors.append("cmdline")
    elif cmdline_data.get("error"):
        errors.append(f"cmdline: {cmdline_data['error']}")
    _apply_cmdlines(processes, cmdline_data)

    # ── netstat (via sockstat) ────────────────────────────────────
    netstat_data = _run_plugin(vol, dump_path, "linux.sockstat.Sockstat")
    if _check_sym("netstat", netstat_data):
        symbol_errors.append("netstat")
    elif netstat_data.get("error"):
        errors.append(f"netstat: {netstat_data['error']}")
    connections = _parse_netstat(netstat_data)

    # ── bash history ──────────────────────────────────────────────
    bash_data = _run_plugin(vol, dump_path, "linux.bash.Bash")
    if _check_sym("bash", bash_data):
        symbol_errors.append("bash")
    elif bash_data.get("error"):
        errors.append(f"bash: {bash_data['error']}")
    bash_history = _parse_bash(bash_data)

    # ── malfind ───────────────────────────────────────────────────
    malfind_data = _run_plugin(vol, dump_path, "linux.malfind.Malfind")
    if _check_sym("malfind", malfind_data):
        symbol_errors.append("malfind")
    elif malfind_data.get("error"):
        errors.append(f"malfind: {malfind_data['error']}")
    malfind = _parse_malfind(malfind_data)

    # ── lsmod ─────────────────────────────────────────────────────
    lsmod_data = _run_plugin(vol, dump_path, "linux.lsmod.Lsmod")
    if _check_sym("lsmod", lsmod_data):
        symbol_errors.append("lsmod")
    elif lsmod_data.get("error"):
        errors.append(f"lsmod: {lsmod_data['error']}")
    modules = _parse_lsmod(lsmod_data)

    # ── summary stats ─────────────────────────────────────────────
    suspicious_procs = [
        p for p in processes
        if p.name in {"nc", "ncat", "netcat", "bash", "sh", "python", "python3",
                      "ruby", "perl", "wget", "curl", "socat", "nmap", "tcpdump",
                      "metasploit", "msfconsole", "msfvenom"}
    ]

    external_conns = [
        c for c in connections
        if c.raddr and not c.raddr.startswith(("127.", "::1", "0.0.0.0", ""))
    ]

    summary = {
        "process_count":        len(processes),
        "hidden_count":         len(hidden_processes),
        "connection_count":     len(connections),
        "external_connections": len(external_conns),
        "bash_entries":         len(bash_history),
        "malfind_count":        len(malfind),
        "module_count":         len(modules),
        "suspicious_names":     len(suspicious_procs),
        "total_high":           len(hidden_processes) + len(malfind) + len(external_conns),
        "plugin_errors":        len(errors),
        "symbol_errors":        len(symbol_errors),
    }

    needs_symbols = len(symbol_errors) > 0
    vol_error_parts = []
    if needs_symbols:
        vol_error_parts.append(
            f"Kernel symbol table not found for {len(symbol_errors)} plugin(s): "
            f"{', '.join(symbol_errors)}. "
            "See the Symbol Setup guide in the UI."
        )
    if errors:
        vol_error_parts.extend(errors)

    return MemoryReport(
        dump_path=dump_path,
        volatility_available=True,
        volatility_error="; ".join(vol_error_parts) if vol_error_parts else None,
        needs_symbols=needs_symbols,
        kernel_version=kernel_version,
        processes=processes,
        hidden_processes=hidden_processes,
        connections=connections,
        bash_history=bash_history,
        malfind=malfind,
        modules=modules,
        summary=summary,
    )
