"""Real-time system memory and process analysis for the forensic platform."""
import os
import time
from typing import Dict, List, Any

def get_live_ram_info() -> Dict[str, Any]:
    """Parse /proc/meminfo for detailed RAM statistics."""
    meminfo: Dict[str, int] = {}
    try:
        with open("/proc/meminfo", "r") as f:
            for line in f:
                if ":" in line:
                    parts = line.split(":")
                    key = parts[0].strip()
                    value = int(parts[1].strip().split()[0])
                    meminfo[key] = value
    except Exception:
        return {"error": "Failed to read /proc/meminfo"}

    total = meminfo.get("MemTotal", 0)
    free = meminfo.get("MemFree", 0)
    available = meminfo.get("MemAvailable", 0)
    buffers = meminfo.get("Buffers", 0)
    cached = meminfo.get("Cached", 0)
    swap_total = meminfo.get("SwapTotal", 0)
    swap_free = meminfo.get("SwapFree", 0)

    used = total - available if available else total - free
    used_pct = round((used / total) * 100, 2) if total else 0

    return {
        "total_kb": total,
        "free_kb": free,
        "available_kb": available,
        "used_kb": used,
        "buffers_kb": buffers,
        "cached_kb": cached,
        "used_pct": used_pct,
        "swap_total_kb": swap_total,
        "swap_free_kb": swap_free,
        "swap_used_kb": swap_total - swap_free,
        "timestamp": time.time()
    }

def get_top_memory_processes(limit: int = 15) -> List[Dict[str, Any]]:
    """Get top memory-consuming processes by parsing /proc/[pid]/statm and /proc/[pid]/cmdline."""
    processes = []
    try:
        pids = [d for d in os.listdir("/proc") if d.isdigit()]
    except Exception:
        return []

    for pid in pids:
        try:
            # RSS is the second field in /proc/[pid]/statm, in pages
            with open(f"/proc/{pid}/statm", "r") as f:
                fields = f.read().split()
                if len(fields) < 2:
                    continue
                rss_pages = int(fields[1])
                # Page size is usually 4KB, but we should use os.sysconf
                page_size = os.sysconf("SC_PAGE_SIZE") // 1024
                rss_kb = rss_pages * page_size

            with open(f"/proc/{pid}/comm", "r") as f:
                name = f.read().strip()

            with open(f"/proc/{pid}/cmdline", "r") as f:
                cmdline = f.read().replace("\x00", " ").strip()
            
            # Use comm if cmdline is empty (kernel threads etc)
            display_name = cmdline if cmdline else f"[{name}]"

            processes.append({
                "pid": int(pid),
                "name": name,
                "cmdline": display_name,
                "memory_kb": rss_kb
            })
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue

    # Sort by memory usage descending
    processes.sort(key=lambda x: x["memory_kb"], reverse=True)
    return processes[:limit]

def generate_memory_ai_insight(ram_info: Dict[str, Any], top_procs: List[Dict[str, Any]]) -> str:
    """Send memory data to Ollama for forensic analysis."""
    from .agent_core import get_agent
    
    agent = get_agent()
    
    # Format process list for the prompt
    proc_summary = "\n".join([f"- PID {p['pid']}: {p['name']} ({p['memory_kb']} KB) - {p['cmdline'][:100]}" for p in top_procs])
    
    prompt = f"""
Analyze the following system memory state for potential security risks, suspicious patterns, or performance anomalies from a forensic perspective.

SYSTEM RAM SUMMARY:
- Total: {ram_info['total_kb']} KB
- Used: {ram_info['used_kb']} KB ({ram_info['used_pct']}%)
- Available: {ram_info['available_kb']} KB
- Swap Used: {ram_info['swap_total_kb'] - ram_info['swap_free_kb']} KB

TOP MEMORY CONSUMING PROCESSES:
{proc_summary}

Provide a COMPLETE FORENSICS REPORT categorized tab-wise.
Use the following Markdown structure strictly:
# Executive Summary
(Brief overview of the memory health and primary findings)

## Resource Utilization Analysis
(Analysis of RAM vs Swap and pressure indicators)

## Security Artifact Assessment
(Detailed analysis of suspicious processes, unexpected command lines, or potential malware indicators)

## Investigation Recommendations
(Specific steps for the forensic examiner)
"""

    try:
        # Using the agent's chat method to get a response
        response = agent.chat(prompt, use_json=False)
        return response
    except Exception as e:
        return f"AI Analysis failed: {str(e)}"

def generate_dump_ai_insight(report_data: Dict[str, Any]) -> str:
    """Send specialized memory dump report to Ollama for forensic analysis."""
    from .agent_core import get_agent
    agent = get_agent()
    
    # Extract key data from the report
    summary = report_data.get("summary", {})
    procs = report_data.get("processes", [])[:10]
    hidden = report_data.get("hidden_processes", [])[:5]
    malfind = report_data.get("malfind", [])[:5]
    conns = report_data.get("connections", [])[:10]
    bash = report_data.get("bash_history", [])[:5]
    modules = report_data.get("modules", [])[:5]
    maps = report_data.get("shared_libraries", [])[:5]
    lsof = report_data.get("open_files", [])[:5]
    
    proc_summary = "\n".join([f"- PID {p.get('pid')}: {p.get('name')} (Hidden: {p.get('hidden', False)})" for p in procs + hidden])
    conn_summary = "\n".join([f"- {c.get('proto')} {c.get('laddr')}:{c.get('lport')} -> {c.get('raddr')}:{c.get('rport')} ({c.get('state')})" for c in conns])
    mal_summary = "\n".join([f"- PID {m.get('pid')} at {m.get('address')}: {m.get('protection')}" for m in malfind])
    bash_summary = "\n".join([f"- PID {b.get('pid')}: {b.get('command')}" for b in bash])
    mod_summary = "\n".join([f"- {m.get('name')} at {m.get('offset')}" for m in modules])
    maps_summary = "\n".join([f"- PID {m.get('pid')}: {m.get('path')} ({m.get('start')}-{m.get('end')})" for m in maps])
    lsof_summary = "\n".join([f"- PID {l.get('pid')}: {l.get('path')} (FD {l.get('fd')})" for l in lsof])

    prompt = f"""
Analyze the following MEMORY DUMP FORENSIC REPORT for high-impact security threats.

SUMMARY DATA:
- Total Processes: {summary.get('process_count')}
- Hidden (psscan) Processes: {summary.get('hidden_count')}
- Malfind Findings: {summary.get('malfind_count')}
- External Connections: {summary.get('external_connections')}
- Bash Commands Recovered: {summary.get('bash_entries')}
- Kernel Modules: {summary.get('module_count')}
- Shared Libraries (Maps): {summary.get('shared_libraries')}
- Open Files (Lsof): {summary.get('open_files')}
- Kernel Version: {report_data.get('kernel_version', 'Unknown')}

TOP PROCESS ARTIFACTS:
{proc_summary}

MALFIND ANALYSIS:
{mal_summary}

NETWORK ARTIFACTS:
{conn_summary}

BASH HISTORY (Recovered from Memory):
{bash_summary}

KERNEL MODULES:
{mod_summary}

SHARED LIBRARIES (High-Impact Maps):
{maps_summary}

OPEN FILES (LSOF):
{lsof_summary}

Provide a DEEP FORENSIC INVESTIGATION REPORT.
Use the following Markdown structure strictly:
# Forensic Summary
(Overall assessment of the dump's integrity and threat level)

## High-Risk Anomalies
(Detailed analysis of HIDDEN processes, MALFIND results, or suspicious SHARED LIBRARIES. Explain WHY these are suspicious.)

## Persistence & Tactical Indicators
(Analysis of suspicious BASH history, KERNEL MODULES, or OPEN FILES indicating data exfiltration or backdoors)

## Investigative Conclusion
(Final verdict and recommended next steps for the analyst. Mention specific PIDs to monitor.)
"""

    try:
        return agent.chat(prompt, use_json=False)
    except Exception as e:
        return f"Dump AI Analysis failed: {str(e)}"
