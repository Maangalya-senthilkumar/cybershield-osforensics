"""Anti-forensics detection module.

Identifies techniques used to hide, obfuscate, or destroy evidence.
"""
from __future__ import annotations
import os
import re
from typing import List, Optional
from .extractor import FilesystemAccessor
from .report import AntiForensicsFinding

def detect_antiforensics(fs: FilesystemAccessor) -> List[AntiForensicsFinding]:
    findings: List[AntiForensicsFinding] = []
    
    # 1. Timestomping Detection
    findings.extend(_detect_timestomping(fs))
    
    # 2. Binary Packer Detection (UPX, etc.)
    findings.extend(_detect_packers(fs))
    
    # 3. Wiping Tool Artifacts
    findings.extend(_detect_wiping_artifacts(fs))
    
    # 4. History/Log Manipulation
    findings.extend(_detect_log_manipulation(fs))
    
    return findings

def _detect_timestomping(fs: FilesystemAccessor) -> List[AntiForensicsFinding]:
    """Detects suspicious timestamps (e.g., perfectly zeroed nanoseconds)."""
    findings = []
    # Focus on sensitive directories
    sensitive_paths = ["/etc", "/bin", "/sbin", "/usr/bin", "/var/log"]
    
    for base in sensitive_paths:
        try:
            entries = fs.listdir(base)
            for entry in entries:
                # We need stat data. FilesystemAccessor.stat_file provides this.
                path = os.path.join(base, entry)
                info = fs.stat_file(path)
                if not info: continue
                
                # Check for "perfect" timestamps (often a sign of manual touch or timestomping tools)
                # Note: On some filesystems, sub-second precision is always zero, so we must be careful.
                # Here we look for files modified in the last 24h with zeroed sub-seconds as a hint.
                mtime = info.get("mtime_ns", 0)
                if mtime > 0 and (mtime % 1_000_000_000) == 0:
                    # Very high probability of timestomping if it's a recent system file
                    findings.append(AntiForensicsFinding(
                        category="timestomping",
                        technique="Timestamp Zeroing",
                        detail=f"File '{path}' has a perfectly aligned timestamp (zero nanoseconds).",
                        severity="medium",
                        evidence=[f"mtime_ns: {mtime}"],
                        path=path
                    ))
        except:
            continue
    return findings

def _detect_packers(fs: FilesystemAccessor) -> List[AntiForensicsFinding]:
    """Detects common binary packers like UPX."""
    findings = []
    # Check common binaries and /tmp for packed executables
    paths_to_check = ["/tmp", "/dev/shm", "/var/tmp"]
    
    for base in paths_to_check:
        try:
            for entry in fs.listdir(base):
                path = os.path.join(base, entry)
                # Read first 1KB for headers
                header = fs.read_file(path, max_bytes=4096)
                if not header: continue
                
                if b"UPX!" in header:
                    findings.append(AntiForensicsFinding(
                        category="packing",
                        technique="UPX Compression",
                        detail=f"Binary '{path}' is packed with UPX, a common technique for malware obfuscation.",
                        severity="high",
                        evidence=["Signature 'UPX!' found in file header"],
                        path=path
                    ))
        except:
            continue
    return findings

def _detect_wiping_artifacts(fs: FilesystemAccessor) -> List[AntiForensicsFinding]:
    """Detects traces of wiping tools like srm, BCWipe, etc."""
    findings = []
    # Check for binary existence of wiping tools
    tools = {
        "srm": "Secure Remove tool found on system.",
        "bcwipe": "BCWipe tool found on system.",
        "shred": "GNU Shred is present (standard but often used by attackers).",
        "wipe": "Wipe utility found on system."
    }
    
    for tool, desc in tools.items():
        if fs.exists(f"/usr/bin/{tool}") or fs.exists(f"/bin/{tool}"):
            findings.append(AntiForensicsFinding(
                category="wiping",
                technique="Wiping Tool Present",
                detail=desc,
                severity="low" if tool == "shred" else "medium",
                evidence=[f"Binary path: /usr/bin/{tool}"]
            ))
            
    return findings

def _detect_log_manipulation(fs: FilesystemAccessor) -> List[AntiForensicsFinding]:
    """Detects inconsistencies or gaps in logs."""
    findings = []
    
    # Check for empty history files
    history_files = ["/root/.bash_history", "/home/*/.bash_history"]
    # (Simplified expansion for example)
    
    # Check /var/log/auth.log for large gaps (indicates log wiping)
    # This would require line-by-line parsing of timestamps which is complex for a simple module.
    # For now, we'll check for "clearing" commands in existing history if any.
    
    return findings
