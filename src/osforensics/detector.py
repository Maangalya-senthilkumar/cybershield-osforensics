"""Heuristics to detect operating system characteristics and tool artefacts.

This module implements simple, conservative heuristics driven by
filesystem artefacts (files, package databases, config files).
"""
from __future__ import annotations

from typing import Dict, List
from .extractor import FilesystemAccessor
import re


def parse_os_release(content: bytes) -> Dict[str, str]:
    data: Dict[str, str] = {}
    try:
        text = content.decode("utf-8", errors="ignore")
    except Exception:
        return data
    for line in text.splitlines():
        if "=" in line:
            k, v = line.split("=", 1)
            v = v.strip().strip('"')
            data[k.strip()] = v
    return data


def detect_os(fs: FilesystemAccessor) -> Dict[str, object]:
    """Return a best-effort OS identification dict.

    Keys: name, id, variant_tags (list), notes
    """
    out: Dict[str, object] = {"name": None, "id": None, "variant_tags": [], "notes": []}

    # Check /etc/os-release first
    if fs.exists("/etc/os-release"):
        content = fs.read_file("/etc/os-release")
        if content:
            info = parse_os_release(content)
            out["name"] = info.get("NAME") or info.get("PRETTY_NAME")
            out["id"] = info.get("ID")
            if out["name"] and any(x in out["name"].lower() for x in ("kali", "blackarch", "parrot", "tails", "tailsos", "backbox")):
                out["variant_tags"].append("offensive- or privacy-focused")

    # heuristics for well-known distros
    # Kali
    if fs.exists("/etc/apt/sources.list"):
        s = fs.read_file("/etc/apt/sources.list")
        if s and b"kali" in s.lower():
            out["variant_tags"].append("kali")

    # BlackArch often uses pacman and has /etc/pacman.d/blackarch or repo lines
    if fs.exists("/etc/pacman.conf"):
        s = fs.read_file("/etc/pacman.conf")
        if s and b"blackarch" in s.lower():
            out["variant_tags"].append("blackarch")

    # Tails/live-boot heuristics
    if fs.exists("/live"):
        out["variant_tags"].append("live-environment")
        out["notes"].append("Found /live directory; may be amnesic or live-boot system")

    # Presence of /etc/tails or tails-specific files
    if fs.exists("/etc/tails.conf") or fs.exists("/etc/tails"):
        out["variant_tags"].append("tails")

    # Check for package DBs: dpkg, rpm
    if fs.exists("/var/lib/dpkg/status"):
        dpkg = fs.read_file("/var/lib/dpkg/status")
        if dpkg:
            # quick check for meta packages
            if b"kali-" in dpkg.lower():
                out["variant_tags"].append("kali")

    # Basic fallback: read /etc/issue
    if not out.get("name") and fs.exists("/etc/issue"):
        s = fs.read_file("/etc/issue")
        if s:
            out["name"] = s.decode("utf-8", errors="ignore").splitlines()[0]

    return out


TOOL_SIGNATURES: Dict[str, List[str]] = {
    # tool_name: list of filename fragments or package names to look for
    "tor": ["tor", "tor-browser", "torrc"],
    "openvpn": ["openvpn", "ovpn"],
    "wireguard": ["wireguard", "wg-quick"],
    "nmap": ["nmap"],
    "metasploit": ["metasploit", "msfconsole", "msfvenom"],
    "sqlmap": ["sqlmap"],
    "burpsuite": ["burpsuite", "burp"],
    "ssh": ["sshd_config", "sshd"],
    "proxychains": ["proxychains"],
    "netcat": ["nc", "netcat"],
    "hydra": ["hydra"],
}


def detect_tools(fs: FilesystemAccessor) -> List[Dict[str, object]]:
    findings = []

    # Search a set of common directories for tool binaries/configs
    search_paths = ["/usr/bin", "/usr/sbin", "/bin", "/sbin", "/opt", "/usr/local/bin", "/home"]

    for tool, signs in TOOL_SIGNATURES.items():
        found = False
        evidence: List[str] = []
        # check typical file locations
        for sp in search_paths:
            entries = fs.list_dir(sp)
            for name in entries:
                lower = name.lower()
                for sign in signs:
                    if sign in lower:
                        found = True
                        evidence.append(f"{sp}/{name}")
        # examine config/known files
        if fs.exists("/etc/tor/torrc") and tool == "tor":
            found = True
            evidence.append("/etc/tor/torrc")

        if found:
            findings.append({"tool": tool, "evidence": evidence})

    return findings
