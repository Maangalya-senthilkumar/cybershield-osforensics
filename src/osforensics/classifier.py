"""Simple classification of detected tools/activities into risk categories.

The classifier is conservative and rule-based: certain tools are high-risk
by default (exploit frameworks), others are dual-use (nmap), and some are
privacy infrastructure (tor) which may be benign or suspicious depending on
context.
"""
from typing import Dict, List

RISK_MAP: Dict[str, str] = {
    "metasploit": "high",
    "sqlmap": "high",
    "hydra": "high",
    "nmap": "dual-use",
    "netcat": "dual-use",
    "burpsuite": "dual-use",
    "tor": "privacy-infrastructure",
    "openvpn": "privacy-infrastructure",
    "wireguard": "privacy-infrastructure",
    "proxychains": "dual-use",
    "ssh": "infrastructure",
}


def classify_findings(findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
    out = []
    for f in findings:
        tool = f.get("tool")
        level = RISK_MAP.get(tool, "unknown")
        out.append({"tool": tool, "risk": level, "evidence": f.get("evidence", [])})
    return out
