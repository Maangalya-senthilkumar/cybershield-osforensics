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

# Tool categories for better organization
CATEGORY_MAP: Dict[str, str] = {
    "metasploit": "attack",
    "sqlmap": "attack",
    "hydra": "attack",
    "nmap": "network",
    "netcat": "network",
    "burpsuite": "web",
    "tor": "privacy",
    "openvpn": "privacy",
    "wireguard": "privacy",
    "proxychains": "privacy",
    "ssh": "network",
}

# Risk level priority for sorting (higher number = higher priority)
RISK_PRIORITY: Dict[str, int] = {
    "high": 3,
    "dual-use": 2,
    "privacy-infrastructure": 1,
    "infrastructure": 0,
    "unknown": -1,
}


def classify_findings(findings: List[Dict[str, object]]) -> List[Dict[str, object]]:
    out = []
    for f in findings:
        tool = f.get("tool")
        level = RISK_MAP.get(tool, "unknown")
        category = CATEGORY_MAP.get(tool, "other")
        out.append({
            "tool": tool, 
            "risk": level, 
            "category": category,
            "evidence": f.get("evidence", [])
        })

    # Sort by risk priority (high to low) then alphabetically by tool name
    out.sort(key=lambda x: (-RISK_PRIORITY.get(x["risk"], -1), x["tool"].lower()))
    return out
