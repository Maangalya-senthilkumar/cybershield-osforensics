# Feature: Advanced Forensic Agent Toolkit

## Overview
The "Advanced Forensic Agent Toolkit" expands the investigation agent's capabilities by bridging the gap between the backend forensic modules and the agent's interactive reasoning layer. This allows examiners to perform deep, automated analysis using natural language.

## Key Capabilities

### 1. Multimedia & Steganography Analysis
The agent can now scan directories for images, video, and audio files to extract:
- **EXIF Metadata**: Device information, timestamps, and GPS locations (with Google Maps links).
- **Steganography Indicators**: Detects appended data, high entropy, and size anomalies that suggest hidden payloads.
- **Tampering Detection**: Compares metadata timestamps with filesystem metadata to find discrepancies.
- **Audio/Video Tagging**: Extracts encoder information and embedded markers.

### 2. Specialized OS Forensics (Tails OS)
Dedicated heuristics for detecting and analyzing Tails OS (The Amnesic Incognito Live System):
- **Persistence Detection**: Identifies Tails-specific encrypted persistence volumes.
- **Amnesia Verification**: Checks for indicators of privacy-oriented system usage.

### 3. Configuration & Security Auditing
Automated auditing of critical system configurations:
- **Hardening Checks**: Audits SSH (`sshd_config`), `sudoers`, and PAM for misconfigurations.
- **Firewall Status**: Inspects IPtables and UFW rules for dangerous open ports.
- **DNS/Network Integrity**: Detects rogue DNS servers in `resolv.conf` and hosts poisoning in `/etc/hosts`.

### 4. Advanced File Carving
Beyond simple directory listing, the agent can now attempt to carve deleted files from unallocated space or image headers, providing the contents of recovered evidence directly to the examiner.

## Next Steps
1. Approve the [Implementation Plan](file:///home/dragon/.gemini/antigravity/brain/ed5ad06a-e384-46f3-9003-71734ae066fe/implementation_plan.md).
2. Execute the tool registrations in `agent_tools.py`.
3. Verify via the Investigation Agent panel.