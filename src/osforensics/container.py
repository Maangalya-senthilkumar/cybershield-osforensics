"""Container forensics heuristics.

Best-effort container analysis for Docker/Podman/containerd/Kubernetes artifacts.
Works on mounted filesystems and live scans; image-mode support is limited to
paths accessible through FilesystemAccessor.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict, List, Optional, Tuple

from .extractor import FilesystemAccessor


_OFFENSIVE_TOOLS = (
    "nmap", "metasploit", "msfconsole", "sqlmap", "hydra", "mimikatz",
    "netcat", "nc ", "nikto", "aircrack", "john", "hashcat",
)

_CMD_RE = re.compile(r"\b(?:nmap|sqlmap|hydra|scp|ssh|curl|wget|nc|netcat|python\s+-m\s+http\.server|socat)\b[^\n\r]{0,140}", re.IGNORECASE)
_IP_PORT_RE = re.compile(r"\b(?:(?:\d{1,3}\.){3}\d{1,3}):(\d{1,5})\b")


def _read_text(fs: FilesystemAccessor, path: str, max_bytes: int = 1_000_000) -> str:
    raw = fs.read_file(path, max_bytes=max_bytes)
    if not raw:
        return ""
    return raw.decode("utf-8", errors="ignore")


def _read_json(fs: FilesystemAccessor, path: str, max_bytes: int = 2_000_000) -> Optional[Dict[str, Any]]:
    txt = _read_text(fs, path, max_bytes=max_bytes)
    if not txt:
        return None
    try:
        return json.loads(txt)
    except Exception:
        return None


def _ts(s: str) -> str:
    if not s:
        return ""
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).isoformat(timespec="seconds")
    except Exception:
        return s


def _safe_list_dir(fs: FilesystemAccessor, path: str) -> List[str]:
    try:
        return fs.list_dir(path)
    except Exception:
        return []


def _tool_hits(text: str) -> List[str]:
    low = (text or "").lower()
    out: List[str] = []
    for t in _OFFENSIVE_TOOLS:
        if t in low and t not in out:
            out.append(t.strip())
    return out


def _extract_cmds(text: str, limit: int = 12) -> List[str]:
    out: List[str] = []
    for m in _CMD_RE.findall(text or ""):
        v = m.strip()
        if v and v not in out:
            out.append(v)
        if len(out) >= limit:
            break
    return out


def _classify_role(cmd_blob: str, tools: List[str], net_hits: List[str]) -> Tuple[str, List[str]]:
    low = (cmd_blob or "").lower()
    reasons: List[str] = []
    if any(x in low for x in ("nmap", "sqlmap", "nikto")):
        reasons.append("recon_commands")
    if any(x in low for x in ("exploit", "metasploit", "msfconsole")):
        reasons.append("exploit_tools")
    if any(x in low for x in ("nc ", "netcat", "socat", "reverse shell", "bash -i")):
        reasons.append("c2_pattern")
    if any(x in low for x in ("scp", "rsync", "curl", "wget")):
        reasons.append("transfer_commands")
    if tools:
        reasons.append("offensive_tools")
    if len(net_hits) >= 2:
        reasons.append("external_connections")

    if "c2_pattern" in reasons:
        return "C2 Infrastructure", reasons
    if "exploit_tools" in reasons:
        return "Exploit Container", reasons
    if "recon_commands" in reasons:
        return "Recon Container", reasons
    if "transfer_commands" in reasons:
        return "Data Exfiltration Node", reasons
    return "General Purpose", reasons


def analyze_containers(fs: FilesystemAccessor) -> Dict[str, Any]:
    """Return structured container-forensics report."""
    runtime_paths = {
        "docker": ["/var/lib/docker", "/run/docker", "/var/run/docker.sock"],
        "containerd": ["/run/containerd", "/var/lib/containerd"],
        "crio": ["/run/crio", "/var/lib/containers/storage/overlay-containers"],
        "podman": ["/var/lib/podman", "/run/podman", "/var/lib/containers/storage"],
        "kubernetes": ["/etc/kubernetes", "/var/lib/kubelet", "/var/lib/etcd"],
    }

    detected_runtime = []
    runtime_evidence = []
    for name, paths in runtime_paths.items():
        hits = [p for p in paths if fs.exists(p)]
        if hits:
            detected_runtime.append(name)
            runtime_evidence.extend(hits)

    docker_present = any(r == "docker" for r in detected_runtime)

    containers: List[Dict[str, Any]] = []
    images: Dict[str, Dict[str, Any]] = {}
    privilege_findings: List[Dict[str, Any]] = []
    host_interactions: List[Dict[str, Any]] = []
    offensive_findings: List[Dict[str, Any]] = []
    attack_chain: List[Dict[str, Any]] = []
    timeline: List[Dict[str, Any]] = []
    fs_changes: List[Dict[str, Any]] = []
    deleted_containers: List[Dict[str, Any]] = []
    escape_indicators: List[str] = []
    network_events: List[Dict[str, Any]] = []

    if docker_present:
        cfg_root = "/var/lib/docker/containers"
        cids = [x for x in _safe_list_dir(fs, cfg_root) if len(x) >= 12][:120]

        # Docker repositories/image mapping
        repos = _read_json(fs, "/var/lib/docker/image/overlay2/repositories.json") or {}
        rep_repos = repos.get("Repositories", {}) if isinstance(repos, dict) else {}
        for image_name, tags in rep_repos.items():
            if isinstance(tags, dict):
                for tag, digest in tags.items():
                    key = f"{image_name}:{tag}"
                    images[key] = {
                        "image": key,
                        "digest": str(digest),
                        "source": "docker-local-store",
                        "build_history": [],
                        "suspicious_commands": [],
                    }

        known_overlay_ids = set()

        for cid in cids:
            cdir = f"{cfg_root}/{cid}"
            cfg = _read_json(fs, f"{cdir}/config.v2.json") or {}
            hostcfg = _read_json(fs, f"{cdir}/hostconfig.json") or {}
            if not cfg:
                continue

            state = cfg.get("State") or {}
            conf = cfg.get("Config") or {}
            graph = cfg.get("GraphDriver") or {}
            gdata = graph.get("Data") or {}
            net = cfg.get("NetworkSettings") or {}
            networks = net.get("Networks") or {}
            mounts = cfg.get("MountPoints") or {}

            name = str(cfg.get("Name") or "").lstrip("/") or cid[:12]
            image = str(conf.get("Image") or cfg.get("Image") or "unknown")
            image_id = str(cfg.get("Image") or "")
            created = _ts(str(cfg.get("Created") or ""))
            started = _ts(str(state.get("StartedAt") or ""))
            finished = _ts(str(state.get("FinishedAt") or ""))
            status = str(state.get("Status") or ("running" if state.get("Running") else "stopped"))
            restart_count = int(state.get("RestartCount") or 0)

            entrypoint = conf.get("Entrypoint") or []
            cmd = conf.get("Cmd") or []
            cmd_str = " ".join([str(x) for x in (entrypoint + cmd)])

            log_path = str(cfg.get("LogPath") or "")
            log_text = _read_text(fs, log_path, max_bytes=500_000) if log_path else ""
            cmd_fragments = _extract_cmds(cmd_str + "\n" + log_text, limit=10)

            exposed_ports = sorted((conf.get("ExposedPorts") or {}).keys())
            ip_addrs: List[str] = []
            bridge_names: List[str] = []
            for nname, ncfg in networks.items():
                bridge_names.append(str(nname))
                ip = str((ncfg or {}).get("IPAddress") or "")
                if ip:
                    ip_addrs.append(ip)

            mounts_list: List[str] = []
            for mname, mobj in mounts.items():
                src = str((mobj or {}).get("Source") or "")
                dst = str((mobj or {}).get("Destination") or mname)
                if src:
                    mounts_list.append(f"{src} -> {dst}")

            binds = [str(x) for x in (hostcfg.get("Binds") or [])]
            mounts_list.extend(binds)

            privileged = bool(hostcfg.get("Privileged", False))
            host_network = str(hostcfg.get("NetworkMode") or "") == "host"
            host_pid = str(hostcfg.get("PidMode") or "") == "host"
            cap_add = [str(x) for x in (hostcfg.get("CapAdd") or [])]
            has_sys_admin = any("SYS_ADMIN" in c for c in cap_add)
            has_docker_sock = any("docker.sock" in m for m in mounts_list)

            net_hits = [m.group(0) for m in _IP_PORT_RE.finditer(log_text)][:20]
            tools = _tool_hits(cmd_str + "\n" + log_text)

            risk = 0
            risk_reasons = []
            if privileged:
                risk += 3
                risk_reasons.append("privileged")
            if host_network:
                risk += 2
                risk_reasons.append("host_network")
            if host_pid:
                risk += 2
                risk_reasons.append("host_pid")
            if has_sys_admin:
                risk += 2
                risk_reasons.append("cap_sys_admin")
            if has_docker_sock:
                risk += 3
                risk_reasons.append("docker_socket_mounted")
            if tools:
                risk += 2
                risk_reasons.append("offensive_tools")
            if net_hits:
                risk += 1
                risk_reasons.append("external_connections")

            role, role_reasons = _classify_role(cmd_str + "\n" + "\n".join(cmd_fragments), tools, net_hits)

            upper_dir = str(gdata.get("UpperDir") or "")
            if upper_dir:
                known_overlay_ids.add(upper_dir.split("/")[-2] if "/" in upper_dir else upper_dir)
                changed = []
                for e in _safe_list_dir(fs, upper_dir)[:20]:
                    changed.append(f"{upper_dir.rstrip('/')}/{e}")
                if changed:
                    fs_changes.append({
                        "container": name,
                        "upperdir": upper_dir,
                        "modified_files": changed[:12],
                    })

            if risk_reasons:
                privilege_findings.append({
                    "container": name,
                    "severity": "high" if risk >= 5 else "medium",
                    "reasons": risk_reasons,
                })
            if mounts_list:
                host_interactions.append({
                    "container": name,
                    "mounts": mounts_list[:15],
                })
            if tools:
                offensive_findings.append({
                    "container": name,
                    "tools": tools,
                })

            attack_chain.append({
                "container": name,
                "role": role,
                "reasons": role_reasons,
            })

            if created:
                timeline.append({"timestamp": created, "event": f"container_created:{name}"})
            if started:
                timeline.append({"timestamp": started, "event": f"container_started:{name}"})
            if finished:
                timeline.append({"timestamp": finished, "event": f"container_stopped:{name}"})

            for h in net_hits[:8]:
                network_events.append({
                    "container": name,
                    "connection": h,
                })

            containers.append({
                "id": cid,
                "name": name,
                "image": image,
                "image_id": image_id,
                "created": created,
                "started": started,
                "stopped": finished,
                "status": status,
                "restart_count": restart_count,
                "command": cmd_str,
                "commands_executed": cmd_fragments,
                "log_path": log_path,
                "networks": bridge_names,
                "ip_addresses": ip_addrs,
                "exposed_ports": exposed_ports,
                "external_connections": net_hits[:10],
                "mounts": mounts_list[:20],
                "privileged": privileged,
                "host_network": host_network,
                "host_pid": host_pid,
                "cap_add": cap_add,
                "risk_score": min(10.0, round(risk * 1.1, 1)),
                "risk_reasons": risk_reasons,
                "role": role,
            })

        # Deleted/orphan overlay heuristics
        overlay_dirs = _safe_list_dir(fs, "/var/lib/docker/overlay2")
        for od in overlay_dirs[:200]:
            if od == "l":
                continue
            if od not in known_overlay_ids and len(od) > 10:
                deleted_containers.append({
                    "artifact": f"/var/lib/docker/overlay2/{od}",
                    "detail": "Overlay layer directory not referenced by active container metadata.",
                })
                if len(deleted_containers) >= 20:
                    break

    # Kubernetes / orchestration indicators
    k8s_paths = [p for p in ("/etc/kubernetes", "/var/lib/kubelet", "/var/lib/etcd", "/etc/kubernetes/manifests") if fs.exists(p)]
    pod_names = _safe_list_dir(fs, "/var/lib/kubelet/pods")[:80] if fs.exists("/var/lib/kubelet/pods") else []
    manifests = _safe_list_dir(fs, "/etc/kubernetes/manifests")[:40] if fs.exists("/etc/kubernetes/manifests") else []
    suspicious_pods = [p for p in pod_names if any(k in p.lower() for k in ("miner", "crypto", "hack", "recon", "c2"))][:10]

    # Global escape indicators
    if any(any("docker.sock" in m for m in c.get("mounts", [])) for c in containers):
        escape_indicators.append("docker_socket_mounted")
    if any(c.get("privileged") for c in containers):
        escape_indicators.append("privileged_container")
    if any(any("SYS_ADMIN" in x for x in c.get("cap_add", [])) for c in containers):
        escape_indicators.append("cap_sys_admin")

    # Image enrichment from imagedb history where possible
    for c in containers:
        image_id = str(c.get("image_id") or "")
        if image_id.startswith("sha256:"):
            digest = image_id.split(":", 1)[1]
            meta = _read_json(fs, f"/var/lib/docker/image/overlay2/imagedb/content/sha256/{digest}")
            if meta:
                history = []
                suspicious = []
                for h in (meta.get("history") or [])[:20]:
                    cmd = str((h or {}).get("created_by") or "")
                    if cmd:
                        history.append(cmd)
                        if _tool_hits(cmd) or "nc " in cmd.lower():
                            suspicious.append(cmd)
                images[c.get("image", c.get("image_id", "unknown"))] = {
                    "image": c.get("image", "unknown"),
                    "digest": image_id,
                    "source": "docker-imagedb",
                    "build_history": history[:12],
                    "suspicious_commands": suspicious[:8],
                }

    containers.sort(key=lambda x: (x.get("risk_score") or 0), reverse=True)
    timeline.sort(key=lambda x: x.get("timestamp") or "")

    detected = bool(detected_runtime or containers or k8s_paths or deleted_containers)
    active = sum(1 for c in containers if c.get("status") == "running")
    max_risk = max([c.get("risk_score") or 0 for c in containers], default=0)

    return {
        "detected": detected,
        "runtime": {
            "detected": detected_runtime,
            "primary": detected_runtime[0] if detected_runtime else "none",
            "evidence": runtime_evidence,
            "version": "unknown",
        },
        "inventory": containers,
        "images": list(images.values()),
        "filesystem": {
            "changes": fs_changes,
            "deleted_container_artifacts": deleted_containers,
        },
        "execution": {
            "commands": [
                {"container": c.get("name"), "commands": c.get("commands_executed", [])}
                for c in containers if c.get("commands_executed")
            ],
        },
        "network": {
            "connections": network_events[:100],
            "bridges": sorted({b for c in containers for b in (c.get("networks") or [])}),
        },
        "privilege": {
            "findings": privilege_findings,
            "escape_indicators": escape_indicators,
        },
        "host_interactions": host_interactions,
        "offensive_tools": offensive_findings,
        "deleted": deleted_containers,
        "timeline": timeline[:300],
        "kubernetes": {
            "detected": bool(k8s_paths),
            "evidence": k8s_paths,
            "pods": pod_names,
            "suspicious_pods": suspicious_pods,
            "manifests": manifests,
            "namespaces": [],
            "cluster_roles": [],
        },
        "risk": {
            "max_score": max_risk,
            "high_risk_containers": [c for c in containers if (c.get("risk_score") or 0) >= 7],
            "container_count": len(containers),
            "active_count": active,
        },
        "attack_chain": attack_chain,
    }
