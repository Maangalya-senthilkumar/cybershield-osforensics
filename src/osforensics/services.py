"""Service Detection Analysis.

Enumerates and categorises system services by examining:
  - systemd unit files  (/lib/systemd/system, /usr/lib/systemd/system, /etc/systemd/system)
  - SysV init scripts   (/etc/init.d, /etc/rc*.d)
  - Known config-file   footprints for common server software

Each service record exposes:
  name, display_name, description, category, state, exec_start, run_user,
  severity, source, flags, unit_path

Categories
----------
  web_server, ftp_server, database, mail, dns, dhcp, ssh,
  remote_access, file_sharing, vpn, container, proxy,
  monitoring, security, crypto_mining, system, other
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from .extractor import FilesystemAccessor


# ─── Result factory ────────────────────────────────────────────────────────────

def _service(
    name: str,
    display_name: str,
    description: str,
    category: str,
    state: str,
    exec_start: str,
    run_user: str,
    severity: str = "info",
    source: str = "systemd",
    flags: Optional[List[str]] = None,
    unit_path: str = "",
) -> Dict:
    return {
        "name":         name,
        "display_name": display_name,
        "description":  description,
        "category":     category,
        "state":        state,
        "exec_start":   exec_start,
        "run_user":     run_user,
        "severity":     severity,
        "source":       source,
        "flags":        flags or [],
        "unit_path":    unit_path,
    }


def _read(fs: FilesystemAccessor, path: str) -> Optional[str]:
    raw = fs.read_file(path, max_bytes=128_000)
    if raw is None:
        return None
    return raw.decode("utf-8", errors="replace")


# ─── Severity helpers ──────────────────────────────────────────────────────────

_SEV_ORDER: Dict[str, int] = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _max_sev(a: str, b: str) -> str:
    return a if _SEV_ORDER.get(a, 4) <= _SEV_ORDER.get(b, 4) else b


# ─── Systemd unit file parser ──────────────────────────────────────────────────

def _parse_unit(text: str) -> Dict[str, Dict[str, str]]:
    """Parse a systemd unit file into {section: {key: value}}."""
    sections: Dict[str, Dict[str, str]] = {}
    cur: Optional[str] = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith(("#", ";")):
            continue
        if line.startswith("[") and line.endswith("]"):
            cur = line[1:-1].strip()
            sections.setdefault(cur, {})
        elif "=" in line and cur is not None:
            key, _, val = line.partition("=")
            sections[cur][key.strip()] = val.strip()
    return sections


# ─── Service categorisation ────────────────────────────────────────────────────

# (regex on lower-cased unit name, category, display_name_hint, base_severity)
_CATEGORY_RULES: List[Tuple[str, str, str, str]] = [
    # Web servers
    (r"^nginx$",                              "web_server",    "Nginx",                   "info"),
    (r"^apache2$|^httpd$",                    "web_server",    "Apache HTTP Server",      "info"),
    (r"^lighttpd$",                           "web_server",    "Lighttpd",                "info"),
    (r"^caddy$",                              "web_server",    "Caddy",                   "info"),
    (r"^h2o$",                                "web_server",    "H2O",                     "info"),
    (r"^cherokee$",                           "web_server",    "Cherokee",                "info"),
    (r"^trafficserver$",                      "web_server",    "Apache Traffic Server",   "info"),

    # FTP servers (inherently risky — plaintext auth)
    (r"^vsftpd$",                             "ftp_server",    "vsftpd",                  "high"),
    (r"^proftpd$",                            "ftp_server",    "ProFTPD",                 "high"),
    (r"^pure-ftpd$",                          "ftp_server",    "Pure-FTPd",               "high"),
    (r"^wu-ftpd$",                            "ftp_server",    "WU-FTPd",                 "high"),
    (r"^ftpd$",                               "ftp_server",    "FTP Daemon",              "high"),

    # Databases
    (r"^mysql$|^mysqld$",                     "database",      "MySQL",                   "info"),
    (r"^mariadb$",                            "database",      "MariaDB",                 "info"),
    (r"^postgresql(@.*)?$",                   "database",      "PostgreSQL",              "info"),
    (r"^mongod$|^mongodb$",                   "database",      "MongoDB",                 "info"),
    (r"^redis(-server)?$",                    "database",      "Redis",                   "medium"),
    (r"^memcached$",                          "database",      "Memcached",               "medium"),
    (r"^elasticsearch$",                      "database",      "Elasticsearch",           "medium"),
    (r"^influxdb$",                           "database",      "InfluxDB",                "info"),
    (r"^cassandra$",                          "database",      "Apache Cassandra",        "info"),
    (r"^couchdb$",                            "database",      "CouchDB",                 "info"),
    (r"^clickhouse(-server)?$",               "database",      "ClickHouse",              "info"),
    (r"^neo4j$",                              "database",      "Neo4j",                   "info"),
    (r"^cockroach$",                          "database",      "CockroachDB",             "info"),
    (r"^rethinkdb$",                          "database",      "RethinkDB",               "info"),
    (r"^minio$",                              "database",      "MinIO Object Storage",    "info"),

    # Mail
    (r"^postfix$",                            "mail",          "Postfix MTA",             "info"),
    (r"^dovecot$",                            "mail",          "Dovecot IMAP/POP3",       "info"),
    (r"^exim4?$",                             "mail",          "Exim MTA",                "info"),
    (r"^sendmail$",                           "mail",          "Sendmail",                "medium"),
    (r"^amavis(d)?$",                         "mail",          "Amavis",                  "info"),
    (r"^spamassassin$",                       "mail",          "SpamAssassin",            "info"),
    (r"^opendkim$",                           "mail",          "OpenDKIM",                "info"),
    (r"^opendmarc$",                          "mail",          "OpenDMARC",               "info"),

    # DNS
    (r"^named$|^bind9?$",                     "dns",           "BIND DNS",                "info"),
    (r"^dnsmasq$",                            "dns",           "dnsmasq",                 "info"),
    (r"^unbound$",                            "dns",           "Unbound",                 "info"),
    (r"^knotd?$",                             "dns",           "Knot DNS",                "info"),
    (r"^pdns(-server)?$",                     "dns",           "PowerDNS Authoritative",  "info"),
    (r"^pdns-recursor$",                      "dns",           "PowerDNS Recursor",       "info"),
    (r"^avahi-daemon$",                       "dns",           "Avahi mDNS",              "low"),

    # DHCP
    (r"^isc-dhcp-server$|^dhcpd$",           "dhcp",          "ISC DHCP Server",         "info"),
    (r"^kea-dhcp4(-server)?$",                "dhcp",          "Kea DHCPv4",              "info"),
    (r"^kea-dhcp6(-server)?$",                "dhcp",          "Kea DHCPv6",              "info"),

    # SSH
    (r"^ssh$|^sshd$|^openssh-server$",        "ssh",           "OpenSSH Server",          "info"),

    # Remote access / desktop (many are high risk)
    (r"^xrdp$",                               "remote_access", "xRDP",                    "high"),
    (r"^vnc.*|vncserver.*",                   "remote_access", "VNC Server",              "high"),
    (r"^x11vnc$",                             "remote_access", "x11vnc",                  "high"),
    (r"^tigervnc.*",                          "remote_access", "TigerVNC",                "high"),
    (r"^teamviewer$",                         "remote_access", "TeamViewer",              "high"),
    (r"^anydesk$",                            "remote_access", "AnyDesk",                 "high"),
    (r"^rustdesk$",                           "remote_access", "RustDesk",                "medium"),
    (r"^telnet(d)?$",                         "remote_access", "Telnet (INSECURE)",        "critical"),
    (r"^inetd$|^xinetd$",                     "remote_access", "inetd/xinetd super-server","medium"),
    (r"^rsh(d)?$",                            "remote_access", "RSH (INSECURE)",           "critical"),
    (r"^rlogin(d)?$",                         "remote_access", "rlogin (INSECURE)",        "critical"),
    (r"^rexec(d)?$",                          "remote_access", "rexec (INSECURE)",         "critical"),

    # File sharing
    (r"^smbd$|^samba$",                       "file_sharing",  "Samba / SMB",             "medium"),
    (r"^nmbd$",                               "file_sharing",  "Samba NetBIOS",           "medium"),
    (r"^nfs(-kernel-server|-server)?$",       "file_sharing",  "NFS Server",              "medium"),
    (r"^rpcbind$",                            "file_sharing",  "RPC Bind",                "medium"),
    (r"^rsync$",                              "file_sharing",  "rsync daemon",            "medium"),
    (r"^glusterd$",                           "file_sharing",  "GlusterFS",               "info"),
    (r"^cephmon$|^cephosd$",                  "file_sharing",  "Ceph",                    "info"),

    # VPN
    (r"^openvpn(@.*)?$",                      "vpn",           "OpenVPN",                 "info"),
    (r"^wg-quick@.*|^wireguard$",             "vpn",           "WireGuard",               "info"),
    (r"^strongswan$|^ipsec$|^charon$",        "vpn",           "StrongSwan / IPsec",      "info"),
    (r"^xl2tpd$",                             "vpn",           "L2TP daemon",             "medium"),
    (r"^pptpd$",                              "vpn",           "PPTP (INSECURE)",          "high"),
    (r"^tincd?$",                             "vpn",           "Tinc",                    "info"),
    (r"^tailscaled$",                         "vpn",           "Tailscale",               "info"),
    (r"^zerotier-one$",                       "vpn",           "ZeroTier",                "info"),

    # Container / Virtualisation
    (r"^docker(d)?$",                         "container",     "Docker",                  "medium"),
    (r"^containerd$",                         "container",     "containerd",              "medium"),
    (r"^podman$",                             "container",     "Podman",                  "info"),
    (r"^libvirtd$",                           "container",     "libvirt",                 "info"),
    (r"^lxd$|^lxcfs$",                       "container",     "LXD / LXC",               "info"),
    (r"^k3s(-server)?$",                      "container",     "k3s Kubernetes",          "medium"),
    (r"^kubelet$",                            "container",     "Kubernetes kubelet",      "medium"),

    # Proxy / Load balancer
    (r"^squid$",                              "proxy",         "Squid Proxy",             "medium"),
    (r"^haproxy$",                            "proxy",         "HAProxy",                 "info"),
    (r"^traefik$",                            "proxy",         "Traefik",                 "info"),
    (r"^envoy$",                              "proxy",         "Envoy",                   "info"),
    (r"^varnish(d)?$",                        "proxy",         "Varnish Cache",           "info"),

    # Monitoring / Logging / Metrics
    (r"^prometheus$",                         "monitoring",    "Prometheus",              "info"),
    (r"^grafana(-server)?$",                  "monitoring",    "Grafana",                 "info"),
    (r"^prometheus-node-exporter$|^node-exporter$", "monitoring", "Node Exporter",        "info"),
    (r"^nagios(4)?$",                         "monitoring",    "Nagios",                  "info"),
    (r"^zabbix-(agent|server|proxy)$",        "monitoring",    "Zabbix",                  "info"),
    (r"^kibana$",                             "monitoring",    "Kibana",                  "info"),
    (r"^logstash$",                           "monitoring",    "Logstash",                "info"),
    (r"^rsyslog$",                            "monitoring",    "rsyslog",                 "info"),
    (r"^syslog-ng$",                          "monitoring",    "syslog-ng",               "info"),
    (r"^journald$|^systemd-journald$",        "monitoring",    "systemd-journald",        "info"),
    (r"^fluentd$|^td-agent$",                "monitoring",    "Fluentd",                 "info"),
    (r"^filebeat$",                           "monitoring",    "Filebeat",                "info"),
    (r"^metricbeat$",                         "monitoring",    "Metricbeat",              "info"),
    (r"^telegraf$",                           "monitoring",    "Telegraf",                "info"),
    (r"^loki$",                               "monitoring",    "Grafana Loki",            "info"),
    (r"^vector$",                             "monitoring",    "Vector",                  "info"),

    # Security
    (r"^fail2ban$",                           "security",      "Fail2ban",                "info"),
    (r"^ufw$",                                "security",      "UFW Firewall",            "info"),
    (r"^apparmor$",                           "security",      "AppArmor",                "info"),
    (r"^auditd$",                             "security",      "Audit Daemon",            "info"),
    (r"^aide$",                               "security",      "AIDE HIDS",               "info"),
    (r"^rkhunter$",                           "security",      "Rootkit Hunter",          "info"),
    (r"^clamd$|^clamav-daemon$",              "security",      "ClamAV",                  "info"),
    (r"^suricata$",                           "security",      "Suricata IDS/IPS",        "info"),
    (r"^snort$",                              "security",      "Snort IDS",               "info"),
    (r"^wazuh-agent$",                        "security",      "Wazuh Agent",             "info"),
    (r"^ossec(d)?$",                          "security",      "OSSEC HIDS",              "info"),
    (r"^crowdsec$",                           "security",      "CrowdSec",                "info"),

    # Crypto mining (always high risk in this context)
    (r"xmr|miner|monero|nicehash|ethminer|cpuminer|nbminer|phoenixminer|t-rex|lolminer",
                                              "crypto_mining", "Crypto Miner",            "critical"),

    # System / infrastructure (info by default, filtered later)
    (r"^cron(d)?$",                           "system",        "Cron",                    "info"),
    (r"^atd$",                                "system",        "at Daemon",               "info"),
    (r"^systemd-.*",                          "system",        "systemd Component",       "info"),
    (r"^dbus(-broker)?$",                     "system",        "D-Bus",                   "info"),
    (r"^udev$",                               "system",        "udev",                    "info"),
    (r"^networkmanager$|^network-manager$",   "system",        "NetworkManager",          "info"),
    (r"^systemd-networkd$",                   "system",        "systemd-networkd",        "info"),
    (r"^snapd$",                              "system",        "snapd",                   "low"),
    (r"^acpid$",                              "system",        "ACPI Daemon",             "info"),
    (r"^cups(-browsed)?$|^cupsd$",            "system",        "CUPS Printing",           "low"),
    (r"^bluetooth(d)?$",                      "system",        "Bluetooth",               "low"),
    (r"^modemmanager$",                       "system",        "Modem Manager",           "info"),
    (r"^polkit$|^polkitd$",                   "system",        "PolicyKit",               "info"),
    (r"^chronyd$|^ntpd$|^systemd-timesyncd$", "system",       "Time Sync",               "info"),
    (r"^ntp$",                                "system",        "NTP",                     "info"),
    (r"^wpa_supplicant$",                     "system",        "WPA Supplicant",          "info"),
    (r"^colord$",                             "system",        "Color Manager",           "info"),
    (r"^irqbalance$",                         "system",        "IRQ Balance",             "info"),
    (r"^smartd$",                             "system",        "S.M.A.R.T. Daemon",       "info"),
    (r"^lvm2-.*",                             "system",        "LVM2",                    "info"),
    (r"^mdadm$",                              "system",        "mdadm RAID",              "info"),
    (r"^fwupd$",                              "system",        "Firmware Updates",        "info"),
    (r"^packagekit$",                         "system",        "PackageKit",              "low"),
    (r"^unattended-upgrades$",                "system",        "Unattended Upgrades",     "info"),
]

_COMPILED: List[Tuple[re.Pattern, str, str, str]] = [
    (re.compile(pat, re.IGNORECASE), cat, hint, sev)
    for pat, cat, hint, sev in _CATEGORY_RULES
]


def _categorize(name: str) -> Tuple[str, str, str]:
    """Returns (category, display_name_hint, base_severity)."""
    base = re.sub(r"\.service$", "", name)
    for pat, cat, hint, sev in _COMPILED:
        if pat.search(base):
            return cat, hint, sev
    return "other", name, "info"


# ─── Risk flag assessment ──────────────────────────────────────────────────────

_UNUSUAL_PATH = re.compile(r"^(/tmp/|/dev/shm/|/var/tmp/|/run/user/|/home/[^/]+/\.)")
_SHELL_EXEC   = re.compile(r"\b(bash|sh|zsh|fish|dash|ksh|csh)\b")


def _assess_flags(exec_start: str, run_user: str, category: str) -> Tuple[List[str], str]:
    """Return (extra_flags, worst_severity_from_flags)."""
    flags: List[str] = []
    sev = "info"

    Binary = exec_start.split()[0] if exec_start else ""
    if Binary and _UNUSUAL_PATH.match(Binary):
        flags.append("unusual-exec-path")
        sev = "critical"

    if Binary and _SHELL_EXEC.search(Binary):
        flags.append("shell-exec")
        sev = _max_sev(sev, "high")

    if run_user.lower() in ("", "root", "0") and category not in ("system", "security"):
        flags.append("root-exec")
        sev = _max_sev(sev, "low")

    return flags, sev


# ─── Enabled-state resolution ──────────────────────────────────────────────────

_WANTS_DIRS = [
    "/etc/systemd/system/multi-user.target.wants",
    "/etc/systemd/system/graphical.target.wants",
    "/etc/systemd/system/default.target.wants",
    "/etc/systemd/system/sockets.target.wants",
    "/etc/systemd/system/timers.target.wants",
    "/etc/systemd/system/network.target.wants",
    "/etc/systemd/system/network-online.target.wants",
    "/etc/systemd/system/sysinit.target.wants",
    "/etc/systemd/system/basic.target.wants",
]


def _get_state(fs: FilesystemAccessor, filename: str) -> str:
    """Infer enabled / disabled / masked / static state without running systemctl."""
    # Enabled = symlink present in a wants directory
    for wants in _WANTS_DIRS:
        if fs.exists(f"{wants}/{filename}"):
            return "enabled"

    # Masked = symlink to /dev/null in /etc/systemd/system
    etc_path = f"/etc/systemd/system/{filename}"
    raw = fs.read_file(etc_path, max_bytes=16)
    if raw is not None and raw.strip() in (b"/dev/null", b"/dev/null\n"):
        return "masked"

    # Static = unit exists directly in /etc/systemd/system but no wants symlink
    if fs.exists(etc_path):
        return "static"

    return "disabled"


# ─── Systemd unit directory scanner ───────────────────────────────────────────

_UNIT_DIRS = [
    "/lib/systemd/system",
    "/usr/lib/systemd/system",
    "/etc/systemd/system",
]


def _scan_systemd(fs: FilesystemAccessor) -> List[Dict]:
    seen: Dict[str, Dict] = {}

    for unit_dir in _UNIT_DIRS:
        for filename in fs.list_dir(unit_dir):
            if not filename.endswith(".service"):
                continue
            # Skip uninstantiated template units
            if filename.endswith("@.service"):
                continue

            path = f"{unit_dir}/{filename}"
            text = _read(fs, path)
            if text is None:
                continue

            name = filename[:-len(".service")]
            sections = _parse_unit(text)
            unit_s = sections.get("Unit",    {})
            svc_s  = sections.get("Service", {})

            description = unit_s.get("Description", "")
            exec_start  = svc_s.get("ExecStart", "").lstrip("-@+!")
            run_user    = svc_s.get("User", "root")

            state = _get_state(fs, filename)
            category, display_hint, base_sev = _categorize(name)

            extra_flags, flag_sev = _assess_flags(exec_start, run_user, category)
            severity = _max_sev(base_sev, flag_sev)

            display = display_hint if display_hint != name else (description[:60] if description else name)

            if name not in seen:
                seen[name] = _service(
                    name=name,
                    display_name=display,
                    description=description,
                    category=category,
                    state=state,
                    exec_start=exec_start,
                    run_user=run_user,
                    severity=severity,
                    source="systemd",
                    flags=extra_flags,
                    unit_path=path,
                )
            else:
                # /etc/systemd/system overrides lib paths (admin-controlled)
                if unit_dir == "/etc/systemd/system":
                    seen[name]["unit_path"] = path
                    seen[name]["state"] = state

    return list(seen.values())


# ─── SysV init script scanner ─────────────────────────────────────────────────

def _scan_sysv(fs: FilesystemAccessor, skip: set) -> List[Dict]:
    """Scan /etc/init.d and rc*.d for SysV services not already known."""
    findings: List[Dict] = []

    # Determine which scripts are enabled via rc[2-5].d symlinks
    enabled: set = set()
    for entry in fs.list_dir("/etc"):
        if not re.match(r"rc[2-5]\.d$", entry):
            continue
        for link in fs.list_dir(f"/etc/{entry}"):
            if link.startswith("S"):
                enabled.add(re.sub(r"^S\d+", "", link))

    for script in fs.list_dir("/etc/init.d"):
        if script in ("README", "skeleton", "rc", "rcS", ".") or script in skip:
            continue
        path = f"/etc/init.d/{script}"
        text = _read(fs, path)
        if text is None:
            continue

        # Extract LSB description
        desc = ""
        m = re.search(r"#\s*Description:\s*(.+)", text)
        if m:
            desc = m.group(1).strip()

        state = "enabled" if script in enabled else "disabled"
        category, display_hint, base_sev = _categorize(script)
        display = display_hint if display_hint != script else (desc[:60] if desc else script)

        findings.append(_service(
            name=script,
            display_name=display,
            description=desc,
            category=category,
            state=state,
            exec_start=path,
            run_user="root",
            severity=base_sev,
            source="sysv",
            flags=[],
            unit_path=path,
        ))
    return findings


# ─── Config-file-based detection ──────────────────────────────────────────────

# (path_to_check, name, display_name, category, severity)
_CFG_INDICATORS: List[Tuple[str, str, str, str, str]] = [
    ("/etc/nginx/nginx.conf",            "nginx",        "Nginx Web Server",         "web_server",    "info"),
    ("/etc/apache2/apache2.conf",        "apache2",      "Apache HTTP Server",       "web_server",    "info"),
    ("/etc/httpd/conf/httpd.conf",       "httpd",        "Apache HTTP Server",       "web_server",    "info"),
    ("/etc/lighttpd/lighttpd.conf",      "lighttpd",     "Lighttpd",                 "web_server",    "info"),
    ("/etc/caddy/Caddyfile",             "caddy",        "Caddy",                    "web_server",    "info"),
    ("/etc/vsftpd.conf",                 "vsftpd",       "vsftpd FTP Server",        "ftp_server",    "high"),
    ("/etc/proftpd/proftpd.conf",        "proftpd",      "ProFTPD Server",           "ftp_server",    "high"),
    ("/etc/pure-ftpd/pure-ftpd.conf",    "pure-ftpd",    "Pure-FTPd Server",         "ftp_server",    "high"),
    ("/etc/mysql/my.cnf",                "mysql",        "MySQL Database",           "database",      "info"),
    ("/etc/mysql/mysql.conf.d",          "mysql",        "MySQL Database",           "database",      "info"),
    ("/etc/mysql/mariadb.conf.d",        "mariadb",      "MariaDB Database",         "database",      "info"),
    ("/etc/postgresql",                  "postgresql",   "PostgreSQL Database",      "database",      "info"),
    ("/etc/mongod.conf",                 "mongod",       "MongoDB",                  "database",      "info"),
    ("/etc/redis/redis.conf",            "redis",        "Redis",                    "database",      "medium"),
    ("/etc/memcached.conf",              "memcached",    "Memcached",                "database",      "medium"),
    ("/etc/elasticsearch",               "elasticsearch","Elasticsearch",            "database",      "medium"),
    ("/etc/influxdb/influxdb.conf",      "influxdb",     "InfluxDB",                 "database",      "info"),
    ("/etc/postfix/main.cf",             "postfix",      "Postfix MTA",              "mail",          "info"),
    ("/etc/dovecot/dovecot.conf",        "dovecot",      "Dovecot IMAP/POP3",        "mail",          "info"),
    ("/etc/exim4",                       "exim4",        "Exim MTA",                 "mail",          "info"),
    ("/etc/bind/named.conf",             "named",        "BIND DNS",                 "dns",           "info"),
    ("/etc/dnsmasq.conf",                "dnsmasq",      "dnsmasq DNS/DHCP",         "dns",           "info"),
    ("/etc/unbound/unbound.conf",        "unbound",      "Unbound DNS",              "dns",           "info"),
    ("/etc/dhcp/dhcpd.conf",             "dhcpd",        "ISC DHCP Server",          "dhcp",          "info"),
    ("/etc/samba/smb.conf",              "samba",        "Samba / SMB",              "file_sharing",  "medium"),
    ("/etc/exports",                     "nfs",          "NFS Server",               "file_sharing",  "medium"),
    ("/etc/nfs.conf",                    "nfs",          "NFS Server",               "file_sharing",  "medium"),
    ("/etc/openvpn",                     "openvpn",      "OpenVPN",                  "vpn",           "info"),
    ("/etc/wireguard",                   "wireguard",    "WireGuard",                "vpn",           "info"),
    ("/etc/strongswan.conf",             "strongswan",   "StrongSwan / IPsec",       "vpn",           "info"),
    ("/etc/xrdp/xrdp.ini",              "xrdp",         "xRDP Remote Desktop",      "remote_access", "high"),
    ("/etc/squid/squid.conf",            "squid",        "Squid Proxy",              "proxy",         "medium"),
    ("/etc/haproxy/haproxy.cfg",         "haproxy",      "HAProxy",                  "proxy",         "info"),
    ("/etc/traefik",                     "traefik",      "Traefik",                  "proxy",         "info"),
    ("/etc/fail2ban/jail.conf",          "fail2ban",     "Fail2ban",                 "security",      "info"),
    ("/etc/audit/auditd.conf",           "auditd",       "audit daemon",             "security",      "info"),
    ("/etc/docker",                      "docker",       "Docker",                   "container",     "medium"),
    ("/etc/prometheus",                  "prometheus",   "Prometheus",               "monitoring",    "info"),
    ("/etc/grafana/grafana.ini",         "grafana",      "Grafana",                  "monitoring",    "info"),
    ("/etc/nagios4",                     "nagios4",      "Nagios",                   "monitoring",    "info"),
    ("/etc/zabbix",                      "zabbix",       "Zabbix",                   "monitoring",    "info"),
]


def _scan_cfg_indicators(fs: FilesystemAccessor, skip: set) -> List[Dict]:
    found: List[Dict] = []
    for cfg_path, name, display_name, category, base_sev in _CFG_INDICATORS:
        if name in skip:
            continue
        if fs.exists(cfg_path):
            found.append(_service(
                name=name,
                display_name=display_name,
                description=f"Detected via configuration file {cfg_path}",
                category=category,
                state="detected",
                exec_start="",
                run_user="unknown",
                severity=base_sev,
                source="detected",
                flags=["config-only"],
                unit_path=cfg_path,
            ))
    return found


# ─── Post-processing: suspicious / high-risk flagging ─────────────────────────

def _flag_suspicious(services: List[Dict]) -> None:
    for svc in services:
        cat  = svc.get("category", "")
        name = svc.get("name", "").lower()
        exec_s = svc.get("exec_start", "")

        # Crypto mining is always critical
        if cat == "crypto_mining":
            svc["severity"] = "critical"
            if "crypto-miner" not in svc["flags"]:
                svc["flags"].append("crypto-miner")

        # FTP servers — plaintext auth
        if cat == "ftp_server":
            if "unencrypted-protocol" not in svc["flags"]:
                svc["flags"].append("unencrypted-protocol")
            svc["severity"] = _max_sev(svc["severity"], "high")

        # Telnet / rsh / rlogin — deprecated plaintext protocols
        if cat == "remote_access" and any(x in name for x in ("telnet", "rsh", "rlogin", "rexec")):
            if "deprecated-protocol" not in svc["flags"]:
                svc["flags"].append("deprecated-protocol")
            svc["severity"] = "critical"

        # VNC — unencrypted by default
        if cat == "remote_access" and "vnc" in name:
            if "unencrypted-protocol" not in svc["flags"]:
                svc["flags"].append("unencrypted-protocol")
            svc["severity"] = _max_sev(svc["severity"], "high")

        # xRDP — high risk remote access
        if name == "xrdp":
            svc["severity"] = _max_sev(svc["severity"], "high")

        # PPTP VPN — broken encryption
        if cat == "vpn" and "pptp" in name:
            if "deprecated-protocol" not in svc["flags"]:
                svc["flags"].append("deprecated-protocol")
            svc["severity"] = _max_sev(svc["severity"], "high")

        # Databases without auth that are externally accessible
        if cat == "database" and name in ("redis", "memcached", "elasticsearch", "mongodb", "mongod"):
            if svc.get("state") == "enabled":
                if "potential-no-auth" not in svc["flags"]:
                    svc["flags"].append("potential-no-auth")
                svc["severity"] = _max_sev(svc["severity"], "medium")

        # Exec from world-writable or temp paths
        if exec_s:
            Binary = exec_s.split()[0]
            if _UNUSUAL_PATH.match(Binary):
                if "unusual-exec-path" not in svc["flags"]:
                    svc["flags"].append("unusual-exec-path")
                svc["severity"] = "critical"


# ─── Main entry point ──────────────────────────────────────────────────────────

def detect_services(fs: FilesystemAccessor) -> List[Dict]:
    """Enumerate all detected services from the filesystem image."""
    systemd_svcs = _scan_systemd(fs)
    known = {s["name"] for s in systemd_svcs}

    for svc in _scan_sysv(fs, skip=known):
        systemd_svcs.append(svc)
        known.add(svc["name"])

    for svc in _scan_cfg_indicators(fs, skip=known):
        systemd_svcs.append(svc)

    _flag_suspicious(systemd_svcs)

    _STATE_ORDER = {"enabled": 0, "static": 1, "indirect": 2, "detected": 3, "disabled": 4, "masked": 5}

    systemd_svcs.sort(key=lambda s: (
        _SEV_ORDER.get(s["severity"], 4),
        _STATE_ORDER.get(s["state"], 6),
        s["name"],
    ))
    return systemd_svcs
