#!/usr/bin/env python3
import subprocess
import sys
import shutil
from pathlib import Path

PLUGINS = [
    ("Boot time", "linux.boottime.Boottime"),
    ("Running processes", "linux.pslist.PsList"),
    ("Process tree", "linux.pstree.PsTree"),
    ("Bash history", "linux.bash.Bash"),
    ("IP addresses", "linux.ip.Addr"),
    ("Network interfaces", "linux.ip.Link"),
    ("Mapped ELF files / shared binaries", "linux.elfs.Elfs"),
    ("Loaded kernel modules", "linux.lsmod.Lsmod"),
]

def run_cmd(cmd):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
        return result.returncode, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "Command timed out"

def find_vol():
    vol_path = shutil.which("vol")
    if vol_path:
        return vol_path
    return None

def print_header(title):
    print("\n" + "=" * 80)
    print(title.upper())
    print("=" * 80)

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <memory_dump>")
        sys.exit(1)

    memdump = Path(sys.argv[1])
    if not memdump.exists():
        print(f"[-] Memory dump not found: {memdump}")
        sys.exit(1)

    vol = find_vol()
    if not vol:
        print("[-] Could not find 'vol' in PATH. Activate the correct venv first.")
        sys.exit(1)

    print(f"[+] Using Volatility: {vol}")
    print(f"[+] Memory dump: {memdump}")

    for title, plugin in PLUGINS:
        print_header(title)
        code, out, err = run_cmd([vol, "-f", str(memdump), plugin])

        if out.strip():
            print(out.strip())
        else:
            print("[!] No stdout output")

        if code != 0:
            print("\n[!] Plugin returned non-zero exit code:", code)
            if err.strip():
                print("[stderr]")
                print(err.strip())

if __name__ == "__main__":
    main()
