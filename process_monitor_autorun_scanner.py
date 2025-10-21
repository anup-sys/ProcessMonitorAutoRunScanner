#!/usr/bin/env python3
"""
Process Monitor + AutoRun Scanner (defensive)
============================================

- Lists running processes (PID, PPID, user, exe, cmdline, network sockets summary).
- Flags potentially suspicious processes by simple heuristics.
- Enumerates common autorun / startup locations for Windows, Linux, macOS.
- Writes a timestamped report into ./reports/report_YYYYMMDD_HHMMSS.txt
- Optionally writes a JSON export.

Usage:
    python process_monitor_autorun_scanner.py
    python process_monitor_autorun_scanner.py --json

Notes:
- Read-only. Does not modify system state.
- Run with appropriate privileges to see all processes (sudo/admin recommended but not required).
"""

import os
import sys
import platform
import json
import psutil
import getpass
import datetime
import subprocess
from pathlib import Path

# -------------------------
# Configuration / heuristics
# -------------------------
TMP_PATH_KEYWORDS = [
    "/tmp",
    "/var/tmp",
    "\\AppData\\Local\\Temp",
    "\\Local\\Temp",
    "/dev/shm",
]
PARENT_PID_FLAG = 1  # ppid==1 (or on windows: pid where parent is services/explorer) can be suspicious for daemons started oddly
WHITELISTED_SYSTEM_NAMES = {
    # Common system processes that legitimately have ppid 1
    "systemd",
    "init",
    "System",
    "services.exe",
    "wininit.exe",
    "launchd",
}

REPORT_DIR = Path("reports")
REPORT_DIR.mkdir(exist_ok=True)

# -------------------------
# Helpers
# -------------------------
def timestamp():
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def safe_text(s):
    try:
        return str(s)
    except Exception:
        return "<unreadable>"

# -------------------------
# Process listing and checks
# -------------------------
def gather_process_info():
    procs = []
    for p in psutil.process_iter(attrs=["pid", "ppid", "name", "username", "cmdline", "exe"]):
        info = p.info
        # add network connections summary (count) if accessible
        conn_count = None
        try:
            conn_count = len(p.connections(kind="inet"))
        except Exception:
            conn_count = None

        proc = {
            "pid": info.get("pid"),
            "ppid": info.get("ppid"),
            "name": info.get("name"),
            "username": info.get("username"),
            "cmdline": safe_text(info.get("cmdline")),
            "exe": safe_text(info.get("exe")),
            "connections": conn_count,
        }
        procs.append(proc)
    return procs

def is_running_from_tmp(exe_path):
    if not exe_path:
        return False
    low = exe_path.lower()
    for kw in TMP_PATH_KEYWORDS:
        if kw.lower() in low:
            return True
    return False

def flag_suspicious_processes(processes):
    flagged = []
    for p in processes:
        reasons = []
        name = (p.get("name") or "").lower()
        exe = p.get("exe") or ""
        ppid = p.get("ppid")

        # missing exe path (packed/ephemeral processes)
        if not exe or exe in ("None", "<unreadable>"):
            reasons.append("missing_exe_path")

        # running from tmp
        if is_running_from_tmp(exe):
            reasons.append("running_from_temp")

        # parent is PID 1 (or None) and process not in whitelist
        if ppid in (1, 0, None):
            if (p.get("name") or "") not in WHITELISTED_SYSTEM_NAMES:
                reasons.append(f"ppid_is_{ppid}")

        # network connections present
        if p.get("connections"):
            # if it has connections and runs from tmp or missing exe, it's more suspicious
            if is_running_from_tmp(exe) or not exe:
                reasons.append("network_and_temp_or_missing_exe")

        if reasons:
            flagged.append({"process": p, "reasons": reasons})
    return flagged

# -------------------------
# Autorun / startup detection
# -------------------------
def get_platform():
    pf = platform.system().lower()
    if "windows" in pf:
        return "windows"
    if "darwin" in pf:
        return "macos"
    if "linux" in pf:
        return "linux"
    return pf

# Windows: registry Run keys + startup folder
def scan_startup_windows():
    results = []
    try:
        import winreg
    except Exception:
        results.append({"location": "winreg", "error": "winreg unavailable (run on Windows with python installed from MS or use pywin32)"})
        return results

    RUN_REG_PATHS = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]

    for hive, path in RUN_REG_PATHS:
        try:
            with winreg.OpenKey(hive, path) as key:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        results.append({"location": f"registry::{path}", "name": name, "command": value})
                        i += 1
                    except OSError:
                        break
        except Exception as e:
            results.append({"location": f"registry::{path}", "error": str(e)})

    # startup folders
    try:
        appdata = os.environ.get("APPDATA")
        if appdata:
            startup_path = Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            if startup_path.exists():
                for f in startup_path.iterdir():
                    results.append({"location": f"startup_folder::{startup_path}", "entry": str(f)})
    except Exception as e:
        results.append({"location": "startup_folder", "error": str(e)})

    return results

# Linux: cron, systemd units (scan unit files), ~/.config/autostart, /etc/rc.local
def scan_startup_linux():
    results = []
    # crontab -l for current user
    try:
        out = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=False)
        if out.returncode == 0:
            results.append({"location": "crontab::user", "content": out.stdout.strip()})
        else:
            results.append({"location": "crontab::user", "content": "<no crontab or no permission>"})
    except Exception as e:
        results.append({"location": "crontab::error", "error": str(e)})

    # check /etc/cron.* and /var/spool/cron
    cron_paths = ["/etc/cron.d", "/etc/cron.daily", "/etc/cron.hourly", "/etc/cron.weekly", "/etc/cron.monthly", "/var/spool/cron"]
    for p in cron_paths:
        try:
            if os.path.exists(p):
                entries = [str(x) for x in Path(p).iterdir()]
                results.append({"location": p, "entries": entries})
        except Exception as e:
            results.append({"location": p, "error": str(e)})

    # systemd unit files (list unit files if systemctl exists)
    try:
        out = subprocess.run(["systemctl", "list-unit-files", "--type=service", "--no-pager", "--no-legend"], capture_output=True, text=True, check=False)
        if out.returncode == 0:
            # just capture unit names with enabled state
            lines = [l.strip() for l in out.stdout.splitlines() if l.strip()]
            results.append({"location": "systemd::unit-files", "count": len(lines), "sample": lines[:20]})
    except Exception:
        results.append({"location": "systemd::unit-files", "note": "systemctl not available or permission denied"})

    # user autostart (freedesktop)
    try:
        user_autostart = Path.home() / ".config" / "autostart"
        if user_autostart.exists():
            entries = [str(x) for x in user_autostart.iterdir()]
            results.append({"location": str(user_autostart), "entries": entries})
    except Exception as e:
        results.append({"location": "autostart_user", "error": str(e)})

    # /etc/rc.local
    try:
        if os.path.exists("/etc/rc.local"):
            results.append({"location": "/etc/rc.local", "entry": "/etc/rc.local"})
    except Exception as e:
        results.append({"location": "/etc/rc.local", "error": str(e)})

    return results

# macOS: LaunchAgents & LaunchDaemons
def scan_startup_macos():
    results = []
    paths = [
        "/Library/LaunchAgents",
        "/Library/LaunchDaemons",
        str(Path.home() / "Library" / "LaunchAgents"),
    ]
    for p in paths:
        try:
            if os.path.exists(p):
                entries = [str(x) for x in Path(p).iterdir()]
                results.append({"location": p, "entries": entries})
        except Exception as e:
            results.append({"location": p, "error": str(e)})
    # also try `launchctl list` to get loaded agents (may require permission)
    try:
        out = subprocess.run(["launchctl", "list"], capture_output=True, text=True, check=False)
        if out.returncode == 0:
            lines = [l for l in out.stdout.splitlines() if l.strip()]
            results.append({"location": "launchctl::list", "sample": lines[:50]})
    except Exception:
        results.append({"location": "launchctl", "note": "launchctl not available or permission denied"})
    return results

def scan_startup_locations():
    pf = get_platform()
    if pf == "windows":
        return scan_startup_windows()
    if pf == "linux":
        return scan_startup_linux()
    if pf == "macos":
        return scan_startup_macos()
    return [{"location": "unknown_platform", "note": f"platform {pf} not explicitly supported"}]

# -------------------------
# Report generation
# -------------------------
def generate_text_report(processes, flagged, autoruns, out_path):
    lines = []
    lines.append("Process Monitor + AutoRun Scanner")
    lines.append(f"Timestamp: {datetime.datetime.now().isoformat()}")
    lines.append(f"Host: {platform.node()} ({platform.system()} {platform.release()})")
    lines.append(f"User running scan: {getpass.getuser()}")
    lines.append("=" * 80)
    lines.append("\n[Processes] (pid | ppid | user | name | connections | exe)")
    for p in processes:
        lines.append(f"{p['pid']} | {p['ppid']} | {p.get('username')} | {p.get('name')} | conn={p.get('connections')} | exe={p.get('exe')}")
    lines.append("\n" + "=" * 80)
    lines.append("\n[Flagged Processes]")
    if flagged:
        for f in flagged:
            proc = f["process"]
            reasons = ", ".join(f["reasons"])
            lines.append(f"-> PID {proc['pid']} ({proc.get('name')}) reasons: {reasons}")
            lines.append(f"   cmdline: {proc.get('cmdline')}")
            lines.append(f"   exe: {proc.get('exe')}")
    else:
        lines.append("No flagged processes found by heuristics.")

    lines.append("\n" + "=" * 80)
    lines.append("\n[Autorun / Startup Entries]")
    for a in autoruns:
        lines.append(json.dumps(a, indent=2, default=str))

    # write to file
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    return out_path

def generate_json_export(processes, flagged, autoruns, out_path):
    payload = {
        "meta": {
            "timestamp": datetime.datetime.now().isoformat(),
            "host": platform.node(),
            "platform": platform.platform(),
            "scanned_by": getpass.getuser(),
        },
        "processes": processes,
        "flagged": flagged,
        "autoruns": autoruns,
    }
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2, default=str)
    return out_path

# -------------------------
# Main
# -------------------------
def main(export_json=False):
    print("Starting Process Monitor + AutoRun Scanner (defensive read-only)...")
    processes = gather_process_info()
    flagged = flag_suspicious_processes(processes)
    autoruns = scan_startup_locations()

    ts = timestamp()
    txt_path = REPORT_DIR / f"report_{ts}.txt"
    generate_text_report(processes, flagged, autoruns, txt_path)
    print(f"Text report written to: {txt_path}")

    if export_json:
        json_path = REPORT_DIR / f"report_{ts}.json"
        generate_json_export(processes, flagged, autoruns, json_path)
        print(f"JSON export written to: {json_path}")

    # summary to console
    print("\nSummary:")
    print(f" Total processes scanned: {len(processes)}")
    print(f" Flagged processes: {len(flagged)}")
    print(f" Autorun/startup entries found: {len(autoruns)}")
    if flagged:
        print("\nFlagged (top 10):")
        for f in flagged[:10]:
            proc = f["process"]
            print(f" - PID {proc['pid']} name={proc.get('name')} reasons={f['reasons']}")

if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Process Monitor + AutoRun Scanner (defensive)")
    parser.add_argument("--json", action="store_true", help="Also export findings to JSON")
    args = parser.parse_args()

    try:
        main(export_json=args.json)
    except KeyboardInterrupt:
        print("\nInterrupted by user. Exiting.")
    except ModuleNotFoundError as e:
        print("Missing module:", e)
        print("Install requirements: pip install psutil")
        sys.exit(1)
    except Exception as e:
        print("Error during scan:", e)
        sys.exit(2)
