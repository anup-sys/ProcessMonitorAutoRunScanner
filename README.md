# Process Monitor + AutoRun Scanner 🛡️

**Defensive, read-only tool** that scans running processes and common autorun/startup locations to help identify suspicious activity on a machine.

---

## ⚠️ Safety & Ethics
- **Read-only**: This tool only reads system state and writes reports.  
- **Do not run** on systems you do not own or have explicit permission to inspect.  
- Use for **defensive**, educational, or incident-response practice only.

---

## 🔎 What it does
- Lists running processes (PID, PPID, username, name, cmdline, exe path).
- Counts network connections per process (when accessible).
- Flags potentially suspicious processes using simple heuristics:
  - Missing `exe` path
  - Running from temporary directories (e.g., `/tmp`, `%TEMP%`)
  - Parent PID = 1 (or unusual parents)
  - Network activity combined with the above
- Enumerates common autorun/startup locations depending on OS:
  - **Windows**: Registry `Run` keys, Startup folder
  - **Linux**: `crontab`, `/etc/cron.*`, systemd unit files, `~/.config/autostart`, `/etc/rc.local`
  - **macOS**: `LaunchAgents`, `LaunchDaemons`, `launchctl list`
- Writes a timestamped human-readable text report to `reports/` and (optionally) a JSON export.

---

## 🧾 Files
- `process_monitor_autorun_scanner.py` — main script
- `reports/` — directory where generated reports are saved
- `requirements.txt` — Python dependencies (suggested)

---

## ⚙️ Requirements
- Python 3.8+
- Recommended: create and use a virtual environment
- Python dependency:
  - `psutil` (install via `pip install psutil`)

`requirements.txt` example:
psutil>=5.8.0

yaml
Copy code

---

## 🚀 Quick start

1. (Optional, recommended) Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate   # Linux / macOS
   # On Windows PowerShell: .\venv\Scripts\Activate.ps1
Install dependencies:

bash
Copy code
pip install -r requirements.txt
# or
pip install psutil
Run the scanner:

bash
Copy code
python process_monitor_autorun_scanner.py
To also export JSON:

bash
Copy code
python process_monitor_autorun_scanner.py --json
Reports will be saved in:

bash
Copy code
reports/report_YYYYMMDD_HHMMSS.txt
reports/report_YYYYMMDD_HHMMSS.json  (if --json provided)
🧪 Example output (snippet)
yaml
Copy code
Process Monitor + AutoRun Scanner
Timestamp: 2025-10-21T14:22:03.123456
Host: anup-Legion-5-15ACH6H (Linux 5.15.0-xx)
User running scan: anup
================================================================================
[Processes] (pid | ppid | user | name | connections | exe)
1 | 0 | root | systemd | conn=0 | exe=/sbin/init
1234 | 1 | anup | suspicious_bin | conn=2 | exe=/tmp/suspicious_bin
...
================================================================================
[Flagged Processes]
-> PID 1234 (suspicious_bin) reasons: running_from_temp, network_and_temp_or_missing_exe
   cmdline: ['/tmp/suspicious_bin', '--serve']
   exe: /tmp/suspicious_bin
...
================================================================================
[Autorun / Startup Entries]
{ "location": "/etc/cron.d", "entries": ["/etc/cron.d/example"] }
...
🛠️ Heuristics & Detection notes
The tool intentionally uses simple heuristics for educational purposes. A flagged process is not proof of compromise.

False positives are expected (e.g., legitimate installers run from /tmp).

Use the report as a starting point for investigation:

Inspect flagged processes with ps auxww, lsof -p <pid>, strace -p <pid> (careful; strace is invasive).

Check file ownership, timestamps, and digital signatures (Windows).

Compare suspect binary hashes to known-good baselines.

🔍 Troubleshooting
ModuleNotFoundError: No module named 'psutil'
→ Install: pip install psutil or use python3 -m pip install --user psutil

If running on a managed distro and pip is blocked, use a virtualenv or install python3-psutil via your package manager:

Debian/Ubuntu: sudo apt install python3-psutil

Fedora: sudo dnf install python3-psutil

To see all processes on Linux/macOS you may need sudo:

bash
Copy code
sudo python process_monitor_autorun_scanner.py
