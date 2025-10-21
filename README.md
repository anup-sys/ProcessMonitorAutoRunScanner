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
python process_monitor_autorun_scanner.py
To also export JSON:
