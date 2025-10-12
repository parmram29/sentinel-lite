# sentinel-lite

An ethical, local-only endpoint telemetry & detection demo.

## What it does
- Snapshots **processes**, **network connections**, and **persistence locations**.
- Writes JSONL logs locally (no exfiltration).
- Runs simple **rules** to raise local alerts.
- Cross-platform best-effort support: Windows, macOS, Linux.

## Ethics & scope
- No credential, content, or keystroke capture.
- Designed for a cybersecurity portfolio.

## Quick start

```bash
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows:
# .venv\Scripts\activate

pip install -r requirements.txt
python agent.py
