#!/usr/bin/env python3
"""User-level notifier for Fedora Crash Doctor Stability Guard.

Reads the securely written event JSON from the root canary and displays
a desktop notification using notify-send.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

EVENT_FILE = Path("/run/fedora-crash-doctor/stability-event.json")
SILENT_MARKERS = (
    Path("/etc/fedora-crash-doctor/silent"),
    Path.home() / ".config/fedora-crash-doctor/silent",
)

def main() -> int:
    if not EVENT_FILE.exists():
        return 0

    # Keep the canary and event file active while allowing kiosk/headless
    # machines, or users who are already suppressing DrKonqi, to opt out of
    # desktop popups without disabling evidence collection.
    if os.environ.get("FCD_SILENT", "").lower() in {"1", "true", "yes", "on"} or any(path.exists() for path in SILENT_MARKERS):
        return 0

    try:
        data = json.loads(EVENT_FILE.read_text(encoding="utf-8"))
    except Exception:
        return 0

    state = data.get("state", "ok")
    if state == "ok":
        # Nothing to notify, or it's just healthy. We only notify recovery.
        # But wait, our state machine emits 'ok' for recovery.
        pass

    title = data.get("title", "Fedora stability warning")
    reasons = data.get("reasons", [])
    actions = data.get("recommended_actions", [])
    offenders = data.get("likely_offenders", [])

    body_lines = []
    if reasons:
        body_lines.extend(reasons)
        body_lines.append("")
        
    if offenders:
        body_lines.append("Largest workload:")
        for off in offenders:
            body_lines.append(f"• {off}")
        body_lines.append("")

    if actions:
        body_lines.extend(actions)

    body = "\n".join(body_lines).strip()
    
    urgency = "normal"
    icon = "dialog-warning"
    if state == "critical":
        urgency = "critical"
        icon = "dialog-error"
    elif state == "ok":
        urgency = "normal"
        icon = "dialog-information"

    # notify-send -u <urgency> -i <icon> <title> <body>
    cmd = ["notify-send", "-u", urgency, "-i", icon, "-a", "Fedora Crash Doctor", title]
    if body:
        cmd.append(body)

    try:
        subprocess.run(cmd, check=True)
    except Exception:
        # Ignore errors if no notification daemon is present
        pass

    return 0

if __name__ == "__main__":
    sys.exit(main())
