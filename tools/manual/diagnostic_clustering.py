"""One-off incident clustering experiment; not an automated test."""
import json
from collector import build_incidents

f = json.load(open("real_scan_2.json"))
incidents = build_incidents(f["findings"], f["checks"])
print(json.dumps(incidents, indent=2))
