#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")"
# pytest discovers and runs both pytest-style tests (tests/test_app_crash_doctor.py,
# tests/test_collector_integration.py, tests/test_coredump_adapter.py) and plain
# unittest.TestCase tests in the same pass; `python3 -m unittest discover` only
# finds the latter, so pytest is the one authoritative runner here.
python3 -m pytest -q tests/
python3 -m py_compile ./*.py
for script in *.sh; do bash -n "$script"; done
python3 - <<'PY'
import xml.etree.ElementTree as ET
ET.parse('polkit/org.fedoracrashdoctor.policy')
print('polkit XML: OK')
PY
