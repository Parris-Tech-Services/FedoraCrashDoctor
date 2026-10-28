#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")" || exit 1
python3 -m unittest discover -s tests -v
python3 -m py_compile ./*.py
for script in ./*.sh; do bash -n "$script"; done
python3 - <<'PY'
import xml.etree.ElementTree as ET
ET.parse('polkit/org.fedoracrashdoctor.policy')
print('polkit XML: OK')
PY
