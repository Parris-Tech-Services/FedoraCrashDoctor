#!/usr/bin/env bash
# Release validator: runs every check it can and reports PASS/FAIL/SKIP for
# each one individually, with a reason whenever something is skipped.
#
# This deliberately never installs anything (no sudo, no dnf, no rpm -i).
# Run ./install_dependencies.sh first if you want fewer SKIPs.
set -uo pipefail
cd "$(dirname "$0")" || exit 1

PASS_COUNT=0
FAIL_COUNT=0
SKIP_COUNT=0

pass() { printf '[PASS] %s\n' "$1"; PASS_COUNT=$((PASS_COUNT + 1)); }
fail() { printf '[FAIL] %s -- %s\n' "$1" "$2"; FAIL_COUNT=$((FAIL_COUNT + 1)); }
skip() { printf '[SKIP] %s -- %s\n' "$1" "$2"; SKIP_COUNT=$((SKIP_COUNT + 1)); }

echo "=== Fedora Crash Doctor release validation ==="
echo "(read-only: never installs packages or build dependencies)"
echo

echo "--- Python ---"
if python3 -m pytest -q tests/; then
  pass "pytest full suite (unittest + pytest-style tests, including installed-tree manifest and version-consistency regressions)"
else
  fail "pytest full suite" "one or more tests failed; see output above"
fi

if python3 -m py_compile ./*.py; then
  pass "python compilation (py_compile)"
else
  fail "python compilation (py_compile)" "a source file failed to compile"
fi

if python3 -c "import json; json.load(open('schema/report.schema.json'))" 2>/tmp/fcd-schema-err.log; then
  pass "report.schema.json is valid JSON"
else
  fail "report.schema.json is valid JSON" "$(cat /tmp/fcd-schema-err.log)"
fi

echo
echo "--- Shell ---"
sh_syntax_ok=1
for script in ./*.sh; do
  if ! bash -n "$script" 2>/tmp/fcd-shsyntax-err.log; then
    sh_syntax_ok=0
    echo "  $script: $(cat /tmp/fcd-shsyntax-err.log)"
  fi
done
if [ "$sh_syntax_ok" -eq 1 ]; then
  pass "shell syntax (bash -n on all *.sh)"
else
  fail "shell syntax (bash -n on all *.sh)" "one or more scripts failed to parse, see above"
fi

if command -v shellcheck >/dev/null 2>&1; then
  if shellcheck ./*.sh; then
    pass "shellcheck"
  else
    fail "shellcheck" "shellcheck reported issues, see output above"
  fi
else
  skip "shellcheck" "shellcheck is not installed"
fi

echo
echo "--- PolicyKit / desktop / systemd ---"
if python3 - <<'PY' 2>/tmp/fcd-polkit-err.log
import xml.etree.ElementTree as ET
ET.parse('polkit/org.fedoracrashdoctor.policy')
PY
then
  pass "PolicyKit policy XML parses"
else
  fail "PolicyKit policy XML parses" "$(cat /tmp/fcd-polkit-err.log)"
fi

if command -v desktop-file-validate >/dev/null 2>&1; then
  if desktop-file-validate packaging/fedora-crash-doctor.desktop; then
    pass "desktop-file-validate"
  else
    fail "desktop-file-validate" "packaging/fedora-crash-doctor.desktop failed validation, see above"
  fi
else
  skip "desktop-file-validate" "desktop-file-validate is not installed"
fi

if command -v systemd-analyze >/dev/null 2>&1; then
  # Both .service units AND the .path unit -- a prior version of this
  # validator only checked *.service and silently never verified the
  # stability .path unit at all.
  if systemd-analyze verify systemd/*.service systemd/*.path 2>/tmp/fcd-systemd-err.log; then
    pass "systemd-analyze verify (services + path unit)"
  else
    fail "systemd-analyze verify (services + path unit)" "$(cat /tmp/fcd-systemd-err.log)"
  fi
else
  skip "systemd-analyze verify (services + path unit)" "systemd-analyze is not installed"
fi

echo
echo "--- Git hygiene ---"
if git diff --check >/tmp/fcd-diffcheck.log 2>&1 && git diff --cached --check >>/tmp/fcd-diffcheck.log 2>&1; then
  pass "git diff --check (whitespace hygiene)"
else
  fail "git diff --check (whitespace hygiene)" "$(cat /tmp/fcd-diffcheck.log)"
fi

echo
echo "--- RPM packaging ---"
RPM_PATH=""
if command -v rpmbuild >/dev/null 2>&1 && command -v rpmdev-setuptree >/dev/null 2>&1; then
  if ./build_rpm.sh >/tmp/fcd-build-rpm.log 2>&1; then
    # Select the newest RPM without parsing ls output (safe for whitespace).
    for rpm in "$HOME"/rpmbuild/RPMS/noarch/fedora-crash-doctor-*.rpm; do
      [ -f "$rpm" ] || continue
      if [ -z "$RPM_PATH" ] || [ "$rpm" -nt "$RPM_PATH" ]; then
        RPM_PATH="$rpm"
      fi
    done
    if [ -n "$RPM_PATH" ]; then
      pass "RPM build ($RPM_PATH)"
    else
      fail "RPM build" "build_rpm.sh exited 0 but no RPM was found under ~/rpmbuild/RPMS; see /tmp/fcd-build-rpm.log"
    fi
  else
    fail "RPM build" "see /tmp/fcd-build-rpm.log"
  fi
else
  skip "RPM build" "rpmbuild/rpmdevtools not installed; run install_dependencies.sh or 'sudo dnf install rpm-build rpmdevtools' first -- validation will not install them itself"
fi

if [ -n "$RPM_PATH" ] && command -v rpmlint >/dev/null 2>&1; then
  if rpmlint "$RPM_PATH"; then
    pass "rpmlint"
  else
    fail "rpmlint" "rpmlint reported issues for $RPM_PATH, see output above"
  fi
elif [ -z "$RPM_PATH" ]; then
  skip "rpmlint" "no RPM was built this run"
else
  skip "rpmlint" "rpmlint is not installed"
fi

echo
echo "=== Summary: $PASS_COUNT passed, $FAIL_COUNT failed, $SKIP_COUNT skipped ==="
if [ "$FAIL_COUNT" -gt 0 ]; then
  exit 1
fi
exit 0
