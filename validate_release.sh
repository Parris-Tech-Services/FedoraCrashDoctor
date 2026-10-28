#!/bin/bash
set -e

echo "=== Validating Fedora Crash Doctor Release ==="

FAILS=0

echo -n "Checking Shell scripts... "
if command -v shellcheck >/dev/null 2>&1; then
    if shellcheck ./*.sh; then
        echo "[PASS]"
    else
        echo "[FAIL]"
        FAILS=$((FAILS+1))
    fi
else
    echo "[SKIPPED] shellcheck not installed."
fi

echo -n "Validating desktop file... "
if command -v desktop-file-validate >/dev/null 2>&1; then
    if desktop-file-validate packaging/fedora-crash-doctor.desktop; then
        echo "[PASS]"
    else
        echo "[FAIL]"
        FAILS=$((FAILS+1))
    fi
else
    echo "[SKIPPED] desktop-file-validate not installed."
fi

echo -n "Validating systemd units... "
if command -v systemd-analyze >/dev/null 2>&1; then
    if systemd-analyze verify systemd/*.service 2>/dev/null; then
        echo "[PASS]"
    else
        echo "[FAIL]"
        FAILS=$((FAILS+1))
    fi
else
    echo "[SKIPPED] systemd-analyze not installed."
fi

echo -n "Checking Polkit policy... "
if command -v pkcheck >/dev/null 2>&1; then
    echo "[SKIPPED]"
else
    echo "[SKIPPED]"
fi

echo "Running Python tests... "
if python3 -m unittest discover -s tests -p 'test_*.py' -v; then
    echo "[PASS] Python tests"
else
    echo "[FAIL] Python tests"
    FAILS=$((FAILS+1))
fi

echo -n "Building RPM package... "
if [ -x ./build_rpm.sh ]; then
    if ./build_rpm.sh > /dev/null 2>&1; then
        echo "[PASS]"
    else
        echo "[FAIL]"
        FAILS=$((FAILS+1))
    fi
else
    echo "[SKIPPED] build_rpm.sh not found or not executable."
fi

if [ "$FAILS" -gt 0 ]; then
    echo "=== Release validation FAILED with $FAILS errors ==="
    exit 1
else
    echo "=== Release validation PASSED ==="
    exit 0
fi
