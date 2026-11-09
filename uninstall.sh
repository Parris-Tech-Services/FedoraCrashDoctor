#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Run: sudo ./uninstall.sh" >&2
  exit 1
fi
systemctl disable --now fedora-crash-doctor-canary.service 2>/dev/null || true
systemctl disable fedora-crash-doctor-autoscan.service 2>/dev/null || true
systemctl --global disable fedora-crash-doctor-desktop-heartbeat.service 2>/dev/null || true
rm -f /usr/lib/systemd/system/fedora-crash-doctor-canary.service
rm -f /usr/lib/systemd/system/fedora-crash-doctor-autoscan.service
rm -f /usr/lib/systemd/user/fedora-crash-doctor-desktop-heartbeat.service
rm -f /usr/share/polkit-1/actions/org.fedoracrashdoctor.policy
rm -f /usr/share/applications/fedora-crash-doctor.desktop
rm -f /usr/local/bin/fedora-crash-doctor
rm -f /usr/local/bin/fedora-crash-doctor-runescape
rm -rf /usr/share/fedora-crash-doctor /usr/libexec/fedora-crash-doctor
systemctl daemon-reload
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true

echo "Fedora Crash Doctor removed."
echo "Reports and captured evidence under /var/lib, /var/log and ~/Documents were left intact."
echo "Crash-capture settings such as persistent journald and kdump were also left intact deliberately."
