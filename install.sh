#!/usr/bin/env bash
set -euo pipefail
if [[ $EUID -ne 0 ]]; then
  echo "Run: sudo ./install.sh" >&2
  exit 1
fi

SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SHARE_DIR=/usr/share/fedora-crash-doctor
LIBEXEC_DIR=/usr/libexec/fedora-crash-doctor

bash "$SOURCE_DIR/install_dependencies.sh"

# Remove v1/v2 service files that pointed into /opt before installing v3 units.
systemctl disable --now fedora-crash-doctor-canary.service 2>/dev/null || true
systemctl disable fedora-crash-doctor-autoscan.service 2>/dev/null || true
rm -f /etc/systemd/system/fedora-crash-doctor-canary.service
rm -f /etc/systemd/system/fedora-crash-doctor-autoscan.service

install -d -m 0755 "$SHARE_DIR" "$LIBEXEC_DIR" /usr/share/polkit-1/actions
install -m 0755 "$SOURCE_DIR/fedora_crash_doctor.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/collector.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/canary.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/desktop_heartbeat.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/autoscan.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/host_stability_audit.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/incident_model.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/incident_observations.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/change_correlation.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/incident_fingerprint.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/confidence_explanation.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/incident_history.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/canary_incident_join.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/stability_playbook.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/reliability_summary.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/device_inventory.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/freeze_classifiers.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/report_schema.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/safe_mitigation.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/telemetry_timeline.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/version.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/chrome_capture.py" "$SHARE_DIR/"
install -m 0755 "$SOURCE_DIR/plasma_capture.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/app_crash_doctor.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/symbolic_analysis.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/coredump_adapter.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/graphics_doctor.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/hardware_doctor.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/memory_oom.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/dadlan_doctor.py" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/VERSION" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/README.md" "$SHARE_DIR/"
install -m 0644 "$SOURCE_DIR/HISTORY.md" "$SHARE_DIR/" 2>/dev/null || true
install -m 0644 "$SOURCE_DIR/TODO.md" "$SHARE_DIR/" 2>/dev/null || true
install -m 0755 "$SOURCE_DIR/privileged_helper.py" "$LIBEXEC_DIR/fedora-crash-doctor-helper"
install -m 0755 "$SOURCE_DIR/stability_notifier.py" "$LIBEXEC_DIR/fedora-crash-doctor-stability-notifier"
install -m 0644 "$SOURCE_DIR/polkit/org.fedoracrashdoctor.policy" /usr/share/polkit-1/actions/
install -m 0644 "$SOURCE_DIR/systemd/fedora-crash-doctor-canary.service" /usr/lib/systemd/system/
install -m 0644 "$SOURCE_DIR/systemd/fedora-crash-doctor-autoscan.service" /usr/lib/systemd/system/
install -m 0644 "$SOURCE_DIR/systemd/fedora-crash-doctor-desktop-heartbeat.service" /usr/lib/systemd/user/
install -m 0644 "$SOURCE_DIR/systemd/fedora-crash-doctor-stability.service" /usr/lib/systemd/user/
install -m 0644 "$SOURCE_DIR/systemd/fedora-crash-doctor-stability.path" /usr/lib/systemd/user/

cat >/usr/local/bin/fedora-crash-doctor <<EOF
#!/usr/bin/env bash
exec /usr/bin/python3 "$SHARE_DIR/fedora_crash_doctor.py" "\$@"
EOF
chmod 0755 /usr/local/bin/fedora-crash-doctor

install -m 0644 "$SOURCE_DIR/packaging/fedora-crash-doctor.desktop" /usr/share/applications/

systemctl daemon-reload
systemctl --global enable fedora-crash-doctor-desktop-heartbeat.service >/dev/null 2>&1 || true
systemctl --global enable fedora-crash-doctor-stability.path >/dev/null 2>&1 || true
update-desktop-database /usr/share/applications >/dev/null 2>&1 || true
restorecon -RF "$SHARE_DIR" "$LIBEXEC_DIR" /usr/share/polkit-1/actions/org.fedoracrashdoctor.policy /usr/share/applications/fedora-crash-doctor.desktop 2>/dev/null || true

# Remove obsolete v1/v2 program files only after v3 is installed.
rm -rf /opt/fedora-crash-doctor

echo
echo "Fedora Crash Doctor $(cat "$SOURCE_DIR/VERSION") installed."
echo "Open the application launcher and search for Fedora Crash Doctor."
echo "The first privileged action asks once; the locked-down helper remains attached until the app closes."
