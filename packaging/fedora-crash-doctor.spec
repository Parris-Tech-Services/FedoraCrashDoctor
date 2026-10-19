Name:           fedora-crash-doctor
Version:        3.2.2
Release:        1%{?dist}
Summary:        Evidence-weighted crash diagnostics for Fedora
License:        MIT
URL:            https://github.com/joshparri/FedoraCrashDoctor
Source0:        %{name}-%{version}.tar.gz
BuildArch:      noarch

Requires:       python3
Requires:       python3-pyside6
Requires:       polkit
Requires:       systemd
Requires:       /usr/bin/notify-send
Recommends:     gdb
Recommends:     inxi
Recommends:     smartmontools
Recommends:     nvme-cli
Recommends:     lm_sensors
Recommends:     pciutils
Recommends:     usbutils
Recommends:     fwupd
Recommends:     rasdaemon
Recommends:     edac-utils
Recommends:     fwts
Recommends:     kexec-tools
Recommends:     btrfs-progs
Recommends:     stress-ng
Recommends:     memtest86+
Recommends:     iw
Recommends:     ksystemlog
Recommends:     gnome-disk-utility

%description
Fedora Crash Doctor provides a Qt GUI, incident timeline, ranked crash
hypotheses, hardware and software evidence collection, low-write system and
KWin heartbeats, controlled tests, and a locked-down PolicyKit helper.

%prep
%autosetup

%build
# Pure Python; nothing to compile.

%install
install -d %{buildroot}%{_datadir}/fedora-crash-doctor
install -m 0755 fedora_crash_doctor.py collector.py canary.py desktop_heartbeat.py chrome_capture.py plasma_capture.py autoscan.py host_stability_audit.py %{buildroot}%{_datadir}/fedora-crash-doctor/
install -m 0755 device_inventory.py freeze_classifiers.py report_schema.py safe_mitigation.py telemetry_timeline.py version.py %{buildroot}%{_datadir}/fedora-crash-doctor/
install -m 0644 app_crash_doctor.py symbolic_analysis.py incident_model.py incident_observations.py change_correlation.py incident_fingerprint.py confidence_explanation.py incident_history.py canary_incident_join.py stability_playbook.py reliability_summary.py coredump_adapter.py graphics_doctor.py hardware_doctor.py memory_oom.py dadlan_doctor.py %{buildroot}%{_datadir}/fedora-crash-doctor/
install -m 0644 VERSION README.md LICENSE CHANGELOG.md HISTORY.md TODO.md %{buildroot}%{_datadir}/fedora-crash-doctor/

install -d %{buildroot}%{_libexecdir}/fedora-crash-doctor
install -m 0755 privileged_helper.py %{buildroot}%{_libexecdir}/fedora-crash-doctor/fedora-crash-doctor-helper
install -m 0755 stability_notifier.py %{buildroot}%{_libexecdir}/fedora-crash-doctor/fedora-crash-doctor-stability-notifier

install -d %{buildroot}%{_unitdir} %{buildroot}%{_userunitdir}
install -m 0644 systemd/fedora-crash-doctor-canary.service %{buildroot}%{_unitdir}/
install -m 0644 systemd/fedora-crash-doctor-autoscan.service %{buildroot}%{_unitdir}/
install -m 0644 systemd/fedora-crash-doctor-desktop-heartbeat.service %{buildroot}%{_userunitdir}/
install -m 0644 systemd/fedora-crash-doctor-stability.service %{buildroot}%{_userunitdir}/
install -m 0644 systemd/fedora-crash-doctor-stability.path %{buildroot}%{_userunitdir}/

install -d %{buildroot}%{_datadir}/polkit-1/actions
install -m 0644 polkit/org.fedoracrashdoctor.policy %{buildroot}%{_datadir}/polkit-1/actions/

install -d %{buildroot}%{_bindir}
cat >%{buildroot}%{_bindir}/fedora-crash-doctor <<'EOF'
#!/usr/bin/env bash
exec /usr/bin/python3 /usr/share/fedora-crash-doctor/fedora_crash_doctor.py "$@"
EOF
chmod 0755 %{buildroot}%{_bindir}/fedora-crash-doctor

install -d %{buildroot}%{_datadir}/applications
install -m 0644 packaging/fedora-crash-doctor.desktop %{buildroot}%{_datadir}/applications/

%post
%systemd_post fedora-crash-doctor-canary.service fedora-crash-doctor-autoscan.service
systemctl --global enable fedora-crash-doctor-desktop-heartbeat.service >/dev/null 2>&1 || :
systemctl --global enable fedora-crash-doctor-stability.path >/dev/null 2>&1 || :

%preun
%systemd_preun fedora-crash-doctor-canary.service fedora-crash-doctor-autoscan.service
if [ $1 -eq 0 ] ; then
  systemctl --global disable fedora-crash-doctor-desktop-heartbeat.service >/dev/null 2>&1 || :
  systemctl --global disable fedora-crash-doctor-stability.path >/dev/null 2>&1 || :
fi

%postun
%systemd_postun_with_restart fedora-crash-doctor-canary.service fedora-crash-doctor-autoscan.service

%files
%license LICENSE
%doc README.md CHANGELOG.md HISTORY.md TODO.md
%{_bindir}/fedora-crash-doctor
%{_datadir}/fedora-crash-doctor/
%{_libexecdir}/fedora-crash-doctor/
%{_unitdir}/fedora-crash-doctor-canary.service
%{_unitdir}/fedora-crash-doctor-autoscan.service
%{_userunitdir}/fedora-crash-doctor-desktop-heartbeat.service
%{_userunitdir}/fedora-crash-doctor-stability.service
%{_userunitdir}/fedora-crash-doctor-stability.path
%{_datadir}/polkit-1/actions/org.fedoracrashdoctor.policy
%{_datadir}/applications/fedora-crash-doctor.desktop

%changelog
* Wed Sep 30 2026 Fedora Crash Doctor contributors <noreply@example.invalid> - 3.2.2-1
 - Add confirmation-gated stability playbooks and silent background mode

* Fri Sep 11 2026 Fedora Crash Doctor contributors <noreply@example.invalid> - 3.2.1-1
- Bounded GDB/debuginfod symbolic backtraces; structured coredump ingestion hardening

* Wed Aug 26 2026 Fedora Crash Doctor contributors <noreply@example.invalid> - 3.2.0-1
- Add host stability audit, explicit CLI, report schema checks and deep scan mode

* Wed Jul 29 2026 Fedora Crash Doctor contributors <noreply@example.invalid> - 3.0.0-1
- Initial packaged v3 release
