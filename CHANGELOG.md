# Changelog

## Unreleased
- Added a dedicated **RuneScape Doctor** tab and CLI addon (`runescape_doctor.py` and `runescape_watchdog.py`):
  - Auto-discovers local JoshRS revision-377 installations (`~/dev/JoshRS/lostcity377`, `jagex2.client.Client`, `start-client.sh`, `/tmp/joshrs-client-persistent.log`, and server ports `52402`/`8888`/`8898`).
  - Detects uncaught Java exceptions on the game loop thread (`Thread-2` dying while AWT/sound threads keep the window open), dead `Thread-2` in live `jcmd`/`jstack` thread dumps, deadlocks, heap OOM, kernel OOM kills, native GL/X11 crashes, KWin Wayland swapchain warnings, and fixed-aspect (`765x503`) black margins.
  - Produces ranked root-cause hypotheses with supporting/contradicting evidence, incident classifications, and correlated timelines.
  - Watchdog catches both CPU-idle hangs and crashed game-loop threads, with bounded restarts and profile escalation.
- Installer, uninstaller and RPM spec ship the new modules plus a `fedora-crash-doctor-runescape` command.

## 3.2.1 — 2026-08-27
- Fixed autoscan boot boundary to correctly inspect only the immediately preceding boot.
- Ensured dynamically generated storage (`storage_*`) and thermal (`thermal`) finding IDs contribute correctly to incident hypotheses.
- Updated GUI to correctly visualize nested PSI metrics from the canary schema.
- Made systemd-oomd audit compatible with flexible memory pressure configurations.
- Implemented structured journal source attribution (enforcing `_COMM` and `SYSLOG_IDENTIFIER` checks) to prevent unprivileged log-spoofing.
- Expanded automated regression suite (`tests/test_analysis.py`, `tests/test_autoscan.py`).

## 3.2.0 — 2026-08-27
- Hardened boot boundary logic to detect clean `systemd-shutdown` sequences and ignore historical crash artifacts.
- Implemented shutdown-context suppression window to ignore Wayland/Plasma teardown noise during clean reboots.
- Updated Wayland compositor regex to safely ignore `xkbcomp` and portal registration teardown errors.
- Removed dead `build_rpm` action from the privileged broker helper to reduce attack surface.

- Added `HISTORY.md` with the full Fedora/Linux crash and freeze master record,
  including diagnosis rankings, chronology, recovery procedure, and current
  improvement priorities.
- Linked the master record from the README.
- Added `TODO.md` with the release-hardening worklist and linked it from the
  README.
- Added a read-only host stability audit for live AVANCE-WS7 prevention checks.
- Added an explicit CLI mode with `--help`, `--version`, and `--cli --scan`.
- Split expensive RPM file verification into explicit `deep` scan mode so
  ordinary full scans stay more responsive.
- Added `validate_release.sh` for broad, CI-friendly best-effort validation.
- Added a repository desktop file for installer and packaging validation.
- Moved manual diagnostic experiments under `tools/manual/` so root-level
  unittest discovery no longer imports them as tests.

## 3.1.0 — 2026-07-29

- Added issue-specific Fix / next steps cards with command copy/run/explain controls.
- Added safer launchers for display settings, filtered logs, evidence capture,
  kdump validation and scan-after-reboot scheduling.
- Added manual verification tracking for rebooted, one-monitor tested, stable
  and still-freezing outcomes.
- Added before/after comparison for saved scans.
- Improved PCIe device naming with likely user-facing roles.
- Replaced vague category warnings with more specific next-action labels.
- Hardened canary analysis against null desktop heartbeat samples.

## 3.0.0 — 2026-07-29

- Added incident timeline and evidence proximity.
- Added ranked hypotheses with confidence and A/B tests.
- Added category health cards and finding filters.
- Added real progress and cancellation.
- Added secure long-lived PolicyKit broker for one prompt per app session.
- Added improved PCIe address-to-device correlation.
- Reclassified perf sampling messages as context rather than crash prediction.
- Expanded system canary with PSI and desktop/KWin heartbeat correlation.
- Made Cockpit explicitly optional.
- Added controlled SMART, Btrfs, Memtest, CPU and RAM tests.
- Added safe kdump validation.
- Added RPM packaging files and regression tests.
