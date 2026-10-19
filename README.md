# Fedora Crash Doctor

A local Qt 6 diagnostic application for Fedora KDE and other Fedora desktops.
It is designed to answer three questions after a crash:

1. **What happened closest to the crash?**
2. **What causes best fit the collected evidence?**
3. **What controlled test would strengthen or weaken each explanation?**

## History and diagnosis record

The project includes a preserved crash/freeze chronology in
[`HISTORY.md`](HISTORY.md). It records the AVANCE-WS7 diagnosis history, recovery
procedures, controlled A/B tests, and the evidence behind the current model:
Intel i915/KWin/Wayland multi-monitor freezes, severe RAM/zram pressure, and
separate USB storage instability can all look like “Fedora froze” while having
different causes.

## Release hardening TODO

The release-readiness worklist lives in [`TODO.md`](TODO.md). It tracks the
remaining hardening pass for full-scan responsiveness, CLI support, test
discovery, privileged broker tests, package validation, report schemas, improved
freeze correlation, UI clarity, and CI-friendly validation.

## Host stability audit

Crash Doctor now includes a read-only host stability audit for AVANCE-WS7-style
prevention work:

```bash
python3 host_stability_audit.py --output host-stability-audit.md
python3 host_stability_audit.py --json --output host-stability-audit.json
```

The audit separates confirmed problems, high-confidence reversible fixes,
controlled A/B experiments, monitoring-only signals, and explanations not
supported by current evidence. It does not install packages, change kernel
parameters, restart services, kill processes, or run destructive tests.

Crash Doctor reports now include a confirmation-gated stability playbook. It
surfaces one-monitor/GPU-acceleration/kernel A/B tests, workload attribution,
coredump-limit guidance, update/reboot readiness and silent-background mode.
Create `~/.config/fedora-crash-doctor/silent` to keep evidence collection and
the canary active without desktop notifications.

The Trends view also shows an **observed stability index** once at least two
dated scans exist. It summarizes recorded shutdowns, kernel panics, incident
findings and evidence coverage; it is not a hardware-health score or proof
that an intermittent fault is fixed. Missing canary or persistent-journal
evidence lowers coverage instead of being counted as healthy. Freeze analysis
reads bounded tails from the active canary log and its three rotated backups
when available.

## CLI examples

Running `fedora_crash_doctor.py` with no arguments launches the GUI. Terminal
mode is explicit:

```bash
python3 fedora_crash_doctor.py --help
python3 fedora_crash_doctor.py --version
python3 fedora_crash_doctor.py --cli --scan --mode quick --output scan.json
python3 fedora_crash_doctor.py --cli --scan --mode full --output scan-full.json
python3 fedora_crash_doctor.py --cli --scan --mode deep --output scan-deep.json
```

`quick` is for ordinary interactive diagnosis. `full` adds richer hardware,
journal, package and network checks while staying suitable for foreground use.
`deep` is explicit maintenance mode and includes expensive verification such as
RPM file verification.

## Release validation

Run the normal test suite or the broader best-effort release validation:

```bash
./run_tests.sh
./validate_release.sh
```

`validate_release.sh` runs required local checks and skips optional developer
tools such as `shellcheck`, `desktop-file-validate`, and `systemd-analyze` when
they are not installed.

## What changed in v3

- **One authentication prompt per app session.** The GUI launches one root-owned,
  action-whitelisted broker through PolicyKit. The broker remains attached to
  that GUI process and exits when the app closes. Buttons do not launch arbitrary
  `python3` or `bash` commands through `pkexec`.
- The PolicyKit default is `auth_admin_keep`. The long-lived broker is what avoids
  repeated prompts for the rest of that app session.
- **Incident timeline** separates events within ten minutes of the journal ending,
  earlier messages from the same boot, and historical background warnings.
- **Ranked likely causes** include confidence, supporting evidence, counter-evidence,
  the best next test, and what would strengthen or weaken the hypothesis.
- **Category cards** for Graphics, Memory, Storage, Thermals, PCIe/Network,
  Firmware and Software.
- **Determinate progress**, current scan step, and a Cancel button.
- Finding filters for **This incident**, **New**, **Recurring** and serious items.
- A **Fix / next steps** workflow with issue-specific fix cards, command blocks,
  copy/run/explain buttons, KDE Display Settings and filtered-log launchers,
  scan-after-reboot scheduling, and manual verification tracking.
- Before/after scan comparison highlights findings that disappeared, stayed
  recurring, or newly appeared after a change.
- **Incident-Clustering Schema**: Crash analysis now explicitly clusters evidence temporally around strict boundaries. Diagnostic data is categorized into:
  - `incident_evidence`: Timestamped evidence firmly within a failure window (e.g. 15 minutes before an unclean shutdown).
  - `boot_warnings`: Evidence unambiguously attributed to a known boot session but falling outside a defined crash window.
  - `unresolved_evidence`: Evidence whose timestamp cannot be safely parsed or attributed to a known boot context (never blindly misattributed).
- **Refined OOM Terminology**: "Out-of-memory" reporting now differentiates between standard `Out-of-memory events` (a single process kill) and `Probable memory-pressure crashes` (where an OOM kill directly precedes an unclean system shutdown), avoiding false panics over browser OOMs.
- Plain-English category labels such as **Try display-safe mode** and
  **Check PCIe device** replace vague “needs attention” wording where the
  evidence supports a more specific next move.
- Corrected PCIe events are joined to the actual `lspci -Dnnk` address, device
  description, likely user-facing device role and active kernel driver. The
  address can appear anywhere in the AER log line.
- `perf: interrupt took too long` is treated as contextual information about perf
  sampling-rate adjustment, not a reliable crash predictor by itself.
- The low-write **system canary** captures CPU/memory/I/O PSI, temperatures, CPU
  frequency, GPU telemetry where exposed, Wi-Fi signal, display connectors and
  top processes. It samples every 15 seconds, rotates logs, and fsyncs once per
  minute rather than on every sample.
- A per-user **desktop/KWin heartbeat** is correlated with the system canary:
  - system canary continues while desktop heartbeat fails → compositor/session
    failure becomes more likely;
  - both stop together → kernel, firmware, power or total-system lock becomes
    more likely.
- **Cockpit is optional** and is never enabled merely by turning on crash capture.
- Separate, confirmed tests for SMART short self-tests, Btrfs scrub, Memtest boot
  readiness, five-minute CPU stress and five-minute RAM stress.
- Safe kdump readiness validation without forcing a panic.
- HTML, JSON and concise support-text exports with optional privacy redaction.
- RPM packaging files and a `build_rpm.sh` helper.

## Install or upgrade from v1/v2

Extract the zip, open a terminal inside the `fedora-crash-doctor` folder, then run:

```bash
chmod +x *.sh *.py
sudo ./install.sh
```

The installer removes the old `/opt/fedora-crash-doctor` copy and old v2 service
unit overrides after v3 is safely installed. Existing reports and captured logs
are preserved.

Open the KDE application launcher and search for **Fedora Crash Doctor**.

## Development setup

To work on Fedora Crash Doctor locally without installing it system-wide:

1. Open a terminal inside the project directory.
2. Ensure you have standard Python 3 and basic KDE dependencies installed.
3. Run the test suite: `./run_tests.sh`
4. Run the main GUI application: `python3 fedora_crash_doctor.py`
5. Generate a test scan manually (writes a JSON report): `python3 collector.py --output test_scan.json`

## Recommended first use

1. Open Fedora Crash Doctor.
2. Select **Enable crash capture**.
3. Leave Cockpit unticked unless you specifically want its local web interface.
4. Reboot.
5. Run a **Quick scan**.
6. After another crash, let the boot-time autoscan load, then review the incident
   timeline and ranked causes.
7. Open **Fix / next steps**, copy or run the suggested commands, mark what you
   changed, reboot if requested, and run another scan to compare before/after.

## Privilege model

The only executable PolicyKit authorises is:

```text
/usr/libexec/fedora-crash-doctor/fedora-crash-doctor-helper
```

It accepts newline-delimited JSON through a private pipe from the GUI and only
implements named actions such as `scan`, `setup_capture`, `smart_short` and
`kdump_validate`. It rejects arbitrary commands and user-supplied output paths.
Reports are returned through the private pipe and saved by the unprivileged GUI.

Closing the application closes the privileged broker. Cancelling an action also
closes it, so the next privileged action asks again.

A passwordless PolicyKit rule example is included under `extras/`, but is not
installed. It is less secure and generally unnecessary because v3 already asks
only once while the application remains open.

## Controlled tests

Normal scans are read-only and never automatically run:

- stress-ng
- Memtest86+
- SMART self-tests
- Btrfs scrub
- filesystem repair
- forced kernel panic tests

Each available test has a separate confirmation. CPU and RAM stress tests are
fixed at five minutes. There is intentionally no automatic forced-panic kdump
validation.

## Data locations

User reports:

```text
~/Documents/Fedora Crash Doctor Reports/
```

System canary:

```text
/var/log/fedora-crash-doctor/canary.log
```

Boot-time autoscan and private baselines:

```text
/var/lib/fedora-crash-doctor/
```

## Proactive Stability Guard

The canary records lightweight rolling telemetry and the desktop heartbeat
records measured KWin ping latency and consecutive failures. Stability Guard
uses debounced NORMAL, WARNING and CRITICAL states, observes trends such as
Chrome aggregate RSS and swap growth, and can preserve read-only Chrome or
Plasma evidence when a sustained warning begins. Aggregate RSS can double-count
shared pages; increasing RSS is reported as sustained memory growth observed,
not as proof of a leak. Automatic capture never kills processes, restarts
services, changes browser or kernel settings, logs out, or reboots.

## Limits

No diagnostic application can guarantee a cause for every hard crash. Sudden
power loss, firmware deadlock, motherboard failure or some GPU lockups can stop
the machine before the final evidence is written. Ranked causes are explicit
hypotheses based on the evidence available, not certainty.


### Background symbolic backtraces

For recurring application crashes with a present core, Stage 2 runs bounded
`coredumpctl debug` analysis in the background. GDB is optional; Fedora debuginfod
is explicitly enabled for symbol downloads. Each worker has a 60-second elapsed
limit, 60-second CPU limit, 1 GiB address-space limit and 10 MiB output cap.
Backtraces can contain process memory values; files are private (0600) in a
private (0700) directory. Unprivileged runs use
`~/.local/state/fedora-crash-doctor/backtraces`; root uses
`/var/log/fedora-crash-doctor/backtraces`.

Application findings expose a `backtrace` object with state and, after capture,
path and byte count. A report exported while the worker is running retains that
snapshot; the completed text file records its final state. No GUI completion
notification or automatic refresh of previously exported reports is provided.

## Engineering standard

Engineering principles: v5.1
Assurance tier: 2
Canonical repository: https://github.com/Parris-Tech-Services/FedoraCrashDoctor
