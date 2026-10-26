You are working on:

`/home/josh/dev/FedoraCrashDoctor`

Take ownership of **Fedora Crash Doctor** as if you are preparing it for a serious v1.0 release.

Your goal is to **upgrade, harden, clean up, test, and improve as much of the project as you safely can in one pass**, while preserving its core purpose:

> Diagnose Fedora/KDE/Linux freezes and crashes using evidence, distinguish desktop/graphics hangs from kernel/system crashes, detect memory/zram thrashing, i915/DRM/KWin issues, storage/USB faults, OOM events, kernel crashes, service failures and other correlated system evidence, and ensure useful evidence survives the next crash.

Do not stop after making one or two easy changes. Inspect the whole repository, identify the highest-value work, implement it, test it thoroughly, and leave the project meaningfully closer to release quality.

## Current verified state

Recent testing already established:

```text
./run_tests.sh
50 tests OK
1 GUI test skipped unless QT_QPA_PLATFORM=offscreen

QT_QPA_PLATFORM=offscreen python3 -m unittest tests.test_gui_integration -v
1 test OK

python3 collector.py --mode quick --output /tmp/fcd_quick_scan_after.json
valid JSON
54 checks

polkit XML: OK
```

Recent fixes already made:

* `collector.py`: duplicate readiness task keys removed.
* `collector.py`: deprecated yearless `datetime.strptime()` parsing for `last -x` timestamps replaced.
* `tests/test_analysis.py`: regression coverage added.

Do not regress these.

The worktree may already contain modifications/untracked scan artifacts. **Inspect git status first and preserve unrelated existing work. Do not blindly reset, clean, checkout, or overwrite files you did not need to modify.**

---

# Priority 1 — Fix full-scan responsiveness

A major current issue:

```bash
rpm -Va 2>&1 | head -6000
```

can run for several minutes and makes the GUI appear hung.

Redesign this properly.

Preferred direction:

* Quick/default scans should remain genuinely quick.
* Expensive package verification should not silently block ordinary scans.
* Introduce an explicit **deep package verification** mode/action if appropriate.
* Add sensible timeouts.
* Record whether a task:

  * completed,
  * timed out,
  * failed,
  * was skipped,
  * was unavailable.
* Never misrepresent a timeout as a clean result.
* Expose elapsed runtime for slow checks.

If the GUI performs scans in the UI thread, fix that architecture rather than merely hiding the delay.

The GUI should remain responsive while scanning.

Add visible progress including, where practical:

```text
Current check
Checks completed / total
Elapsed time for current check
Overall elapsed time
```

Allow cancellation safely.

A cancelled scan must result in a coherent partial report, not corrupt state.

---

# Priority 2 — Build a proper CLI

Currently:

```bash
python3 fedora_crash_doctor.py --help
```

launches the GUI.

Fix this.

Implement a clean `argparse` CLI.

At minimum support:

```text
--help
--version
--cli
--scan
--mode quick
--mode full
--output PATH
```

Add sensible aliases/subcommands if they improve the interface.

Unknown arguments must produce a normal CLI error rather than silently launching the GUI.

Running with no arguments may still launch the GUI.

Useful examples should appear in `--help`.

Keep CLI behaviour backwards-compatible where reasonable.

---

# Priority 3 — Fix test discovery

This command should behave properly:

```bash
python3 -m unittest discover -s . -p 'test_*.py'
```

Currently top-level ad hoc scripts such as `test_clustering.py` get imported and produce noise / “NO TESTS RAN”.

Clean this up.

Preferred approach:

* real tests belong under `tests/`;
* developer experiments/manual diagnostics belong under something like:

```text
tools/
scripts/
devtools/
```

Move or convert top-level pseudo-tests appropriately.

Afterwards, standard test discovery should not unexpectedly execute diagnostic scripts.

Do not destroy useful experiments; relocate/document them.

---

# Priority 4 — Thoroughly test the privileged broker

`privileged_helper.py` is security-sensitive.

Add meaningful automated integration/unit tests around its dispatch and validation logic without performing dangerous privileged operations.

Use:

* temporary directories,
* fake commands,
* dependency injection/mocking,
* controlled fixture data.

Test at least:

### Action allowlisting

Unknown actions must fail closed.

### Request validation

Test:

* malformed JSON,
* oversized requests,
* missing required fields,
* unexpected fields where relevant,
* invalid types.

### Device validation

Reject suspicious targets such as:

```text
/dev/../../etc/passwd
/dev/null;reboot
/dev/sda && command
arbitrary files
```

Allow only device patterns/actions that are genuinely intended.

### Path validation

Prevent traversal and unsafe arbitrary output/input paths.

### Argument injection

Ensure externally influenced strings are not passed through unsafe shell expansion.

Prefer argv arrays and `shell=False`.

### Baseline writes

Test:

* valid baseline creation,
* invalid names,
* traversal attempts,
* atomic writes,
* interrupted writes if relevant,
* permissions expectations.

### Error handling

The broker should return structured, safe errors without exposing unnecessary internals or traceback spam to ordinary users.

Do not weaken the existing privilege boundary to make testing easier.

---

# Priority 5 — Add package/install validation

Inspect all packaging assets.

Where available, validate:

```bash
rpmbuild -ba ...
desktop-file-validate ...
systemd-analyze verify ...
shellcheck ...
```

If tools are missing, report that clearly rather than failing the whole development run unnecessarily.

Fix packaging problems you find.

Validate:

* RPM spec
* executable paths
* Python module paths
* desktop launcher
* icons
* PolicyKit policy
* systemd units
* install/uninstall behaviour implied by packaging
* file permissions
* state/log directories
* dependencies

Create a reusable script or Makefile target such as:

```bash
./validate_release.sh
```

or equivalent.

It should perform as much release validation as the local machine supports.

---

# Priority 6 — Formalise the report format

The scanner output is an API between:

* collector,
* analyser,
* GUI,
* exports,
* future versions.

Protect it.

Add either:

* a JSON Schema, or
* a rigorously validated typed structure,

plus representative golden fixtures.

Test that:

* quick scans conform;
* full scans conform;
* partial/cancelled scans conform;
* failed/unavailable checks conform;
* historical fixtures can still be opened;
* unknown future fields don't unnecessarily break readers.

Add a report/schema version.

For example:

```json
{
  "schema_version": 1
}
```

Do not silently break existing reports without migration/backwards compatibility handling.

---

# Priority 7 — Improve analysis around the actual Fedora freeze history

Fedora Crash Doctor exists because this workstation has experienced multiple distinct failure modes.

Strengthen analysis so it explicitly distinguishes them.

## A. Intel i915 / DRM / KWin / Wayland display hang

Historical evidence has included:

```text
i915
Atomic update failure on pipe A
Atomic update failure on pipe B
kwin_wayland unresponsive
```

TTY remained reachable during some freezes.

Recognise this pattern as something like:

```text
Display-stack / compositor hang
System likely remained alive
```

Correlate:

* i915/DRM errors,
* KWin failures,
* Wayland messages,
* display topology,
* Chrome/Electron GPU failures,
* TTY/heartbeat/canary evidence if available.

Avoid claiming a hardware GPU failure unless evidence supports it.

---

## B. Memory/zram collapse

A separate freeze showed approximately:

```text
zram/swap: 8191 / 8191 MB
available RAM: ~475 MB
I/O PSI: ~85%
load: >30
KWin main thread hanging
```

This is a very different failure class.

Add strong detection/reporting for:

```text
memory exhaustion
swap/zram saturation
PSI memory pressure
PSI I/O pressure
runaway processes
desktop starvation caused by reclaim/thrashing
```

If not already captured, extend telemetry to include:

```text
MemAvailable
swap used / total
zram usage
/proc/pressure/memory
/proc/pressure/io
load average
top processes by RSS
top processes by swap
systemd cgroup memory
```

Historical/continuous samples are far more valuable than only capturing these after reboot.

---

## C. Plasma-shell-only hangs

Distinguish:

```text
plasmashell/panel failure
```

from:

```text
KWin/display-stack failure
```

and from:

```text
whole-system/kernel failure
```

If only the panel dies while the compositor/system stays healthy, say so.

---

## D. USB/storage instability

Historical evidence has included:

```text
USB disconnect
Buffer I/O error
lost async page write
EXT4 errors
JBD2 errors
UAS/bridge instability
```

Some of these belonged to external USB devices and should not be blamed on the internal NVMe.

Improve device attribution.

Reports should clearly say which physical/logical device generated an error.

Use data from:

```text
lsblk
udevadm
/sys
SMART
NVMe SMART
USB VID:PID
mount information
filesystem UUID
```

where practical.

Separate:

```text
internal system disk
external USB storage
USB bridge/enclosure
flash drive
```

Do not tell users their boot disk is failing because an unrelated `/dev/sda` USB stick disconnected.

---

## E. Realtek RTL8821CE / PCIe AER

We've seen correctable AER/PCIe messages involving RTL8821CE.

Treat these as evidence, but don't automatically blame them for freezes.

Correlation matters.

Crash Doctor should prefer wording such as:

```text
Correctable PCIe errors observed.
No strong temporal correlation with the freeze was established.
```

rather than recommending random kernel flags.

---

# Priority 8 — Improve crash correlation

The key feature should not merely be:

> “Here are 200 warnings.”

Build or improve an **event timeline** around likely freeze/crash time.

For example:

```text
10:42:11  MemAvailable falls below threshold
10:42:16  zram reaches 98%
10:42:18  PSI I/O jumps to 71%
10:42:20  load average = 29
10:42:23  kwin_wayland heartbeat lost
10:42:28  desktop heartbeat missing
10:43:02  canary still alive
10:45:14  reboot begins
```

This allows meaningful inference:

```text
OS alive, desktop dead
```

or:

```text
entire machine stopped emitting telemetry
```

Use timestamps consistently and robustly.

Consider clock/boot-relative timestamp issues.

---

# Priority 9 — Improve confidence scoring

Diagnostic conclusions should clearly separate:

```text
Observed evidence
Likely explanation
Alternative explanations
Confidence
Recommended next action
```

Avoid overconfident language.

Example:

```text
Likely cause: severe memory pressure
Confidence: High

Evidence:
- zram 100% utilised
- MemAvailable < 500 MiB
- I/O PSI 85%
- load increased above 30
- KWin became unresponsive immediately afterwards

Alternative:
- GPU/display fault occurred concurrently

Recommended next action:
- inspect historical process memory samples
```

Make confidence explainable rather than magic.

If there is already a scoring engine, improve its transparency and tests.

---

# Priority 10 — Improve continuous capture

The best Crash Doctor is one that already has the evidence when the PC freezes.

Inspect:

```text
canary.py
desktop_heartbeat.py
systemd services/timers
capture setup
```

Consider collecting a small rolling telemetry buffer.

Keep it efficient.

For example once every 5–15 seconds record lightweight values such as:

```text
timestamp
boot ID
load
MemAvailable
swap/zram usage
PSI memory
PSI I/O
desktop heartbeat
KWin process existence/state
plasmashell process existence/state
top N memory processes
GPU/i915 counters if cheaply available
```

Do NOT constantly run expensive commands like full SMART tests, `rpm -Va`, giant `journalctl` scans, etc.

Use bounded storage / rotation.

A freeze should leave behind several minutes of pre-freeze telemetry.

---

# Priority 11 — Make “quick”, “full” and “deep” mean something

Define clear tiers.

For example:

## Quick

Target: seconds.

Safe/lightweight:

* system information
* current/previous boot journal highlights
* memory/swap
* PSI
* GPU errors
* services
* display session
* crash capture readiness
* recent storage errors

## Full

Target: reasonable interactive duration.

Adds:

* SMART data
* deeper journal correlation
* package/repository status
* Btrfs statistics
* coredumps
* richer hardware mapping

## Deep / maintenance

Explicit user action.

Potentially:

* `rpm -Va`
* SMART self-tests
* Btrfs scrub
* stress testing
* kdump test crash
* expensive filesystem scans

Dangerous/destructive actions must never occur just because the user clicked “Scan”.

---

# Priority 12 — Safety architecture

Audit every subprocess call.

Prefer:

```python
subprocess.run(
    [cmd, arg1, arg2],
    shell=False,
    ...
)
```

Avoid shell pipelines when Python can perform filtering itself.

Audit:

* user-controlled paths
* device paths
* temporary files
* symlink attacks
* command injection
* privilege escalation surface
* environment variables
* PATH dependence
* inherited file descriptors
* permissions on logs/state
* predictable temp filenames

Use secure temporary files/directories.

Privileged helper should expose **small semantic actions**, not arbitrary command execution.

Do not add a generic “run command as root” feature.

---

# Priority 13 — Clean the codebase

Inspect architecture for:

* duplicated logic
* giant functions
* inconsistent task records
* brittle parsing
* magic strings
* stale comments
* dead code
* debug prints
* broad `except Exception`
* mutable global state
* hidden side effects
* naming inconsistencies

Refactor where it improves maintainability without needlessly rewriting stable code.

Add type hints where they meaningfully help.

Run a formatter/linter if appropriate and available.

`git diff --check` currently finds trailing whitespace in modified areas of:

```text
canary.py
collector.py
```

Clean whitespace in files you already touch, while avoiding giant irrelevant formatting diffs.

---

# Priority 14 — Improve parser robustness

Linux command output changes.

Audit parsing of:

```text
journalctl
last
last -x
lsblk
smartctl
nvme
btrfs
systemctl
coredumpctl
dnf
rpm
kscreen-doctor if used
```

Prefer machine-readable formats where available:

```text
--json
--json=short
--output=json
lsblk -J
```

rather than parsing human-formatted tables.

Keep fallbacks for unavailable versions.

Locale-sensitive parsing should be minimised.

Set a safe predictable locale for commands where necessary.

---

# Priority 15 — Better UI

Inspect the PySide6 GUI as an actual diagnostic application.

Improve obvious usability issues.

Important areas:

* responsive scans;
* progress visibility;
* cancellation;
* quick vs full scan distinction;
* evidence vs conclusions;
* severity indicators;
* confidence;
* expandable raw evidence;
* clear timestamps;
* copy/export buttons;
* indication when elevated privileges are required;
* clear “not checked” vs “healthy” distinction;
* previous scan/history comparison;
* useful error messages.

Do not turn the GUI into a huge redesign merely for aesthetics.

Prioritise diagnostic clarity.

---

# Priority 16 — Releases/versioning

Add or improve:

```text
--version
VERSION or package version source
changelog/release notes where appropriate
```

Avoid version strings duplicated in ten places.

Ensure RPM/package versioning can derive from a sensible single source.

---

# Priority 17 — Documentation

Update the README so a new Fedora user can understand:

### What Crash Doctor does

### What it does not prove

### Quick start

### GUI launch

### CLI examples

### Quick/full/deep modes

### Privileged actions

### Crash-capture setup

### How to analyse the previous boot

### How to install/uninstall

### Where reports/logs live

### Privacy

Explain that reports may contain:

* usernames
* hostnames
* process names
* device identifiers
* logs

and should be reviewed before sharing publicly.

Document safe troubleshooting philosophy:

> Observe first. Correlate evidence. Avoid random kernel parameters.

---

# Priority 18 — CI-friendly checks

Create a straightforward command that verifies the project as fully as possible without needing actual root/hardware side effects.

Ideal outcome:

```bash
./run_tests.sh
./validate_release.sh
```

can exercise:

* unit tests
* GUI offscreen test
* JSON schema
* PolicyKit XML
* desktop file validation
* Python compile/import checks
* standard unittest discovery
* packaging checks where tools exist
* systemd unit verification
* shellcheck where available
* `git diff --check`

Do not make optional missing developer tools appear to be application failures.

---

# Priority 19 — Add regression tests for every bug you fix

Any meaningful bug found during this pass should receive a regression test when practical.

Especially test:

* timeout behaviour
* cancellation
* partial reports
* scan modes
* CLI parsing
* broker validation
* report schema
* timestamp parsing
* device attribution
* memory-pressure classification
* i915/KWin classification
* unknown/unavailable tool handling

---

# Priority 20 — Actually run the application

Do not rely only on static inspection.

Use safe/local operations to run:

```bash
python3 fedora_crash_doctor.py --help
python3 fedora_crash_doctor.py --version
python3 fedora_crash_doctor.py --cli --scan --mode quick ...
```

Run an offscreen GUI integration test.

If feasible without performing dangerous work, exercise the GUI scan path as well.

Do NOT intentionally crash the machine.

Do NOT trigger:

* kernel panic/kdump test crash,
* destructive disk testing,
* SMART long tests,
* Btrfs scrub,
* stress tests,

unless they are mocked/simulated.

---

# Do not

* wipe existing changes;
* reset the repository;
* silently modify unrelated projects;
* weaken PolicyKit security;
* add arbitrary root command execution;
* add random kernel parameters;
* claim hardware is failing without evidence;
* claim a test passed if it was skipped;
* mistake unavailable data for healthy data;
* make full scans block forever;
* hide failures behind broad exception handlers;
* make a huge UI rewrite while leaving core diagnostic weaknesses unfixed.

---

# Before modifying

Run and inspect:

```bash
cd /home/josh/dev/FedoraCrashDoctor
git status --short
git diff --stat
git diff
find . -maxdepth 2 -type f | sort
```

Understand the architecture first.

Preserve unrelated local changes.

---

# After implementation

Run the broadest safe validation available.

At minimum attempt:

```bash
./run_tests.sh
QT_QPA_PLATFORM=offscreen python3 -m unittest tests.test_gui_integration -v
python3 -m unittest discover -s tests -v
python3 -m unittest discover -s . -p 'test_*.py' -v
python3 -m compileall .
python3 fedora_crash_doctor.py --help
python3 fedora_crash_doctor.py --version
python3 collector.py --mode quick --output /tmp/fcd_final_quick.json
git diff --check
```

Also run any new schema/release-validation/packaging tests you add.

Run a full scan only if its newly-designed behaviour is bounded and safe.

If a dependency/tool is missing, record that accurately.

---

# Final response format

When finished, give me:

## 1. What you changed

Group changes by architecture/functionality rather than listing every line.

## 2. Bugs found and fixed

Include root cause.

## 3. New tests

Explain what each important new test protects.

## 4. Verification results

Give exact pass/fail/skip counts and commands.

## 5. Remaining risks

Especially anything requiring real privileged/system testing:

* PolicyKit running as root
* installed systemd units
* real SMART operations
* real Btrfs scrub
* real kdump
* crash capture across an actual hard freeze
* RPM installation onto a clean Fedora machine

## 6. Changed files

List them.

## 7. Git diff/status

Tell me what was pre-existing versus what you changed when distinguishable.

## 8. Release readiness

Give a realistic assessment:

```text
Development tests:
Integration tests:
Packaging:
Privilege boundary:
Real hardware:
Crash capture:
Overall release confidence:
```

Do **not** say “100% fixed” unless the evidence genuinely permits that.

Most importantly: **keep working through the highest-value improvements rather than stopping after the first successful test.**

# Priority 8 — systemd-oomd Configuration

Configured systemd-oomd to protect the KDE session (session.slice) while monitoring and potentially sacrificing runaway processes in app.slice and background.slice based on swap exhaustion and memory pressure limits (50%).
Status: Completed.


---

## Greptile PR #3 review handoff — 26 October 2026 (GRA-065)

**Canonical source:** `Parris-Tech-Services/FedoraCrashDoctor`, central task register `TODO.md` on `main`. **Reviewed scope:** [PR #3](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3), 11 changed files, source `feat/stability-io-guard-2026-10-19` targeting `fix/stability-verification-2026-10-19`, exact reviewed head `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. **Greptile run:** `35547564`, `COMPLETED` 2026-10-26 21:35:05 UTC, confidence 1/5. **Findings:** 9 inline comments (2 P1, 7 P2), all initially unaddressed. These are line-validated source concerns, **not independently reproduced exploits or passing regression tests**. The reviewed head matched the current PR source branch when checked. No new review was triggered. The existing unnumbered 20-priority TODO above is preserved as-is.

- [x] **FCD-GR-001** [P2 / REVIEW] Resume and complete the already-running Greptile PR #3 diff review without duplicate spend. **Evidence:** run `35547564`, reviewed head `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`, [PR #3](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3). **Acceptance met:** terminal COMPLETED status, 9 inline comments retrieved, source paths/lines inspected, 2 P1 + 7 P2 translated to unique tasks below. This checks only the review/handoff, **not any repairs**.

- [ ] **FCD-GR-002** [P1] Stop command-line passwords entering I/O telemetry and exported reports.
  - **Start/triage:** On the reviewed SHA, trace `io_top[].cmd` from `/proc/<pid>/cmdline` into canary samples and JSON export; use a synthetic password fixture only, never real credentials. Check whether any existing reports were shared and whether earlier `cmd` telemetry requires a separate tracked remediation.
  - **Evidence:** canary.py:209-217 (`IoTracker.update`), fedora_crash_doctor.py:1904-1922 (`redact`, `export_json`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763874), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** Privacy/release gate: do not share raw canary logs or export test fixtures with credentials. Check active PR #3 owner and parallel agent claims; preserve existing unrelated telemetry fields.
  - **Proposed minimal fix:** Remove `cmd` from newly introduced `io_top` records and adjust consumers/tests; avoid attempting unreliable password regex scrubbing. Review remaining pre-existing command-line export surfaces separately.
  - **Acceptance:** Synthetic secret-in-argv negative test proves `io_top` and exported JSON/text contain no secret; IoTracker rate/unit attribution still works; `./run_tests.sh`, `./validate_release.sh`, redaction/export regression.
  - **Closure:** Review modified PR diff and exported fixture, document any historical log handling; Greptile addressed status and CI evidence required before closing. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-003** [P1] Prevent untrusted desktop heartbeat files from hanging the privileged canary.
  - **Start/triage:** Verify the read-only `/run/user` bind and synchronous `Path.read_text()` of user-owned heartbeat files; safely reproduce with a temporary FIFO under an isolated test directory, never the installed root service.
  - **Evidence:** canary.py:335-345 (`desktop_heartbeat`), systemd/fedora-crash-doctor-canary.service:17-18; Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763884), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** Coordinate PR #3 source branch; maintain least-privilege access and working real desktop heartbeat; no untrusted file content should block the sampler.
  - **Proposed minimal fix:** Open with nonblocking, no-follow semantics, verify regular-file type and size, read a bounded payload, reject malformed/unsafe entries and continue sampling. Consider owner and race checks.
  - **Acceptance:** FIFO without writer, symlink, oversized JSON, malformed JSON, regular heartbeat, user-session absence and repeat sampling; systemd unit validation, `./run_tests.sh`, `./validate_release.sh`.
  - **Closure:** Show bounded test duration and continued samples under attack; verify real heartbeat in an authorised Fedora test environment before merge and Greptile resolution. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-004** [P2] Reject stale or previous-boot desktop swap samples in current warnings.
  - **Start/triage:** Compare `top_swap` sample timestamps and boot IDs against current boot and collection time; construct old-boot/stopped-canary fixtures.
  - **Evidence:** storage_stability.py:137-160 (`desktop_swap_finding`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763907), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** Pair with FCD-GR-005; preserve historical evidence for retrospective incident timelines, but do not describe it as live state.
  - **Proposed minimal fix:** Require a recent same-boot sample for current-state warnings, or explicitly classify older observations as historical with distinct wording.
  - **Acceptance:** Current same-boot fresh, old same-boot, previous-boot, missing timestamp/boot ID and canary stopped; no restart recommendation from stale evidence.
  - **Closure:** Focused tests plus full suite, reviewed PR comment resolved only after verification. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-005** [P2] Stop treating generic VmSwap as proof desktop pages are disk-backed.
  - **Start/triage:** Check `top_swap[].swap_kb` origin and `/proc/swaps` interpretation; test desktop pages solely in zram while an unrelated process uses disk swap.
  - **Evidence:** storage_stability.py:137-165 (`desktop_swap_finding`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763894), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** FCD-GR-004 freshness checks; FCD-GR-006 classifier should not infer a failure from these measurements.
  - **Proposed minimal fix:** Describe disk-backed desktop swap as an unconfirmed risk unless per-process backing is evidenced; downgrade confidence and remove definite disk-swap/restart claims.
  - **Acceptance:** Zram-only desktop plus other-process disk swap, true supported attribution, no disk swap and mixed swap; assert evidence and advice wording.
  - **Closure:** Unit and integration tests, Greptile re-review and addressed evidence. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-006** [P2] Keep storage measurements from fabricating Plasma/KWin failure diagnoses.
  - **Start/triage:** Pass a synthetic `storage_desktop_in_disk_swap` finding containing only a process name to `classify_freeze_evidence`; confirm whether it emits `plasma_shell_only_failure` or display failure absent any actual error.
  - **Evidence:** collector.py:1690-1698 (`collect`), freeze_classifiers.py:43-120 (`classify_freeze_evidence`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763944), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** FCD-GR-004 and FCD-GR-005 refine input validity; coordinate with existing classifier work on parallel branch before touching shared files.
  - **Proposed minimal fix:** Classify failures using typed incident/error evidence rather than name-only matches in storage performance measurements.
  - **Acceptance:** Measurement-only plasmashell/kwin cases must not create failure classes; real compositor failure evidence still classifies; `./run_tests.sh` and relevant classifier tests.
  - **Closure:** Record before/after classifier outputs, re-review and checks. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-007** [P2] Do not hardcode a potentially unrelated device for I/O bandwidth limits.
  - **Start/triage:** Inspect generated `systemd-run` and `systemctl` commands on a non-default root disk; do not execute device commands on real storage during review.
  - **Evidence:** stability_playbook.py:88-100 (`storage_run_heavy_jobs_gently`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763915), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** FCD-GR-008 device identification where auto-selection is used; confirmation-gated manual actions remain mandatory.
  - **Proposed minimal fix:** Use a verified physical backing device or an explicit clearly labelled placeholder with user selection guidance; avoid silently targeting a different disk.
  - **Acceptance:** SATA, second NVMe, encrypted mapper, unknown device and no-device fixtures; assert commands target only intended device or remain non-executable placeholders.
  - **Closure:** Command-generation tests, manual safety review and Greptile resolution. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-008** [P2] Resolve encrypted/LVM root through physical backing disk for QLC detection.
  - **Start/triage:** Model mountinfo `/dev/dm-*` and sysfs `slaves` chain with test fixtures; verify model lookup currently stops at a virtual mapper.
  - **Evidence:** storage_stability.py:67-97 (`root_disk`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763920), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** FCD-GR-009 capacity semantics; FCD-GR-007 can reuse reliable backing-device identification.
  - **Proposed minimal fix:** Walk mapped-device backing relationships or structured `lsblk` data, handle multiple backing disks without guessing, return unknown safely.
  - **Acceptance:** Plain partition, LUKS, LVM, nested mapper, missing sysfs, multiple disks and malformed mountinfo; no false physical-device attribution.
  - **Closure:** Focused tests and integration regression with Greptile re-review. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-009** [P2] Avoid equating root filesystem fill percentage with entire SSD capacity.
  - **Start/triage:** Compare `shutil.disk_usage(root)` with actual device layout; create split-root/home and shared-device fixtures.
  - **Evidence:** storage_stability.py:115-133, 204-217 (`qlc_fill_finding`, `analyse_storage_stability`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763929), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** FCD-GR-008 disk identification if computing whole-drive capacity; do not overstate confidence on unmeasured layouts.
  - **Proposed minimal fix:** Either calculate physical-device capacity accurately or label and score the observation as root-filesystem usage only.
  - **Acceptance:** Single root, split partitions, full home but free root, nearly full root with spare device capacity, unknown layout; assert title/confidence/evidence accuracy.
  - **Closure:** Focused tests and wording review, Greptile addressed only after evidence. Leave OPEN until code PR, CI and provider evidence exist.

- [ ] **FCD-GR-010** [P2] Correct process start-time fixture and test PID reuse handling.
  - **Start/triage:** Count `/proc/<pid>/stat` fields in test fixture and verify `start_time[19]` is actually populated; test PID reuse with changed start time.
  - **Evidence:** tests/test_storage_stability.py:105-132, canary.py:190-204 (`IoTracker`); Greptile run `35547564`, [original inline comment](https://github.com/Parris-Tech-Services/FedoraCrashDoctor/pull/3#discussion_r4382763952), reviewed source `e9bf8ecf223f66018dd206978ecdb01cc68d4ee4`. Source-path risk validated; reproduction still required.
  - **Dependencies/claim/privacy:** FCD-GR-002 may change expected `io_top` payload; coordinate test updates to avoid conflicting assertions.
  - **Proposed minimal fix:** Correct fixture to match kernel stat field layout; assert changed-start-time same PID does not inherit previous counters.
  - **Acceptance:** Initial sample, stable PID rate, same PID new start time reset, negative delta, malformed stat; `./run_tests.sh` and `./validate_release.sh`.
  - **Closure:** Test evidence and Greptile comment resolved only after code/test PR is verified. Leave OPEN until code PR, CI and provider evidence exist.

**Execution order:** `FCD-GR-002` → `003` (privacy and canary availability P1) → `004` → `005` → `006` (correct diagnosis inputs) → `008` → `009` → `007` (device/cap correctness) → `010` (PID regression). Respect current PR #3 and parallel classifier work; never auto-merge or install privileged services as part of documentation triage. **Release gate:** Do not merge PR #3 until the P1 paths are mitigated and tests pass. Existing historical command-line logging should be investigated separately if it remains reachable; this PR review does not certify the rest of the application.
