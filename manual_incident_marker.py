"""'Mark incident now' -- a lightweight, explicit way to record that a
freeze/incident just happened (or happened at an approximate past time),
without waiting for journal boot-boundary detection to notice it, which
only ever fires after a reboot and can miss a freeze the machine partially
recovered from on its own.

This reads the current canary rolling buffer directly
(/var/log/fedora-crash-doctor/canary.log, world-readable, the same file
collector.py's own canary_log check reads) and creates a narrow,
user-anchored incident record saved using the same scan-*.json naming
convention ordinary scan reports use, so incident_history.py and the
GUI's own Trends tab pick it up for fingerprinting/recurrence tracking
like any other incident -- no new file format, no privileged access
needed (this never touches privileged_helper.py).

A manually marked incident intentionally does not run collector.py's full
journal analysis/hypothesis engine (that is a much heavier, full scan);
it only preserves canary telemetry around the marked moment and records
the fact that this moment was flagged. Run a full scan afterwards for
ranked hypotheses.
"""
from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from canary_incident_join import attach_canary_evidence
from collector import analyse_canary, assess_readiness, category_status, tail_file
from confidence_explanation import explain_incident
from incident_model import attach_incident_identity
from report_schema import REPORT_SCHEMA_VERSION
from version import app_version

CANARY_LOG_PATH = Path("/var/log/fedora-crash-doctor/canary.log")
WINDOW_BEFORE = timedelta(minutes=10)
WINDOW_AFTER = timedelta(minutes=2)

LIMITATIONS = [
    "This incident was manually marked by the user, not detected from journal boot-boundary "
    "analysis, so no automated hypothesis was generated -- run a full scan for ranked hypotheses.",
    "A manual mark only preserves canary telemetry around the marked moment; it does not "
    "re-analyse the journal.",
]


def read_recent_canary_samples(path: Path = CANARY_LOG_PATH, lines: int = 1200) -> list[dict[str, Any]]:
    """The same parsing collector.analyse_canary() applies to the
    canary_log check's output, reused directly so this stays consistent
    with the real scan pipeline rather than a second parser."""
    if not path.exists():
        return []
    checks = {"canary_log": {"output": tail_file(path, lines)}}
    return analyse_canary(checks).get("samples", [])


def mark_incident(
    at: datetime | None = None,
    note: str | None = None,
    canary_samples: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Build one manually-anchored incident dict. `at` defaults to now
    (naive local time, matching how the rest of the app already treats
    journal-derived timestamps)."""
    anchor = at or datetime.now()
    window_start = anchor - WINDOW_BEFORE
    window_end = anchor + WINDOW_AFTER
    samples = canary_samples if canary_samples is not None else read_recent_canary_samples()

    boot_id = "unknown"
    for sample in reversed(samples):
        if sample.get("boot_id"):
            boot_id = sample["boot_id"]
            break

    incident: dict[str, Any] = {
        "boot_id": boot_id,
        "boot_index": "0",
        "incident_start": window_start.isoformat(),
        "incident_end": window_end.isoformat(),
        "incident_anchor_ts": anchor.isoformat(),
        "failure_boundary": "user_marked",
        "incident_evidence": [],
        "coredumps": [],
        "strongest_hypothesis": "User-marked incident; no automated hypothesis",
        "supporting_evidence": [],
        "next_step": "Run a full scan for ranked hypotheses; review the canary telemetry captured around the marked time.",
        "confidence": "low",
        "confidence_explanation": "No automated hypothesis was generated for a manually marked incident.",
        "hypotheses": [],
        "sort_key": anchor.timestamp(),
    }
    if note:
        incident["user_note"] = note

    attach_incident_identity(incident, checks=None)
    attach_canary_evidence(incident, samples)
    incident["hypothesis_explanations"] = explain_incident(incident)
    return incident


def build_manual_scan_report(incident: dict[str, Any]) -> dict[str, Any]:
    """Wrap one manually-marked incident in the same top-level report
    shape collector.collect() produces (all REQUIRED_REPORT_KEYS present),
    so it can be opened directly in the GUI and is picked up by
    incident_history.py exactly like an ordinary scan report."""
    generated = datetime.now().isoformat()
    return {
        "schema": 3,
        "schema_version": REPORT_SCHEMA_VERSION,
        "metadata": {
            "generated": generated,
            "mode": "manual-mark",
            "version": app_version(),
        },
        "counts": {"critical": 0, "warning": 0, "info": 0},
        "incidents": [incident],
        "boot_warnings": [],
        "unresolved_evidence": [],
        "overall": {
            "title": "Manually marked incident",
            "confidence": "low",
            "summary": "A user marked this moment as an incident; run a full scan for ranked hypotheses.",
        },
        "hypotheses": [],
        "freeze_classes": [],
        "categories": category_status([], {}),
        "readiness": assess_readiness({}),
        "findings": [],
        "timeline": [],
        "telemetry_timeline": [],
        "canary": {"samples": incident.get("canary_samples", []), "interpretation": "See the marked incident."},
        "checks": {},
        "test_targets": {"smart_devices": []},
        "limitations": list(LIMITATIONS),
    }


def save_manual_incident(
    report_dir: Path,
    at: datetime | None = None,
    note: str | None = None,
) -> Path:
    """Mark an incident now (or at `at`) and save it into `report_dir`
    using the scan-*.json naming convention. Returns the saved path."""
    incident = mark_incident(at=at, note=note)
    report = build_manual_scan_report(incident)
    report_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    path = report_dir / f"scan-manual-{stamp}.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    return path
