"""Evidence-backed long-term stability summary.

This is deliberately an observed stability index, not a claim that hardware
or Fedora is healthy. It is computed from saved scan reports, exposes the
counts and coverage used by the formula, and refuses to score a single scan.
It never writes reports or changes host state.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any


def _timestamp(report: dict[str, Any]) -> datetime | None:
    value = (report.get("metadata") or {}).get("generated")
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except (TypeError, ValueError):
        return None


def _reports_with_timestamps(reports: list[dict[str, Any]]) -> list[tuple[datetime, dict[str, Any]]]:
    result = []
    for report in reports:
        if not isinstance(report, dict):
            continue
        timestamp = _timestamp(report)
        if timestamp is not None:
            result.append((timestamp, report))
    return sorted(result, key=lambda item: item[0])


def _readiness_has(report: dict[str, Any], name: str, accepted: set[str]) -> bool:
    for source in (report.get("readiness") or {}).get("sources", []) or []:
        if source.get("name") == name and source.get("status") in accepted:
            return True
    return False


def build_reliability_summary(reports: list[dict[str, Any]]) -> dict[str, Any]:
    """Build a bounded, explainable summary from scan reports.

    The score is intentionally named an observed stability index. Its formula
    is public in the returned object and is not a hardware-health guarantee:

    100 - min(40, 20 * unclean_shutdowns)
        - min(30, 30 * kernel_panics)
        - min(20, 5 * critical_incident_reports)
        - min(15, 1 * warning_incident_reports)
        - 10 when canary coverage is below 50%
        - 10 when persistent-journal coverage is below 50%

    A report with no incident is not automatically treated as proof of a
    healthy boot; coverage is shown separately and affects the score.
    """
    dated = _reports_with_timestamps(reports)
    total = len(dated)
    incidents = [incident for _, report in dated for incident in report.get("incidents", []) or []]
    unclean = sum(incident.get("failure_boundary") == "unclean shutdown" for incident in incidents)
    kernel_panics = sum(incident.get("failure_boundary") == "kernel panic" for incident in incidents)
    critical_incident_reports = sum(
        any(finding.get("severity") == "critical" and finding.get("scope") == "this_incident"
            for finding in report.get("findings", []) or [])
        for _, report in dated
    )
    warning_incident_reports = sum(
        any(finding.get("severity") == "warning" and finding.get("scope") == "this_incident"
            for finding in report.get("findings", []) or [])
        for _, report in dated
    )

    canary_scans = sum(bool((report.get("canary") or {}).get("samples")) for _, report in dated)
    journal_scans = sum(
        _readiness_has(report, "Persistent Journal", {"verified_persistent", "available_with_records"})
        for _, report in dated
    )
    canary_coverage = canary_scans / total if total else 0.0
    journal_coverage = journal_scans / total if total else 0.0

    components = [
        {"name": "unclean_shutdowns", "penalty": min(40, 20 * unclean), "count": unclean},
        {"name": "kernel_panics", "penalty": min(30, 30 * kernel_panics), "count": kernel_panics},
        {"name": "critical_incident_reports", "penalty": min(20, 5 * critical_incident_reports), "count": critical_incident_reports},
        {"name": "warning_incident_reports", "penalty": min(15, warning_incident_reports), "count": warning_incident_reports},
    ]
    if total and canary_coverage < 0.5:
        components.append({"name": "low_canary_coverage", "penalty": 10, "coverage": canary_coverage})
    if total and journal_coverage < 0.5:
        components.append({"name": "low_journal_coverage", "penalty": 10, "coverage": journal_coverage})

    score = None if total < 2 else max(0, 100 - sum(item["penalty"] for item in components))
    summary: dict[str, Any] = {
        "kind": "observed_stability_index",
        "score": score,
        "score_state": "ready" if score is not None else "insufficient_data",
        "formula": "100 - capped incident penalties - coverage penalties; not a hardware-health guarantee",
        "reports": total,
        "incidents": len(incidents),
        "unclean_shutdowns": unclean,
        "kernel_panics": kernel_panics,
        "coverage": {
            "canary_scans": canary_scans,
            "canary_fraction": round(canary_coverage, 3),
            "persistent_journal_scans": journal_scans,
            "persistent_journal_fraction": round(journal_coverage, 3),
        },
        "score_components": components,
        "limitations": [
            "A score summarizes recorded observations; it cannot prove that an intermittent fault is fixed.",
            "Fewer than two dated scans produce insufficient_data rather than a score.",
            "A missing canary or journal lowers evidence coverage; it is not treated as a healthy result.",
        ],
    }
    if dated:
        summary["window"] = {"start": dated[0][0].isoformat(), "end": dated[-1][0].isoformat()}
    return summary
