from reliability_summary import build_reliability_summary


def _report(generated, *, boundary=None, canary=True, journal=True, critical=False, warning=False):
    incidents = [] if boundary is None else [{"failure_boundary": boundary}]
    findings = []
    if critical:
        findings.append({"severity": "critical", "scope": "this_incident"})
    if warning:
        findings.append({"severity": "warning", "scope": "this_incident"})
    sources = []
    if journal:
        sources.append({"name": "Persistent Journal", "status": "verified_persistent"})
    return {
        "metadata": {"generated": generated},
        "incidents": incidents,
        "findings": findings,
        "canary": {"samples": [{"ts": generated}]} if canary else {"samples": []},
        "readiness": {"sources": sources},
    }


def test_single_scan_is_not_scored():
    summary = build_reliability_summary([_report("2026-10-15T10:00:00+11:00")])
    assert summary["score"] is None
    assert summary["score_state"] == "insufficient_data"


def test_clean_two_scan_window_has_full_score_and_coverage():
    summary = build_reliability_summary([
        _report("2026-10-15T10:00:00+11:00"),
        _report("2026-10-16T10:00:00+11:00"),
    ])
    assert summary["score"] == 100
    assert summary["coverage"]["canary_fraction"] == 1.0
    assert summary["coverage"]["persistent_journal_fraction"] == 1.0


def test_penalties_are_explicit_and_capped():
    summary = build_reliability_summary([
        _report("2026-10-15T10:00:00+11:00", boundary="unclean shutdown", canary=False, journal=False, critical=True, warning=True),
        _report("2026-10-16T10:00:00+11:00", boundary="kernel panic", canary=False, journal=False, critical=True),
    ])
    assert summary["score"] == 19
    penalties = {item["name"]: item["penalty"] for item in summary["score_components"]}
    assert penalties["unclean_shutdowns"] == 20
    assert penalties["kernel_panics"] == 30
    assert penalties["critical_incident_reports"] == 10
    assert penalties["warning_incident_reports"] == 1
    assert penalties["low_canary_coverage"] == 10
    assert penalties["low_journal_coverage"] == 10
