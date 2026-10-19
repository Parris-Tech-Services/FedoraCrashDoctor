"""Tests for the 'Mark incident now' manual incident marker."""
from __future__ import annotations

import json
from datetime import datetime

from manual_incident_marker import (
    build_manual_scan_report,
    mark_incident,
    read_recent_canary_samples,
    save_manual_incident,
)
from report_schema import REQUIRED_REPORT_KEYS, validate_report


def _sample(ts, boot_id="boot1", heartbeat_age=5, kwin_ok=True):
    return {"ts": ts, "boot_id": boot_id, "desktop_heartbeat_age_s": heartbeat_age, "kwin_ok": kwin_ok}


class TestMarkIncident:
    def test_defaults_to_now(self):
        before = datetime.now()
        incident = mark_incident(canary_samples=[])
        after = datetime.now()
        anchor = datetime.fromisoformat(incident["incident_anchor_ts"])
        assert before <= anchor <= after

    def test_explicit_time_is_used_as_the_anchor(self):
        at = datetime(2026, 9, 10, 22, 0, 0)
        incident = mark_incident(at=at, canary_samples=[])
        assert incident["incident_anchor_ts"] == at.isoformat()

    def test_window_brackets_the_anchor(self):
        at = datetime(2026, 9, 10, 22, 0, 0)
        incident = mark_incident(at=at, canary_samples=[])
        start = datetime.fromisoformat(incident["incident_start"])
        end = datetime.fromisoformat(incident["incident_end"])
        assert start < at < end

    def test_failure_boundary_is_user_marked(self):
        incident = mark_incident(canary_samples=[])
        assert incident["failure_boundary"] == "user_marked"

    def test_has_incident_identity_attached(self):
        incident = mark_incident(canary_samples=[])
        assert incident["incident_id"].startswith("inc_")
        assert incident["failure_scope"] in (
            "application", "plasmashell_panel", "compositor_session", "desktop_environment",
            "whole_system", "clean_shutdown", "unknown",
        )

    def test_note_is_preserved_when_given(self):
        incident = mark_incident(canary_samples=[], note="screen went black")
        assert incident["user_note"] == "screen went black"

    def test_note_omitted_when_not_given(self):
        incident = mark_incident(canary_samples=[])
        assert "user_note" not in incident

    def test_boot_id_derived_from_the_most_recent_matching_canary_sample(self):
        at = datetime(2026, 9, 10, 22, 0, 0)
        samples = [
            _sample("2026-09-10T21:55:00+10:00", boot_id="boot-old"),
            _sample("2026-09-10T21:56:00+10:00", boot_id="boot-current"),
        ]
        incident = mark_incident(at=at, canary_samples=samples)
        assert incident["boot_id"] == "boot-current"

    def test_no_canary_samples_still_produces_a_usable_incident(self):
        incident = mark_incident(canary_samples=[])
        assert incident["boot_id"] == "unknown"
        assert incident["evidence_completeness"]["canary_telemetry"] == "not_collected"

    def test_canary_evidence_is_attached_when_samples_fall_in_window(self):
        at = datetime(2026, 9, 10, 22, 0, 0)
        samples = [_sample("2026-09-10T21:55:00+10:00")]
        incident = mark_incident(at=at, canary_samples=samples)
        assert len(incident["canary_samples"]) == 1
        assert incident["evidence_completeness"]["canary_telemetry"] == "complete"

    def test_no_hypotheses_means_no_hypothesis_explanations(self):
        incident = mark_incident(canary_samples=[])
        assert incident["hypotheses"] == []
        assert incident["hypothesis_explanations"] == []


class TestBuildManualScanReport:
    def test_report_has_every_required_key(self):
        incident = mark_incident(canary_samples=[])
        report = build_manual_scan_report(incident)
        assert REQUIRED_REPORT_KEYS <= set(report)

    def test_report_validates_against_the_real_schema_validator(self):
        incident = mark_incident(canary_samples=[])
        report = build_manual_scan_report(incident)
        validate_report(report)  # must not raise

    def test_report_metadata_marks_the_manual_mode(self):
        incident = mark_incident(canary_samples=[])
        report = build_manual_scan_report(incident)
        assert report["metadata"]["mode"] == "manual-mark"

    def test_report_contains_the_incident(self):
        incident = mark_incident(canary_samples=[])
        report = build_manual_scan_report(incident)
        assert report["incidents"] == [incident]

    def test_report_is_json_serializable(self):
        incident = mark_incident(canary_samples=[])
        report = build_manual_scan_report(incident)
        json.dumps(report)  # must not raise


class TestSaveManualIncident:
    def test_saves_a_scan_prefixed_file(self, tmp_path):
        path = save_manual_incident(tmp_path, at=datetime(2026, 9, 10, 22, 0, 0))
        assert path.name.startswith("scan-manual-")
        assert path.exists()

    def test_saved_file_is_readable_json_with_the_incident(self, tmp_path):
        path = save_manual_incident(tmp_path, at=datetime(2026, 9, 10, 22, 0, 0), note="test note")
        data = json.loads(path.read_text())
        assert data["incidents"][0]["user_note"] == "test note"

    def test_saved_file_is_picked_up_by_incident_history(self, tmp_path):
        save_manual_incident(tmp_path, at=datetime(2026, 9, 10, 22, 0, 0))
        from incident_history import load_incident_history
        history = load_incident_history(tmp_path)
        assert len(history) == 1
        assert history[0]["failure_boundary"] == "user_marked"

    def test_creates_report_dir_if_missing(self, tmp_path):
        target = tmp_path / "nested" / "dir"
        path = save_manual_incident(target, at=datetime(2026, 9, 10, 22, 0, 0))
        assert path.exists()


class TestReadRecentCanarySamples:
    def test_missing_file_returns_empty_list(self, tmp_path):
        assert read_recent_canary_samples(tmp_path / "does-not-exist.log") == []

    def test_reads_and_parses_real_ndjson_format(self, tmp_path):
        log = tmp_path / "canary.log"
        log.write_text(
            json.dumps({"ts": "2026-09-10T22:00:00+10:00", "boot_id": "b1"}) + "\n"
            + json.dumps({"ts": "2026-09-10T22:01:00+10:00", "boot_id": "b1"}) + "\n"
        )
        samples = read_recent_canary_samples(log)
        assert len(samples) == 2
