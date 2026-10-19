"""Tests for joining canary/desktop-heartbeat telemetry onto an incident."""
from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from canary_incident_join import attach_canary_evidence, heartbeat_continuity, samples_in_window

# Incident windows below are naive Sydney-local times (AEST, +10:00 in September).
pytestmark = pytest.mark.usefixtures("sydney_host_tz")


def _sample(ts, heartbeat_age=5, kwin_ok=True):
    return {"ts": ts, "desktop_heartbeat_age_s": heartbeat_age, "kwin_ok": kwin_ok}


def _incident(**overrides):
    base = {
        "incident_start": "2026-09-10T09:45:00",
        "incident_end": "2026-09-10T10:01:00",
        "failure_scope": "unknown",
        "failure_scope_reasoning": ["no evidence"],
        "evidence_completeness": {
            "journal": "unavailable", "coredump": "unavailable",
            "canary_telemetry": "not_collected", "desktop_heartbeat": "not_collected",
            "user_observations": "not_collected",
        },
        "evidence_sources": [],
    }
    base.update(overrides)
    return base


class TestSamplesInWindow:
    def test_only_samples_inside_the_window_match(self):
        samples = [
            _sample("2026-09-10T09:00:00+10:00"),   # before window
            _sample("2026-09-10T09:50:00+10:00"),   # inside
            _sample("2026-09-10T11:00:00+10:00"),   # after window
        ]
        matched = samples_in_window(samples, "2026-09-10T09:45:00", "2026-09-10T10:01:00")
        assert len(matched) == 1
        assert matched[0]["ts"] == "2026-09-10T09:50:00+10:00"

    def test_timezone_aware_canary_ts_compared_against_naive_window(self):
        samples = [_sample("2026-09-10T09:50:00+10:00")]
        matched = samples_in_window(samples, "2026-09-10T09:45:00", "2026-09-10T10:01:00")
        assert len(matched) == 1

    def test_different_offset_is_converted_before_window_comparison(self):
        sample_ts = "2026-09-10T00:50:00+01:00"
        local_ts = datetime.fromisoformat(sample_ts).astimezone().replace(tzinfo=None)
        start = (local_ts - timedelta(minutes=5)).isoformat()
        end = (local_ts + timedelta(minutes=5)).isoformat()
        matched = samples_in_window([_sample(sample_ts)], start, end)
        assert len(matched) == 1

    @pytest.mark.parametrize(
        "zone, window_start, window_end",
        [
            ("UTC", "2026-09-09T23:45:00", "2026-09-10T00:01:00"),
            ("America/Los_Angeles", "2026-09-09T16:45:00", "2026-09-09T17:01:00"),
        ],
    )
    def test_window_follows_the_host_timezone_not_the_sample_offset(self, host_tz, zone, window_start, window_end):
        """The same +10:00 sample lands in a window written in whatever zone
        the host is in, and the Sydney-local window no longer matches."""
        host_tz(zone)
        samples = [_sample("2026-09-10T09:50:00+10:00")]
        assert len(samples_in_window(samples, window_start, window_end)) == 1
        assert samples_in_window(samples, "2026-09-10T09:45:00", "2026-09-10T10:01:00") == []

    def test_malformed_window_returns_empty(self):
        assert samples_in_window([_sample("2026-09-10T09:50:00+10:00")], "not-a-date", "also-not-a-date") == []

    def test_malformed_sample_ts_is_skipped(self):
        samples = [{"ts": "garbage"}, _sample("2026-09-10T09:50:00+10:00")]
        matched = samples_in_window(samples, "2026-09-10T09:45:00", "2026-09-10T10:01:00")
        assert len(matched) == 1


class TestHeartbeatContinuity:
    def test_too_few_samples_is_inconclusive(self):
        assert heartbeat_continuity([_sample("t1")]) == "inconclusive"

    def test_alive_then_lost_is_the_target_pattern(self):
        samples = [_sample(f"t{i}", heartbeat_age=5, kwin_ok=True) for i in range(3)] + \
                  [_sample(f"t{i}", heartbeat_age=60, kwin_ok=False) for i in range(3, 6)]
        assert heartbeat_continuity(samples) == "canary_alive_heartbeat_lost"

    def test_always_alive_is_both_alive(self):
        samples = [_sample(f"t{i}", heartbeat_age=5, kwin_ok=True) for i in range(6)]
        assert heartbeat_continuity(samples) == "both_alive"

    def test_always_dead_is_inconclusive_not_a_guess(self):
        """Can't distinguish 'system dead too' from 'desktop already dead
        before this window for an unrelated reason' from telemetry alone."""
        samples = [_sample(f"t{i}", heartbeat_age=60, kwin_ok=False) for i in range(6)]
        assert heartbeat_continuity(samples) == "inconclusive"


class TestAttachCanaryEvidence:
    def test_no_canary_data_at_all_leaves_not_collected(self):
        incident = _incident()
        attach_canary_evidence(incident, [])
        assert incident["evidence_completeness"]["canary_telemetry"] == "not_collected"

    def test_canary_exists_but_nothing_in_window_is_unavailable(self):
        incident = _incident()
        attach_canary_evidence(incident, [_sample("2026-01-01T00:00:00+10:00")])
        assert incident["evidence_completeness"]["canary_telemetry"] == "unavailable"

    def test_samples_in_window_mark_complete_and_are_attached(self):
        incident = _incident()
        samples = [_sample("2026-09-10T09:50:00+10:00")]
        attach_canary_evidence(incident, samples)
        assert incident["evidence_completeness"]["canary_telemetry"] == "complete"
        assert incident["evidence_completeness"]["desktop_heartbeat"] == "complete"
        assert incident["evidence_sources"] == ["canary_telemetry", "desktop_heartbeat"]
        assert len(incident["canary_samples"]) == 1

    def test_refines_unknown_scope_to_desktop_environment_on_the_target_pattern(self):
        incident = _incident(failure_scope="unknown")
        samples = (
            [_sample(f"2026-09-10T09:4{i}:00+10:00", heartbeat_age=5, kwin_ok=True) for i in range(6, 9)]
            + [_sample(f"2026-09-10T09:5{i}:00+10:00", heartbeat_age=60, kwin_ok=False) for i in range(5)]
        )
        attach_canary_evidence(incident, samples)
        assert incident["failure_scope"] == "desktop_environment"
        assert len(incident["failure_scope_reasoning"]) == 2  # original + new reasoning
        assert "canary" in incident["failure_scope_reasoning"][-1].lower()

    def test_never_overrides_a_scope_already_established_from_logs(self):
        """A confirmed whole_system boundary must not be second-guessed by
        telemetry, even if the pattern superficially looks compatible."""
        incident = _incident(failure_scope="whole_system", failure_scope_reasoning=["unclean shutdown"])
        samples = (
            [_sample(f"2026-09-10T09:4{i}:00+10:00", heartbeat_age=5, kwin_ok=True) for i in range(6, 9)]
            + [_sample(f"2026-09-10T09:5{i}:00+10:00", heartbeat_age=60, kwin_ok=False) for i in range(5)]
        )
        attach_canary_evidence(incident, samples)
        assert incident["failure_scope"] == "whole_system"
        assert incident["failure_scope_reasoning"] == ["unclean shutdown"]

    def test_both_alive_pattern_does_not_change_unknown_scope(self):
        incident = _incident(failure_scope="unknown")
        samples = [_sample(f"2026-09-10T09:5{i}:00+10:00", heartbeat_age=5, kwin_ok=True) for i in range(3)]
        attach_canary_evidence(incident, samples)
        assert incident["failure_scope"] == "unknown"

    def test_returns_the_same_incident_object(self):
        incident = _incident()
        assert attach_canary_evidence(incident, []) is incident
