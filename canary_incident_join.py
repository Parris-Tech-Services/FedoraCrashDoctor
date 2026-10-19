"""Join canary/desktop-heartbeat telemetry onto an incident.

collector.analyse_canary() already produces a rolling stream of samples
that carry both system-canary liveness (the sample itself existing proves
the canary process was alive enough to write it) and
desktop_heartbeat_age_s/kwin_ok in the same record. This module finds the
samples that fall inside an incident's own evidence window and uses them
to close two of incident_model's evidence_completeness gaps
(canary_telemetry, desktop_heartbeat) -- and, only when failure_scope is
still 'unknown', to distinguish "the whole system stopped" from "the
desktop/compositor stopped while the system canary kept running", which
log evidence alone often cannot do. This is exactly the
canary-continued-but-heartbeat-lost pattern the mission describes.

Like incident_observations.refine_failure_scope_with_observations(), this
is deliberately conservative: it never overrides a failure_scope the logs
already established with hard evidence, and it never touches mechanism/
hypotheses at all -- telemetry sharpens scope, it does not prove a cause.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any

MAX_ATTACHED_SAMPLES = 40
HEARTBEAT_STALE_SECONDS = 20


def _parse_ts(value: str) -> datetime | None:
    try:
        parsed = datetime.fromisoformat(value)
        # Incident windows are derived from local journal timestamps while
        # canary samples normally carry an explicit offset. Convert aware
        # samples to the host's local timezone before comparing them to the
        # journal window; simply dropping the offset can move a sample into a
        # different incident.
        if parsed.tzinfo is not None:
            parsed = parsed.astimezone()
        return parsed.replace(tzinfo=None)
    except (ValueError, TypeError):
        return None


def _heartbeat_ok(sample: dict[str, Any]) -> bool:
    return (sample.get("desktop_heartbeat_age_s") or 0) <= HEARTBEAT_STALE_SECONDS and sample.get("kwin_ok") is not False


def samples_in_window(
    canary_samples: list[dict[str, Any]], window_start: str, window_end: str
) -> list[dict[str, Any]]:
    """canary_samples that fall within [window_start, window_end]
    (incident_start/incident_end, both naive-local ISO strings). Canary
    timestamps are timezone-aware; they are compared as naive local time,
    consistent with how the rest of collector.py already treats
    journal-derived timestamps."""
    start = _parse_ts(window_start)
    end = _parse_ts(window_end)
    if start is None or end is None:
        return []
    matched = []
    for sample in canary_samples:
        ts = _parse_ts(sample.get("ts", ""))
        if ts is not None and start <= ts <= end:
            matched.append(sample)
    return matched


def heartbeat_continuity(samples: list[dict[str, Any]]) -> str:
    """'canary_alive_heartbeat_lost' / 'both_alive' / 'inconclusive'.

    Requires the heartbeat to look OK near the start of the window and
    stale/failed near the end, so this reports an actual loss observed
    during the window -- not merely "the last few samples happen to look
    stale", which could equally mean the heartbeat was already stale
    before this incident for an unrelated reason, or that too few samples
    exist to say anything.
    """
    if len(samples) < 2:
        return "inconclusive"
    head, tail = samples[:3], samples[-3:]
    head_alive = any(_heartbeat_ok(s) for s in head)
    tail_dead = all(not _heartbeat_ok(s) for s in tail)
    if head_alive and tail_dead:
        return "canary_alive_heartbeat_lost"
    if all(_heartbeat_ok(s) for s in samples):
        return "both_alive"
    return "inconclusive"


def attach_canary_evidence(
    incident: dict[str, Any], canary_samples: list[dict[str, Any]]
) -> dict[str, Any]:
    """Mutate `incident` in place: attach a bounded slice of in-window
    canary samples, record heartbeat continuity, update
    evidence_completeness, and -- only if failure_scope is still 'unknown'
    -- refine it using the canary_alive_heartbeat_lost pattern. Also
    returns `incident` for convenient chaining."""
    window_start = incident.get("incident_start", "")
    window_end = incident.get("incident_end", "")
    matched = samples_in_window(canary_samples, window_start, window_end)

    incident["canary_samples"] = matched[-MAX_ATTACHED_SAMPLES:]
    continuity = heartbeat_continuity(matched)
    incident["canary_desktop_heartbeat_continuity"] = continuity

    completeness = incident.get("evidence_completeness")
    if completeness is not None:
        if matched:
            completeness["canary_telemetry"] = "complete"
        elif canary_samples:
            completeness["canary_telemetry"] = "unavailable"
        # else: leave whatever it already was (e.g. not_collected) -- no
        # canary data existed for this scan at all.

        heartbeat_fields_present = any(
            s.get("desktop_heartbeat_age_s") is not None or s.get("kwin_ok") is not None for s in matched
        )
        if heartbeat_fields_present:
            completeness["desktop_heartbeat"] = "complete"
        elif matched:
            completeness["desktop_heartbeat"] = "unavailable"

        # Keep the report's source list consistent with the detailed
        # completeness states.  The incident is created before canary data is
        # joined, so attach_incident_identity() cannot know these sources yet.
        sources = list(dict.fromkeys(incident.get("evidence_sources", [])))
        if completeness.get("canary_telemetry") == "complete" and "canary_telemetry" not in sources:
            sources.append("canary_telemetry")
        if completeness.get("desktop_heartbeat") == "complete" and "desktop_heartbeat" not in sources:
            sources.append("desktop_heartbeat")
        incident["evidence_sources"] = sources

    if incident.get("failure_scope") == "unknown" and continuity == "canary_alive_heartbeat_lost":
        reasoning = list(incident.get("failure_scope_reasoning", []))
        reasoning.append(
            "Canary telemetry shows the system canary continued producing samples while the "
            "desktop/KWin heartbeat went from healthy to stale or failed within this window -- "
            "consistent with the desktop environment being unresponsive while the underlying "
            "system stayed alive."
        )
        incident["failure_scope"] = "desktop_environment"
        incident["failure_scope_reasoning"] = reasoning

    return incident
