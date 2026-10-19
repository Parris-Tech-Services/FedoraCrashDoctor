"""Structured Incident identity, failure-scope classification, and
evidence-completeness accounting.

collector.build_incidents() already groups evidence around boot boundaries
and ranks explanatory hypotheses per incident (title/category/score/
confidence/supports/against/next_test) -- that ranking machinery is not
duplicated here and is not touched by this module. This module answers two
narrower questions cleanly, and keeps them separate:

  WHAT stopped responding, and how much of the system was affected?
    -> classify_failure_scope() / FAILURE_SCOPES

  WHY did it probably happen?
    -> collector.py's existing incident["hypotheses"], unchanged; this
       module only adds mechanism_tags(), a coarse normalisation of those
       existing hypotheses' categories for later fingerprinting, not a new
       ranking.

An earlier version of this module conflated the two into one
"classification" enum (e.g. gpu_drm_i915_incident, memory_thrashing,
plasmashell_panel_failure all as siblings), which meant a desktop freeze
caused by i915 could only ever be labelled as the GPU incident itself,
instead of "the desktop/compositor stopped responding (scope), most likely
because of the GPU/DRM path (mechanism, ranked, not certain)". That is what
FAILURE_SCOPES + mechanism_tags() replaces.

attach_incident_identity() adds a small number of keys to an existing
incident dict (incident_id, failure_scope, failure_scope_reasoning,
mechanism_tags, evidence_sources, evidence_completeness) without removing
or renaming any existing key, so every current consumer (report_schema,
the GUI, existing tests) is unaffected.
"""
from __future__ import annotations

import hashlib
from typing import Any

# WHAT stopped responding / how much of the system was affected. An
# incident is classified into exactly one of these, falling back to
# 'unknown' rather than guessing when the available evidence does not
# clearly support a more specific scope. Never add a value here that this
# module cannot actually justify from real evidence.
FAILURE_SCOPES = (
    "application",
    "plasmashell_panel",
    "compositor_session",
    "desktop_environment",
    "whole_system",
    "clean_shutdown",
    "unknown",
)

# Coarse, stable tags for collector.py's existing hypothesis categories,
# used only for later fingerprinting/family-matching (Section 8). This is a
# normalisation of hypotheses collector.py already ranked -- it never
# generates a hypothesis of its own.
MECHANISM_TAGS = (
    "memory_pressure",
    "thermal",
    "gpu_drm",
    "storage_filesystem",
    "hardware_ras",
    "unknown_kernel_firmware_power",
    "application_fault",
    "unknown",
)

_CATEGORY_TO_MECHANISM = {
    "Memory": "memory_pressure",
    "Thermals": "thermal",
    "Graphics": "gpu_drm",
    "Storage": "storage_filesystem",
    "PCIe / Network": "hardware_ras",
    # collector.py's single Firmware-category hypothesis is explicitly
    # titled "Unknown Kernel, Firmware or Power Failure" -- it does not
    # itself distinguish a kernel lockup from a power-loss event, so this
    # tag doesn't invent that distinction either.
    "Firmware": "unknown_kernel_firmware_power",
    "Software": "application_fault",
}

# Explicit states for "how much evidence do we actually have here", so a
# False/missing value is never read as "checked and healthy". See
# evidence_completeness().
EVIDENCE_STATES = ("complete", "partial", "not_collected", "unavailable", "failed", "truncated")

_GRAPHICS_SYMPTOM_IDS = {"intel_display", "other_gpu"}


def compute_incident_id(boot_id: str, anchor_ts: str) -> str:
    """Stable identifier derived ONLY from the incident's boot and its
    anchor timestamp -- the raw boundary-event timestamp collector.py
    detected, before the +/- window padding around it. Deliberately does
    NOT depend on failure_boundary, failure_scope, confidence, or any
    attached evidence, since later sections can revise all of those for
    the same real-world incident without it becoming "a new incident".

    This is a best-effort stable anchor, not a cryptographic guarantee: if
    a future evidence source retroactively determines the true anchor
    event happened at a materially different timestamp than today's
    boundary detection found, the id will still change -- there is
    currently no more stable anchor available than the detected boundary
    event itself. Section 8's fingerprint/family matching (evidence-pattern
    based, not raw id equality) is the intended way to recognise "probably
    the same recurring problem" across that rarer kind of change; this id
    is only for recognising the same computed incident across a rescan or
    across additive evidence being joined onto it.
    """
    digest = hashlib.sha256(f"{boot_id}|{anchor_ts}".encode()).hexdigest()
    return f"inc_{digest[:16]}"


def _symptom_ids(incident: dict[str, Any]) -> set[str]:
    return {
        e["finding"]["id"]
        for e in incident.get("incident_evidence", [])
        if isinstance(e, dict) and isinstance(e.get("finding"), dict) and e["finding"].get("id")
    }


def _coredump_executables(incident: dict[str, Any]) -> set[str]:
    names = set()
    for c in incident.get("coredumps", []) or []:
        exe = (c or {}).get("executable")
        if exe:
            names.add(str(exe).rsplit("/", 1)[-1].lower())
    return names


def classify_failure_scope(incident: dict[str, Any]) -> tuple[str, list[str]]:
    """Classify one incident dict onto a FAILURE_SCOPES value -- WHAT
    stopped responding, not why. Uses only evidence already on the
    incident dict. Never manufactures certainty: ambiguous or absent
    evidence produces 'unknown' rather than a guess.

    failure_scope='whole_system' is used for every boundary type that
    itself means the machine stopped (kernel panic, watchdog lockup,
    unclean shutdown) regardless of which symptom evidence happens to
    co-occur in the same window -- a graphics-symptom-adjacent unclean
    shutdown is scope=whole_system with a leading gpu_drm mechanism tag,
    not its own separate "GPU incident" scope, because the GPU evidence
    does not establish that only the desktop/GPU stack was affected.

    desktop_environment is declared in FAILURE_SCOPES but not reachable
    today: distinguishing "the whole desktop environment stopped
    responding" from "the compositor process specifically crashed" needs
    desktop-heartbeat telemetry this module does not have access to yet.
    """
    boundary = incident.get("failure_boundary")
    symptoms = _symptom_ids(incident)
    coredump_exes = _coredump_executables(incident)

    if boundary in {"kernel panic", "watchdog lockup", "unclean shutdown"}:
        return "whole_system", [f"Boot boundary '{boundary}' means the machine stopped responding entirely."]
    if boundary == "clean shutdown":
        return "clean_shutdown", ["Boot boundary was a clean, orderly shutdown/reboot sequence."]
    if boundary == "compositor crash":
        return "compositor_session", ["Boot boundary was a Wayland/KWin compositor crash; the system boot itself continued."]
    if boundary == "OOM event":
        # An OOM-kill boundary that is NOT also an unclean-shutdown boundary
        # means the kernel's OOM killer acted and the boot continued -- but
        # that alone does not tell us whether only one process, the whole
        # desktop, or nothing user-visible was affected.
        return "unknown", [
            "An OOM kill was logged and the boot continued, but no further evidence establishes "
            "how much of the system (if anything user-visible) was actually affected."
        ]

    if "plasmashell" in coredump_exes:
        return "plasmashell_panel", ["A coredump for plasmashell was recorded in this window."]
    if coredump_exes and not symptoms:
        return "application", [
            f"Coredump(s) recorded for {', '.join(sorted(coredump_exes))} with no other "
            "system-level symptom evidence in this window."
        ]
    if "wayland" in symptoms or (symptoms & _GRAPHICS_SYMPTOM_IDS):
        return "compositor_session", ["Compositor/graphics error evidence was recorded in this window."]

    return "unknown", ["No evidence pattern in this window established a specific failure scope."]


def mechanism_tags(incident: dict[str, Any]) -> list[str]:
    """Normalise collector.py's existing ranked hypotheses (by category)
    into coarse, stable tags, in the same rank order as
    incident['hypotheses']. This reuses that existing ranking; it does not
    add, remove, re-score, or re-order any hypothesis."""
    tags = []
    for h in incident.get("hypotheses", []) or []:
        tags.append(_CATEGORY_TO_MECHANISM.get(h.get("category"), "unknown"))
    return tags


def evidence_completeness(incident: dict[str, Any], checks: dict[str, Any] | None) -> dict[str, str]:
    """Per-source evidence state, using EVIDENCE_STATES rather than a bare
    boolean, so "no data" is never conflated with "checked and healthy".

    journal/coredump reflect this module's direct evidence inputs. Canary and
    desktop-heartbeat evidence is initially marked 'not_collected' here and
    is updated to complete/unavailable by the post-boundary telemetry join
    when a scan has samples. User observations remain a separate optional
    source. These states are explicit so missing data is never read as
    "healthy".
    """
    checks = checks or {}

    if not checks:
        journal_state = "not_collected"
    elif incident.get("incident_evidence"):
        journal_state = "complete"
    else:
        journal_state = "unavailable"

    if "coredumps_json" not in checks:
        coredump_state = "not_collected"
    elif incident.get("coredumps"):
        coredump_state = "complete"
    else:
        coredump_state = "unavailable"

    return {
        "journal": journal_state,
        "coredump": coredump_state,
        "canary_telemetry": "not_collected",
        "desktop_heartbeat": "not_collected",
        "user_observations": "not_collected",
    }


def attach_incident_identity(incident: dict[str, Any], checks: dict[str, Any] | None = None) -> dict[str, Any]:
    """Mutate `incident` in place, adding incident_id/failure_scope/
    failure_scope_reasoning/mechanism_tags/evidence_sources/
    evidence_completeness, and also return it for convenient chaining."""
    incident["incident_id"] = compute_incident_id(
        incident.get("boot_id", "unknown"),
        incident.get("incident_anchor_ts", incident.get("incident_start", "")),
    )
    scope, reasoning = classify_failure_scope(incident)
    incident["failure_scope"] = scope
    incident["failure_scope_reasoning"] = reasoning
    incident["mechanism_tags"] = mechanism_tags(incident)

    sources = []
    if incident.get("incident_evidence"):
        sources.append("journal")
    if incident.get("coredumps"):
        sources.append("coredump")
    incident["evidence_sources"] = sources
    incident["evidence_completeness"] = evidence_completeness(incident, checks)
    return incident
