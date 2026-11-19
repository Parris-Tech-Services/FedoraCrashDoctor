#!/usr/bin/env python3
"""Turn sustained canary memory/I-O pressure into an incident.

Journal-driven incidents only exist when the kernel logs something (an OOM
kill, a GPU error, a panic). A userspace process that exhausts RAM and then
aborts itself -- e.g. a V8 heap OOM -- thrashes zram/swap and freezes the
desktop without any such log line, so the scan's verdict fell back to an
older, unrelated incident. The canary records the pressure directly; this
module promotes a sustained run of it in the current boot to an incident.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable

IO_FULL_THRESHOLD = 40.0  # % of time all tasks stalled on I/O (avg10)
MEM_SOME_THRESHOLD = 20.0  # % of time some task stalled on memory (avg10)
MIN_PRESSURED_SAMPLES = 3


def _number(value: Any) -> float:
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def _normal_boot_id(value: Any) -> str:
    return str(value or "").replace("-", "").strip().lower()


def _parse_ts(sample: dict[str, Any]) -> datetime | None:
    ts = sample.get("ts")
    if ts:
        try:
            return datetime.fromisoformat(str(ts))
        except ValueError:
            pass
    epoch = sample.get("epoch")
    if epoch:
        try:
            return datetime.fromtimestamp(float(epoch)).astimezone()
        except (TypeError, ValueError, OSError):
            return None
    return None


def build_pressure_incident(
    samples: list[dict[str, Any]],
    current_boot_id: str,
    confidence_label: Callable[[float], str],
) -> dict[str, Any] | None:
    """Return an incident for sustained pressure in the current boot, or None."""
    boot = _normal_boot_id(current_boot_id)
    if not boot:
        return None

    pressured = []
    for sample in samples:
        if _normal_boot_id(sample.get("boot_id")) != boot:
            continue
        when = _parse_ts(sample)
        if when is None:
            continue
        io_full = _number((sample.get("psi_io") or {}).get("full_avg10"))
        mem_some = _number((sample.get("psi_mem") or {}).get("some_avg10"))
        if io_full >= IO_FULL_THRESHOLD or mem_some >= MEM_SOME_THRESHOLD:
            pressured.append((when, io_full, mem_some, sample.get("memory") or {}))

    if len(pressured) < MIN_PRESSURED_SAMPLES:
        return None

    pressured.sort(key=lambda item: item[0])
    start, end = pressured[0][0], pressured[-1][0]
    peak_io = max(pressured, key=lambda item: item[1])
    peak_mem = max(pressured, key=lambda item: item[2])
    min_available = min(_number(m.get("mem_available_mb")) for _, _, _, m in pressured)
    zram_full = any(
        _number(m.get("zram_used_mb")) and _number(m.get("zram_used_mb")) >= 0.9 * _number(
            next((d.get("size_mb") for d in m.get("swap_devices") or [] if "zram" in str(d.get("name"))), 0)
        )
        for _, _, _, m in pressured
    )

    supports = [
        f"Canary recorded sustained pressure in {len(pressured)} samples "
        f"from {start.strftime('%H:%M:%S')} to {end.strftime('%H:%M:%S')}.",
        f"Peak I/O PSI full avg10 {peak_io[1]:.1f}% at {peak_io[0].strftime('%H:%M:%S')}.",
        f"Peak memory PSI some avg10 {peak_mem[2]:.1f}% at {peak_mem[0].strftime('%H:%M:%S')}.",
    ]
    if min_available:
        supports.append(f"MemAvailable fell to {int(min_available)} MiB.")
    if zram_full:
        supports.append("zram swap was at least 90% full.")

    score = 0.8
    title = "Memory/swap exhaustion with swap-I/O thrashing (recorded by canary telemetry)"
    hypothesis = {
        "title": title,
        "category": "Memory",
        "score": score,
        "confidence": confidence_label(score),
        "supports": supports,
        "against": [
            "No kernel OOM kill was logged; the process responsible must be "
            "identified from the memory-growth report or coredumps."
        ],
        "next_test": "Review 'Why did memory fill?' for the top memory growers in this window.",
    }
    return {
        "boot_id": current_boot_id,
        "boot_index": "0",
        "incident_start": start.isoformat(),
        "incident_end": end.isoformat(),
        "incident_anchor_ts": peak_io[0].isoformat(),
        "failure_boundary": "memory pressure (canary)",
        "incident_evidence": [],
        "coredumps": [],
        "strongest_hypothesis": title,
        "supporting_evidence": supports,
        "next_step": hypothesis["next_test"],
        "confidence": hypothesis["confidence"],
        "confidence_explanation": f"Ranked {hypothesis['confidence']} from direct canary PSI measurements.",
        "hypotheses": [hypothesis],
        "sort_key": end.timestamp(),
    }
