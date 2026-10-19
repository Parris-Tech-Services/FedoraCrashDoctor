"""Storage-side causes of desktop freezes that are not drive failures.

Three patterns seen on AVANCE-WS7 (Intel 660p QLC NVMe, btrfs root):

* A QLC SSD that is nearly full has only a small SLC write cache. A large
  sustained write (archive extraction, build tree install, VM image copy)
  exhausts it, write latency jumps, and btrfs commits, swap and every other
  disk user stall behind it.
* Desktop processes (plasmashell, KWin, Xwayland) with a lot of memory in
  disk-backed swap. While the disk is saturated they wait seconds for their
  own memory, so the panel and compositor freeze even with free RAM.
* One process saturating the disk. The canary records per-process
  throughput (``io_top``) while I/O pressure is high, so the culprit and its
  systemd unit can be named instead of guessed.

All three are performance findings, not evidence of a failing drive.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Any

# Consumer QLC NAND drives, matched against the sysfs model string. Kept
# deliberately small and specific; an unknown model is never assumed QLC.
QLC_MODEL_MARKERS = (
    "SSDPEKNW",  # Intel 660p
    "SSDPEKNU",  # Intel 665p / 670p
    "QVO",  # Samsung 860/870 QVO
    "P1SSD8",  # Crucial P1
    "P3SSD8",  # Crucial P3 (non-Plus)
    "ROCKET Q",  # Sabrent Rocket Q
    "MP400",  # Corsair MP400
)

QLC_FULL_WARN_PCT = 80.0
DESKTOP_PROCESSES = {"plasmashell", "kwin_wayland", "kwin_x11", "Xwayland", "ksmserver", "kded6", "kded5"}
DESKTOP_SWAP_WARN_MB = 150
IO_STALL_PSI_FULL = 15.0

# Findings from this module describe performance, not drive health.
PERFORMANCE_FINDING_IDS = {"storage_qlc_nearly_full", "storage_desktop_in_disk_swap", "storage_io_culprit"}


def _finding(finding_id: str, severity: str, category: str, title: str, explanation: str, evidence: list[str], confidence: str = "moderate") -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "explanation": explanation,
        "evidence": evidence,
        "scope": "current",
        "confidence": confidence,
    }


def is_qlc_model(model: str) -> bool:
    upper = (model or "").upper()
    return any(marker in upper for marker in QLC_MODEL_MARKERS)


def root_disk(mountinfo: str | None = None, sys_root: str = "/sys") -> dict[str, str] | None:
    """Whole-disk name and model behind the root filesystem, from sysfs.

    Uses the mount source (e.g. /dev/nvme0n1p3) rather than the major:minor
    field, which btrfs reports as an anonymous 0:N device.
    """
    if mountinfo is None:
        try:
            mountinfo = Path("/proc/self/mountinfo").read_text()
        except OSError:
            return None
    source = None
    for line in mountinfo.splitlines():
        before, _, after = line.partition(" - ")
        fields, tail = before.split(), after.split()
        if len(fields) > 4 and fields[4] == "/" and len(tail) >= 2:
            source = tail[1]
    if not source or not source.startswith("/dev/"):
        return None
    name = os.path.basename(os.path.realpath(source))
    node = Path(sys_root) / "class" / "block" / name
    if not node.exists():
        return None
    disk = Path(os.path.realpath(node))
    if (disk / "partition").exists():
        disk = disk.parent
    try:
        model = (disk / "device" / "model").read_text().strip()
    except OSError:
        model = ""
    return {"disk": disk.name, "model": model}


def disk_swap_in_use(swaps: str | None = None) -> list[dict[str, Any]]:
    """Swap areas on real storage (not zram) that currently hold pages."""
    if swaps is None:
        try:
            swaps = Path("/proc/swaps").read_text()
        except OSError:
            return []
    result = []
    for line in swaps.splitlines()[1:]:
        fields = line.split()
        if len(fields) >= 5 and not fields[0].startswith("/dev/zram"):
            try:
                used_kb = int(fields[3])
            except ValueError:
                continue
            if used_kb > 0:
                result.append({"device": fields[0], "used_mb": used_kb // 1024})
    return result


def qlc_fill_finding(model: str, total_bytes: int, used_bytes: int) -> dict[str, Any] | None:
    if not is_qlc_model(model) or total_bytes <= 0:
        return None
    used_pct = used_bytes / total_bytes * 100
    if used_pct < QLC_FULL_WARN_PCT:
        return None
    free_gib = (total_bytes - used_bytes) / 1024**3
    return _finding(
        "storage_qlc_nearly_full",
        "warning",
        "Storage",
        "QLC SSD is nearly full, so large writes can stall the whole system",
        "This drive uses QLC flash with a fast SLC write cache that shrinks as the drive fills. "
        "A large sustained write (extracting archives, installing node_modules, copying VM or profile disks) "
        "exhausts it, write latency rises sharply, and swap, btrfs commits and the desktop wait behind it. "
        "Keeping at least 20-25% free restores most of the cache. This is a capacity and performance issue, not a failing drive.",
        [f"Root drive model: {model}", f"Root filesystem {used_pct:.0f}% used ({free_gib:.0f} GiB free)"],
        confidence="high",
    )


def desktop_swap_finding(samples: list[dict[str, Any]], disk_swaps: list[dict[str, Any]]) -> dict[str, Any] | None:
    if not disk_swaps:
        return None
    latest = next((s for s in reversed(samples) if isinstance((s.get("processes") or {}).get("top_swap"), list)), None)
    if not latest:
        return None
    desktop = [p for p in latest["processes"]["top_swap"] if isinstance(p, dict) and p.get("name") in DESKTOP_PROCESSES]
    swapped_mb = sum(int(p.get("swap_kb") or 0) for p in desktop) // 1024
    if swapped_mb < DESKTOP_SWAP_WARN_MB:
        return None
    lines = [f"{p.get('name')}: {int(p.get('swap_kb') or 0) // 1024} MB swapped, {int(p.get('rss_kb') or 0) // 1024} MB in RAM" for p in desktop if p.get("swap_kb")]
    lines += [f"Disk-backed swap in use: {s['device']} ({s['used_mb']} MB)" for s in disk_swaps]
    lines.append(f"Sample time: {latest.get('ts', 'unknown')}")
    return _finding(
        "storage_desktop_in_disk_swap",
        "warning",
        "Memory",
        "Desktop processes are swapped out, so disk stalls freeze the panel and compositor",
        "Part of the desktop's memory has been pushed to swap and some of it overflowed onto the disk swapfile. "
        "When the disk is busy, plasmashell and KWin must wait for the disk to read their own memory back, which looks like a frozen desktop "
        "even though plenty of RAM is free.",
        lines,
    )


def io_culprit_finding(samples: list[dict[str, Any]]) -> dict[str, Any] | None:
    worst: dict[tuple[str, str], dict[str, Any]] = {}
    peak_full = 0.0
    for sample in samples:
        try:
            full = float((sample.get("psi_io") or {}).get("full_avg10") or 0)
        except (TypeError, ValueError):
            continue
        top = sample.get("io_top")
        if full < IO_STALL_PSI_FULL or not isinstance(top, list):
            continue
        peak_full = max(peak_full, full)
        for proc in top:
            if not isinstance(proc, dict):
                continue
            key = (str(proc.get("name") or "unknown"), str(proc.get("unit") or ""))
            rate = float(proc.get("read_mb_s") or 0) + float(proc.get("write_mb_s") or 0)
            if rate > worst.get(key, {}).get("rate", -1):
                worst[key] = {"rate": rate, "proc": proc, "ts": sample.get("ts", "unknown"), "full": full}
    if not worst:
        return None
    ranked = sorted(worst.values(), key=lambda item: item["rate"], reverse=True)[:3]
    lines = [
        f"{r['proc'].get('name')} ({r['proc'].get('unit') or 'no unit'}): {r['proc'].get('read_mb_s')} MB/s read, "
        f"{r['proc'].get('write_mb_s')} MB/s write at {r['ts']} (I/O PSI full {r['full']:.0f}%)"
        for r in ranked
    ]
    top_name = ranked[0]["proc"].get("name")
    return _finding(
        "storage_io_culprit",
        "warning",
        "Storage",
        f"Heavy disk I/O from {top_name} coincided with I/O stalls",
        "The canary recorded which processes were reading and writing most while the system was stalled on storage. "
        "Running jobs like this at low disk priority, or capping their bandwidth, keeps the desktop responsive.",
        lines,
        confidence="high",
    )


def analyse_storage_stability(canary: dict[str, Any], *, root: str = "/") -> list[dict[str, Any]]:
    samples = [s for s in (canary or {}).get("samples") or [] if isinstance(s, dict)]
    findings: list[dict[str, Any]] = []
    disk = root_disk()
    if disk:
        try:
            usage = shutil.disk_usage(root)
            finding = qlc_fill_finding(disk["model"], usage.total, usage.used)
            if finding:
                findings.append(finding)
        except OSError:
            pass
    for finding in (desktop_swap_finding(samples, disk_swap_in_use()), io_culprit_finding(samples)):
        if finding:
            findings.append(finding)
    return findings
