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

import math
import os
import shutil
import time
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
PERFORMANCE_FINDING_IDS = {"storage_qlc_nearly_full", "storage_desktop_swap_possible", "storage_io_culprit"}


def _finding(finding_id: str, severity: str, category: str, title: str, explanation: str, evidence: list[str], confidence: str = "moderate", scope: str = "current") -> dict[str, Any]:
    return {
        "id": finding_id,
        "severity": severity,
        "category": category,
        "title": title,
        "explanation": explanation,
        "evidence": evidence,
        "scope": scope,
        "confidence": confidence,
    }


def is_qlc_model(model: str) -> bool:
    upper = (model or "").upper()
    return any(marker in upper for marker in QLC_MODEL_MARKERS)


def _physical_block_devices(name: str, sys_root: str, seen: set[str] | None = None) -> list[dict[str, str]]:
    """Resolve partitions and device-mapper layers to physical block devices."""
    seen = set(seen or ())
    if name in seen:
        return []
    seen.add(name)
    node = Path(sys_root) / "class" / "block" / name
    if not node.exists():
        return []
    resolved = Path(os.path.realpath(node))
    if (resolved / "partition").exists():
        return _physical_block_devices(resolved.parent.name, sys_root, seen)

    try:
        model = (resolved / "device" / "model").read_text().strip()
    except OSError:
        model = ""
    if model:
        return [{"disk": resolved.name, "model": model}]

    slaves = resolved / "slaves"
    if slaves.is_dir():
        devices: list[dict[str, str]] = []
        for slave in sorted(slaves.iterdir(), key=lambda item: item.name):
            devices.extend(_physical_block_devices(slave.name, sys_root, seen))
        if devices:
            return devices
    return [{"disk": resolved.name, "model": ""}]


def root_disk(mountinfo: str | None = None, sys_root: str = "/sys") -> dict[str, str] | None:
    """Resolve the root mount source through partitions, LUKS and LVM to a disk.

    The mount source is used instead of mountinfo's major:minor field, which
    btrfs may report as an anonymous device. Device-mapper nodes are followed
    through their sysfs slaves links to their physical backing devices.
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
    devices = _physical_block_devices(name, sys_root)
    if not devices:
        return None
    # Prefer a positively identified QLC backing disk if a mapped root spans
    # more than one physical device; otherwise use the first resolved leaf.
    selected = next((item for item in devices if is_qlc_model(item.get("model", ""))), devices[0])
    return {"disk": selected["disk"], "model": selected["model"]}

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
    """Report root-filesystem capacity, not whole-SSD or NAND cache fullness."""
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
        "QLC-backed root filesystem is nearly full",
        "The root filesystem is on a QLC SSD and is itself nearly full, which can constrain writes and temporary working space on this filesystem. "
        "Filesystem usage does not reveal how full the whole physical SSD is or how much SLC write cache remains, so this is a root-filesystem capacity warning only. "
        "It is not evidence of a failing drive.",
        [f"Root backing device model: {model}", f"Root filesystem {used_pct:.0f}% used ({free_gib:.0f} GiB free)"],
        confidence="moderate",
    )

def desktop_swap_finding(
    samples: list[dict[str, Any]],
    disk_swaps: list[dict[str, Any]],
    *,
    current_boot_id: str | None = None,
    now_epoch: float | None = None,
    max_age_seconds: int = 30,
) -> dict[str, Any] | None:
    """Report only a possible swap risk; VmSwap cannot identify its backing device."""
    if not disk_swaps:
        return None
    if current_boot_id is None:
        try:
            current_boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        except OSError:
            return None
    if not current_boot_id:
        return None
    now_epoch = time.time() if now_epoch is None else now_epoch

    latest = None
    for sample in reversed(samples):
        if sample.get("boot_id") != current_boot_id:
            continue
        try:
            stamp = float(sample.get("epoch"))
        except (TypeError, ValueError):
            continue
        if not math.isfinite(stamp) or stamp > now_epoch or now_epoch - stamp > max_age_seconds:
            continue
        top_swap = (sample.get("processes") or {}).get("top_swap")
        if isinstance(top_swap, list):
            latest = sample
            break
    if not latest:
        return None

    desktop = [
        p for p in latest["processes"]["top_swap"]
        if isinstance(p, dict) and p.get("name") in DESKTOP_PROCESSES
    ]
    swapped_mb = sum(int(p.get("swap_kb") or 0) for p in desktop) // 1024
    if swapped_mb < DESKTOP_SWAP_WARN_MB:
        return None

    lines = [
        f"{p.get('name')}: {int(p.get('swap_kb') or 0) // 1024} MB total swapped, {int(p.get('rss_kb') or 0) // 1024} MB in RAM"
        for p in desktop if p.get("swap_kb")
    ]
    lines += [f"Disk-backed swap is in use system-wide: {s['device']} ({s['used_mb']} MB)" for s in disk_swaps]
    lines.append(f"Sample time: {latest.get('ts', 'unknown')}")
    lines.append("Backing device for these process pages is unknown; VmSwap does not distinguish zram from disk swap.")
    return _finding(
        "storage_desktop_swap_possible",
        "info",
        "Memory",
        "Desktop processes have swapped memory; backing device is unknown",
        "The current-boot canary observed swapped memory in desktop processes while disk-backed swap was also in use system-wide. "
        "Linux VmSwap does not reveal which swap device owns those pages, so this does not prove the desktop is waiting on disk. "
        "Treat it as context only; no disk-stall diagnosis or desktop-restart recommendation is justified.",
        lines,
        confidence="low",
        scope="possible",
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
