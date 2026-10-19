#!/usr/bin/env python3
"""Low-write system heartbeat for post-freeze correlation.

Runs as root under systemd. Samples lightweight /proc and /sys metrics.
Adapts sampling frequency during memory/I-O pressure.
"""
from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import os
import re
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from safe_mitigation import StabilityController

LOG_DIR = Path("/var/log/fedora-crash-doctor")
LOG_FILE = LOG_DIR / "canary.log"
NORMAL_INTERVAL = 5
WARNING_INTERVAL = 5
CRITICAL_INTERVAL = 2
FSYNC_EVERY_NORMAL = 60
FSYNC_EVERY_PRESSURE = 10


def read_text(path: str, default: str = "") -> str:
    try:
        return Path(path).read_text(errors="replace").strip()
    except Exception:
        return default


def read_psi(name: str) -> dict[str, float]:
    text = read_text(f"/proc/pressure/{name}")
    result: dict[str, float] = {}
    for line in text.splitlines():
        bits = line.split()
        if not bits:
            continue
        prefix = bits[0]
        for bit in bits[1:]:
            if "=" not in bit:
                continue
            key, value = bit.split("=", 1)
            if key in {"avg10", "avg60"}:
                try:
                    result[f"{prefix}_{key}"] = float(value)
                except ValueError:
                    pass
    return result


def memory() -> dict[str, int]:
    values: dict[str, int] = {}
    for line in read_text("/proc/meminfo").splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        match = re.search(r"(\d+)", value)
        if match:
            values[key] = int(match.group(1)) // 1024
    swap_devices = []
    for line in read_text("/proc/swaps").splitlines()[1:]:
        bits = line.split()
        if len(bits) >= 4:
            try:
                swap_devices.append({"name": bits[0], "type": bits[1], "size_mb": int(bits[2]) // 1024, "used_mb": int(bits[3]) // 1024})
            except ValueError:
                pass
    return {
        "mem_available_mb": values.get("MemAvailable", 0),
        "mem_total_mb": values.get("MemTotal", 0),
        "swap_used_mb": max(0, values.get("SwapTotal", 0) - values.get("SwapFree", 0)),
        "swap_total_mb": values.get("SwapTotal", 0),
        "slab_mb": values.get("Slab", 0),
        "sreclaimable_mb": values.get("SReclaimable", 0),
        "sunreclaim_mb": values.get("SUnreclaim", 0),
        "dirty_mb": values.get("Dirty", 0),
        "writeback_mb": values.get("Writeback", 0),
        "anon_mb": values.get("Active(anon)", 0) + values.get("Inactive(anon)", 0),
        "file_mb": values.get("Active(file)", 0) + values.get("Inactive(file)", 0),
        "swapcached_mb": values.get("SwapCached", 0),
        "pagetables_mb": values.get("PageTables", 0),
        "zram_used_mb": sum(item["used_mb"] for item in swap_devices if item["name"].startswith("/dev/zram")),
        "disk_swap_used_mb": sum(item["used_mb"] for item in swap_devices if not item["name"].startswith("/dev/zram")),
        "swap_devices": swap_devices,
    }


def vmstat() -> dict[str, int]:
    stats = {}
    keys = {"pgscan_kswapd", "pgscan_direct", "pgsteal_kswapd", "pgsteal_direct",
            "pswpin", "pswpout", "pgmajfault", "workingset_refault"}
    for line in read_text("/proc/vmstat").splitlines():
        bits = line.split()
        if len(bits) == 2:
            key = bits[0]
            if key in keys or any(key.startswith(k) for k in keys):
                stats[key] = int(bits[1])
    return stats


def diskstats() -> dict[str, dict[str, int]]:
    disks = {}
    for line in read_text("/proc/diskstats").splitlines():
        bits = line.split()
        if len(bits) >= 14:
            name = bits[2]
            if name.startswith("loop") or name.startswith("ram"):
                continue
            disks[name] = {
                "r_ios": int(bits[3]),
                "r_sectors": int(bits[5]),
                "w_ios": int(bits[7]),
                "w_sectors": int(bits[9]),
                "in_flight": int(bits[11]),
                "io_ticks": int(bits[12]),
            }
    return disks


def zram_stats() -> dict[str, dict[str, int]]:
    stats = {}
    for path in Path("/sys/block").glob("zram*"):
        try:
            name = path.name
            mm_stat = (path / "mm_stat").read_text().split()
            stats[name] = {
                "orig_bytes": int(mm_stat[0]),
                "compr_bytes": int(mm_stat[1]),
                "mem_used_bytes": int(mm_stat[2])
            }
        except Exception:
            pass
    return stats


IO_TOP_PSI_SOME = 10.0  # % I/O PSI some (avg10) that triggers per-process attribution
IO_TOP_MIN_BYTES_S = 512 * 1024


def _unit_from_cgroup(cgroup: str) -> str:
    """Deepest systemd unit in a cgroup v2 path.

    Only components whose parent is a slice (or the user manager) are units;
    deeper ones, like Konsole's tab(N).scope inside its app scope, are plain
    sub-cgroups that systemctl set-property can't address.
    """
    parts = [p for p in cgroup.strip().split("::", 1)[-1].split("/") if p]
    units = [
        part for i, part in enumerate(parts)
        if part.endswith((".service", ".scope", ".slice"))
        and (i == 0 or parts[i - 1].endswith(".slice") or parts[i - 1].startswith("user@"))
    ]
    return units[-1] if units else ""


class IoTracker:
    """Per-process disk throughput from /proc/<pid>/io byte counters.

    Rates need two readings, so the first update after a quiet period only
    primes the counters. Reading /proc/*/io costs a few milliseconds, so the
    canary only calls this while I/O pressure is elevated or a detailed sample
    is due.
    """

    def __init__(self) -> None:
        self.previous: dict[int, tuple[int, int, str]] = {}
        self.previous_time: float | None = None

    @staticmethod
    def _read(pid: int) -> tuple[int, int] | None:
        read_b = write_b = None
        for line in read_text(f"/proc/{pid}/io").splitlines():
            if line.startswith("read_bytes:"):
                read_b = int(line.split()[1])
            elif line.startswith("write_bytes:"):
                write_b = int(line.split()[1])
        return (read_b, write_b) if read_b is not None and write_b is not None else None

    def update(self, limit: int = 5) -> list[dict[str, Any]]:
        now = time.monotonic()
        current: dict[int, tuple[int, int, str]] = {}
        for pid_str in os.listdir("/proc"):
            if not pid_str.isdigit():
                continue
            pid = int(pid_str)
            counters = self._read(pid)
            if counters is None:
                continue
            start_time = (read_text(f"/proc/{pid}/stat").rsplit(")", 1)[-1].split() or ["0"] * 20)
            current[pid] = (counters[0], counters[1], start_time[19] if len(start_time) > 19 else "")
        elapsed = now - self.previous_time if self.previous_time is not None else 0.0
        top: list[dict[str, Any]] = []
        if elapsed >= 0.5:
            for pid, (read_b, write_b, started) in current.items():
                prev = self.previous.get(pid)
                if not prev or prev[2] != started:  # new process or reused PID
                    continue
                read_rate = max(0, read_b - prev[0]) / elapsed
                write_rate = max(0, write_b - prev[1]) / elapsed
                if read_rate + write_rate < IO_TOP_MIN_BYTES_S:
                    continue
                stat = read_text(f"/proc/{pid}/stat")
                top.append({
                    "pid": pid,
                    "name": stat[stat.find("(") + 1:stat.rfind(")")] if "(" in stat else "",
                    "cmd": read_text(f"/proc/{pid}/cmdline").replace("\0", " ").strip()[:100],
                    "read_mb_s": round(read_rate / 1048576, 1),
                    "write_mb_s": round(write_rate / 1048576, 1),
                    "unit": _unit_from_cgroup(read_text(f"/proc/{pid}/cgroup")),
                })
            top.sort(key=lambda item: item["read_mb_s"] + item["write_mb_s"], reverse=True)
        self.previous, self.previous_time = current, now
        return top[:limit]


def gather_processes() -> dict[str, Any]:
    processes = []
    blocked = []
    mem_total_kb = 0
    for line in read_text("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            try:
                mem_total_kb = int(line.split()[1])
            except (IndexError, ValueError):
                pass
            break
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        try:
            pid = int(pid_str)
            status_text = read_text(f"/proc/{pid}/status")
            if not status_text: continue
            stat = read_text(f"/proc/{pid}/stat").split()
            cmdline = read_text(f"/proc/{pid}/cmdline").replace('\0', ' ').strip()

            rss = 0
            swap = 0
            anon = 0
            file_mem = 0
            ppid = 0
            state = stat[2]
            threads = int(stat[19]) if len(stat) > 19 else 1

            for line in status_text.splitlines():
                if line.startswith("VmRSS:"): rss = int(line.split()[1])
                elif line.startswith("VmSwap:"): swap = int(line.split()[1])
                elif line.startswith("RssAnon:"): anon = int(line.split()[1])
                elif line.startswith("RssFile:"): file_mem = int(line.split()[1])
                elif line.startswith("PPid:"): ppid = int(line.split()[1])

            name = stat[1].strip("()")

            if state == 'D':
                wchan = read_text(f"/proc/{pid}/wchan")
                blocked.append({
                    "pid": pid, "name": name, "cmd": cmdline[:60], "wchan": wchan
                })

            if rss == 0 and swap == 0:
                continue

            group = "Other"
            cmd_lower = cmdline.lower()
            if "google/chrome" in cmd_lower or "chrome --" in cmd_lower: group = "Google Chrome"
            elif "antigravity" in cmd_lower: group = "Antigravity"
            elif "vscode" in cmd_lower or "code-insiders" in cmd_lower: group = "VS Code"
            elif "plasmashell" in cmd_lower or "kwin" in cmd_lower: group = "Plasma / KWin"
            elif "node" in cmd_lower: group = "Node.js"
            elif "python" in cmd_lower: group = "Python"
            elif "java" in cmd_lower: group = "Java"
            elif "electron" in cmd_lower: group = "Electron App"

            cgroup = read_text(f"/proc/{pid}/cgroup")
            oom_score = read_text(f"/proc/{pid}/oom_score")

            processes.append({
                "pid": pid, "ppid": ppid, "name": name, "cmd": cmdline[:100],
                "rss_kb": rss, "swap_kb": swap, "anon_kb": anon, "file_kb": file_mem,
                "rss_percent": round((rss / mem_total_kb) * 100, 1) if mem_total_kb else None,
                "state": state, "threads": threads, "group": group,
                "cgroup": cgroup[:240],
                "oom_score": int(oom_score) if oom_score.isdigit() else None,
            })
        except Exception:
            pass

    processes.sort(key=lambda x: x["rss_kb"], reverse=True)
    top_rss = processes[:25]

    processes.sort(key=lambda x: x["swap_kb"], reverse=True)
    top_swap = processes[:25]

    groups = {}
    for p in processes:
        g = groups.setdefault(p["group"], {"rss_kb": 0, "swap_kb": 0, "count": 0})
        g["rss_kb"] += p["rss_kb"]
        g["swap_kb"] += p["swap_kb"]
        g["count"] += 1

    return {"top_rss": top_rss, "top_swap": top_swap, "groups": groups, "blocked": blocked}


def max_temp_c() -> float | None:
    temps = []
    for path in Path("/sys/class/thermal").glob("thermal_zone*/temp"):
        try:
            value = float(path.read_text().strip())
            if value > 1000: value /= 1000
            if -20 <= value <= 150: temps.append(value)
        except Exception: pass
    for path in Path("/sys/class/hwmon").glob("hwmon*/temp*_input"):
        try:
            value = float(path.read_text().strip()) / 1000
            if -20 <= value <= 150: temps.append(value)
        except Exception: pass
    return round(max(temps), 1) if temps else None


def average_cpu_mhz() -> float | None:
    values = []
    for path in Path("/sys/devices/system/cpu").glob("cpu[0-9]*/cpufreq/scaling_cur_freq"):
        try: values.append(float(path.read_text().strip()) / 1000)
        except Exception: pass
    return round(sum(values) / len(values), 1) if values else None


def desktop_heartbeat() -> dict[str, Any]:
    now = time.time()
    newest = None
    for path in Path("/run/user").glob("[0-9]*/fedora-crash-doctor/desktop-heartbeat.json"):
        try:
            data = json.loads(path.read_text())
            stamp = float(data.get("epoch", path.stat().st_mtime))
            if newest is None or stamp > newest[0]:
                newest = (stamp, data)
        except Exception: pass
    if not newest:
        return {"desktop_heartbeat_age_s": None, "kwin_ok": None, "kwin_ping_ms": None, "kwin_consecutive_failures": None, "plasmashell_ok": None, "desktop_session": None, "desktop": None}
    stamp, data = newest
    return {
        "desktop_heartbeat_age_s": round(max(0, now - stamp), 1),
        "kwin_ok": data.get("kwin_ok"),
        "kwin_ping_ms": data.get("kwin_ping_ms"),
        "kwin_consecutive_failures": data.get("kwin_consecutive_failures", 0),
        "plasmashell_ok": data.get("plasmashell_ok"),
        "desktop_session": data.get("session"),
        "desktop": data.get("desktop"),
    }


def chrome_summary() -> dict[str, Any]:
    processes = []
    for pid_str in os.listdir("/proc"):
        if not pid_str.isdigit():
            continue
        try:
            pid = int(pid_str)
            cmdline = read_text(f"/proc/{pid}/cmdline").replace("\0", " ").strip()
            if not re.search(r"(?:google-chrome|chromium|chrome)", cmdline, re.I):
                continue
            status = read_text(f"/proc/{pid}/status")
            rss = next((int(line.split()[1]) for line in status.splitlines() if line.startswith("VmRSS:")), 0)
            processes.append({"pid": pid, "rss_kb": rss, "type": next((part.split("=", 1)[1] for part in cmdline.split() if part.startswith("--type=")), "browser"), "gpu": "--type=gpu-process" in cmdline})
        except (OSError, ValueError):
            pass
    total_rss_kb = sum(item["rss_kb"] for item in processes)
    return {
        "process_count": len(processes),
        "aggregate_rss_mb": round(total_rss_kb / 1024, 1),
        "aggregate_rss_note": "Aggregate RSS may double-count shared pages and is not exact unique physical RAM.",
        "largest_process_rss_mb": round(max((item["rss_kb"] for item in processes), default=0) / 1024, 1),
        "gpu_process_present": any(item["gpu"] for item in processes),
    }


def recent_journal_events() -> dict[str, str]:
    result = {"graphics": "", "storage": "", "coredump": "", "kernel": ""}
    try:
        output = subprocess.run(
            ["journalctl", "-k", "-b", "0", "--since=-60 seconds", "--output=short-iso-precise", "--no-pager"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=3, text=True,
        ).stdout
        result["kernel"] = output
        result["graphics"] = "\n".join(line for line in output.splitlines() if re.search(r"i915|drm|GPU HANG|GPU reset|atomic update failure", line, re.I))
        result["storage"] = "\n".join(line for line in output.splitlines() if re.search(r"I/O error|Buffer I/O|nvme.*error|ata.*link down|btrfs.*error", line, re.I))
        result["coredump"] = "\n".join(line for line in output.splitlines() if re.search(r"systemd-coredump|dumped core|FatalProcessOutOfMemory|out of memory", line, re.I))
    except Exception:
        pass
    return result


def filesystem_free_mb(path: str = "/") -> int | None:
    try:
        stat = os.statvfs(path)
        return int(stat.f_bavail * stat.f_frsize / (1024 * 1024))
    except OSError:
        return None


def automatic_capture(event: dict[str, Any], sample_data: dict[str, Any]) -> str | None:
    """Capture implicated user evidence without terminating or restarting anything."""
    try:
        owner = json.loads(Path("/etc/fedora-crash-doctor/owner.json").read_text())
        home = Path(owner["home"])
        paths = []
        chrome_triggered = event.get("category") == "memory" and sample_data.get("chrome", {}).get("process_count", 0) > 0
        if event.get("state") == "critical" or chrome_triggered:
            import chrome_capture
            paths.append(chrome_capture.capture_chrome_incident(home=home).get("capture_path"))
        if event.get("state") == "critical" or event.get("category") == "desktop" or sample_data.get("kwin_ok") is False:
            import plasma_capture
            paths.append(plasma_capture.capture_frozen_plasma(home=home).get("capture_path"))
        return ", ".join(path for path in paths if path) or None
    except Exception:
        return None


def sample(controller: StabilityController, last_detailed_time: float, io_tracker: IoTracker | None = None) -> tuple[dict[str, Any], int, float]:
    load = read_text("/proc/loadavg").split()
    mem = memory()
    psi_cpu = read_psi("cpu")
    psi_mem = read_psi("memory")
    psi_io = read_psi("io")

    # Adaptive interval calculation
    mem_avail_pct = (mem["mem_available_mb"] / max(1, mem["mem_total_mb"])) * 100
    swap_used_pct = (mem["swap_used_mb"] / max(1, mem["swap_total_mb"])) * 100 if mem["swap_total_mb"] else 0
    io_some = psi_io.get("some_avg10", 0)
    mem_some = psi_mem.get("some_avg10", 0)

    interval = NORMAL_INTERVAL
    if mem_avail_pct < 10 or swap_used_pct > 90 or io_some > 40 or mem_some > 20:
        interval = CRITICAL_INTERVAL
    elif mem_avail_pct < 20 or swap_used_pct > 70 or io_some > 15 or mem_some > 10:
        interval = WARNING_INTERVAL

    row: dict[str, Any] = {
        "ts": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "epoch": time.time(),
        "boot_id": read_text("/proc/sys/kernel/random/boot_id"),
        "uptime_s": round(float(read_text("/proc/uptime", "0").split()[0]), 1),
        "load1": float(load[0]) if load else 0,
        "load5": float(load[1]) if len(load) > 1 else 0,
        "avg_cpu_mhz": average_cpu_mhz(),
        "memory": mem,
        "psi_cpu": psi_cpu,
        "psi_mem": psi_mem,
        "psi_io": psi_io,
        "zram": zram_stats(),
        "filesystem_free_mb": filesystem_free_mb(),
    }
    
    now = time.monotonic()
    needs_detailed = False
    if interval < NORMAL_INTERVAL and controller.state == "ok":
        needs_detailed = True
    elif now - last_detailed_time > (60 if interval == NORMAL_INTERVAL else 15):
        needs_detailed = True
        
    if needs_detailed:
        row["max_temp_c"] = max_temp_c()
        row["vmstat"] = vmstat()
        row["diskstats"] = diskstats()
        row["processes"] = gather_processes()
        row["journal_events"] = recent_journal_events()
        row["memory_events"] = read_text("/sys/fs/cgroup/memory.events")
        try:
            row["systemd_oomd_active"] = subprocess.run(["systemctl", "is-active", "systemd-oomd.service"], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, text=True).stdout.strip() == "active"
        except Exception:
            row["systemd_oomd_active"] = None
        last_detailed_time = now

    # Name the processes behind an I/O stall while it is happening; the
    # tracker is re-primed whenever pressure returns after a quiet spell.
    if io_tracker is not None:
        if io_some >= IO_TOP_PSI_SOME or needs_detailed:
            row["io_top"] = io_tracker.update()
        else:
            io_tracker.previous_time = None

    row.update(desktop_heartbeat())
    row["chrome"] = chrome_summary()

    row["early_warning"] = controller.process_sample(row)

    return row, interval, last_detailed_time


def main() -> int:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    handler = RotatingFileHandler(LOG_FILE, maxBytes=15 * 1024 * 1024, backupCount=3)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logger = logging.getLogger("fcd-canary")
    logger.setLevel(logging.INFO)
    logger.addHandler(handler)

    next_fsync = time.monotonic()
    last_detailed = 0.0

    controller = StabilityController(capture_callback=automatic_capture)
    io_tracker = IoTracker()
    while True:
        started = time.monotonic()
        try:
            data, interval, last_detailed = sample(controller, last_detailed, io_tracker)
            logger.info(json.dumps(data, separators=(",", ":")))
            handler.flush()

            fsync_target = FSYNC_EVERY_NORMAL if interval == NORMAL_INTERVAL else FSYNC_EVERY_PRESSURE
            if time.monotonic() >= next_fsync:
                try:
                    os.fdatasync(handler.stream.fileno())
                except OSError:
                    pass
                next_fsync = time.monotonic() + fsync_target

        except Exception as exc:
            logger.info(json.dumps({"ts": datetime.now().isoformat(), "collector_error": str(exc)}))
            interval = NORMAL_INTERVAL

        delay = max(0.5, interval - (time.monotonic() - started))
        time.sleep(delay)


if __name__ == "__main__":
    raise SystemExit(main())
