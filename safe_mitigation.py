#!/usr/bin/env python3
"""Conservative early-warning decisions for freeze prevention.

This module only decides what to warn about. It deliberately performs no process
termination, reboot, compositor restart, or privileged mutation.
"""
from __future__ import annotations

import json
import os
import tempfile
from collections import deque
from statistics import median, quantiles
from pathlib import Path
from typing import Any

def evaluate_sample(sample: dict[str, Any]) -> dict[str, Any]:
    memory = sample.get("memory") or {}
    psi_mem = sample.get("psi_mem") or {}
    psi_io = sample.get("psi_io") or {}
    
    mem_available = float(memory.get("mem_available_mb") or sample.get("mem_available_mb") or 0)
    mem_total = float(memory.get("mem_total_mb") or sample.get("mem_total_mb") or 0)
    swap_used = float(memory.get("swap_used_mb") or sample.get("swap_used_mb") or 0)
    swap_total = float(memory.get("swap_total_mb") or sample.get("swap_total_mb") or 0)
    mem_some = float(psi_mem.get("some_avg10") or sample.get("psi_memory_some_avg10") or 0)
    io_full = float(psi_io.get("full_avg10") or sample.get("psi_io_full_avg10") or 0)
    
    mem_avail_pct = (mem_available / mem_total) if mem_total else 1.0
    swap_used_pct = (swap_used / swap_total) if swap_total else 0.0
    
    hb_age = sample.get("desktop_heartbeat_age_s")
    kwin_ok = sample.get("kwin_ok")
    plasma_ok = sample.get("plasmashell_ok")
    journal_events = sample.get("journal_events") or {}
    coredump_value = journal_events.get("coredump") or ""
    coredump_lines = coredump_value.splitlines() if isinstance(coredump_value, str) else list(coredump_value)

    # A single runaway process can exhaust the machine before systemd-oomd
    # reaches its cgroup threshold.  Keep this evidence-based: process RSS is
    # only promoted when pressure or swap use is already elevated, and the
    # warning explicitly names the observed workload without claiming that it
    # is a leak or the sole cause.
    top_rss = (sample.get("processes") or {}).get("top_rss") or []
    largest = top_rss[0] if top_rss else {}
    largest_rss_mb = float(largest.get("rss_kb") or 0) / 1024
    largest_name = str(largest.get("name") or largest.get("group") or "workload")
    largest_group = str(largest.get("group") or largest_name)
    largest_share = largest_rss_mb / mem_total if mem_total else 0.0

    severity = "ok"
    category = "healthy"
    title = "System healthy"
    reasons = []

    if len(coredump_lines) >= 3 and (mem_some >= 10 or io_full >= 15 or swap_used_pct > 0.60):
        severity = "critical"
        category = "memory"
        title = "Coredump storm is adding pressure"
        reasons = [
            f"{len(coredump_lines)} coredump events were recorded in the recent window.",
            "Coredump processing can consume substantial memory and I/O while the desktop is already under pressure.",
        ]
    elif (
        largest_rss_mb >= max(2048, mem_total * 0.40)
        and largest_share >= 0.40
        and (mem_some >= 15 or io_full >= 20 or swap_used_pct > 0.70)
    ):
        severity = "critical"
        category = "memory"
        title = f"One workload is consuming {int(largest_rss_mb)} MB RAM"
        reasons = [
            f"Largest workload: {largest_group} ({int(largest_rss_mb)} MB RSS).",
            f"That process uses about {int(largest_share * 100)}% of physical RAM.",
            f"Available RAM: {int(mem_available)} MB; swap: {int(swap_used_pct * 100)}% used.",
            "Memory or I/O pressure is already elevated.",
        ]
    elif (
        largest_rss_mb >= max(2048, mem_total * 0.25)
        and largest_share >= 0.25
        and (mem_some >= 10 or io_full >= 15 or swap_used_pct > 0.60)
    ):
        severity = "warning"
        category = "memory"
        title = f"A single workload is using {int(largest_rss_mb)} MB RAM"
        reasons = [
            f"Largest workload: {largest_group} ({int(largest_rss_mb)} MB RSS).",
            f"That process uses about {int(largest_share * 100)}% of physical RAM.",
            "Memory or I/O pressure is rising; this workload may be driving swap thrash.",
        ]
    elif mem_avail_pct < 0.08 and swap_used_pct > 0.85 and mem_some >= 20 and io_full >= 20:
        severity = "critical"
        category = "memory"
        title = f"Memory pressure is critical \u2014 swap is {int(swap_used_pct * 100)}% full."
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%",
            "Memory pressure: severe",
            "I/O pressure: severe"
        ]
    elif mem_avail_pct < 0.15 and swap_used_pct > 0.70 and mem_some >= 10:
        severity = "warning"
        category = "memory"
        title = "Memory pressure is rising"
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%",
            "Memory pressure: elevated"
        ]
    elif hb_age is not None and hb_age > 20:
        severity = "warning"
        category = "desktop"
        title = "Desktop heartbeat lost"
        reasons = [f"Desktop heartbeat stale ({hb_age}s)"]
    elif kwin_ok is False:
        severity = "warning"
        category = "desktop"
        title = "KWin Wayland unresponsive"
        reasons = ["KWin failed its ping response."]
    elif plasma_ok is False and kwin_ok is True:
        severity = "warning"
        category = "desktop"
        title = "Plasmashell missing"
        reasons = ["plasmashell is not running, but KWin is OK."]
    elif journal_events.get("graphics"):
        severity = "warning"
        category = "desktop"
        title = "Display-stack errors observed"
        reasons = ["Recent kernel graphics evidence was recorded; this does not establish causation."]
    elif mem_avail_pct < 0.08 and swap_used_pct > 0.85:
        # Fallback to critical if missing PSI data but RAM is completely exhausted
        severity = "critical"
        category = "memory"
        title = f"Memory pressure is critical \u2014 swap is {int(swap_used_pct * 100)}% full."
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%"
        ]
    elif mem_avail_pct < 0.15 and swap_used_pct > 0.70:
        severity = "warning"
        category = "memory"
        title = "Memory pressure is rising"
        reasons = [
            f"Available RAM: {int(mem_available)} MB",
            f"zram/swap: {int(swap_used_pct * 100)}%"
        ]

    offenders = []
    processes = sample.get("processes") or {}
    for proc in (processes.get("top_rss") or [])[:3]:
        name = proc.get("name")
        group = proc.get("group") or name
        rss_mb = int((proc.get("rss_kb") or 0) / 1024)
        if rss_mb > 500:
            offenders.append(f"{group} \u2014 {rss_mb} MB")

    actions = []
    if severity == "warning" and category == "memory":
        actions.append("The desktop is still responsive.")
        actions.append(f"Save work, then stop or restart the heavy {largest_name} workload before swap thrash worsens.")
    elif severity == "critical" and category == "memory":
        actions.append(f"Save important work immediately, then stop or restart {largest_name} before the desktop freezes.")
        if coredump_lines:
            actions.append("Leave crash capture enabled, but avoid opening graphical crash reports until pressure subsides.")
    
    plasma_recovery = None
    if plasma_ok is False and kwin_ok is True:
        plasma_recovery = "Offer plasmashell --replace as a panel-only recovery action."

    return {
        "severity": severity,
        "category": category,
        "title": title,
        "reasons": reasons,
        "likely_offenders": offenders,
        "recommended_actions": actions,
        "timestamp": sample.get("ts", ""),
        "plasma_shell_recovery": plasma_recovery,
        "automatic_action_taken": False
    }


class StabilityController:
    def __init__(self, owner_config: Path = Path("/etc/fedora-crash-doctor/owner.json"), out_dir: Path = Path("/run/fedora-crash-doctor"), capture_callback=None, capture_cooldown: float = 600.0):
        self.state = "ok" # ok, pending, warning, critical, recovering
        self.pressure_count = 0
        self.recovery_count = 0
        self.owner_config = owner_config
        self.out_dir = out_dir
        self.capture_callback = capture_callback
        self.capture_cooldown = max(0.0, float(capture_cooldown))
        self.history: deque[dict[str, Any]] = deque(maxlen=360)
        self.baseline: dict[str, dict[str, float]] = {}
        self.last_capture_monotonic = -float('inf')
        
    def get_owner(self) -> dict[str, int] | None:
        try:
            if not self.owner_config.exists():
                return None
            data = json.loads(self.owner_config.read_text())
            return {"uid": int(data["uid"]), "gid": int(data["gid"])}
        except Exception:
            return None
        
    def process_sample(self, sample: dict[str, Any]) -> dict[str, Any] | None:
        self.history.append(sample)
        self._update_baseline(sample)
        eval_result = evaluate_sample(sample)
        trend = self.trends()
        eval_result["trends"] = trend
        if trend.get("chrome_rss_mb_per_min", 0) >= 50 and eval_result["severity"] == "ok":
            eval_result["severity"] = "warning"
            eval_result["category"] = "memory"
            eval_result["title"] = "Chrome memory growth observed"
            eval_result["reasons"] = [f"Chrome aggregate RSS is growing at {trend['chrome_rss_mb_per_min']:.1f} MB/min.", "This is sustained memory growth observed, not proof of a memory leak."]
        if trend.get("swap_mb_per_min", 0) >= 50 and eval_result["severity"] == "ok":
            eval_result["severity"] = "warning"
            eval_result["category"] = "memory"
            eval_result["title"] = "Swap use is increasing"
            eval_result["reasons"] = [f"Swap use is increasing at {trend['swap_mb_per_min']:.1f} MB/min."]
        latency = sample.get("kwin_ping_ms")
        if latency is not None and latency > max(250, self.baseline.get("kwin_ping_ms", {}).get("p95", 0) * 3):
            if eval_result["severity"] == "ok":
                eval_result["severity"] = "warning"
                eval_result["category"] = "desktop"
                eval_result["title"] = "KWin response latency is abnormally high"
                eval_result["reasons"] = [f"KWin ping latency: {latency:.1f} ms."]
        raw_sev = eval_result["severity"]

        if raw_sev in {"warning", "critical"}:
            self.recovery_count = 0
            self.pressure_count += 1
        else:
            self.pressure_count = 0
            self.recovery_count += 1

        new_state = self.state
        emit = False

        if self.state == "ok":
            if raw_sev in {"warning", "critical"}:
                new_state = "pending"
        elif self.state == "pending":
            if self.pressure_count >= 2:
                new_state = raw_sev
                emit = True
            elif raw_sev == "ok" and self.recovery_count >= 2:
                new_state = "ok"
        elif self.state == "warning":
            if raw_sev == "critical" and self.pressure_count >= 2:
                new_state = "critical"
                emit = True
            elif raw_sev == "ok":
                new_state = "recovering"
                emit = True
        elif self.state == "critical":
            if raw_sev == "ok":
                new_state = "recovering"
                emit = True
        elif self.state == "recovering":
            if raw_sev in {"warning", "critical"}:
                new_state = raw_sev
                emit = True
            elif self.recovery_count >= 5:
                new_state = "ok"
                emit = True

        self.state = new_state

        if emit:
            out = {
                "state": self.state,
                "category": eval_result.get("category", ""),
                "title": eval_result.get("title", ""),
                "reasons": eval_result.get("reasons", []),
                "likely_offenders": eval_result.get("likely_offenders", []),
                "recommended_actions": eval_result.get("recommended_actions", []),
                "timestamp": eval_result.get("timestamp", ""),
                "automatic_action_taken": False
            }
            out["health_state"] = {"ok": "NORMAL", "warning": "WARNING", "critical": "CRITICAL", "recovering": "WARNING"}.get(self.state, "NORMAL")
            out["trends"] = eval_result.get("trends", {})
            out["baseline"] = self.baseline
            if self.state in {"recovering", "ok"}:
                out["title"] = "System recovered"
                out["reasons"] = ["Pressure has subsided and conditions are healthy."]
                out["recommended_actions"] = []
                out["category"] = "healthy"
            
            self._capture_evidence(out, sample)
            self._notify_user(out)
            return out

        return None

    def _update_baseline(self, sample: dict[str, Any]) -> None:
        if len(self.history) < 12:
            return
        values = {
            "kwin_ping_ms": sample.get("kwin_ping_ms"),
            "chrome_rss_mb": (sample.get("chrome", {}) or {}).get("aggregate_rss_mb"),
            "plasmashell_rss_mb": (sample.get("plasmashell", {}) or {}).get("rss_mb"),
            "swap_used_mb": (sample.get("memory", {}) or {}).get("swap_used_mb"),
            "psi_mem": (sample.get("psi_mem", {}) or {}).get("some_avg10"),
            "psi_io": (sample.get("psi_io", {}) or {}).get("full_avg10"),
        }
        for key, value in values.items():
            if value is None:
                continue
            raw_numbers = [((item.get("chrome", {}) or {}).get("aggregate_rss_mb") if key == "chrome_rss_mb" else (item.get("plasmashell", {}) or {}).get("rss_mb") if key == "plasmashell_rss_mb" else (item.get("memory", {}) or {}).get("swap_used_mb") if key == "swap_used_mb" else (item.get("psi_mem", {}) or {}).get("some_avg10") if key == "psi_mem" else (item.get("psi_io", {}) or {}).get("full_avg10") if key == "psi_io" else item.get(key)) for item in self.history]
            numbers = [float(number) for number in raw_numbers if number is not None]
            if len(numbers) >= 5:
                q = quantiles(numbers, n=100, method="inclusive")
                self.baseline[key] = {"median": median(numbers), "p90": q[89], "p95": q[94], "p99": q[98]}

    def trends(self) -> dict[str, float]:
        if len(self.history) < 2:
            return {}
        first, last = self.history[0], self.history[-1]
        elapsed = max(1.0, float(last.get("epoch", 0) or 0) - float(first.get("epoch", 0) or 0))
        def delta(path: tuple[str, ...]) -> float:
            def value(item):
                current: Any = item
                for key in path:
                    current = current.get(key) if isinstance(current, dict) else None
                return float(current) if current is not None else None
            a, b = value(first), value(last)
            return ((b - a) / elapsed) * 60 if a is not None and b is not None else 0.0
        return {
            "chrome_rss_mb_per_min": delta(("chrome", "aggregate_rss_mb")),
            "swap_mb_per_min": delta(("memory", "swap_used_mb")),
            "zram_mb_per_min": delta(("memory", "zram_used_mb")),
            "kwin_latency_ms_per_min": delta(("kwin_ping_ms",)),
            "psi_mem_per_min": delta(("psi_mem", "some_avg10")),
            "psi_io_per_min": delta(("psi_io", "full_avg10")),
        }

    def _capture_evidence(self, event: dict[str, Any], sample: dict[str, Any]) -> None:
        if not self.capture_callback or event.get("state") not in {"warning", "critical"}:
            return
        import time
        now = time.monotonic()
        if event.get("state") == "warning" and now - self.last_capture_monotonic < self.capture_cooldown:
            return
        try:
            event["trigger_reason"] = event.get("title", "")
            event["trigger_metrics"] = {key: value for key, value in (event.get("trends") or {}).items() if value}
            event["trigger_time"] = event.get("timestamp", "")
            path = self.capture_callback(event, sample)
            event["evidence_capture_path"] = str(path) if path else None
            event["automatic_action_taken"] = bool(path)
            self.last_capture_monotonic = now
        except Exception as exc:
            event["capture_error"] = str(exc)
        
    def _notify_user(self, payload: dict[str, Any]) -> None:
        owner = self.get_owner()
        if not owner:
            return
            
        try:
            self.out_dir.mkdir(mode=0o755, parents=True, exist_ok=True)
            
            target = self.out_dir / "stability-event.json"
            fd, name = tempfile.mkstemp(prefix="stability-", dir=self.out_dir)
            with os.fdopen(fd, "w") as stream:
                json.dump(payload, stream)
                stream.flush()
                os.fsync(stream.fileno())
                
            os.chown(name, owner["uid"], owner["gid"])
            os.chmod(name, 0o600)
            os.replace(name, target)
        except Exception:
            pass
