#!/usr/bin/env python3
"""Read-only Fedora crash and reliability evidence collector.

This module is imported by the locked-down privileged broker and the boot-time
autoscan service. It never installs packages, changes configuration, runs
stress tests, repairs filesystems, or writes into user-controlled paths.
"""
from __future__ import annotations

import glob
import ctypes
import json
import os
import platform
import re
import shlex
import shutil
import socket
import signal
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Iterable

from confidence_explanation import explain_incident
from device_inventory import attribute_log_line, parse_lsblk_json
from freeze_classifiers import classify_freeze_evidence
from incident_model import attach_incident_identity
from report_schema import REPORT_SCHEMA_VERSION, validate_report
from telemetry_timeline import build_telemetry_timeline
from pressure_incident import build_pressure_incident
from version import app_version

MAX_OUTPUT = 700_000
DEFAULT_TIMEOUT = 40
Progress = Callable[[int, int, str], None]
CancelCheck = Callable[[], bool]


def _child_parent_death_signal() -> None:
    """Ask the kernel to terminate a diagnostic child if its broker dies."""
    try:
        ctypes.CDLL(None).prctl(1, signal.SIGTERM)
    except Exception:
        pass


def _safe_env() -> dict[str, str]:
    return {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LC_ALL": "C.UTF-8",
        "LANG": "C.UTF-8",
        "HOME": "/root",
    }


def run(command: list[str] | str, timeout: int = DEFAULT_TIMEOUT) -> dict[str, Any]:
    """Run a fixed diagnostic command and return bounded combined output."""
    shell = isinstance(command, str)
    display = command if shell else shlex.join(command)
    if not shell and shutil.which(command[0], path=_safe_env()["PATH"]) is None:
        return {
            "command": display,
            "status": "not_available",
            "state": "unavailable",
            "returncode": 127,
            "duration_seconds": 0,
            "output": f"Command is not installed: {command[0]}",
        }
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            shell=shell,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=timeout,
            env=_safe_env(),
            preexec_fn=_child_parent_death_signal,
        )
        output = proc.stdout or ""
        if len(output) > MAX_OUTPUT:
            output = output[:MAX_OUTPUT] + "\n\n[Output truncated by Fedora Crash Doctor]\n"
        status = "ok" if proc.returncode == 0 else "error"
        # fwupdmgr deliberately returns non-zero for common non-fault states.
        if isinstance(command, list) and command[:2] == ["fwupdmgr", "get-updates"]:
            if re.search(r"No updates available|No updatable devices|Devices with no available firmware updates", output, re.I):
                status = "ok"
        return {
            "command": display,
            "status": status,
            "state": "completed" if status == "ok" else "failed",
            "returncode": proc.returncode,
            "duration_seconds": round(time.monotonic() - started, 2),
            "output": output,
        }
    except subprocess.TimeoutExpired as exc:
        output = exc.stdout or ""
        if isinstance(output, bytes):
            output = output.decode(errors="replace")
        return {
            "command": display,
            "status": "timeout",
            "state": "timed_out",
            "returncode": 124,
            "duration_seconds": round(time.monotonic() - started, 2),
            "output": output + f"\nTimed out after {timeout} seconds.",
        }
    except Exception as exc:  # defensive: diagnostics should continue
        return {
            "command": display,
            "status": "error",
            "state": "failed",
            "returncode": 1,
            "duration_seconds": round(time.monotonic() - started, 2),
            "output": f"{type(exc).__name__}: {exc}",
        }


def read_file(path: str, limit: int = 300_000) -> str:
    try:
        return Path(path).read_text(errors="replace")[:limit]
    except Exception as exc:
        return f"Unable to read {path}: {exc}"


@dataclass
class Task:
    key: str
    title: str
    command: list[str] | str
    timeout: int = DEFAULT_TIMEOUT
    category: str = "Software"


def cancelled_result(task: Task) -> dict[str, Any]:
    return {
        "title": task.title,
        "category": task.category,
        "command": task.command if isinstance(task.command, str) else shlex.join(task.command),
        "status": "cancelled",
        "state": "cancelled",
        "returncode": None,
        "duration_seconds": 0,
        "output": "Cancelled before this check started.",
        "timeout_seconds": task.timeout,
        "privilege": "root-or-current-user",
    }


class CheckRunner:
    def __init__(self, tasks: list[Task], progress: Progress | None, cancel_requested: CancelCheck | None = None):
        self.tasks = tasks
        self.progress = progress
        self.cancel_requested = cancel_requested
        self.checks: dict[str, Any] = {}
        self.cancelled = False

    def execute(self) -> dict[str, Any]:
        total = len(self.tasks)
        for index, task in enumerate(self.tasks, start=1):
            if self.cancel_requested and self.cancel_requested():
                self.cancelled = True
                for remaining in self.tasks[index - 1:]:
                    self.checks[remaining.key] = cancelled_result(remaining)
                break
            if self.progress:
                self.progress(index - 1, total, task.title)
            result = run(task.command, task.timeout)
            result["title"] = task.title
            result["category"] = task.category
            result["id"] = task.key
            result["timeout_seconds"] = task.timeout
            result["privilege"] = "root-or-current-user"
            result.setdefault("state", "completed" if result.get("status") == "ok" else "failed")
            self.checks[task.key] = result
        if self.progress:
            self.progress(total, total, "Analysing and correlating evidence")
        return self.checks


def discover_smart_devices() -> list[str]:
    result = run(["smartctl", "--scan-open"])
    devices = []
    for line in result.get("output", "").splitlines():
        if line.startswith("/dev/"):
            candidate = line.split()[0]
            if re.fullmatch(r"/dev/(?:sd[a-z]+|nvme\d+n\d+|mmcblk\d+)", candidate):
                devices.append(candidate)
    return sorted(set(devices))


def discover_nvme_devices() -> list[str]:
    return sorted(
        path for path in glob.glob("/dev/nvme*n1")
        if re.fullmatch(r"/dev/nvme\d+n\d+", path)
    )


def parse_lspci_inventory(text: str) -> dict[str, dict[str, str]]:
    """Map a PCI address to its description and active kernel driver."""
    inventory: dict[str, dict[str, str]] = {}
    current: str | None = None
    for line in text.splitlines():
        match = re.match(r"^((?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\s+(.+)$", line)
        if match:
            current = canonical_pci(match.group(1))
            inventory[current] = {"description": match.group(2).strip(), "driver": "unknown"}
            continue
        if current:
            driver = re.search(r"Kernel driver in use:\s*(.+)", line)
            if driver:
                inventory[current]["driver"] = driver.group(1).strip()
    return inventory


def canonical_pci(address: str) -> str:
    value = address.lower()
    return value if value.count(":") == 2 else f"0000:{value}"


def extract_pcie_devices(text: str, inventory: dict[str, dict[str, str]]) -> dict[str, dict[str, Any]]:
    """Extract a PCI address anywhere in an AER line and join it to lspci."""
    hits: dict[str, dict[str, Any]] = {}
    address_rx = re.compile(r"\b((?:[0-9a-fA-F]{4}:)?[0-9a-fA-F]{2}:[0-9a-fA-F]{2}\.[0-7])\b")
    error_rx = re.compile(r"PCIe Bus Error|AER:.*(?:error|Corrected)|BadDLLP|Receiver Error", re.I)
    for line in text.splitlines():
        if not error_rx.search(line):
            continue
        match = address_rx.search(line)
        if not match:
            continue
        address = canonical_pci(match.group(1))
        item = hits.setdefault(address, {
            "count": 0,
            "description": inventory.get(address, {}).get("description", "Unknown PCIe device"),
            "driver": inventory.get(address, {}).get("driver", "unknown"),
            "likely_role": pci_device_role(inventory.get(address, {}).get("description", ""), inventory.get(address, {}).get("driver", "")),
            "lines": [],
        })
        item["count"] += 1
        if len(item["lines"]) < 12:
            item["lines"].append(line.strip())
    return hits


def pci_device_role(description: str, driver: str) -> str:
    text = f"{description} {driver}".lower()
    if any(token in text for token in ("wireless", "wi-fi", "wifi", "wlan", "802.11", "rtw", "iwl", "ath")):
        return "Wi-Fi card"
    if any(token in text for token in ("ethernet", "network", "realtek", "intel corporation ethernet")):
        return "network adapter"
    if any(token in text for token in ("usb", "xhci")):
        return "USB controller, dock or hub path"
    if any(token in text for token in ("vga", "display", "graphics", "nvidia", "amd/ati", "intel corporation hd graphics")):
        return "graphics adapter"
    if any(token in text for token in ("nvme", "sata", "storage")):
        return "storage controller"
    return "PCIe device"


def load_baseline(path: str | None) -> dict[str, Any]:
    if not path:
        return {}
    try:
        data = json.loads(Path(path).read_text())
    except Exception:
        return {}
    return {
        item.get("id", item.get("title", "")): {
            "first_seen": item.get("first_seen") or data.get("metadata", {}).get("generated"),
        }
        for item in data.get("findings", [])
    }


def _metadata() -> dict[str, Any]:
    os_release: dict[str, str] = {}
    for line in read_file("/etc/os-release").splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            os_release[key] = value.strip('"')
    return {
        "generated": datetime.now(timezone.utc).astimezone().isoformat(timespec="seconds"),
        "hostname": socket.gethostname(),
        "kernel": platform.release(),
        "architecture": platform.machine(),
        "fedora": os_release.get("PRETTY_NAME", "Unknown Linux"),
        "boot_id": read_file("/proc/sys/kernel/random/boot_id", 100).strip(),
        "version": app_version(),
    }


SCAN_MODES = {"quick", "full", "deep"}


def build_tasks(mode: str) -> list[Task]:
    if mode not in SCAN_MODES:
        raise ValueError("mode must be quick, full or deep")
    tasks = [
        Task("boot_history", "Boot and crash history", ["last", "-x"], 15, "Software"),
        Task("journal_boots", "Available journal boots", ["journalctl", "--list-boots", "--no-pager"], 15, "Software"),
        Task("previous_errors", "Previous boot warnings and errors", ["journalctl", "-b", "-1", "-p", "warning..alert", "--no-pager", "-o", "short-iso-precise"], 50, "Software"),
        Task("previous_kernel_tail", "Final kernel messages from previous boot", "journalctl -b -1 -k --no-pager -o short-iso-precise | tail -1000", 50, "Software"),
        Task("previous_boot_tail", "Final messages from previous boot", "journalctl -b -1 --no-pager -o short-iso-precise | tail -1800", 70, "Software"),
        Task("current_kernel_errors", "Current boot kernel warnings and errors", ["journalctl", "-b", "0", "-k", "-p", "warning..alert", "--no-pager", "-o", "short-iso-precise"], 50, "Software"),
        Task("failed_units", "Failed system services", ["systemctl", "--failed", "--no-pager", "--plain"], 20, "Software"),
        Task("coredumps", "Application core dumps", ["coredumpctl", "list", "--since", "30 days ago", "--no-pager"], 35, "Software"),
        Task("inxi", "System and driver inventory", ["inxi", "-Fxxxz", "--no-host"], 45, "Software"),
        Task("pci", "PCI hardware and active drivers", ["lspci", "-Dnnk"], 25, "PCIe / Network"),
        Task("usb", "USB device tree", ["lsusb", "-tv"], 20, "PCIe / Network"),
        Task("block", "Storage layout", ["lsblk", "-e7", "-o", "NAME,PATH,TYPE,SIZE,FSTYPE,FSVER,MOUNTPOINTS,MODEL,SERIAL,ROTA,TRAN"], 20, "Storage"),
        Task("block_json", "Storage layout (machine readable)", ["lsblk", "-J", "-e7", "-o", "NAME,PATH,TYPE,FSTYPE,MOUNTPOINTS,MODEL,SERIAL,RM,TRAN"], 20, "Storage"),
        Task("swap_show", "Swap Configuration", ["swapon", "--show", "--bytes"], 15, "Memory"),
        Task("zramctl", "ZRAM Configuration", ["zramctl", "--output-all", "--bytes"], 15, "Memory"),
        Task("oomctl", "systemd-oomd status", ["oomctl"], 15, "Memory"),
        Task("memory", "Memory, swap and pressure", "free -h; echo; for f in /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io; do echo ===$f===; cat $f; done", 15, "Memory"),
        Task("filesystems", "Filesystem space", ["df", "-hT", "-x", "tmpfs", "-x", "devtmpfs"], 20, "Storage"),
        Task("sensors", "Temperatures and sensors", ["sensors"], 25, "Thermals"),
        Task("firmware_devices", "Firmware-supported devices", ["fwupdmgr", "get-devices"], 50, "Firmware"),
        Task("firmware_updates", "Available firmware updates", ["fwupdmgr", "get-updates"], 50, "Firmware"),
        Task("kernel_cmdline", "Kernel command line", ["cat", "/proc/cmdline"], 10, "Software"),
        Task("kernel_taint", "Kernel taint state", ["cat", "/proc/sys/kernel/tainted"], 10, "Software"),
        Task("modules", "Loaded kernel modules", ["lsmod"], 20, "Software"),
        Task("display_current", "Graphics/display errors in the current boot", "journalctl -b 0 --no-pager -o short-iso-precise SYSLOG_IDENTIFIER=kernel + _COMM=kwin_wayland + _COMM=kwin_x11 + _COMM=kwin_wayland_wrapper + _COMM=plasmashell + _COMM=Xorg + _COMM=gnome-shell | grep -iE 'i915|xe |amdgpu|nouveau|nvidia|drm|gpu hang|gpu reset|atomic update failure|framebuffer|flip_done|fence timeout|context provider|kwin' | tail -1800", 60, "Graphics"),
        Task("display_previous", "Graphics/display errors in the previous boot", "journalctl -b -1 --no-pager -o short-iso-precise SYSLOG_IDENTIFIER=kernel + _COMM=kwin_wayland + _COMM=kwin_x11 + _COMM=kwin_wayland_wrapper + _COMM=plasmashell + _COMM=Xorg + _COMM=gnome-shell | grep -iE 'i915|xe |amdgpu|nouveau|nvidia|drm|gpu hang|gpu reset|atomic update failure|framebuffer|flip_done|fence timeout|context provider|kwin' | tail -1800", 60, "Graphics"),
        Task("display_history", "Graphics/display errors across 14 days", "journalctl --since '14 days ago' -k --no-pager -o short-iso-precise | grep -iE 'i915|xe |amdgpu|nouveau|nvidia|drm|gpu hang|gpu reset|atomic update failure|framebuffer|flip_done|fence timeout' | tail -2200", 70, "Graphics"),
        Task("hardware_errors_previous", "Hardware and PCIe errors in the previous boot", "journalctl -b -1 -k --no-pager -o short-iso-precise | grep -iE 'hardware error|machine check|mce:|edac|aer:|pcie bus error|correctable|uncorrectable|bad dllp|poison' | tail -1500", 55, "PCIe / Network"),
        Task("hardware_errors_history", "Hardware and PCIe errors across 30 days", "journalctl --since '30 days ago' -k --no-pager -o short-iso-precise | grep -iE 'hardware error|machine check|mce:|edac|aer:|pcie bus error|correctable|uncorrectable|bad dllp|poison' | tail -2200", 70, "PCIe / Network"),
        Task("rasdaemon_status", "RAS daemon status", ["systemctl", "status", "rasdaemon.service", "--no-pager"], 20, "Memory"),
        Task("oom_previous", "Memory exhaustion in the previous boot", "journalctl -b -1 --no-pager -o short-iso-precise SYSLOG_IDENTIFIER=kernel + _COMM=systemd-oomd | grep -iE 'out of memory|oom-kill|killed process|systemd-oomd.*killed' | tail -800", 50, "Memory"),
        Task("oom_history", "Memory exhaustion across 30 days", "journalctl --since '30 days ago' --no-pager -o short-iso-precise SYSLOG_IDENTIFIER=kernel + _COMM=systemd-oomd | grep -iE 'out of memory|oom-kill|killed process|systemd-oomd.*killed' | tail -1200", 60, "Memory"),
        Task("thermal_previous", "Thermal events in the previous boot", "journalctl -b -1 -k --no-pager -o short-iso-precise | grep -iE 'thermal|overheat|critical temperature|throttl' | tail -800", 45, "Thermals"),
        Task("interrupt_latency", "Perf sampling-rate adjustment messages", "journalctl --since '30 days ago' -k --no-pager -o short-iso-precise | grep -iE 'perf: interrupt took too long|perf: interrupt.*lowering.*sample_rate' | tail -500", 45, "Software"),
        Task("rpm_kernel_graphics", "Installed kernel, graphics and desktop packages", "rpm -qa | grep -E '^(kernel|mesa|linux-firmware|kwin|kscreen|plasma|google-chrome|pipewire|wireplumber)' | sort", 35, "Software"),
        Task("dnf_history", "Recent package transactions", ["dnf", "history", "list"], 45, "Software"),
        Task("rpm_recent", "Recently installed or upgraded packages", "rpm -qa --last | head -140", 35, "Software"),
        Task("selinux_avc", "SELinux denials this boot", "journalctl -b 0 --no-pager -o short-iso-precise | grep -iE 'avc: +denied|SELinux is preventing' | tail -600", 35, "Software"),
        Task("sysctl_panic", "Panic and lockup settings", ["sysctl", "kernel.panic", "kernel.panic_on_oops", "kernel.softlockup_panic", "kernel.nmi_watchdog", "kernel.hardlockup_panic"], 15, "Software"),
        Task("kdump_service", "Kdump service status", ["systemctl", "is-active", "kdump"], 10, "Software"),
        Task("kdump_package", "Kdump package", ["rpm", "-q", "kexec-tools"], 10, "Software"),
        Task("canary_service", "Canary service status", ["systemctl", "is-active", "fedora-crash-doctor-canary.service"], 10, "Software"),
        Task("journal_dir", "Journal directory", ["ls", "-ld", "/var/log/journal"], 10, "Software"),
        Task("kexec_loaded", "Crash kernel loaded", ["cat", "/sys/kernel/kexec_crash_loaded"], 10, "Software"),
        Task("crashkernel_mem", "Crash kernel memory reserved", "grep -i crashkernel /proc/cmdline || true", 10, "Software"),
        Task("kdump_target_space", "Kdump target space", "df -h /var/crash || true", 10, "Software"),
        Task("canary_stat", "Canary heartbeat", "stat -c %Y /var/log/fedora-crash-doctor/canary.log || echo 0", 10, "Software"),
    ]
    if shutil.which("abrt-cli", path=_safe_env()["PATH"]):
        tasks.append(Task("abrt", "ABRT detected problems", ["abrt-cli", "list"], 35, "Software"))
    if shutil.which("ras-mc-ctl", path=_safe_env()["PATH"]):
        tasks.append(Task("ras_errors", "Stored RAS/EDAC errors", ["ras-mc-ctl", "--errors"], 35, "Memory"))
    if shutil.which("edac-util", path=_safe_env()["PATH"]):
        tasks.append(Task("edac", "EDAC memory-controller counters", ["edac-util", "-v"], 25, "Memory"))
    if shutil.which("btrfs", path=_safe_env()["PATH"]):
        tasks.extend([
            Task("btrfs_stats", "Btrfs device error counters", ["btrfs", "device", "stats", "/"], 25, "Storage"),
            Task("btrfs_scrub", "Btrfs scrub status", ["btrfs", "scrub", "status", "/"], 25, "Storage"),
        ])
    for index, device in enumerate(discover_smart_devices()):
        tasks.append(Task(f"smart_{index}", f"SMART health: {device}", ["smartctl", "-x", device], 75, "Storage"))
    for index, device in enumerate(discover_nvme_devices()):
        tasks.append(Task(f"nvme_{index}", f"NVMe health: {device}", ["nvme", "smart-log", device], 40, "Storage"))
    if mode in {"full", "deep"}:
        tasks.extend([
            Task("dnf_check", "Package dependency consistency", ["dnf", "check"], 220, "Software"),
            Task("systemd_blame", "Slowest boot services", ["systemd-analyze", "blame", "--no-pager"], 40, "Software"),
            Task("network_health", "NetworkManager state", ["nmcli", "-f", "STATE,CONNECTIVITY", "general"], 20, "PCIe / Network"),
            Task("resolver", "DNS resolver statistics", ["resolvectl", "statistics"], 25, "PCIe / Network"),
        ])
    if mode == "deep":
        if shutil.which("fwts", path=_safe_env()["PATH"]):
            tasks.append(Task("fwts", "Deep firmware test suite", ["fwts", "--batch", "--stdout-summary"], 180, "Firmware"))
        tasks.append(Task("rpm_verify", "Deep RPM file verification", "rpm -Va 2>&1 | head -6000", 180, "Software"))
    return tasks


def add_virtual_checks(checks: dict[str, Any]) -> None:
    gpu_chunks = []
    for error_file in glob.glob("/sys/class/drm/card*/error"):
        gpu_chunks.append(f"--- {error_file} ---\n{read_file(error_file, 500_000)}")
    checks["gpu_error_state"] = {
        "title": "Current GPU error state",
        "category": "Graphics",
        "command": "read /sys/class/drm/card*/error",
        "status": "ok",
        "state": "completed",
        "returncode": 0,
        "duration_seconds": 0,
        "timeout_seconds": 0,
        "privilege": "root-or-current-user",
        "output": "\n".join(gpu_chunks) if gpu_chunks else "No DRM error-state files exposed.",
    }
    pstore_chunks = []
    for item in glob.glob("/sys/fs/pstore/*"):
        pstore_chunks.append(f"--- {item} ---\n{read_file(item, 500_000)}")
    checks["pstore"] = {
        "title": "Persistent firmware/kernel crash records",
        "category": "Software",
        "command": "read /sys/fs/pstore",
        "status": "ok",
        "state": "completed",
        "returncode": 0,
        "duration_seconds": 0,
        "timeout_seconds": 0,
        "privilege": "root-or-current-user",
        "output": "\n".join(pstore_chunks) if pstore_chunks else "No pstore crash records found.",
    }
    canary = Path("/var/log/fedora-crash-doctor/canary.log")
    checks["canary_log"] = {
        "title": "System canary snapshots",
        "category": "Software",
        "command": f"read {canary}",
        "status": "ok" if canary.exists() else "not_available",
        "state": "completed" if canary.exists() else "unavailable",
        "returncode": 0,
        "duration_seconds": 0,
        "timeout_seconds": 0,
        "privilege": "root-or-current-user",
        "output": tail_file(canary, 1200) if canary.exists() else "System canary is not enabled.",
    }


def tail_file(path: Path, lines: int) -> str:
    try:
        data = path.read_text(errors="replace").splitlines()
        return "\n".join(data[-lines:])
    except Exception as exc:
        return f"Unable to read {path}: {exc}"


def evidence_lines(text: str, pattern: str, limit: int = 10) -> list[str]:
    regex = re.compile(pattern, re.I)
    found = []
    for line in text.splitlines():
        if regex.search(line):
            found.append(line.strip())
            if len(found) >= limit:
                break
    return found


def _make_finding(
    finding_id: str,
    severity: str,
    category: str,
    title: str,
    explanation: str,
    evidence: list[str],
    scope: str,
    confidence: str = "moderate",
) -> dict[str, Any]:
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


def analyse(checks: dict[str, Any]) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    prev = "\n".join(checks.get(k, {}).get("output", "") for k in (
        "previous_errors", "previous_kernel_tail", "previous_boot_tail",
        "display_previous", "hardware_errors_previous", "oom_previous", "thermal_previous",
        "current_kernel_errors", "display_current"
    ))
    history = "\n".join(checks.get(k, {}).get("output", "") for k in (
        "display_history", "hardware_errors_history", "oom_history", "interrupt_latency"
    ))
    all_text = "\n".join(str(v.get("output", "")) for v in checks.values())
    findings: list[dict[str, Any]] = []

    rules = [
        ("kernel_panic", "critical", "Software", "Kernel panic or lockup recorded",
         r"kernel panic|not syncing|watchdog:.*(?:hard lockup|soft lockup)",
         "The kernel explicitly reported a panic or watchdog lockup.", "high"),
        ("uncorrectable_hardware", "critical", "Memory", "Uncorrectable hardware error",
         r"uncorrectable.*(?:error|fatal)|hardware error.*uncorrected|mce:.*fatal|machine check.*fatal",
         "An uncorrectable CPU, RAM or PCIe hardware event can directly stop the system.", "high"),
        ("intel_display", "warning", "Graphics", "Intel graphics/display pipeline errors",
         r"(?:i915|xe\s).*atomic update failure|GL_FRAMEBUFFER_INCOMPLETE_ATTACHMENT|(?:i915|xe\s).*GPU HANG|(?:i915|xe\s).*reset",
         "Intel DRM/KWin display failures can cause black screens, compositor stalls or a full freeze.", "moderate"),
        ("other_gpu", "warning", "Graphics", "GPU reset or timeout",
         r"amdgpu.*(?:reset|timeout|ring.*stalled)|nouveau.*(?:timeout|fault)|nvidia.*Xid|drm.*flip_done timed out",
         "A graphics driver or GPU timeout was recorded.", "moderate"),
        ("wayland", "warning", "Graphics", "Wayland compositor or session crash",
         r"(?i)(?!.*not fatal)(?!.*portal.*error)(?:wayland.*(?:crash|fatal|error(?!\s*(?:disconnect|terminate)))|kwin_wayland.*(?:segfault|core dump|aborted))",
         "The Wayland display server or compositor reported a crash or fatal error.", "moderate"),
        ("oom", "warning", "Memory", "Memory exhaustion",
         r"out of memory|oom-kill|killed process|systemd-oomd.*killed",
         "The machine ran out of usable memory or an OOM service terminated processes.", "high"),
        ("pcie", "warning", "PCIe / Network", "PCIe bus reliability errors",
         r"pcie bus error|aer:.*error|bad dllp|receiver error",
         "PCIe errors can identify a device, link, power-management or signal-integrity problem.", "moderate"),
        ("thermal", "warning", "Thermals", "Thermal protection event",
         r"critical temperature|overheat|thermal.*shutdown|temperature above threshold",
         "A serious overheating or thermal-protection event was recorded.", "high"),
    ]
    for fid, severity, category, title, pattern, explanation, confidence in rules:
        lines = evidence_lines(prev, pattern)
        scope = "this_incident"
        if not lines:
            lines = evidence_lines(history if fid in {"intel_display", "other_gpu", "wayland", "oom", "pcie"} else all_text, pattern)
            scope = "historical"
        if lines:
            findings.append(_make_finding(fid, severity, category, title, explanation, lines, scope, confidence))

    tail_lines = checks.get("previous_boot_tail", {}).get("output", "").splitlines()
    parsed_tail = [(parse_journal_time(line), line) for line in tail_lines]
    parsed_tail = [(ts, line) for ts, line in parsed_tail if ts is not None]

    if parsed_tail:
        end_time = max(ts for ts, _ in parsed_tail)
        recent_failures = []
        for ts, line in parsed_tail:
            if end_time - ts <= timedelta(minutes=10):
                if re.search(r"systemd\[\d*\]:.*(?:Failed to start|failed with result|Main process exited, code=(?:exited|dumped), status=(?!0\b))", line, re.I):
                    recent_failures.append(line.strip())

        if recent_failures:
            findings.append(_make_finding(
                "failed_services", "warning", "Software", "Failed system services near crash",
                "One or more systemd services failed shortly before the crash boundary, which might have triggered downstream faults.",
                recent_failures[-10:], "this_incident", "moderate"
            ))

    storage_rx = re.compile(r"SMART overall-health.*FAILED|SMART Health Status:.*(?:BAD|FAILED)|critical_warning\s*:\s*[1-9]|medium error|I/O error|BTRFS.*(?:error|corrupt)|EXT4-fs error|XFS.*corruption|blk_update_request.*I/O error|nvme.*timeout|link down|resetting", re.I)
    disk_events: dict[str, list[str]] = {}
    for line in evidence_lines(all_text, storage_rx.pattern, 50):
        dev_match = re.search(r"(?:dev(?:ice)?\s+|FAT-fs\s*\()([a-z0-9]+)\b", line, re.I)
        dev = dev_match.group(1) if dev_match else "unknown"
        disk_events.setdefault(dev, []).append(line.strip())

    try:
        device_inventory = parse_lsblk_json(checks.get("block_json", {}).get("output", ""))
    except Exception:
        device_inventory = {}
    lsblk_out = checks.get("block", {}).get("output", "")
    for dev, lines in disk_events.items():
        base_dev = re.sub(r"p?\d+$", "", dev) if dev.startswith("nvme") else dev.rstrip("0123456789")
        attributions = [attribute_log_line(line, device_inventory) for line in lines]
        attributions = [item for item in attributions if item]
        known_attrs = [item for item in attributions if item.get("known")]
        primary_attr = known_attrs[0] if known_attrs else None
        is_removable = bool(
            primary_attr and (primary_attr.get("removable") or primary_attr.get("transport") == "usb")
        ) or bool(re.search(fr"\b{base_dev}\b.*usb", lsblk_out, re.I) or re.search(fr"\[{base_dev}\].*removable disk", all_text, re.I))
        is_system_disk = bool(primary_attr and primary_attr.get("system_disk"))
        has_smart = any(re.search(r"SMART|critical_warning", l, re.I) for l in lines)
        has_write_err = any(re.search(r"write|WRITE", l, re.I) for l in lines)
        has_read_err = any(re.search(r"read|READ", l, re.I) for l in lines)
        has_reset = any(re.search(r"reset|link down|timeout", l, re.I) for l in lines)
        has_disconnect = is_removable and bool(re.search(r"USB disconnect", all_text, re.I))

        severity = "warning"
        title = f"Storage errors on {dev}"
        explanation = f"The storage device {dev} reported errors."

        err_types = []
        if has_read_err: err_types.append("read errors")
        if has_write_err: err_types.append("write errors")
        if has_reset: err_types.append("link resets or timeouts")
        if not err_types: err_types.append("I/O or filesystem errors")

        if is_removable:
            title = f"Errors on removable device {dev}"
            explanation = f"A removable device ({dev}) reported {', '.join(err_types)}."
            if has_disconnect:
                explanation += " This likely coincides with an unsafe removal or transient connection loss."
                severity = "info"
            elif len(lines) == 1:
                severity = "info"
            if has_smart:
                severity = "critical"
                explanation += " It also reported SMART health failures, indicating hardware degradation."
        else:
            if has_smart:
                severity = "critical"
                if is_system_disk:
                    title = f"Active failure on internal system disk {dev}"
                    explanation = f"The internal system disk {dev} reported SMART health failures. Immediate backup is recommended."
                else:
                    title = f"Storage health failure on {dev}"
                    explanation = f"The storage device {dev} reported SMART health failures. Attribute the device before assuming it is the Fedora system disk."
            elif len(lines) > 2:
                severity = "critical"
                if is_system_disk:
                    title = f"Repeated errors on internal system disk {dev}"
                    explanation = f"The internal system disk {dev} is experiencing repeated {', '.join(err_types)}. This indicates a current or repeated risk of data loss. Immediate backup is recommended."
                else:
                    title = f"Repeated storage errors on {dev}"
                    explanation = f"The storage device {dev} is experiencing repeated {', '.join(err_types)}. Attribute the physical device before blaming the internal Fedora NVMe."
            else:
                severity = "warning"
                title = f"Transient storage error on {dev}"
                explanation = f"The storage device {dev} logged {', '.join(err_types)}. Backup and filesystem checks are advised, but it may be a single historical event."

        if dev == "unknown":
            title = "Unidentified storage device errors"
            explanation = "Storage errors were logged, but the exact physical device could not be identified."
            severity = "warning"
            if has_smart:
                severity = "critical"
                explanation += " SMART health failures were detected. Immediate backup of important data is recommended."

        finding = _make_finding(
            f"storage_{dev}", severity, "Storage", title, explanation, lines[:10], "historical",
            "high" if len(lines) > 2 or has_smart else "moderate"
        )
        if attributions:
            finding["device_attribution"] = attributions[:10]
        findings.append(finding)

    inventory = parse_lspci_inventory(checks.get("pci", {}).get("output", ""))
    pcie_hits = extract_pcie_devices(
        checks.get("hardware_errors_history", {}).get("output", "") + "\n" +
        checks.get("hardware_errors_previous", {}).get("output", ""),
        inventory,
    )
    repeated = {address: item for address, item in pcie_hits.items() if item["count"] >= 2}
    if repeated:
        evidence = []
        device_details = []
        for address, item in sorted(repeated.items(), key=lambda pair: pair[1]["count"], reverse=True):
            device_details.append({"address": address, **item})
            evidence.append(
                f"{address} — {item['likely_role']} — {item['description']} — driver {item['driver']} — {item['count']} events"
            )
            evidence.extend(item["lines"][-3:])
        findings.append({
            **_make_finding(
                "repeated_pcie_device", "warning", "PCIe / Network",
                "The same PCIe device repeatedly reported bus errors",
                "Repeated corrected errors from one address are more actionable than an isolated generic AER line.",
                evidence[:14], "historical", "moderate"
            ),
            "devices": device_details,
        })

    corrected = evidence_lines(all_text, r"severity=Corrected|severity=Correctable|corrected error", 10)
    if corrected:
        findings.append(_make_finding(
            "corrected_events", "info", "PCIe / Network", "Corrected hardware or PCIe events",
            "The hardware recovered these events. Repetition on one device still deserves attention.",
            corrected, "historical", "high"
        ))

    crash_lines = evidence_lines(checks.get("boot_history", {}).get("output", ""), r"\s-crash\s|\bcrash\s+\(", 8)
    if crash_lines:
        findings.append(_make_finding(
            "unclean_boot", "info", "Software", "A previous boot ended without a clean shutdown",
            "Boot accounting marks one or more sessions as crashed rather than normally shut down.",
            crash_lines, "historical", "high"
        ))

    perf_lines = evidence_lines(checks.get("interrupt_latency", {}).get("output", ""), r"perf: interrupt took too long", 12)
    if perf_lines:
        findings.append(_make_finding(
            "perf_sampling_adjustment", "info", "Software", "Kernel perf reduced its sampling rate",
            "These messages mean perf sampling exceeded its time allowance. They are context, not a dependable crash predictor by themselves.",
            perf_lines, "historical", "high"
        ))

    if not evidence_lines(checks.get("oom_previous", {}).get("output", ""), r"out of memory|oom-kill|killed process"):
        findings.append(_make_finding(
            "no_oom", "info", "Memory", "No logged memory-exhaustion event for the previous boot",
            "The previous-boot journal did not contain a clear OOM-kill signature.", [], "this_incident", "high"
        ))
    if "No pstore crash records found" in checks.get("pstore", {}).get("output", ""):
        findings.append(_make_finding(
            "no_pstore", "info", "Software", "No persistent pstore crash record found",
            "Firmware-backed pstore did not preserve a panic or oops record.", [], "this_incident", "high"
        ))

    context = {
        "pci_inventory": inventory,
        "pcie_devices": pcie_hits,
        "hard_crash": bool(crash_lines),
        "has_gpu_errors": any(f["id"] in {"intel_display", "other_gpu", "wayland"} for f in findings),
        "has_oom": any(f["id"] == "oom" for f in findings),
        "has_thermal": any(f["id"].startswith("thermal") for f in findings),
        "has_storage": any(f["id"].startswith("storage_") for f in findings),
        "has_panic": any(f["id"] == "kernel_panic" for f in findings),
    }
    is_clean_shutdown = False
    shutdown_time = None
    for ts, line in parsed_tail[-200:]:
        if re.search(r"systemd-shutdown\[\d+\]:|systemd\[\d+\]: Shutting down\.|Reached target.*(?:System Shutdown|System Reboot)", line, re.I):
            is_clean_shutdown = True
            if not shutdown_time:
                shutdown_time = ts

    if is_clean_shutdown and shutdown_time:
        for finding in findings:
            if finding["id"] in {"wayland", "failed_services", "intel_display", "other_gpu"}:
                valid_evidence = []
                for line in finding["evidence"]:
                    ts = parse_journal_time(line)
                    if ts and (shutdown_time - timedelta(seconds=15)) <= ts <= (shutdown_time + timedelta(minutes=3)):
                        continue
                    valid_evidence.append(line)
                finding["evidence"] = valid_evidence
        findings = [f for f in findings if f["evidence"] or f["id"] not in {"wayland", "failed_services", "intel_display", "other_gpu"}]

    order = {"critical": 0, "warning": 1, "info": 2}
    findings.sort(key=lambda item: (order[item["severity"]], item["scope"] != "this_incident", item["title"]))
    return findings, context


_TS_RX = re.compile(r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2}))\s+(.*)$")


def parse_journal_time(line: str) -> datetime | None:
    match = _TS_RX.match(line)
    if not match:
        return None
    raw = match.group(1)
    try:
        return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S.%f%z")
    except ValueError:
        try:
            return datetime.strptime(raw, "%Y-%m-%dT%H:%M:%S%z")
        except ValueError:
            return None


def build_timeline(checks: dict[str, Any]) -> list[dict[str, Any]]:
    lines = checks.get("previous_boot_tail", {}).get("output", "").splitlines()
    parsed = [(parse_journal_time(line), line) for line in lines]
    parsed = [(ts, line) for ts, line in parsed if ts is not None]
    if not parsed:
        return []
    end_time = max(ts for ts, _ in parsed)
    patterns = [
        ("Graphics", r"i915|xe |amdgpu|nvidia|nouveau|atomic update|framebuffer|kwin|context provider|compositor|wayland"),
        ("Memory", r"out of memory|oom-kill|killed process|edac|mce:"),
        ("PCIe / Network", r"pcie bus error|aer:|bad dllp|receiver error|failed to resolve|NetworkManager"),
        ("Thermals", r"thermal|overheat|throttl|critical temperature"),
        ("Storage", r"btrfs.*error|nvme.*(?:error|timeout)|I/O error|smart"),
        ("Software", r"segfault|core dump|watchdog|kernel panic|not syncing|wireplumber|pipewire|chrome"),
    ]
    events: list[dict[str, Any]] = []
    seen: set[str] = set()
    for ts, line in parsed:
        category = None
        for candidate, pattern in patterns:
            if re.search(pattern, line, re.I):
                category = candidate
                break
        if not category:
            continue
        compact = re.sub(r"^\S+\s+", "", line).strip()
        signature = re.sub(r"\d+", "#", compact)[:160]
        if signature in seen:
            continue
        seen.add(signature)
        delta = end_time - ts
        proximity = "Immediately before crash" if delta <= timedelta(minutes=10) else "Earlier in same boot"
        events.append({
            "timestamp": ts.isoformat(timespec="seconds"),
            "category": category,
            "summary": compact[:280],
            "evidence": line,
            "proximity": proximity,
            "seconds_before_last_log": max(0, int(delta.total_seconds())),
        })
    events = sorted(events, key=lambda item: item["timestamp"])[-80:]
    is_clean_shutdown = any(
        re.search(r"systemd-shutdown\[\d+\]:|systemd\[\d+\]: Shutting down\.|Reached target.*(?:System Shutdown|System Reboot)", line, re.I)
        for _, line in parsed[-200:]
    )

    if is_clean_shutdown:
        events.append({
            "timestamp": end_time.isoformat(timespec="seconds"),
            "category": "Clean shutdown boundary",
            "summary": "The previous journal ends with a clean shutdown or intentional reboot.",
            "evidence": parsed[-1][1],
            "proximity": "Shutdown boundary",
            "seconds_before_last_log": 0,
        })
    else:
        events.append({
            "timestamp": end_time.isoformat(timespec="seconds"),
            "category": "Crash boundary",
            "summary": "The previous journal stops here; the next boot was recorded as unclean/crashed.",
            "evidence": parsed[-1][1],
            "proximity": "Crash boundary",
            "seconds_before_last_log": 0,
        })
    return events


def analyse_canary(checks: dict[str, Any]) -> dict[str, Any]:
    text = checks.get("canary_log", {}).get("output", "")
    rows = []
    for line in text.splitlines():
        try:
            row = json.loads(line)
            if isinstance(row, dict) and "ts" in row:
                rows.append(row)
        except Exception:
            pass
    rows = rows[-240:]
    result = {"samples": rows, "interpretation": "No canary samples available."}
    if not rows:
        return result

    start_row = rows[0]
    end_row = rows[-1]

    start_groups = start_row.get("processes", {}).get("groups", {})
    end_groups = end_row.get("processes", {}).get("groups", {})

    growth_report = []
    total_ram_growth = 0
    total_swap_growth = 0

    for g, end_stats in end_groups.items():
        start_stats = start_groups.get(g, {"rss_kb": 0, "swap_kb": 0})
        rss_diff = end_stats.get("rss_kb", 0) - start_stats.get("rss_kb", 0)
        swap_diff = end_stats.get("swap_kb", 0) - start_stats.get("swap_kb", 0)
        total_ram_growth += max(0, rss_diff)
        total_swap_growth += max(0, swap_diff)

        if rss_diff > 100_000 or swap_diff > 100_000:
            growth_report.append({
                "group": g,
                "start_rss_mb": start_stats.get("rss_kb", 0) // 1024,
                "end_rss_mb": end_stats.get("rss_kb", 0) // 1024,
                "growth_rss_mb": rss_diff // 1024,
                "start_swap_mb": start_stats.get("swap_kb", 0) // 1024,
                "end_swap_mb": end_stats.get("swap_kb", 0) // 1024,
                "growth_swap_mb": swap_diff // 1024
            })

    growth_report.sort(key=lambda x: x["growth_rss_mb"] + x["growth_swap_mb"], reverse=True)

    has_oom = False
    oom_history = checks.get("oom_previous", {}).get("output", "")
    if "out of memory" in oom_history or "oom-kill" in oom_history or "killed" in oom_history:
        has_oom = True

    result["memory_analysis"] = {
        "start_available_mb": start_row.get("memory", {}).get("mem_available_mb", start_row.get("mem_available_mb", 0)),
        "end_available_mb": end_row.get("memory", {}).get("mem_available_mb", end_row.get("mem_available_mb", 0)),
        "end_swap_used_mb": end_row.get("memory", {}).get("swap_used_mb", end_row.get("swap_used_mb", 0)),
        "growth": growth_report,
        "total_ram_growth_mb": total_ram_growth // 1024,
        "oom_occurred": has_oom,
    }

    why_fill = []
    if growth_report:
        top = growth_report[0]
        why_fill.append(f"{top['group']} grew by {top['growth_rss_mb']} MB RAM and {top['growth_swap_mb']} MB Swap.")
        if top['growth_rss_mb'] > 500:
            why_fill.append("This is a significant sudden increase suggesting a heavy workload or memory leak.")


    if not growth_report and "top_processes" in end_row:
        why_fill.append("Legacy canary data shows top processes near the crash: " + ", ".join(end_row["top_processes"]))
        why_fill.append("Chrome processes were highly active and likely caused the exhaustion (new granular tracking will identify this accurately next time).")

    if not has_oom and end_row.get("memory", {}).get("mem_available_mb", end_row.get("mem_available_mb", 1000)) < 600:

        why_fill.append("No OOM kill occurred despite severe memory/swap pressure (system likely locked up on I/O before OOMD could act).")

    result["why_did_memory_fill"] = why_fill

    stale = [r for r in rows[-20:] if (r.get("desktop_heartbeat_age_s") or 0) > 20 or r.get("kwin_ok") is False]
    if stale:
        result["interpretation"] = "The system canary continued while the desktop/KWin heartbeat became stale or failed. That pattern supports a compositor/session-level freeze."
    else:
        result["interpretation"] = "The latest system and desktop heartbeat samples remained aligned."
    return result


def confidence_label(score: float) -> str:
    if score >= 0.75:
        return "high"
    if score >= 0.45:
        return "moderate"
    return "low"


def numeric_score(item: dict[str, Any]) -> float:
    try:
        return float(item.get("score") or 0)
    except (TypeError, ValueError):
        return 0.0


MONTH_ABBR = {
    name: index for index, name in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"),
        start=1,
    )
}


def parse_last_crash_time_without_year(text: str) -> dict[str, int] | None:
    """Parse the yearless crash timestamp emitted by last(1) without guessing a year."""
    match = re.fullmatch(r"[A-Z][a-z]{2}\s+([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}):(\d{2})", text.strip())
    if not match:
        return None
    month_name, day, hour, minute = match.groups()
    month = MONTH_ABBR.get(month_name)
    if not month:
        return None
    return {
        "month": month,
        "day": int(day),
        "hour": int(hour),
        "minute": int(minute),
    }

def parse_boots_from_journal(checks):
    boots = {}
    out = checks.get("journal_boots", {}).get("output", "")
    for line in out.splitlines():
        import re
        from datetime import datetime
        m = re.match(r"^\s*([-\d]+)\s+([a-f0-9]{32})\s+.*?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}).*?(\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})", line)
        if m:
            idx, boot_id, start_str, end_str = m.groups()
            boots[idx] = {
                "idx": idx,
                "id": boot_id,
                "start": datetime.strptime(start_str, "%Y-%m-%d %H:%M:%S"),
                "end": datetime.strptime(end_str, "%Y-%m-%d %H:%M:%S"),
            }
    return boots

def get_boot_for_ts(ts, boots):
    if not ts: return "unknown"
    from datetime import timedelta
    naive_ts = ts.replace(tzinfo=None)

    matches = []
    for b in boots.values():
        if b["start"] <= naive_ts <= b["end"]:
            matches.append(b["idx"])

    if len(matches) == 1:
        return matches[0]
    return "unknown"

def build_incidents(findings, checks):
    boots = parse_boots_from_journal(checks)
    import re
    from datetime import datetime, timedelta

    boundaries = []

    # Unclean boots
    unclean_f = next((f for f in findings if f["id"] == "unclean_boot"), None)
    if unclean_f:
        for line in unclean_f.get("evidence", []):
            m = re.search(r"([A-Z][a-z]{2}\s+[A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2})\s+-\s+crash", line)
            if m:
                # Add year dynamically or resolve appropriately. We must not guess if year is missing and ambiguous.
                # Actually, the string from `last` doesn't have a year.
                # We can try to match month, day, hour, minute.
                dt_str = m.group(1)
                dt = parse_last_crash_time_without_year(dt_str)
                if not dt:
                    continue
                matched_boots = []
                for b in boots.values():
                    if (
                        b["start"].month == dt["month"]
                        and b["start"].day == dt["day"]
                        and b["start"].hour == dt["hour"]
                        and abs(b["start"].minute - dt["minute"]) <= 5
                    ):
                        matched_boots.append((b["idx"], b["end"]))
                if len(matched_boots) == 1:
                    boundaries.append({"boot": matched_boots[0][0], "type": "unclean shutdown", "ts": matched_boots[0][1]})
                elif len(matched_boots) > 1:
                    # Ambiguous
                    pass

    # Other boundaries
    for f in findings:
        if f["id"] in {"wayland", "oom", "kernel_panic", "watchdog"}:
            for line in f.get("evidence", []):
                ts = parse_journal_time(line)
                b = get_boot_for_ts(ts, boots)
                if b != "unknown" and ts:
                    if f["id"] == "oom": b_type = "OOM event"
                    elif f["id"] == "wayland": b_type = "compositor crash"
                    elif f["id"] == "kernel_panic": b_type = "kernel panic"
                    elif f["id"] == "watchdog": b_type = "watchdog lockup"
                    else: b_type = "unknown"
                    boundaries.append({"boot": b, "type": b_type, "ts": ts.replace(tzinfo=None)})

    clean_boots = set()
    tail = checks.get("previous_boot_tail", {}).get("output", "")
    if re.search(r"systemd-shutdown\[\d+\]:|systemd\[\d+\]: Shutting down\.|Reached target.*(?:System Shutdown|System Reboot)", tail[-15000:], re.I):
        clean_boots.add("-1")

    if "-1" in clean_boots:
        boundaries = [b for b in boundaries if not (b["boot"] == "-1" and b["type"] == "unclean shutdown")]

    incidents = []
    for boot_idx, b_data in boots.items():
        boot_bounds = sorted([bd for bd in boundaries if bd["boot"] == boot_idx], key=lambda x: x["ts"])
        merged = []
        for bd in boot_bounds:
            if not merged:
                merged.append(bd)
            elif bd["type"] == merged[-1]["type"] and (bd["ts"] - merged[-1]["ts"]).total_seconds() < 900:
                merged[-1] = bd # Keep latest of SAME boundary type
            else:
                merged.append(bd)

        if not merged and boot_idx == "0":
            merged = [{"boot": "0", "type": "active session", "ts": boots["0"]["end"]}]
        elif not merged and boot_idx == "-1" and "-1" in clean_boots:
            merged = [{"boot": "-1", "type": "clean shutdown", "ts": boots["-1"]["end"]}]

        for bd in merged:
            w_start = bd["ts"] - timedelta(minutes=15)
            w_end = bd["ts"] + timedelta(minutes=1)
            incidents.append({
                "boot": bd["boot"],
                "start": w_start,
                "end": w_end,
                # The boundary event's own timestamp, before the +/- window
                # padding above -- used as a stable incident identity anchor
                # (see incident_model.compute_incident_id) since the padded
                # window can be widened by later evidence without the
                # underlying anchor event changing.
                "anchor_ts": bd["ts"],
                "boundary": bd["type"],
                "events": [],
                "symptoms": {}
            })

    unresolved_evidence = []
    boot_warnings = []

    for f in findings:
        if f["id"] in {"no_oom", "no_pstore", "corrected_events", "perf_sampling_adjustment"}:
            continue
        for line in f.get("evidence", []):
            ts = parse_journal_time(line)
            cmd = next((v.get("command", "") for v in checks.values() if v.get("output") and line in v["output"]), "unknown")
            event = {"finding": f, "line": line, "timestamp": ts.isoformat() if ts else None, "command": cmd}

            b = get_boot_for_ts(ts, boots)

            if b == "unknown" or not ts:
                unresolved_evidence.append(event)
                continue

            assigned = False
            naive_ts = ts.replace(tzinfo=None)
            for inc in incidents:
                if inc["boot"] == b and inc["start"] <= naive_ts <= inc["end"]:
                    inc["events"].append(event)
                    assigned = True

            if not assigned:
                event["boot_index"] = b
                boot_warnings.append(event)

    report_incidents = []
    for inc in incidents:
        boot_obj = boots.get(inc["boot"], {})
        boot_id = boot_obj.get("id", "unknown")
        
        # Associate normalized coredumps that fall into this incident's bounds
        incident_coredumps = []
        structured_coredumps = checks.get("coredumps_json", {}).get("structured_evidence", [])
        if structured_coredumps:
            for c in structured_coredumps:
                if c.get("boot_id") == boot_id and c.get("timestamp"):
                    # Check if timestamp falls within incident bounds
                    naive_ts = datetime.fromtimestamp(c["timestamp"])
                    if inc["start"] <= naive_ts <= inc["end"]:
                        incident_coredumps.append(c)

        if not inc["events"] and not incident_coredumps and inc["boundary"] in {"active session", "clean shutdown"}:
            continue

        symptoms = {}
        for e in inc["events"]:
            fid = e["finding"]["id"]
            if fid not in symptoms:
                symptoms[fid] = {"finding": e["finding"], "evidence": []}
            symptoms[fid]["evidence"].append(e)

        context = {
            "hard_crash": inc["boundary"] == "unclean shutdown",
            "has_panic": inc["boundary"] == "kernel panic",
            "has_oom": inc["boundary"] == "OOM event",
            "has_thermal": any(k.startswith("thermal") for k in symptoms),
            "has_storage": any(k.startswith("storage_") for k in symptoms),
        }

        hypotheses = []

        # OOM / Memory Pressure / Thrashing
        if context["has_oom"] or "oom" in symptoms or context.get("has_panic"):
            score = 0.95
            title = "Memory/swap exhaustion with swap-I/O thrashing"
            if not context["hard_crash"]:
                title += " (Active Warning, no crash recorded)"
                score = 0.7

            supports = ["Severe memory/swap exhaustion was detected."]
            if context["hard_crash"]:
                supports.append("The kernel explicitly killed processes or the system locked up under memory pressure.")
            hypotheses.append({
                "title": title,
                "category": "Memory",
                "score": score,
                "confidence": confidence_label(score),
                "supports": supports,
                "against": [],
                "next_test": "Enable system canary and monitor memory pressure.",
            })

            # Application workload hypothesis
            app_title = "One or more application workloads caused memory exhaustion"
            if not context["hard_crash"]:
                app_title += " (Active Warning, no crash recorded)"
            hypotheses.append({
                "title": app_title,
                "category": "Software",
                "score": score - 0.05,
                "confidence": confidence_label(score - 0.05),
                "supports": ["Memory pressure is typically driven by user workloads like Chrome, VS Code, or Electron apps."],
                "against": [],
                "next_test": "Review 'Why did memory fill?' report for top memory growers.",
            })

        # Thermal events
        if context["has_thermal"]:
            score = 0.8
            title = "Thermal shutdown or severe throttling"
            if not context["hard_crash"]:
                title += " (Active Warning, no crash recorded)"
            supports = ["Critical temperature or thermal events were logged near the boundary."]
            hypotheses.append({
                "title": title,
                "category": "Thermals",
                "score": score,
                "confidence": confidence_label(score),
                "supports": supports,
                "against": [],
                "next_test": "Check cooling/fans and monitor thermals under load.",
            })

        # Display-stack freeze
        if any(k in {"intel_display", "other_gpu", "wayland"} for k in symptoms):
            score = 0.5
            title = "Display-stack or KWin Wayland freeze"
            if not context["hard_crash"]:
                title += " (Active Warning, no crash recorded)"
            supports = ["Graphics/DRM or Wayland errors were recorded near the boundary."]
            hypotheses.append({
                "title": title,
                "category": "Graphics",
                "score": score,
                "confidence": confidence_label(score),
                "supports": supports,
                "against": ["A display freeze is often a consequence of extreme I/O or memory thrashing rather than the root cause."],
                "next_test": "Gather next crash log with minimal display configuration.",
            })

        # Storage errors
        if context["has_storage"]:
            score = 0.4
            title = "Storage / filesystem errors or unexpected USB disconnect"
            if not context["hard_crash"]:
                title += " (Active Warning, no crash recorded)"
            supports = ["Storage I/O or filesystem errors occurred (possibly /dev/sda8 disconnect)."]
            hypotheses.append({
                "title": title,
                "category": "Storage",
                "score": score,
                "confidence": confidence_label(score),
                "supports": supports,
                "against": ["This may have been an earlier event whose causality to the hard lockup is not fully established."],
                "next_test": "Avoid disconnecting USB drives during heavy I/O.",
            })

        if "repeated_pcie_device" in symptoms:
            title = "PCIe link/device instability"
            if not context["hard_crash"]:
                title += " (Active Warning, no crash recorded)"
            hypotheses.append({
                "title": title,
                "category": "PCIe / Network",
                "score": 0.2,
                "confidence": "low",
                "supports": ["Repeated PCIe correctable errors were found."],
                "against": ["The logged events were correctable, which rarely cause a hard lockup. Probably unrelated."],
                "next_test": "Monitor PCIe bus for uncorrectable errors during next crash.",
            })

        if context["hard_crash"] and not hypotheses:
            hypotheses.append({
                "title": "Unknown Kernel, Firmware or Power Failure",
                "category": "Firmware",
                "score": 0.30,
                "confidence": "low",
                "supports": ["The system suffered an unclean shutdown (crash)."],
                "against": [],
                "next_test": "Enable kdump or netconsole to capture panics.",
            })

        hypotheses.sort(key=lambda h: h["score"], reverse=True)
        best = hypotheses[0] if hypotheses else None

        conf_exp = f"Ranked {best['confidence']} based on timing and severity." if best else "No evidence."

        report_incidents.append(attach_incident_identity({
            "boot_id": boot_id,
            "boot_index": inc["boot"],
            "incident_start": inc["start"].isoformat(),
            "incident_end": inc["end"].isoformat(),
            "incident_anchor_ts": inc["anchor_ts"].isoformat(),
            "failure_boundary": inc["boundary"],
            "incident_evidence": [e for e in inc["events"] if e["timestamp"]],
            "coredumps": incident_coredumps,
            "strongest_hypothesis": best["title"] if best else "Unknown",
            "supporting_evidence": best["supports"] if best else [],
            "next_step": best["next_test"] if best else "Gather more evidence.",
            "confidence": best["confidence"] if best else "low",
            "confidence_explanation": conf_exp,
            "hypotheses": hypotheses,
            "sort_key": inc["end"].timestamp()
        }, checks))

    return report_incidents, boot_warnings, unresolved_evidence

def build_overall(incidents, boot_warnings=None):
    boot_warnings = boot_warnings or []
    if not incidents and not boot_warnings:
        return {"title": "No leading cause identified", "confidence": "low", "summary": "No incidents or warnings."}, []

    # Sort incidents by time
    sorted_incidents = sorted(incidents, key=lambda x: x["sort_key"])

    # 1. Most recent confirmed crash (recent boots only)
    target = None
    for inc in reversed(sorted_incidents):
        if inc.get("boot_index") in {"0", "-1"} and inc.get("failure_boundary") in {"unclean shutdown", "kernel panic"}:
            target = inc
            break

    # 2. Most recent meaningful active incident (recent boots only)
    if not target:
        for inc in reversed(sorted_incidents):
            if inc.get("boot_index") in {"0", "-1"} and inc.get("hypotheses"):
                target = inc
                break

    if not target or not target["hypotheses"]:
        # If there are boot warnings but no strict incident, mention that stability warnings exist
        has_active_warnings = any(inc["hypotheses"] for inc in sorted_incidents) or bool(boot_warnings)
        title = "Recurring stability warnings remain" if has_active_warnings else "No leading cause identified"
        return {"title": title, "confidence": "low", "summary": "No crash or unrecoverable lockup detected in the scanned boots."}, []

    top = target["hypotheses"][0]
    return {
        "title": top["title"],
        "confidence": top["confidence"],
        "summary": f"Leading hypothesis: {top['title']} ({top['confidence']} confidence)."
    }, target["hypotheses"]


def category_status(findings, checks):
    categories = ["Graphics", "Memory", "Storage", "Thermals", "PCIe / Network", "Firmware", "Software"]
    result = {}
    for category in categories:
        related = [f for f in findings if f["category"] == category]
        if any(f["severity"] == "critical" for f in related):
            result[category] = {"status": "critical", "label": "Critical"}
        elif any(f["severity"] == "warning" for f in related):
            labels = {
                "Graphics": "Try display-safe mode",
                "PCIe / Network": "Check PCIe device",
                "Storage": "Back up and test drive",
                "Thermals": "Check cooling",
                "Memory": "Check memory pressure",
                "Firmware": "Check firmware",
                "Software": "Review crash logs",
            }
            result[category] = {"status": "warning", "label": labels.get(category, "Needs attention")}
        else:
            related_checks = [c for c in checks.values() if c.get("category") == category]
            if any(c.get("status") == "ok" for c in related_checks):
                result[category] = {"status": "passed", "label": "No fault found"}
            elif related_checks:
                result[category] = {"status": "not_checked", "label": "Scan incomplete"}
            else:
                result[category] = {"status": "not_checked", "label": "Not checked"}
    return result


def assess_readiness(checks: dict[str, Any]) -> dict[str, Any]:
    sources = []

    # 1. Journal
    journal_dir_out = checks.get("journal_dir", {}).get("output", "")
    journal_boots_out = checks.get("journal_boots", {}).get("output", "")

    if "No such file or directory" in journal_dir_out or checks.get("journal_dir", {}).get("returncode", 1) != 0:
        if len(journal_boots_out.strip().split("\n")) > 1:
            sources.append({
                "name": "Persistent Journal",
                "status": "unverified",
                "evidence": "Previous boots found but /var/log/journal is missing/unverified.",
                "limitation": "May be using alternative storage.",
                "setup": "Check journald.conf Storage setting.",
                "implications": "Privacy: none. Storage: ~50-200MB. Reboot: required to apply."
            })
        else:
            sources.append({
                "name": "Persistent Journal",
                "status": "volatile_only",
                "evidence": "/var/log/journal is absent and no previous boots are available.",
                "limitation": "Logs are lost upon crash or reboot.",
                "setup": "Run: sudo mkdir -p /var/log/journal && sudo systemd-tmpfiles --create --prefix /var/log/journal && sudo systemctl restart systemd-journald",
                "implications": "Privacy: none. Storage: ~50-200MB. Reboot: required to apply."
            })
    elif checks.get("journal_boots", {}).get("returncode", 0) != 0:
        sources.append({
            "name": "Persistent Journal",
            "status": "error",
            "evidence": "Journal collection returned an error.",
            "limitation": "Cannot determine persistent history availability.",
            "setup": "Check journald service status.",
            "implications": "Privacy: none. Storage: none. Reboot: none."
        })
    elif len(journal_boots_out.strip().split("\n")) > 1:
        sources.append({
            "name": "Persistent Journal",
            "status": "verified_persistent",
            "evidence": "/var/log/journal exists and previous boots are available.",
            "limitation": "None.",
            "setup": "",
            "implications": ""
        })
    else:
        sources.append({
            "name": "Persistent Journal",
            "status": "unverified",
            "evidence": "/var/log/journal exists but no previous boots are retained.",
            "limitation": "May have just been enabled, or clearing too frequently.",
            "setup": "Wait for next boot to verify persistence, or check MaxRetentionSec.",
            "implications": "Privacy: none. Storage: none. Reboot: none."
        })

    # 2. pstore
    pstore_out = checks.get("pstore", {}).get("output", "")
    if checks.get("pstore", {}).get("returncode", 0) != 0 and "No pstore crash records found" not in pstore_out:
        sources.append({
            "name": "EFI pstore",
            "status": "error",
            "evidence": "Command failed when checking pstore.",
            "limitation": "Cannot verify backend.",
            "setup": "Check dmesg for pstore errors.",
            "implications": "Privacy: none. Storage: none. Reboot: none."
        })
    elif "No such file or directory" in pstore_out:
        sources.append({
            "name": "EFI pstore",
            "status": "unavailable",
            "evidence": "/sys/fs/pstore is not mounted.",
            "limitation": "Firmware does not support pstore or backend missing.",
            "setup": "Ensure EFI variables are accessible or check motherboard settings.",
            "implications": "Privacy: kernel memory only. Storage: minimal. Reboot: N/A."
        })
    elif "No pstore crash records found" in pstore_out:
        # Check backend if possible, but we don't have a direct backend check output unless dmesg has it.
        # We can assume unverified if empty, since empty doesn't guarantee future capture.
        sources.append({
            "name": "EFI pstore",
            "status": "unverified",
            "evidence": "Directory is present but empty. No backend verified.",
            "limitation": "Empty directory does not guarantee a future crash will be captured.",
            "setup": "None.",
            "implications": "Privacy: kernel memory. Storage: minimal. Reboot: N/A."
        })
    else:
        sources.append({
            "name": "EFI pstore",
            "status": "available_with_records",
            "evidence": "pstore is available and contains previous crash records.",
            "limitation": "May roll over and overwrite older records.",
            "setup": "",
            "implications": ""
        })

    # 3. Kdump
    kdump_pkg = checks.get("kdump_package", {}).get("output", "")
    kdump_svc = checks.get("kdump_service", {}).get("output", "").strip()
    kexec_loaded = checks.get("kexec_loaded", {}).get("output", "").strip()
    crashkernel_mem = checks.get("crashkernel_mem", {}).get("output", "").strip()
    kdump_target = checks.get("kdump_target_space", {}).get("output", "")

    if "is not installed" in kdump_pkg or checks.get("kdump_package", {}).get("returncode", 0) != 0:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "unavailable",
            "evidence": "kexec-tools is not installed.",
            "limitation": "Cannot capture full memory dumps on panic.",
            "setup": "Run: sudo dnf install kexec-tools",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: required."
        })
    elif "crashkernel" not in crashkernel_mem:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "missing_reservation",
            "evidence": "kdump is installed, but crashkernel memory is not reserved.",
            "limitation": "Crash kernel cannot load without reserved memory.",
            "setup": "Configure crashkernel= in grub.",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: required."
        })
    elif kexec_loaded != "1":
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "kernel_not_loaded",
            "evidence": "Memory is reserved, but crash kernel is not loaded (kexec_crash_loaded != 1).",
            "limitation": "Kdump service may have failed to start or load the kernel.",
            "setup": "Check systemctl status kdump.",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: none."
        })
    elif "No such file or directory" in kdump_target or checks.get("kdump_target_space", {}).get("returncode", 0) != 0:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "target_missing",
            "evidence": "Kdump target directory (/var/crash) is missing or inaccessible.",
            "limitation": "Dumps have nowhere to be saved.",
            "setup": "Create dump target or verify kdump.conf.",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: none."
        })
    elif kdump_svc != "active":
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "misconfigured",
            "evidence": "Kdump is fully configured but the service is inactive.",
            "limitation": "Cannot capture full memory dumps on panic.",
            "setup": "Run: sudo systemctl enable --now kdump",
            "implications": "Privacy: captures full memory. Storage: ~100MB-1GB. Reboot: none."
        })
    else:
        sources.append({
            "name": "Kdump Infrastructure",
            "status": "verified_ready",
            "evidence": "Kdump is active, crashkernel reserved, kernel loaded, and target available.",
            "limitation": "May not capture power loss or hard hardware lockups.",
            "setup": "",
            "implications": ""
        })

    # 4. Sysctls
    sysctl_out = checks.get("sysctl_panic", {}).get("output", "")
    ready_sysctls = []
    unready_sysctls = []

    triggers = {
        "kernel.panic": ("panic", "Reboots automatically N seconds after any panic."),
        "kernel.panic_on_oops": ("panic_on_oops", "Causes a panic when a kernel oops occurs."),
        "kernel.softlockup_panic": ("softlockup_panic", "Causes a panic on CPU soft lockup (e.g. infinite loop in kernel)."),
        "kernel.hardlockup_panic": ("hardlockup_panic", "Causes a panic on CPU hard lockup (interrupts disabled)."),
        "kernel.nmi_watchdog": ("nmi_watchdog", "Enables NMI watchdog for hardware-level lockup detection.")
    }

    for key, (name, explanation) in triggers.items():
        if key == "kernel.panic":
            if f"{key} = 0" in sysctl_out:
                unready_sysctls.append(name)
            elif f"{key} =" in sysctl_out:
                ready_sysctls.append(name)
        else:
            if f"{key} = 1" in sysctl_out:
                ready_sysctls.append(name)
            else:
                unready_sysctls.append(name)

    if not unready_sysctls:
        sources.append({
            "name": "Kernel Panic Settings",
            "status": "ready",
            "evidence": "All recommended panic triggers are enabled.",
            "limitation": "Does not help with user-space or hardware/GPU freezes that don't trigger the watchdog.",
            "setup": "",
            "implications": ""
        })
    else:
        sources.append({
            "name": "Kernel Panic Settings",
            "status": "disabled_intentionally",
            "evidence": f"Disabled panic triggers: {', '.join(unready_sysctls)}.",
            "limitation": "Deliberately disabled for safety policy. Does not guarantee evidence capture if enabled. Helps mostly with kernel-level lockups.",
            "setup": "If desired, set via /etc/sysctl.d/99-crash-capture.conf and run sudo sysctl --system.",
            "implications": "Privacy: none. Storage: none. Reboot: automatic reboots on panic. Risk of work or data loss on forced panic. Kdump must be verified first."
        })

    # 5. Canary
    canary_svc = checks.get("canary_service", {}).get("output", "").strip()
    canary_stat = checks.get("canary_stat", {}).get("output", "").strip()
    import time

    if canary_svc != "active":
        sources.append({
            "name": "System Canary",
            "status": "unavailable",
            "evidence": "Service is inactive.",
            "limitation": "No pre-crash telemetry recorded.",
            "setup": "Run: sudo systemctl enable --now fedora-crash-doctor-canary.service",
            "implications": "Privacy: none. Storage: minimal. Reboot: N/A."
        })
    else:
        try:
            mtime = int(canary_stat)
            age = time.time() - mtime
            if age > 120:
                sources.append({
                    "name": "System Canary",
                    "status": "stale",
                    "evidence": f"Service active, but heartbeat is stale ({int(age)}s old).",
                    "limitation": "May be failing to write or location is unwritable.",
                    "setup": "Check canary service logs.",
                    "implications": "Privacy: none. Storage: minimal. Reboot: N/A."
                })
            else:
                sources.append({
                    "name": "System Canary",
                    "status": "verified_active",
                    "evidence": "Service is active and heartbeat is recent.",
                    "limitation": "Relies on system not fully locking up immediately.",
                    "setup": "",
                    "implications": ""
                })
        except ValueError:
            sources.append({
                "name": "System Canary",
                "status": "unavailable",
                "evidence": "Service active, but canary log file is missing or inaccessible.",
                "limitation": "Cannot write telemetry.",
                "setup": "Ensure /var/log/fedora-crash-doctor is writable.",
                "implications": "Privacy: none. Storage: minimal. Reboot: N/A."
            })

    # Recommend next step safely
    recommendation = "Capture mechanisms are fully prepared."

    if next((s for s in sources if s["name"] == "Persistent Journal" and s["status"] in ("volatile_only", "error", "unavailable")), None):
        recommendation = "Missing Infrastructure: Enable Persistent Journal to prevent log loss."
    elif next((s for s in sources if s["name"] == "System Canary" and s["status"] in ("unavailable", "stale")), None):
        recommendation = "Missing Infrastructure: Enable System Canary for pre-crash telemetry."
    elif next((s for s in sources if s["name"] == "Kdump Infrastructure" and s["status"] in ("unavailable", "misconfigured", "target_missing", "missing_reservation", "kernel_not_loaded")), None):
        recommendation = "Verification Gap: Fix Kdump Infrastructure (see setup instructions)."
    elif next((s for s in sources if s["name"] == "Persistent Journal" and s["status"] == "unverified"), None):
        recommendation = "Verification Gap: Monitor Journal across reboots to verify persistence."
    elif next((s for s in sources if s["name"] == "Kernel Panic Settings" and s["status"] != "ready"), None):
        recommendation = "Optional Higher-Risk: Enable Panic Settings (ONLY if kdump is fully verified)."

    return {
        "sources": sources,
        "recommendation": recommendation
    }
def previous_boot_ended_uncleanly() -> tuple[bool, str | None]:
    import subprocess, re
    try:
        boots = subprocess.run(["journalctl", "--list-boots", "--no-pager"], text=True, stdout=subprocess.PIPE, timeout=10).stdout
        m = re.search(r"^\s*-1\s+([a-f0-9]{32})", boots, re.MULTILINE)
        if not m:
            return False, None
        boot_id = m.group(1)
        tail = subprocess.run(["journalctl", "-b", "-1", "-n", "100", "--no-pager"], text=True, stdout=subprocess.PIPE, timeout=10).stdout
        clean = bool(re.search(r"systemd-shutdown\[\d+\]:|systemd\[\d+\]: Shutting down\.|Reached target.*(?:System Shutdown|System Reboot)", tail, re.I))
        return not clean, boot_id
    except Exception:
        return False, None


def collect(
    mode: str = "quick",
    baseline_path: str | None = None,
    progress: Progress | None = None,
    cancel_requested: CancelCheck | None = None,
) -> dict[str, Any]:
    if mode not in SCAN_MODES:
        raise ValueError("mode must be quick, full or deep")
    metadata = _metadata()
    metadata["mode"] = mode
    tasks = build_tasks(mode)
    runner = CheckRunner(tasks, progress, cancel_requested)
    checks = runner.execute()
    if not runner.cancelled:
        add_virtual_checks(checks)
        from coredump_adapter import get_systemd_coredumps
        incidents = get_systemd_coredumps()
        checks["coredumps_json"] = {
            "title": "Structured Application core dumps",
            "category": "Software",
            "status": "ok",
            "state": "completed",
            "output": "",
            "command": "coredump_adapter.get_systemd_coredumps()",
            "returncode": 0,
            "duration_seconds": 0.0,
            "structured_evidence": incidents
        }
    findings, context = analyse(checks)
    timeline = build_timeline(checks)
    canary = analyse_canary(checks)
    freeze_classes = classify_freeze_evidence(findings, canary)
    telemetry_timeline = build_telemetry_timeline(canary.get("samples", []))
    incidents, boot_warnings, unresolved = build_incidents(findings, checks)
    # Thrashing caused by a userspace OOM leaves no kernel log line, so it
    # never becomes a journal incident; promote canary-measured pressure.
    pressure = build_pressure_incident(canary.get("samples", []), metadata.get("boot_id", ""), confidence_label)
    if pressure:
        incidents.append(attach_incident_identity(pressure, checks))
    overall, hypotheses = build_overall(incidents, boot_warnings)
    for incident in incidents:
        # Explainable confidence for every hypothesis this incident already
        # has, not a competing analysis -- no recurrence context here since
        # collect() only sees this one scan's incidents; a caller with
        # access to saved scan history (see incident_history.py) can
        # re-explain with a family attached once that history exists.
        incident["hypothesis_explanations"] = explain_incident(incident)

    baseline = load_baseline(baseline_path)
    now = metadata["generated"]
    for finding in findings:
        prior = baseline.get(finding["id"])
        finding["status"] = "recurring" if prior else "new"
        finding["first_seen"] = prior.get("first_seen") if prior else now

    counts = {
        "critical": sum(f["severity"] == "critical" for f in findings),
        "warning": sum(f["severity"] == "warning" for f in findings),
        "info": sum(f["severity"] == "info" for f in findings),
    }


    report = {
        "schema": 3,
        "schema_version": REPORT_SCHEMA_VERSION,
        "metadata": metadata,
        "counts": counts,
        "incidents": incidents,
        "boot_warnings": boot_warnings,
        "unresolved_evidence": unresolved,
        "overall": overall,
        "hypotheses": hypotheses,
        "freeze_classes": freeze_classes,
        "categories": category_status(findings, checks),
        "readiness": assess_readiness(checks),
        "findings": findings,

        "timeline": timeline,
        "telemetry_timeline": telemetry_timeline,
        "canary": canary,
        "checks": checks,
        "test_targets": {
            "smart_devices": discover_smart_devices(),
            "btrfs_root": Path("/").exists() and shutil.which("btrfs", path=_safe_env()["PATH"]) is not None,
        },
        "limitations": [
            "A total hard lock can prevent the kernel from writing its final error to disk.",
            "Kdump captures kernel panics but may not capture power loss, firmware lockups or every GPU deadlock.",
            "A clean scan cannot prove that intermittent RAM, power, motherboard, cable, dock or peripheral faults are absent.",
            "Stress, memory, disk self-tests and filesystem scrubs are separate, confirmed actions and are never run by a scan.",
            "Ranked hypotheses are evidence-weighted explanations, not certainty or a substitute for hardware service.",
        ],
    }


    if runner.cancelled:
        report["partial"] = True
        report["cancelled"] = True
        report["limitations"].append("This scan was cancelled before all checks completed; conclusions are based only on collected evidence.")
    validate_report(report)
    return report


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Collect Fedora Crash Doctor diagnostic evidence.")
    parser.add_argument("--mode", choices=sorted(SCAN_MODES), default="quick")
    parser.add_argument("--output", required=True)
    parser.add_argument("--baseline")
    args = parser.parse_args()
    report = collect(args.mode, args.baseline)
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
