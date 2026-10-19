"""Evidence-driven, confirmation-gated stability actions.

The playbook is deliberately declarative. Crash Doctor may display or export
these actions, but it never executes them automatically.
"""
from __future__ import annotations

from typing import Any


def _action(action_id: str, title: str, rationale: str, commands: list[str], risk: str = "low", reboot: bool = False) -> dict[str, Any]:
    return {
        "id": action_id,
        "title": title,
        "rationale": rationale,
        "commands": commands,
        "risk": risk,
        "requires_confirmation": True,
        "reboot_required": reboot,
        "automatic_action_taken": False,
    }


def build_playbook(findings: list[dict[str, Any]], checks: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    ids = {str(item.get("id")) for item in findings}
    actions: list[dict[str, Any]] = []
    if {"intel_display", "other_gpu", "wayland"} & ids:
        actions.extend([
            _action(
                "graphics_one_monitor_ab",
                "Run a one-monitor Wayland A/B test",
                "Separates i915/KWin multi-monitor timing problems from general desktop instability.",
                ["Disconnect all but one monitor", "Use the system normally and record whether the freeze recurs", "Reconnect monitors one at a time"],
            ),
            _action(
                "graphics_disable_app_acceleration",
                "Disable Chrome/Electron GPU acceleration for the test",
                "Removes GPU client pressure while preserving the current kernel parameters.",
                ["Use the browser/application's documented disable-GPU setting", "Do not add global i915 flags for this test"],
            ),
            _action(
                "graphics_alternate_kernel",
                "Test the newest installed kernel",
                "The active kernel may contain a graphics regression even when the hardware is healthy.",
                ["Reboot", "Select the newest installed kernel in GRUB Advanced options", "Run Quick scan after login"],
                reboot=True,
            ),
        ])
    if {"node_heap_crash", "coredump_storm", "oom"} & ids:
        actions.append(_action(
            "memory_attribute_workload",
            "Attribute and contain the memory-growing workload",
            "A single application can exhaust the desktop before systemd-oomd acts; identify the project and restart only that workload.",
            ["Review canary top_rss/cgroup/oom_score", "Save work", "Stop or restart the named application", "Do not kill unrelated desktop processes"],
            risk="moderate",
        ))
    if {"node_heap_crash", "coredump_storm"} & ids:
        actions.append(_action(
            "coredump_limits",
            "Bound coredump storage and processing",
            "Large cores can consume enough RAM and I/O to worsen the incident while they are being processed.",
            ["Review systemd-coredump ProcessSizeMax, ExternalSizeMax and JournalSizeMax", "Apply a documented drop-in only after review", "Keep Crash Doctor's metadata and canary evidence"],
            risk="moderate",
        ))
    if ids & {"intel_display", "oom", "node_heap_crash", "coredump_storm", "pcie"}:
        actions.append(_action(
            "update_graphics_kernel",
            "Update stable Fedora kernel and graphics packages",
            "A newer kernel/Mesa/Plasma stack is a reversible preventative step; activation requires reboot.",
            ["sudo dnf upgrade --refresh", "Reboot when convenient", "Verify uname -r and rerun Quick scan"],
            reboot=True,
        ))
    actions.append(_action(
        "silent_background_mode",
        "Keep evidence collection silent",
        "Suppresses desktop notification popups while retaining canary and report files.",
        ["Create ~/.config/fedora-crash-doctor/silent", "Leave the canary and desktop heartbeat enabled"],
    ))
    return actions
