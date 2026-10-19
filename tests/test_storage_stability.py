"""Storage-side freeze causes: QLC fill level, desktop in disk swap, I/O culprit."""
from __future__ import annotations

import time
from pathlib import Path
from unittest.mock import patch

import canary
import collector
import stability_playbook
import storage_stability as ss

GIB = 1024**3


def _sample(ts="2026-10-19T15:58:00+11:00", io_full=0.0, io_top=None, top_swap=None):
    row = {"ts": ts, "psi_io": {"full_avg10": io_full}}
    if io_top is not None:
        row["io_top"] = io_top
    if top_swap is not None:
        row["processes"] = {"top_swap": top_swap}
    return row


class TestQlcFill:
    def test_known_qlc_models_are_recognised_and_others_are_not(self):
        for model in ("INTEL SSDPEKNW512G8", "Samsung SSD 870 QVO 1TB", "CT1000P1SSD8", "Sabrent Rocket Q"):
            assert ss.is_qlc_model(model), model
        for model in ("Samsung SSD 980 PRO 1TB", "WDC WDS100T2B0C", "", "INTEL SSDPEKKW256G8"):
            assert not ss.is_qlc_model(model), model

    def test_warns_only_for_qlc_above_80_percent(self):
        assert ss.qlc_fill_finding("INTEL SSDPEKNW512G8", 475 * GIB, 402 * GIB)["id"] == "storage_qlc_nearly_full"
        assert ss.qlc_fill_finding("INTEL SSDPEKNW512G8", 475 * GIB, 300 * GIB) is None
        assert ss.qlc_fill_finding("Samsung SSD 980 PRO 1TB", 475 * GIB, 470 * GIB) is None

    def test_finding_says_it_is_not_a_failing_drive(self):
        finding = ss.qlc_fill_finding("INTEL SSDPEKNW512G8", 475 * GIB, 402 * GIB)
        assert "not a failing drive" in finding["explanation"]
        assert any("85% used" in line for line in finding["evidence"])


class TestRootDisk:
    def test_uses_mount_source_not_btrfs_anonymous_device(self, tmp_path: Path):
        disk = tmp_path / "devices" / "nvme0n1"
        part = disk / "nvme0n1p3"
        part.mkdir(parents=True)
        (part / "partition").write_text("3")
        (disk / "device").mkdir()
        (disk / "device" / "model").write_text("INTEL SSDPEKNW512G8\n")
        (tmp_path / "class" / "block").mkdir(parents=True)
        (tmp_path / "class" / "block" / "nvme0n1p3").symlink_to(part)
        mountinfo = "62 1 0:35 /root / rw,relatime shared:1 - btrfs /dev/nvme0n1p3 rw,compress=zstd:1\n"
        assert ss.root_disk(mountinfo, sys_root=str(tmp_path)) == {"disk": "nvme0n1", "model": "INTEL SSDPEKNW512G8"}

    def test_non_device_root_returns_none(self):
        assert ss.root_disk("1 1 0:1 / / rw - overlay overlay rw\n") is None


class TestDesktopSwap:
    SWAPS = "Filename Type Size Used Priority\n/swap/swapfile file 16777212 341504 10\n/dev/zram0 partition 8388604 3200000 100\n"

    def test_only_disk_backed_swap_counts(self):
        assert ss.disk_swap_in_use(self.SWAPS) == [{"device": "/swap/swapfile", "used_mb": 333}]
        assert ss.disk_swap_in_use("Filename Type Size Used Priority\n/dev/zram0 partition 8388604 3200000 100\n") == []

    def test_warns_when_plasma_is_largely_swapped_and_disk_swap_is_used(self):
        top_swap = [
            {"name": "plasmashell", "swap_kb": 434_032, "rss_kb": 340_688},
            {"name": "kwin_wayland", "swap_kb": 49_284, "rss_kb": 163_084},
            {"name": "chrome", "swap_kb": 900_000, "rss_kb": 600_000},
        ]
        finding = ss.desktop_swap_finding([_sample(top_swap=top_swap)], ss.disk_swap_in_use(self.SWAPS))
        assert finding["id"] == "storage_desktop_in_disk_swap"
        assert finding["category"] == "Memory"
        assert any(line.startswith("plasmashell: 423 MB swapped") for line in finding["evidence"])
        assert not any("chrome" in line for line in finding["evidence"])

    def test_no_warning_when_only_zram_or_desktop_barely_swapped(self):
        heavy = [_sample(top_swap=[{"name": "plasmashell", "swap_kb": 434_032, "rss_kb": 1}])]
        assert ss.desktop_swap_finding(heavy, []) is None
        light = [_sample(top_swap=[{"name": "plasmashell", "swap_kb": 20_000, "rss_kb": 300_000}])]
        assert ss.desktop_swap_finding(light, ss.disk_swap_in_use(self.SWAPS)) is None


class TestIoCulprit:
    def test_names_the_heaviest_process_during_stalls(self):
        samples = [
            _sample(io_full=3, io_top=[{"name": "quiet", "unit": "a.service", "read_mb_s": 99, "write_mb_s": 99}]),
            _sample(ts="15:58", io_full=23.6, io_top=[
                {"name": "7z", "unit": "app-org.kde.konsole-3141028.scope", "read_mb_s": 54.0, "write_mb_s": 22.4},
                {"name": "chrome", "unit": "app-com.google.Chrome-43868.scope", "read_mb_s": 0.6, "write_mb_s": 0.0},
            ]),
        ]
        finding = ss.io_culprit_finding(samples)
        assert finding["title"] == "Heavy disk I/O from 7z coincided with I/O stalls"
        assert "app-org.kde.konsole-3141028.scope" in finding["evidence"][0]
        assert not any("quiet" in line for line in finding["evidence"])  # below the stall threshold

    def test_no_finding_without_attribution_data(self):
        assert ss.io_culprit_finding([_sample(io_full=40)]) is None
        assert ss.io_culprit_finding([_sample(io_full=40, io_top="bad"), {"psi_io": None}]) is None


class TestCanaryIoTracker:
    def test_first_update_primes_then_reports_rates_with_unit(self):
        procs = {"101": ("7z", "0::/user.slice/app.slice/app-org.kde.konsole-1.scope/tab(2).scope\n")}
        counters = {"101": [0, 0]}

        def fake_read(path: str, default: str = "") -> str:
            pid = path.split("/")[2]
            if path.endswith("/io"):
                r, w = counters[pid]
                return f"rchar: 1\nread_bytes: {r}\nwrite_bytes: {w}\n"
            if path.endswith("/stat"):
                return f"{pid} ({procs[pid][0]}) S " + " ".join(["0"] * 16) + " 4242 0"
            if path.endswith("/cgroup"):
                return procs[pid][1]
            if path.endswith("/cmdline"):
                return "7z\0x\0archive.zip"
            return default

        clock = iter([100.0, 102.0])
        with patch("canary.os.listdir", return_value=["101", "self"]), \
             patch("canary.read_text", side_effect=fake_read), \
             patch("canary.time.monotonic", side_effect=lambda: next(clock)):
            tracker = canary.IoTracker()
            assert tracker.update() == []
            counters["101"] = [100 * 1048576, 40 * 1048576]
            top = tracker.update()
        assert top == [{
            "pid": 101, "name": "7z", "cmd": "7z x archive.zip",
            "read_mb_s": 50.0, "write_mb_s": 20.0, "unit": "app-org.kde.konsole-1.scope",
        }]

    def test_unit_from_cgroup(self):
        assert canary._unit_from_cgroup("0::/user.slice/user-1002.slice/user@1002.service/app.slice/app-com.google.Chrome-43868.scope\n") == "app-com.google.Chrome-43868.scope"
        assert canary._unit_from_cgroup("0::/\n") == ""
        # Konsole's tab(N).scope is a sub-cgroup, not a unit set-property can use.
        assert canary._unit_from_cgroup("0::/user.slice/user-1002.slice/user@1002.service/app.slice/app-org.kde.konsole-3141028.scope/tab(3141194).scope\n") == "app-org.kde.konsole-3141028.scope"
        assert canary._unit_from_cgroup("0::/system.slice/fedora-crash-doctor-canary.service\n") == "fedora-crash-doctor-canary.service"

    def test_live_tracker_runs_quickly(self):
        tracker = canary.IoTracker()
        start = time.monotonic()
        tracker.update()
        tracker.update()
        assert time.monotonic() - start < 5


class TestIntegration:
    def test_storage_performance_warnings_get_a_non_failure_label(self):
        findings = [ss.qlc_fill_finding("INTEL SSDPEKNW512G8", 475 * GIB, 402 * GIB)]
        assert collector.category_status(findings, {})["Storage"]["label"] == "Free space / reduce disk load"
        drive_fault = findings + [{"id": "smart_failure", "severity": "warning", "category": "Storage"}]
        assert collector.category_status(drive_fault, {})["Storage"]["label"] == "Back up and test drive"

    def test_playbook_offers_free_space_and_gentle_heavy_jobs(self):
        actions = stability_playbook.build_playbook([{"id": "storage_qlc_nearly_full"}, {"id": "storage_desktop_in_disk_swap"}])
        ids = [a["id"] for a in actions]
        assert {"storage_free_space", "storage_run_heavy_jobs_gently", "storage_refresh_swapped_desktop"} <= set(ids)
        assert all(a["requires_confirmation"] and not a["automatic_action_taken"] for a in actions)

    def test_canary_unit_exposes_run_user_read_only_but_keeps_home_hidden(self):
        unit = (Path(__file__).resolve().parent.parent / "systemd" / "fedora-crash-doctor-canary.service").read_text()
        assert "ProtectHome=tmpfs" in unit
        assert "BindReadOnlyPaths=-/run/user" in unit
        assert "ProtectHome=yes" not in unit.replace("# ", "\n").split("ProtectHome=tmpfs")[1]
