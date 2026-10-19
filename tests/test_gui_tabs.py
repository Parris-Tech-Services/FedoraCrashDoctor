"""Offscreen GUI tests for the Stability Guard, Memory / OOM and System
History tabs: missing or malformed health data, and repeated refreshes."""
from __future__ import annotations

import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from PySide6.QtWidgets import QApplication

import fedora_crash_doctor

OOM_LINE = (
    "2026-08-27T15:51:41+1000 AVANCE-WS7 systemd-oomd[709]: Killed "
    "/user.slice/user-1002.slice/user@1002.service/app.slice/app-org.chromium.Chromium-3905462.scope "
    "due to memory used (22240563200) / total (24681861120) and swap used (8589836288) / "
    "total (8589930496) being more than 90.00%"
)


def _lines(*objs) -> str:
    return "".join((o if isinstance(o, str) else json.dumps(o)) + "\n" for o in objs)


class GuiTabTestCase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.app = QApplication.instance() or QApplication([])

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.log = self.tmp / "canary.log"
        log_patch = patch.object(fedora_crash_doctor, "CANARY_LOG_PATH", self.log)
        log_patch.start()
        self.addCleanup(log_patch.stop)
        with patch.object(fedora_crash_doctor.MainWindow, "load_pending_autoscan"), \
             patch.object(fedora_crash_doctor.MainWindow, "refresh_trends"), \
             patch("subprocess.run", side_effect=FileNotFoundError("not on this host")):
            # Builds every tab, including the initial Stability Guard and
            # Memory / OOM refreshes, with no host tools and no canary log.
            self.win = fedora_crash_doctor.MainWindow()
        self.win.refresh_trends = lambda: None
        self.addCleanup(self.win.close)

    def tab_titles(self) -> list[str]:
        return [self.win.tabs.tabText(i) for i in range(self.win.tabs.count())]


class StabilityGuardTabTests(GuiTabTestCase):
    def refresh(self) -> str:
        with patch("subprocess.run", side_effect=FileNotFoundError("systemctl")):
            self.win.refresh_stability_guard()
        return self.win.stability_guard_detail.toPlainText()

    def test_tab_is_built_without_any_health_data(self):
        self.assertIn("Stability Guard", self.tab_titles())
        text = self.win.stability_guard_detail.toPlainText()
        self.assertIn("Canary: Inactive", text)
        self.assertIn("Current memory pressure: Unknown", text)
        self.assertIn("Number of warnings: 0", text)

    def test_malformed_lines_never_break_the_tab(self):
        cases = {
            "non-object last line": _lines({"psi_mem": {"some_avg10": 1}}, "[1, 2]"),
            "string early_warning": _lines({"early_warning": "warning"}),
            "wrong-typed blocks": _lines({"chrome": [1], "memory": "x", "psi_mem": None, "psi_io": {"full_avg10": "bad"}}),
            "garbage and truncation": "not json\n{\"psi_mem\": {\"some_av",
            "null offenders, numeric stamps": _lines(
                {"early_warning": {"state": "warning", "timestamp": 5, "title": "t", "likely_offenders": None}},
                {"early_warning": {"state": "ok", "title": "System recovered", "timestamp": 9}},
            ),
        }
        for name, content in cases.items():
            with self.subTest(name):
                self.log.write_text(content)
                text = self.refresh()
                self.assertIn("Current protection", text)
                self.assertIn("History", text)

    def test_non_object_line_does_not_hide_the_last_good_sample(self):
        self.log.write_text(_lines({"psi_mem": {"some_avg10": 12.34}, "memory": {"swap_used_mb": 7, "swap_total_mb": 8}}, "[]"))
        text = self.refresh()
        self.assertIn("Current memory pressure: 12.3%", text)
        self.assertIn("Swap: 7 / 8 MB", text)

    def test_warning_and_recovery_are_counted_and_reported(self):
        self.log.write_text(_lines(
            {"early_warning": {"state": "warning", "timestamp": "2026-10-19T10:00:00", "title": "Memory pressure", "likely_offenders": ["chrome", 3]}},
            {"early_warning": {"state": "critical", "timestamp": "2026-10-19T10:01:00", "title": "Swap exhausted", "likely_offenders": ["chrome"]}},
            {"early_warning": {"state": "ok", "timestamp": "2026-10-19T10:05:00", "title": "System recovered"}},
        ))
        text = self.refresh()
        self.assertIn("Number of warnings: 1", text)
        self.assertIn("Number of critical events: 1", text)
        self.assertIn("Reason: Swap exhausted", text)
        self.assertIn("Recovered: Yes", text)
        self.assertIn("Latest recovery: 2026-10-19T10:05:00", text)

    def test_log_values_are_escaped_not_rendered_as_html(self):
        self.log.write_text(_lines({"early_warning": {"state": "critical", "timestamp": "t", "title": "<b>x</b>", "likely_offenders": ["<i>app</i>"]}}))
        text = self.refresh()
        self.assertIn("Reason: <b>x</b>", text)
        self.assertIn("Largest workload: <i>app</i>", text)

    def test_null_kwin_latency_is_unknown_not_none(self):
        self.log.write_text(_lines({"kwin_ping_ms": None}))
        self.assertIn("KWin latency: Unknown ms", self.refresh())

    def test_repeated_refreshes_are_stable(self):
        self.log.write_text(_lines({"early_warning": {"state": "warning", "timestamp": "t1", "title": "w"}}))
        first = self.refresh()
        for _ in range(5):
            self.assertEqual(self.refresh(), first)
        self.log.unlink()
        self.assertIn("Number of warnings: 0", self.refresh())


class MemoryOomTabTests(GuiTabTestCase):
    def fake_run(self, outputs):
        def run(cmd, *args, **kwargs):
            out = outputs.get(cmd[0], "")
            if isinstance(out, BaseException):
                raise out
            return subprocess.CompletedProcess(cmd, 0, stdout=out)
        return run

    def test_tab_is_built_without_host_tools(self):
        self.assertIn("Memory / OOM", self.tab_titles())
        self.assertIn("No systemd-oomd kills this boot.", self.win.memory_oom_detail.toPlainText())

    def test_tool_timeouts_and_missing_tools_do_not_break_the_tab(self):
        for failure in (FileNotFoundError("free"), subprocess.TimeoutExpired("free", 2), PermissionError("oomctl")):
            with self.subTest(type(failure).__name__), patch("subprocess.run", side_effect=failure):
                self.win.refresh_memory_oom()
                self.assertIn("Memory Pressure", self.win.memory_oom_detail.toPlainText())

    def test_oom_kill_is_reported_and_repeated_refreshes_do_not_accumulate(self):
        run = self.fake_run({"journalctl": OOM_LINE, "swapon": "/swap/swapfile file 16G 0B 10"})
        with patch("subprocess.run", side_effect=run):
            for _ in range(4):
                self.win.refresh_memory_oom()
        text = self.win.memory_oom_detail.toPlainText()
        self.assertIn("OOM Kills (This Boot: 1)", text)
        self.assertEqual(text.count("Killed "), 1)

    def test_command_output_starts_on_its_own_line(self):
        with patch("subprocess.run", side_effect=self.fake_run({"free": "total used"})):
            self.win.refresh_memory_oom()
        text = self.win.memory_oom_detail.toPlainText()
        self.assertNotIn("\\n", text)
        self.assertIn("RAM (free -h):\ntotal used", text)

    def expand_button(self):
        layout = self.win.memory_oom_detail.parent().layout()
        return layout.itemAt(2).layout().itemAt(2).widget()

    def test_expand_btrfs_not_offered_when_size_is_unreadable(self):
        # What an unprivileged `btrfs filesystem show --raw /` prints on Fedora.
        show = ("Label: 'fedora'  uuid: 5c3c5ad7\n\tTotal devices 1 FS bytes used 382586445824\n"
                "\tdevid    1 size 0 used 0 path /dev/nvme0n1p3 MISSING\n")
        with patch("subprocess.run", side_effect=self.fake_run({"btrfs": show, "lsblk": "509332495872"})):
            self.win.refresh_memory_oom()
        self.assertTrue(self.expand_button().isHidden())

    def test_expand_btrfs_offered_only_when_device_is_genuinely_larger(self):
        show = "\tdevid    1 size {} used 1 path /dev/nvme0n1p3\n"
        device = 509332495872
        for fs_size, offered in ((device, False), (device - 2 * 1024**3, True)):
            with self.subTest(fs_size=fs_size), \
                 patch("subprocess.run", side_effect=self.fake_run({"btrfs": show.format(fs_size), "lsblk": str(device)})):
                self.win.refresh_memory_oom()
                self.assertEqual(not self.expand_button().isHidden(), offered)

    def test_swap_button_hidden_only_when_disk_swap_exists(self):
        layout = self.win.memory_oom_detail.parent().layout()
        swap_btn = layout.itemAt(2).layout().itemAt(1).widget()
        with patch("subprocess.run", side_effect=self.fake_run({"swapon": "/dev/zram0 partition 8G 0B 100"})):
            self.win.refresh_memory_oom()
        self.assertFalse(swap_btn.isHidden())
        with patch("subprocess.run", side_effect=self.fake_run({"swapon": "/swap/swapfile file 16G 0B 10"})):
            self.win.refresh_memory_oom()
        self.assertTrue(swap_btn.isHidden())


class SystemHistoryTabTests(GuiTabTestCase):
    def leaf_titles(self) -> list[str]:
        tree = self.win.history_tree
        return [tree.topLevelItem(i).child(j).text(1)
                for i in range(tree.topLevelItemCount())
                for j in range(tree.topLevelItem(i).childCount())]

    def test_no_report_shows_not_checked_and_no_health_claims(self):
        self.assertIn("System History", self.tab_titles())
        self.assertIn("No scan or history report loaded", self.win.history_source_label.text())
        self.assertTrue(self.win.history_issues)
        for issue in self.win.history_issues:
            self.assertNotIn("Healthy", issue.get("status", ""))

    def test_repeated_report_loads_do_not_duplicate_entries(self):
        self.win.report = {"checks": {}, "findings": []}
        self.win.load_report()
        first = self.leaf_titles()
        for _ in range(5):
            self.win.load_report()
        self.assertEqual(self.leaf_titles(), first)

    def test_missing_history_file_reports_error_and_keeps_tab_usable(self):
        self.win.populate_system_history(path=self.tmp / "gone.json")
        self.assertIn("File not found", self.win.history_detail.toPlainText())
        self.win.report = None
        self.win.load_report()
        self.assertIn("No scan or history report loaded", self.win.history_source_label.text())


if __name__ == "__main__":
    unittest.main()
