import json
import os
import stat
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runescape_doctor as rd


def ids(findings):
    return [f.id for f in findings]


class DiagnoseRuleTests(unittest.TestCase):
    def test_heap_oom_in_client_log(self):
        findings = rd.diagnose({"client": "Exception in thread \"main\" java.lang.OutOfMemoryError: Java heap space"})
        self.assertIn("java-heap-oom", ids(findings))

    def test_kernel_oom_killer_only_matches_journal(self):
        line = "Out of memory: Killed process 4242 (java) total-vm:9000000kB"
        self.assertIn("kernel-oom-killer", ids(rd.diagnose({"journal": line})))
        self.assertNotIn("kernel-oom-killer", ids(rd.diagnose({"client": line})))

    def test_native_graphics_frame_in_hs_err(self):
        hs_err = (
            "# A fatal error has been detected by the Java Runtime Environment:\n"
            "#\n#  SIGSEGV (0xb) at pc=0x00007f1234, pid=1234, tid=1235\n#\n"
            "# Problematic frame:\n# C  [libGL.so.1+0x1234]  glXMakeCurrent+0x40\n"
        )
        findings = rd.diagnose({"hs_err": hs_err})
        self.assertIn("jvm-fatal-error", ids(findings))
        self.assertIn("native-gfx-frame", ids(findings))
        gfx = next(f for f in findings if f.id == "native-gfx-frame")
        self.assertIn("libGL.so.1", gfx.evidence)
        self.assertEqual(gfx.source, "hs_err")

    def test_non_graphics_frame_is_not_flagged_as_graphics(self):
        hs_err = "# Problematic frame:\n# V  [libjvm.so+0x9a1b2c]  Something::else()+0x10\n"
        self.assertNotIn("native-gfx-frame", ids(rd.diagnose({"hs_err": hs_err})))

    def test_gpu_hang_in_journal(self):
        line = "kernel: i915 0000:00:02.0: [drm] GPU HANG: ecode 9:1:85dffffb, in java [1234]"
        self.assertIn("gpu-hang", ids(rd.diagnose({"journal": line})))

    def test_kernel_segfault_in_java(self):
        line = "kernel: java[4321]: segfault at 0 ip 00007f sp 00007f error 4 in libjvm.so"
        self.assertIn("kernel-segfault-java", ids(rd.diagnose({"journal": line})))

    def test_deadlock_in_thread_dump(self):
        dump = "Full thread dump OpenJDK 64-Bit Server VM\n\nFound one Java-level deadlock:\n"
        self.assertIn("java-deadlock", ids(rd.diagnose({"threads": dump})))

    def test_x11_error_and_missing_lib_and_version_mismatch(self):
        text = (
            "X Error of failed request:  BadAlloc (insufficient resources for operation)\n"
            "java.lang.UnsatisfiedLinkError: libawt_xawt.so: libXtst.so.6: cannot open shared object file\n"
            "java.lang.UnsupportedClassVersionError: Foo has been compiled by a more recent version\n"
        )
        found = ids(rd.diagnose({"client": text}))
        for expected in ("x11-gl-error", "missing-native-lib", "java-version-mismatch"):
            self.assertIn(expected, found)

    def test_coredump_listing_flags_java_cores(self):
        listing = "Mon 2026-11-09 10:00:00 AEDT 1234 1000 1000 SIGSEGV present /usr/lib/jvm/java-17/bin/java 5.0M"
        self.assertIn("java-coredump", ids(rd.diagnose({"coredump": listing})))

    def test_clean_evidence_gives_no_findings(self):
        self.assertEqual(rd.diagnose({"client": "Welcome to RuneScape.", "journal": "kernel: all quiet"}), [])

    def test_findings_sorted_most_severe_first(self):
        sources = {
            "client": "java.net.SocketTimeoutException: Read timed out",
            "journal": "kernel: i915 0000:00:02.0: GPU HANG",
        }
        order = [f.severity for f in rd.diagnose(sources)]
        self.assertEqual(order, sorted(order, key=lambda s: rd.SEVERITY_ORDER[s]))
        self.assertEqual(order[0], "critical")

    def test_one_finding_per_rule(self):
        text = "java.lang.OutOfMemoryError\njava.lang.OutOfMemoryError\n"
        found = ids(rd.diagnose({"client": text, "hs_err": text}))
        self.assertEqual(found.count("java-heap-oom"), 1)

    def test_uncaught_game_thread_exception_detected_with_stack_frame(self):
        log = (
            'Exception in thread "Thread-2" java.lang.ArrayIndexOutOfBoundsException: Index 32767 out of bounds for length 16384\n'
            '\tat jagex2.client.Client.updateFacingDirection(Client.java:5400)\n'
            '\tat jagex2.client.Client.updateEntity(Client.java:5226)\n'
        )
        findings = rd.diagnose({"client": log})
        self.assertIn("java-uncaught-game-thread-exception", ids(findings))
        top = findings[0]
        self.assertEqual(top.id, "java-uncaught-game-thread-exception")
        self.assertEqual(top.severity, "critical")
        self.assertIn("Index 32767 out of bounds", top.evidence)
        self.assertIn("Client.updateFacingDirection(Client.java:5400)", top.evidence)

    def test_dead_game_loop_thread_in_thread_dump_detected(self):
        dump = (
            "Full thread dump OpenJDK 64-Bit Server VM (25.0.4.1+0):\n"
            '"XToolkit-Shutdown-Thread" #30 [123] daemon prio=5\n'
            '"AWT-EventQueue-0" #34 [124] prio=6\n'
            '"Java Sound Event Dispatcher" #38 [125] daemon prio=5\n'
            '"Thread-0" #27 [126] daemon prio=1\n'
        )
        findings = rd.diagnose({"threads": dump})
        self.assertIn("java-game-thread-missing", ids(findings))

    def test_alive_game_loop_thread_in_thread_dump_not_flagged(self):
        dump = (
            "Full thread dump OpenJDK 64-Bit Server VM (25.0.4.1+0):\n"
            '"XToolkit-Shutdown-Thread" #30 [123] daemon prio=5\n'
            '"AWT-EventQueue-0" #34 [124] prio=6\n'
            '"Java Sound Event Dispatcher" #38 [125] daemon prio=5\n'
            '"Thread-2" #39 [127] prio=5\n'
            '\tat jagex2.client.GameShell.run(GameShell.java:731)\n'
        )
        findings = rd.diagnose({"threads": dump})
        self.assertNotIn("java-game-thread-missing", ids(findings))

    def test_classify_and_build_hypotheses_for_joshrs_freeze(self):
        log = (
            'Exception in thread "Thread-2" java.lang.ArrayIndexOutOfBoundsException: Index 32767 out of bounds for length 16384\n'
            '\tat jagex2.client.Client.updateFacingDirection(Client.java:5400)\n'
        )
        sysinfo = {"session_type": "wayland", "joshrs_root": "/home/josh/dev/JoshRS/lostcity377"}
        findings = rd.diagnose({"client": log}, sysinfo)
        cls = rd.classify_incident(findings, {"server_online": True})
        self.assertEqual(cls["category"], "application_game_thread_hang")
        hyps = rd.build_hypotheses(findings, sysinfo, {"client": log}, {"server_online": True})
        hyp_ids = [h["id"] for h in hyps]
        self.assertIn("hypothesis-game-thread-exception", hyp_ids)
        self.assertIn("hypothesis-black-margins-fixed-viewport", hyp_ids)
        timeline = rd.build_timeline(
            {"client": log, "journal": "Nov 09 11:07:09 host kwin_wayland[6958]: Failed to allocate a graphics buffer for a swapchain"},
            "Nov 09 11:13:58 host systemd[1879]: joshrs-client.service: Consumed 26min CPU time",
        )
        self.assertGreaterEqual(len(timeline), 3)


class SysinfoRuleTests(unittest.TestCase):
    def test_wayland_low_memory_new_java(self):
        sysinfo = {
            "session_type": "wayland", "mem_available_mb": 600, "swap_total_mb": 0,
            "java_major": 21, "java_version_line": 'openjdk version "21.0.5"',
        }
        found = ids(rd.diagnose({}, sysinfo))
        for expected in ("wayland-session", "low-free-memory", "very-new-java"):
            self.assertIn(expected, found)

    def test_missing_java(self):
        self.assertIn("java-missing", ids(rd.diagnose({}, {"java_version_line": ""})))

    def test_healthy_x11_system_is_quiet(self):
        sysinfo = {"session_type": "x11", "mem_available_mb": 8000, "java_major": 17,
                   "java_version_line": 'openjdk version "17.0.9"'}
        self.assertEqual(rd.diagnose({}, sysinfo), [])


class CollectorTests(unittest.TestCase):
    def test_collect_sysinfo_parses_java_version(self):
        with patch.object(rd, "_run", side_effect=lambda cmd, timeout=8.0: (
            'openjdk version "1.8.0_392"\nOpenJDK Runtime Environment' if cmd[-1] == "-version" else ""
        )):
            info = rd.collect_sysinfo()
        self.assertEqual(info["java_major"], 8)

    def test_collect_sysinfo_flags_missing_java(self):
        with patch.object(rd, "_run", return_value=f"{rd.ERROR_PREFIX} collector unavailable: nope"):
            self.assertEqual(rd.collect_sysinfo()["java_version_line"], "")

    def test_journal_is_filtered_to_relevant_lines(self):
        blob = "kernel: java[1]: segfault at 0\nsystemd: unrelated noise\nkernel: i915 GPU HANG\n"
        with patch.object(rd, "_run", return_value=blob):
            out = rd.collect_journal()
        self.assertIn("segfault", out)
        self.assertIn("GPU HANG", out)
        self.assertNotIn("unrelated noise", out)

    def test_journal_total_failure_reports_error(self):
        with patch.object(rd, "_run", return_value=f"{rd.ERROR_PREFIX} collector unavailable"):
            self.assertTrue(rd.collect_journal().startswith(rd.ERROR_PREFIX))

    def test_no_coredumps_is_empty(self):
        with patch.object(rd, "_run", return_value="No coredumps found."):
            self.assertEqual(rd.collect_coredumps(), "")

    def test_find_hs_err_respects_age_and_dirs(self):
        with tempfile.TemporaryDirectory() as tmp:
            fresh = Path(tmp) / "hs_err_pid111.log"
            stale = Path(tmp) / "hs_err_pid222.log"
            fresh.write_text("x")
            stale.write_text("x")
            old = time.time() - 30 * 86400
            os.utime(stale, (old, old))
            found = rd.find_hs_err([tmp], limit=50)
            self.assertIn(fresh.resolve(), found)
            self.assertNotIn(stale.resolve(), found)


class CaptureTests(unittest.TestCase):
    def test_capture_writes_private_report_with_findings(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            log = Path(tmp) / "client.log"
            log.write_text("Exception: java.lang.OutOfMemoryError: Java heap space\n")
            with patch.dict(os.environ, {"HOME": str(home), "XDG_STATE_HOME": str(home / "state")}), \
                    patch.object(rd, "_run", return_value=""), \
                    patch.object(rd, "find_hs_err", return_value=[]):
                summary = rd.capture_runescape_incident(
                    base=Path(tmp) / "captures", client_log=log,
                    now=datetime(2026, 11, 9, 1, 0, tzinfo=timezone.utc),
                )
            self.assertTrue(summary["capture_complete"])
            capture_dir = Path(summary["capture_path"])
            self.assertEqual(stat.S_IMODE(capture_dir.stat().st_mode), 0o700)
            saved = json.loads((capture_dir / "report.json").read_text())
            self.assertIn("java-heap-oom", [f["id"] for f in saved["findings"]])
            self.assertEqual(stat.S_IMODE((capture_dir / "report.json").stat().st_mode), 0o600)
            self.assertIn("Java heap", (capture_dir / "report.txt").read_text())
            self.assertTrue((capture_dir / "client.txt").exists())

    def test_capture_survives_missing_tools_and_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            err = f"{rd.ERROR_PREFIX} collector unavailable: missing"
            with patch.dict(os.environ, {"HOME": str(home), "XDG_STATE_HOME": str(home / "state")}), \
                    patch.object(rd, "_run", return_value=err), \
                    patch.object(rd, "find_hs_err", return_value=[]):
                summary = rd.capture_runescape_incident(base=Path(tmp) / "captures")
            self.assertTrue(summary["capture_complete"])
            for name in ("journal", "coredumpctl", "client-log"):
                self.assertIn(name, summary["failed_collectors"])

    def test_two_captures_in_same_second_do_not_collide(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp) / "home"
            home.mkdir()
            now = datetime(2026, 11, 9, 1, 0, tzinfo=timezone.utc)
            with patch.dict(os.environ, {"HOME": str(home), "XDG_STATE_HOME": str(home / "state")}), \
                    patch.object(rd, "_run", return_value=""), \
                    patch.object(rd, "find_hs_err", return_value=[]):
                a = rd.capture_runescape_incident(base=Path(tmp) / "c", now=now)
                b = rd.capture_runescape_incident(base=Path(tmp) / "c", now=now)
            self.assertNotEqual(a["capture_path"], b["capture_path"])


if __name__ == "__main__":
    unittest.main()
