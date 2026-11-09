import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import runescape_doctor
import runescape_watchdog as rw


class ConfigTests(unittest.TestCase):
    def test_build_command_for_jar_uses_profile_flags_and_env(self):
        cfg = rw.Config(jar_path="/games/rs2.jar", java_path="/usr/bin/java",
                        client_args=["-w", "1"], extra_jvm_args=["-Xmx1g"])
        argv, env = rw.build_command(cfg, "xwayland-safe")
        self.assertEqual(argv[0], "/usr/bin/java")
        self.assertIn("-Dsun.java2d.opengl=false", argv)
        self.assertIn("-Xmx1g", argv)
        self.assertEqual(argv[-4:], ["-jar", "/games/rs2.jar", "-w", "1"])
        self.assertEqual(env["_JAVA_AWT_WM_NONREPARENTING"], "1")

    def test_default_profile_adds_no_flags(self):
        argv, _ = rw.build_command(rw.Config(jar_path="/games/rs2.jar"))
        self.assertEqual(argv, ["java", "-jar", "/games/rs2.jar"])

    def test_software_profile_forces_mesa_software_rendering(self):
        _, env = rw.build_command(rw.Config(jar_path="/x.jar"), "software")
        self.assertEqual(env["LIBGL_ALWAYS_SOFTWARE"], "1")

    def test_custom_command_splices_jvm_placeholder(self):
        cfg = rw.Config(custom_command=["java", "{jvm}", "-cp", "client.jar", "Main"])
        argv, _ = rw.build_command(cfg, "stable-graphics")
        self.assertEqual(argv[0], "java")
        self.assertIn("-Dsun.java2d.xrender=false", argv)
        self.assertEqual(argv[-3:], ["-cp", "client.jar", "Main"])
        self.assertNotIn("{jvm}", argv)

    def test_no_client_raises_config_error(self):
        with self.assertRaises(rw.ConfigError):
            rw.build_command(rw.Config())

    def test_unknown_profile_falls_back_to_default(self):
        argv, _ = rw.build_command(rw.Config(jar_path="/x.jar"), "nonsense")
        self.assertEqual(argv, ["java", "-jar", "/x.jar"])

    def test_config_round_trip_and_bad_input(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "sub" / "runescape.json"
            rw.save_config(rw.Config(jar_path="/a.jar", profile="software", max_restarts=9), path)
            loaded = rw.load_config(path)
            self.assertEqual((loaded.jar_path, loaded.profile, loaded.max_restarts), ("/a.jar", "software", 9))
            path.write_text('{"jar_path": "/b.jar", "bogus": 1}')
            self.assertEqual(rw.load_config(path).jar_path, "/b.jar")
            path.write_text("not json")
            self.assertEqual(rw.load_config(path), rw.Config())
            path.write_text("[1, 2]")
            self.assertEqual(rw.load_config(path), rw.Config())
        self.assertEqual(rw.load_config(Path("/nonexistent/runescape.json")), rw.Config())

    def test_escalation_order(self):
        self.assertEqual(rw.next_profile("default"), "stable-graphics")
        self.assertEqual(rw.next_profile("stable-graphics"), "xwayland-safe")
        self.assertEqual(rw.next_profile("xwayland-safe"), "software")
        self.assertEqual(rw.next_profile("software"), "software")
        self.assertEqual(rw.next_profile("low-memory"), "low-memory")


class ExistingServerRecoveryTests(unittest.TestCase):
    def make_state(self, tmp, **changes):
        state = {
            "joshrs_install": {"root": tmp},
            "servers": [], "ports": {"game_52402": False, "http_8888": False, "mgmt_8898": False},
            "server_online": False, "client_running": True,
        }
        state.update(changes)
        return state

    def test_missing_original_launcher_does_not_guess_a_node_world(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(runescape_doctor, "collect_live_status",
                             return_value=self.make_state(tmp)), \
                patch.object(rw.subprocess, "Popen") as spawn:
            ok, detail = rw.start_joshrs_server()
            self.assertFalse(ok)
            self.assertIn("original server launcher was not found", detail)
            spawn.assert_not_called()

    def test_symlinked_server_launcher_is_not_trusted(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "other.sh").write_text("#!/bin/sh\n")
            (root / "start-server.sh").symlink_to(root / "other.sh")
            self.assertIsNone(rw.discover_joshrs_server_launcher({"root": tmp}))

    def test_existing_world_never_spawns_a_competing_server(self):
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(runescape_doctor, "collect_live_status",
                             return_value=self.make_state(tmp, servers=[{"pid": 431834}])), \
                patch.object(rw.subprocess, "Popen") as spawn:
            ok, detail = rw.start_joshrs_server()
            self.assertFalse(ok)
            self.assertIn("second world", detail)
            spawn.assert_not_called()
        with tempfile.TemporaryDirectory() as tmp, \
                patch.object(runescape_doctor, "collect_live_status",
                             return_value=self.make_state(tmp, ports={"game_52402": False, "http_8888": True})), \
                patch.object(rw.subprocess, "Popen") as spawn:
            self.assertFalse(rw.start_joshrs_server()[0])
            spawn.assert_not_called()

    def test_known_launcher_only_and_verified_port_before_claiming_restored(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "start-server.sh").write_text("#!/usr/bin/env bash\n# existing launcher\n")
            states = [self.make_state(tmp), self.make_state(tmp, server_online=True)]
            with patch.object(runescape_doctor, "collect_live_status", side_effect=states), \
                    patch.object(runescape_doctor, "state_dir", return_value=Path(tmp)), \
                    patch.object(rw.subprocess, "Popen") as spawn:
                ok, detail = rw.start_joshrs_server()
            self.assertTrue(ok)
            self.assertIn("started the game listener", detail)
            self.assertEqual(spawn.call_args.args[0], ["bash", str(Path(tmp, "start-server.sh"))])
            self.assertEqual(spawn.call_args.kwargs["cwd"], tmp)
            self.assertEqual(spawn.call_args.kwargs["stdin"], subprocess.DEVNULL)
            self.assertTrue(spawn.call_args.kwargs["start_new_session"])
            self.assertEqual((Path(tmp) / "server-start.log").stat().st_mode & 0o777, 0o600)



class FreezeDetectorTests(unittest.TestCase):
    def test_busy_process_is_never_frozen(self):
        det = rw.FreezeDetector(10)
        for t in range(0, 100, 2):
            self.assertFalse(det.update(float(t), t, "S"))

    def test_no_cpu_progress_for_threshold_is_frozen(self):
        det = rw.FreezeDetector(10)
        self.assertFalse(det.update(0.0, 50, "S"))
        self.assertFalse(det.update(9.0, 50, "S"))
        self.assertTrue(det.update(10.0, 50, "S"))

    def test_progress_resets_the_timer(self):
        det = rw.FreezeDetector(10)
        det.update(0.0, 50, "S")
        det.update(8.0, 51, "S")
        self.assertFalse(det.update(17.0, 51, "S"))
        self.assertTrue(det.update(18.0, 51, "S"))

    def test_stopped_process_is_not_frozen(self):
        det = rw.FreezeDetector(10)
        det.update(0.0, 50, "T")
        self.assertFalse(det.update(60.0, 50, "T"))

    def test_long_gap_such_as_suspend_does_not_count(self):
        det = rw.FreezeDetector(10, max_gap=30)
        det.update(0.0, 50, "S")
        self.assertFalse(det.update(500.0, 50, "S"))
        self.assertTrue(det.update(511.0, 50, "S"))


class RestartPolicyTests(unittest.TestCase):
    def test_restarts_then_escalates_then_gives_up(self):
        policy = rw.RestartPolicy(rw.Config(max_restarts=3, restart_delay=2))
        self.assertEqual(policy.record_failure(5, "default"), (True, "default", 2))
        self.assertEqual(policy.record_failure(5, "default"), (True, "stable-graphics", 4))
        self.assertEqual(policy.record_failure(5, "stable-graphics"), (True, "xwayland-safe", 6))
        restart, _, _ = policy.record_failure(5, "xwayland-safe")
        self.assertFalse(restart)

    def test_long_stable_run_resets_the_count(self):
        policy = rw.RestartPolicy(rw.Config(max_restarts=1, restart_delay=1))
        policy.record_failure(5, "default")
        restart, profile, _ = policy.record_failure(rw.STABLE_RUN_SECONDS + 1, "default")
        self.assertTrue(restart)
        self.assertEqual(profile, "default")
        self.assertEqual(policy.failures, 1)

    def test_escalation_can_be_disabled(self):
        policy = rw.RestartPolicy(rw.Config(max_restarts=5, restart_delay=0, auto_escalate=False))
        policy.record_failure(5, "default")
        self.assertEqual(policy.record_failure(5, "default")[1], "default")

    def test_delay_is_capped(self):
        policy = rw.RestartPolicy(rw.Config(max_restarts=50, restart_delay=3))
        delays = [policy.record_failure(5, "software")[2] for _ in range(10)]
        self.assertEqual(max(delays), 15)


class ProcessHelperTests(unittest.TestCase):
    def test_read_proc_stat_of_self(self):
        ticks, state = rw.read_proc_stat(os.getpid())
        self.assertIsInstance(ticks, int)
        self.assertIn(state, "RSD")

    def test_read_proc_stat_of_missing_pid(self):
        self.assertIsNone(rw.read_proc_stat(2 ** 22 + 12345))

    def test_describe_exit(self):
        self.assertEqual(rw.describe_exit(None), "unknown exit status")
        self.assertEqual(rw.describe_exit(3), "exit code 3")
        self.assertEqual(rw.describe_exit(-11), "killed by SIGSEGV")


class SupervisorTests(unittest.TestCase):
    """Real subprocesses, with diagnosis collectors stubbed so tests stay fast and hermetic."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        home = Path(self.tmp.name)
        patches = [
            patch.dict(os.environ, {"HOME": str(home), "XDG_STATE_HOME": str(home / "state"),
                                    "XDG_CONFIG_HOME": str(home / "config")}),
            patch.object(runescape_doctor, "_run", return_value=""),
            patch.object(runescape_doctor, "find_hs_err", return_value=[]),
        ]
        for p in patches:
            p.start()
            self.addCleanup(p.stop)
        self.addCleanup(self.tmp.cleanup)
        self.events = []

    def emit(self, kind, message):
        self.events.append((kind, message))

    def kinds(self):
        return [k for k, _ in self.events]

    def make(self, code, **overrides):
        cfg = rw.Config(custom_command=[sys.executable, "-c", code], restart_delay=0,
                        poll_seconds=0.1, freeze_seconds=1)
        for key, value in overrides.items():
            setattr(cfg, key, value)
        return rw.Supervisor(cfg, emit=self.emit)

    def test_clean_exit_finishes_without_restart(self):
        self.assertEqual(self.make("pass").run(), 0)
        self.assertEqual(self.kinds(), ["start", "exit"])

    def test_crash_restarts_escalates_and_gives_up(self):
        sup = self.make("import sys; sys.exit(3)", max_restarts=2)
        self.assertEqual(sup.run(), 1)
        starts = [m for k, m in self.events if k == "start"]
        self.assertEqual(len(starts), 3)
        self.assertIn("profile 'default'", starts[0])
        self.assertIn("profile 'default'", starts[1])
        self.assertIn("profile 'stable-graphics'", starts[2])
        self.assertEqual(self.kinds().count("crash"), 3)
        self.assertIn("giveup", self.kinds())
        self.assertIn("report", self.kinds())
        self.assertTrue(any("exit code 3" in m for k, m in self.events if k == "crash"))

    def test_crash_report_uses_the_client_log(self):
        code = "import sys; print('java.lang.OutOfMemoryError: Java heap space'); sys.exit(1)"
        self.make(code, max_restarts=0).run()
        findings = [m for k, m in self.events if k == "finding"]
        self.assertTrue(any("heap" in m.lower() for m in findings), findings)

    def test_frozen_client_is_detected_and_killed(self):
        sup = self.make("import time; time.sleep(60)", max_restarts=0)
        started = time.monotonic()
        self.assertEqual(sup.run(), 1)
        self.assertLess(time.monotonic() - started, 30)
        self.assertIn("frozen", self.kinds())
        self.assertIn("giveup", self.kinds())

    def test_crashed_game_thread_with_busy_audio_loop_is_detected_as_frozen(self):
        code = (
            "import sys, time\n"
            "print('Exception in thread \"Thread-2\" java.lang.ArrayIndexOutOfBoundsException: Index 32767', flush=True)\n"
            "end = time.time() + 30\n"
            "while time.time() < end:\n"
            "    _ = sum(range(5000))\n"
            "    time.sleep(0.01)\n"
        )
        sup = self.make(code, max_restarts=0, freeze_seconds=60)
        started = time.monotonic()
        self.assertEqual(sup.run(), 1)
        self.assertLess(time.monotonic() - started, 15)
        self.assertIn("frozen", self.kinds())
        self.assertIn("giveup", self.kinds())

    def test_missing_client_config_returns_2(self):
        sup = rw.Supervisor(rw.Config(), emit=self.emit)
        self.assertEqual(sup.run(), 2)
        self.assertEqual(self.kinds(), ["error"])

    def test_unrunnable_command_returns_2(self):
        sup = rw.Supervisor(rw.Config(custom_command=["/nonexistent/binary"]), emit=self.emit)
        self.assertEqual(sup.run(), 2)
        self.assertIn("error", self.kinds())

    def test_stop_leaves_client_running(self):
        marker = "time.sleep(61)"
        sup = self.make(f"import time; {marker}", freeze_seconds=600)
        result = []
        thread = threading.Thread(target=lambda: result.append(sup.run()))
        thread.start()
        try:
            deadline = time.monotonic() + 10
            while "start" not in self.kinds() and time.monotonic() < deadline:
                time.sleep(0.05)
            time.sleep(0.4)
            sup.stop()
            thread.join(timeout=10)
            self.assertEqual(result, [0])
            self.assertIn("stop", self.kinds())
            self.assertTrue(rw.find_pids(r"sleep\(61\)"), "client should still be running")
        finally:
            for pid, _ in rw.find_pids(r"sleep\(61\)"):
                try:
                    os.killpg(pid, signal.SIGKILL)
                except OSError:
                    pass

    def test_attached_frozen_process_is_killed(self):
        child = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            sup = rw.Supervisor(rw.Config(poll_seconds=0.1, freeze_seconds=1), emit=self.emit)
            started = time.monotonic()
            self.assertEqual(sup.watch_pid(child.pid), 1)
            self.assertLess(time.monotonic() - started, 30)
            self.assertIn("frozen", self.kinds())
            self.assertIsNotNone(child.wait(timeout=10))
        finally:
            if child.poll() is None:
                child.kill()

    def test_attached_process_that_ends_is_reported_not_relaunched(self):
        child = subprocess.Popen([sys.executable, "-c", "pass"])
        child.wait()
        sup = rw.Supervisor(rw.Config(custom_command=[sys.executable, "-c", "pass"], poll_seconds=0.1),
                            emit=self.emit)
        self.assertEqual(sup.watch_pid(child.pid), 0)
        self.assertNotIn("start", self.kinds())
        self.assertIn("exit", self.kinds())


if __name__ == "__main__":
    unittest.main()
