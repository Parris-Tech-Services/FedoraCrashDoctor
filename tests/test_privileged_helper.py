#!/usr/bin/env python3
import io
import json
import os
import stat
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
import privileged_helper as helper


class PrivilegedHelperSecurityTests(unittest.TestCase):
    def test_unknown_action_fails_closed(self):
        with self.assertRaises(ValueError):
            helper.dispatch({"action": "run_arbitrary_command", "params": {}}, 1000, 1000, "/home/user", "req")

    def test_invalid_scan_mode_rejected_before_collection(self):
        with self.assertRaises(ValueError):
            helper.dispatch({"action": "scan", "params": {"mode": "maintenance"}}, 1000, 1000, "/home/user", "req")

    def test_smart_device_path_validation_rejects_injection(self):
        bad_devices = [
            "/dev/../../etc/passwd",
            "/dev/null;reboot",
            "/dev/sda && reboot",
            "/dev/sda$(reboot)",
            "/tmp/fake-device",
            "/etc/passwd",
        ]
        for device in bad_devices:
            with self.subTest(device=device):
                with self.assertRaises(ValueError):
                    helper.dispatch({"action": "smart_short", "params": {"device": device}}, 1000, 1000, "/home/user", "req")

    def test_smart_short_allows_only_discovered_devices(self):
        with mock.patch.object(helper, "discover_smart_devices", return_value=["/dev/sda"]):
            with mock.patch.object(helper, "command", return_value={"ok": True, "output": "started"}):
                result = helper.dispatch({"action": "smart_short", "params": {"device": "/dev/sda"}}, 1000, 1000, "/home/user", "req")
        self.assertTrue(result["ok"])
        self.assertEqual(result["device"], "/dev/sda")

    def test_save_baseline_uses_uid_directory_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as tmp:
            with mock.patch.object(helper, "STATE_DIR", Path(tmp)):
                helper.save_baseline(1234, {"schema_version": 1, "ok": True})
                path = Path(tmp) / "baselines" / "1234" / "latest.json"
                self.assertTrue(path.exists())
                self.assertEqual(json.loads(path.read_text())["ok"], True)
                self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
                self.assertEqual(stat.S_IMODE(path.parent.stat().st_mode), 0o700)

    def test_save_baseline_replaces_symlink_not_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "outside.json"
            target.write_text("outside")
            base_dir = Path(tmp) / "baselines" / "1234"
            base_dir.mkdir(parents=True)
            os.symlink(target, base_dir / "latest.json")
            with mock.patch.object(helper, "STATE_DIR", Path(tmp)):
                helper.save_baseline(1234, {"safe": True})
            self.assertEqual(target.read_text(), "outside")
            self.assertFalse((base_dir / "latest.json").is_symlink())
            self.assertEqual(json.loads((base_dir / "latest.json").read_text())["safe"], True)

    def test_command_rejects_invalid_executable(self):
        with self.assertRaises(ValueError):
            helper.command(["bad;name"], 1)


if __name__ == "__main__":
    unittest.main()


class BrokerRequestHandlingTests(unittest.TestCase):
    """handle_request_line() with dispatch() mocked: no root work runs."""

    def setUp(self):
        self.sent: list[dict] = []
        self.release = threading.Event()
        self.threads: list[threading.Thread] = []
        helper.active_tasks.clear()
        for patcher in (
            mock.patch.object(helper, "send", side_effect=self.sent.append),
            mock.patch.object(helper, "dispatch", side_effect=self._fake_dispatch),
        ):
            patcher.start()
            self.addCleanup(patcher.stop)
        # Cleanups run last-in first-out: let workers finish while still patched.
        self.addCleanup(helper.active_tasks.clear)
        self.addCleanup(self._finish_workers)

    def _finish_workers(self):
        self.release.set()
        for t in self.threads:
            t.join(5)

    def _fake_dispatch(self, req, uid, gid, home, request_id):
        if not self.release.wait(5):
            raise TimeoutError("test never released the worker")
        return "Cancelled." if req["state"]["cancel_flag"] else {"done": request_id}

    def _line(self, **payload):
        return json.dumps(payload) + "\n"

    def _handle(self, raw):
        t = helper.handle_request_line(raw, 1000, 1000, "/home/u")
        if t is not None:
            self.threads.append(t)
        return t

    def _start(self, request_id, action="scan"):
        return self._handle(self._line(id=request_id, action=action, params={}))

    def _results(self):
        return [m for m in self.sent if m.get("type") == "result"]

    def test_oversized_request_rejected_without_starting_work(self):
        raw = self._line(id="big", action="scan", params={"pad": "x" * helper.MAX_REQUEST})
        self.assertIsNone(self._handle(raw))
        self.assertEqual(self.sent, [{"type": "error", "id": None, "error": "Request too large"}])
        self.assertEqual(helper.active_tasks, {})

    def test_active_task_limit_rejects_extra_requests(self):
        threads = [self._start(f"r{i}") for i in range(helper.MAX_ACTIVE_TASKS)]
        self.assertTrue(all(threads))
        self.assertIsNone(self._start("one-too-many"))
        rejected = self._results()
        self.assertEqual(len(rejected), 1)
        self.assertEqual(rejected[0]["id"], "one-too-many")
        self.assertFalse(rejected[0]["ok"])
        self.assertIn("Too many", rejected[0]["error"])
        self.release.set()
        for t in threads:
            t.join(5)
        self.assertEqual(helper.active_tasks, {})
        # Capacity is available again once the workers finish.
        self.assertIsNotNone(self._start("after"))

    def test_duplicate_active_id_rejected_and_original_stays_cancellable(self):
        first = self._start("dup")
        self.assertIsNone(self._start("dup"))
        self.assertEqual(self._results()[0]["id"], "dup")
        self.assertIn("already active", self._results()[0]["error"])
        self._handle(self._line(action="cancel", target_id="dup"))
        self.release.set()
        first.join(5)
        self.assertEqual(self._results()[-1], {"type": "result", "id": "dup", "ok": True, "data": "Cancelled."})
        self.assertEqual(helper.active_tasks, {})

    def test_id_can_be_reused_after_the_task_finishes(self):
        self.release.set()
        self._start("again").join(5)
        self.assertIsNotNone(self._start("again"))

    def test_cancel_sets_flag_and_acknowledges_without_a_result(self):
        t = self._start("job")
        self._handle(self._line(action="cancel", target_id="job"))
        self.assertTrue(helper.active_tasks["job"]["cancel_flag"])
        self.assertIn({"type": "cancel_ack", "target_id": "job", "found": True}, self.sent)
        self.assertEqual(self._results(), [])
        self.release.set()
        t.join(5)
        self.assertEqual(self._results(), [{"type": "result", "id": "job", "ok": True, "data": "Cancelled."}])

    def test_cancel_of_unknown_id_is_harmless(self):
        self._handle(self._line(action="cancel", target_id="nope"))
        self.assertEqual(self.sent, [{"type": "cancel_ack", "target_id": "nope", "found": False}])

    def test_cancel_matches_ids_truncated_to_the_same_length(self):
        long_id = "a" * (helper.MAX_REQUEST_ID + 20)
        t = self._start(long_id)
        self._handle(self._line(action="cancel", target_id=long_id))
        self.release.set()
        t.join(5)
        self.assertEqual(self._results()[-1]["data"], "Cancelled.")

    def test_malformed_line_after_a_valid_request_is_not_attributed_to_it(self):
        self._start("good")
        self._handle("{not json\n")
        error = self._results()[0]
        self.assertEqual(error["id"], "")
        self.assertFalse(error["ok"])

    def test_missing_id_and_non_object_rejected(self):
        self.assertIsNone(self._handle(self._line(action="scan")))
        self.assertIsNone(self._handle("[1, 2]\n"))
        errors = [r["error"] for r in self._results()]
        self.assertIn("Request id required", errors[0])
        self.assertIn("must be an object", errors[1])
        self.assertEqual(helper.active_tasks, {})

    def test_client_supplied_state_cannot_preset_cancel(self):
        raw = self._line(id="s", action="scan", params={}, state={"cancel_flag": True})
        t = self._handle(raw)
        self.release.set()
        t.join(5)
        self.assertEqual(self._results()[-1]["data"], {"done": "s"})



class BrokerSendTests(unittest.TestCase):
    def test_concurrent_sends_produce_whole_json_lines(self):
        out = io.StringIO()
        with mock.patch.object(helper.sys, "stdout", out):
            workers = [threading.Thread(target=lambda n=n: [helper.send({"type": "progress", "id": f"t{n}", "label": "x" * 500}) for _ in range(50)]) for n in range(8)]
            for w in workers:
                w.start()
            for w in workers:
                w.join(5)
        lines = out.getvalue().splitlines()
        self.assertEqual(len(lines), 400)
        for line in lines:
            json.loads(line)
