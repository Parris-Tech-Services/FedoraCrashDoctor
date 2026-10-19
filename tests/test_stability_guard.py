#!/usr/bin/env python3
import sys
import unittest
from unittest.mock import patch
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from safe_mitigation import StabilityController

class StabilityGuardTests(unittest.TestCase):
    def setUp(self):
        self.controller = StabilityController(owner_config=Path("/dev/null"), out_dir=Path("/tmp/fcd-test-out"))
        
    def _mem_sample(self, avail_mb, total_mb=16000, swap_used=0, some_psi=0, io_full=0, hb_age=0):
        return {
            "epoch": len(getattr(self, "samples", [])) * 5,
            "memory": {"mem_available_mb": avail_mb, "mem_total_mb": total_mb, "swap_used_mb": swap_used, "swap_total_mb": 8192},
            "psi_mem": {"some_avg10": some_psi},
            "psi_io": {"full_avg10": io_full},
            "desktop_heartbeat_age_s": hb_age,
            "kwin_ok": True,
            "plasmashell_ok": True,
            "processes": {"top_rss": [{"name": "chrome", "group": "Google Chrome", "rss_kb": 3_500_000}]}
        }

    def test_low_available_memory_alone_is_not_critical(self):
        sample = self._mem_sample(700, total_mb=16000, swap_used=0, some_psi=0, io_full=0)
        self.assertNotEqual(self.controller.process_sample(sample), "critical")

    def test_runaway_single_workload_escalates_under_pressure(self):
        sample = self._mem_sample(3500, total_mb=16000, swap_used=6000, some_psi=20, io_full=25)
        sample["processes"] = {
            "top_rss": [{"name": "next-server", "group": "Other", "rss_kb": 7_500_000}]
        }
        result = self.controller.process_sample(sample)
        self.assertIsNone(result)  # first sample is debounced
        result = self.controller.process_sample(sample)
        self.assertIsNotNone(result)
        self.assertEqual(result["state"], "critical")
        self.assertIn("next-server", " ".join(result["recommended_actions"]))

    def test_coredump_storm_escalates_under_pressure(self):
        sample = self._mem_sample(2500, total_mb=16000, swap_used=6000, some_psi=15, io_full=20)
        sample["journal_events"] = {"coredump": ["core dumped"] * 3}
        result = self.controller.process_sample(sample)
        self.assertIsNone(result)
        result = self.controller.process_sample(sample)
        self.assertIsNotNone(result)
        self.assertEqual(result["state"], "critical")
        self.assertIn("Coredump storm", result["title"])

    def test_normal_zram_use_is_not_memory_failure(self):
        sample = self._mem_sample(8000, swap_used=2000, some_psi=0, io_full=0)
        self.assertIsNone(self.controller.process_sample(sample))
        self.assertEqual(self.controller.state, "ok")

    def test_chrome_sustained_growth_is_observed_not_leak(self):
        results = []
        for index in range(12):
            sample = self._mem_sample(8000)
            sample["epoch"] = index * 60
            sample["chrome"] = {"aggregate_rss_mb": 1000 + index * 100}
            result = self.controller.process_sample(sample)
            if result:
                results.append(result)
        self.assertEqual(self.controller.state, "warning")
        self.assertTrue(any("sustained memory growth observed" in " ".join(result["reasons"]) for result in results))
        self.assertFalse(any("memory leak" in result["title"].lower() for result in results))

    @patch('time.monotonic')
    def test_automatic_capture_is_rate_limited(self, mock_monotonic):
        captured = []
        self.controller.capture_cooldown = 600.0
        self.controller.capture_callback = lambda event, sample: captured.append(event["trigger_reason"]) or "/tmp/capture"
        
        # Test 1: First capture allowed
        mock_monotonic.return_value = 100.0
        for _ in range(2):
            self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(len(captured), 1)
        
        # Test 2: Immediate second capture denied
        mock_monotonic.return_value = 110.0
        self.controller.process_sample(self._mem_sample(8000))
        self.controller.process_sample(self._mem_sample(8000))
        for _ in range(2):
            self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(len(captured), 1)
        
        # Test 3: Capture after configured cooldown allowed
        mock_monotonic.return_value = 701.0
        self.controller.process_sample(self._mem_sample(8000))
        self.controller.process_sample(self._mem_sample(8000))
        for _ in range(2):
            self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(len(captured), 2)
        
        # Test 4: Non-default cooldown values
        self.controller.capture_cooldown = 100.0
        mock_monotonic.return_value = 802.0
        self.controller.process_sample(self._mem_sample(8000))
        self.controller.process_sample(self._mem_sample(8000))
        for _ in range(2):
            self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(len(captured), 3)

        # Test 5: Negative cooldown is clamped to zero
        from safe_mitigation import StabilityController
        c = StabilityController(capture_cooldown=-50.0)
        self.assertEqual(c.capture_cooldown, 0.0)

    def test_transient_pressure_does_not_notify(self):
        # 1 warning sample
        res1 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNone(res1)
        self.assertEqual(self.controller.state, "pending")
        
        # 1 ok sample
        res2 = self.controller.process_sample(self._mem_sample(8000))
        self.assertIsNone(res2)
        # It takes 2 OKs to recover from pending
        self.assertEqual(self.controller.state, "pending")
        
        res3 = self.controller.process_sample(self._mem_sample(8000))
        self.assertIsNone(res3)
        self.assertEqual(self.controller.state, "ok")

    def test_sustained_warning_pressure_notifies_once(self):
        res1 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNone(res1)
        
        res2 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNotNone(res2)
        self.assertEqual(res2["state"], "warning")
        
        res3 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNone(res3)
        self.assertEqual(self.controller.state, "warning")

    def test_escalation_to_critical_notifies_again(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(res["state"], "warning")
        
        # Escalate to critical -> notify immediately
        res2 = self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
        self.assertIsNotNone(res2)
        self.assertEqual(res2["state"], "critical")

    def test_persistent_critical_pressure_does_not_spam(self):
        self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
        res = self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25))
        self.assertEqual(res["state"], "critical")
        
        for _ in range(5):
            self.assertIsNone(self.controller.process_sample(self._mem_sample(400, swap_used=8000, some_psi=25, io_full=25)))

    def test_recovery_is_recognised(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(self.controller.state, "warning")
        
        # 1 ok -> recovering (notify)
        res = self.controller.process_sample(self._mem_sample(8000))
        self.assertIsNotNone(res)
        self.assertEqual(res["state"], "recovering")
        self.assertEqual(res["title"], "System recovered")
        
        for _ in range(3):
            self.assertIsNone(self.controller.process_sample(self._mem_sample(8000)))
            self.assertEqual(self.controller.state, "recovering")
            
        # 5th ok -> back to ok (no notify needed, just internal state)
        res_final = self.controller.process_sample(self._mem_sample(8000))
        # Wait, the code says emit=True when returning to 'ok'. Let's see what happens.
        self.assertIsNotNone(res_final)
        self.assertEqual(res_final["state"], "ok")

    def test_largest_workload_identified_no_causality(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        
        self.assertIn("Google Chrome \u2014 3417 MB", res["likely_offenders"])

    def test_later_recurrence_can_notify_again(self):
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res1 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertEqual(res1["state"], "warning")
        
        # Recover
        self.controller.process_sample(self._mem_sample(8000))
        for _ in range(4):
            self.controller.process_sample(self._mem_sample(8000))
            
        self.assertEqual(self.controller.state, "ok")
        
        # Warn again
        self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        res2 = self.controller.process_sample(self._mem_sample(1000, swap_used=6000, some_psi=15))
        self.assertIsNotNone(res2)
        self.assertEqual(res2["state"], "warning")

if __name__ == "__main__":
    unittest.main()
