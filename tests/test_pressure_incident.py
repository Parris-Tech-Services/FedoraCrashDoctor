#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from collector import build_overall, confidence_label
from incident_model import attach_incident_identity
from pressure_incident import build_pressure_incident

BOOT = "5ba0435e-5767-46ca-bdb2-67af8a727eeb"


def sample(ts, io_full=0.0, mem_some=0.0, boot=BOOT):
    return {
        "ts": ts,
        "boot_id": boot,
        "psi_io": {"full_avg10": io_full},
        "psi_mem": {"some_avg10": mem_some},
        "memory": {
            "mem_available_mb": 311,
            "zram_used_mb": 8191,
            "swap_devices": [{"name": "/dev/zram0", "type": "partition", "size_mb": 8191, "used_mb": 8191}],
        },
    }


THRASHING = [
    sample("2026-09-30T08:40:46+10:00", io_full=74.3, mem_some=37.3),
    sample("2026-09-30T08:40:48+10:00", io_full=71.6, mem_some=35.8),
    sample("2026-09-30T08:40:50+10:00", io_full=70.2, mem_some=32.7),
    sample("2026-09-30T08:41:00+10:00", io_full=50.5, mem_some=21.3),
]


class PressureIncidentTests(unittest.TestCase):
    def test_sustained_pressure_becomes_memory_incident(self):
        incident = build_pressure_incident(THRASHING, BOOT, confidence_label)
        self.assertIsNotNone(incident)
        self.assertEqual(incident["boot_index"], "0")
        self.assertEqual(incident["hypotheses"][0]["category"], "Memory")
        self.assertEqual(incident["confidence"], "high")
        joined = " ".join(incident["supporting_evidence"])
        self.assertIn("74.3%", joined)
        self.assertIn("zram", joined)

    def test_pressure_outranks_stale_display_incident(self):
        # The 2026-09-30 freeze: the only journal incident in the current boot
        # was a compositor crash five days earlier, which won the verdict.
        stale = {
            "boot_index": "0",
            "failure_boundary": "compositor crash",
            "hypotheses": [{"title": "Display-stack or KWin Wayland freeze", "confidence": "moderate", "score": 0.5}],
            "sort_key": 1790311894.0,  # 2026-09-25
        }
        pressure = attach_incident_identity(build_pressure_incident(THRASHING, BOOT, confidence_label), {})
        overall, _ = build_overall([stale, pressure])
        self.assertTrue(overall["title"].startswith("Memory/swap exhaustion"))

    def test_brief_spike_is_ignored(self):
        self.assertIsNone(build_pressure_incident(THRASHING[:2], BOOT, confidence_label))

    def test_other_boot_is_ignored(self):
        other = [dict(s, boot_id="00000000-0000-0000-0000-000000000000") for s in THRASHING]
        self.assertIsNone(build_pressure_incident(other, BOOT, confidence_label))

    def test_journal_style_boot_id_matches(self):
        self.assertIsNotNone(build_pressure_incident(THRASHING, BOOT.replace("-", ""), confidence_label))

    def test_calm_samples_and_missing_timestamps_are_ignored(self):
        calm = [sample(f"2026-09-30T08:3{i}:00+10:00", io_full=1.0, mem_some=0.5) for i in range(5)]
        undated = [dict(s, ts=None) for s in THRASHING]
        self.assertIsNone(build_pressure_incident(calm + undated, BOOT, confidence_label))


if __name__ == "__main__":
    unittest.main()
