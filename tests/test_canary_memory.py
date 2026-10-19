import json
import unittest
from unittest.mock import patch

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

from canary import (
    gather_processes, memory, vmstat, diskstats, zram_stats,
    read_psi
)
import tempfile
import shutil

class TestCanaryMemory(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.proc_dir = Path(self.test_dir) / "proc"
        self.proc_dir.mkdir()
        self.sys_dir = Path(self.test_dir) / "sys_block"
        self.sys_dir.mkdir()

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_gather_processes_grouping(self):
        # Mock PID 100 (Chrome)
        p100 = self.proc_dir / "100"
        p100.mkdir()
        (p100 / "status").write_text("VmRSS: 1024000\nVmSwap: 512000\nRssAnon: 500\nRssFile: 100\nPPid: 1")
        (p100 / "stat").write_text("100 (chrome) S 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20")
        (p100 / "cmdline").write_text("/opt/google/chrome/chrome --type=renderer")

        # Mock PID 101 (Antigravity)
        p101 = self.proc_dir / "101"
        p101.mkdir()
        (p101 / "status").write_text("VmRSS: 512000\nVmSwap: 0\nRssAnon: 200\nRssFile: 50\nPPid: 1")
        (p101 / "stat").write_text("101 (antigravity) R 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20")
        (p101 / "cmdline").write_text("/opt/antigravity/antigravity")

        def mock_read_text(p):
            name = Path(p).name
            if name in ["status", "stat", "cmdline", "wchan"]:
                return (self.proc_dir / Path(p).parent.name / name).read_text()
            return ""

        with patch("os.listdir", return_value=["100", "101", "not_pid"]), \
             patch("canary.read_text", side_effect=mock_read_text):
             
            res = gather_processes()
            groups = res["groups"]
            
            self.assertIn("Google Chrome", groups)
            self.assertEqual(groups["Google Chrome"]["rss_kb"], 1024000)
            self.assertEqual(groups["Google Chrome"]["swap_kb"], 512000)
            
            self.assertIn("Antigravity", groups)
            self.assertEqual(groups["Antigravity"]["rss_kb"], 512000)
            self.assertEqual(groups["Antigravity"]["swap_kb"], 0)

            process = next(item for item in res["top_rss"] if item["name"] == "chrome")
            self.assertIn("rss_percent", process)
            self.assertIn("oom_score", process)
            
    def test_vmstat_parsing(self):
        with patch("canary.read_text", return_value="pgscan_kswapd 100\npswpin 50\nother 999"):
            stats = vmstat()
            self.assertEqual(stats["pgscan_kswapd"], 100)
            self.assertEqual(stats["pswpin"], 50)
            self.assertNotIn("other", stats)

    def test_diskstats_parsing(self):
        diskstats_text = "   8       0 sda 100 0 200 0 300 0 400 0 0 500 600\n   7       0 loop0 1 2 3 4 5 6 7 8 9 10 11"
        with patch("canary.read_text", return_value=diskstats_text):
            stats = diskstats()
            self.assertIn("sda", stats)
            self.assertEqual(stats["sda"]["r_ios"], 100)
            self.assertEqual(stats["sda"]["r_sectors"], 200)
            self.assertEqual(stats["sda"]["w_ios"], 300)
            self.assertEqual(stats["sda"]["w_sectors"], 400)
            self.assertNotIn("loop0", stats)

    def test_zram_stats(self):
        zram0 = self.sys_dir / "zram0"
        zram0.mkdir(parents=True)
        (zram0 / "mm_stat").write_text("1000 500 2000 0 0 0 0")
        
        with patch("pathlib.Path.glob", return_value=[zram0]):
            stats = zram_stats()
            self.assertIn("zram0", stats)
            self.assertEqual(stats["zram0"]["orig_bytes"], 1000)
            self.assertEqual(stats["zram0"]["compr_bytes"], 500)
            self.assertEqual(stats["zram0"]["mem_used_bytes"], 2000)

if __name__ == "__main__":
    unittest.main()
