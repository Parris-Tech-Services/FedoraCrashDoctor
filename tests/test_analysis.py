#!/usr/bin/env python3
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from collector import analyse, analyse_canary, build_incidents, build_overall, build_tasks, build_timeline, extract_pcie_devices, parse_last_crash_time_without_year, parse_lspci_inventory


def check(title, output, category="Software", status="ok"):
    return {"title": title, "output": output, "category": category, "status": status, "returncode": 0, "duration_seconds": 0, "command": "test"}


class AnalysisTests(unittest.TestCase):
    def test_clean_reboot_classification(self):
        checks = {
            "journal_boots": check("boots", "0 00000000000000000000000000000000 2026-07-29 10:00:00 2026-07-29 11:00:00\n-1 11111111111111111111111111111111 2026-07-29 09:00:00 2026-07-29 09:59:00"),
            "previous_boot_tail": check("tail", "2026-07-29T09:58:00+1000 host systemd[1]: Reached target System Reboot.\n2026-07-29T09:58:10+1000 host kwin_wayland[123]: segfault at 0\n"),
            "boot_history": check("history", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 10:00 - still running\nreboot   system boot  7.1.5-200.fc44.x Wed Jul 29 09:00 - crash  (01:00)"),
        }
        findings, context = analyse(checks)
        incidents, warnings, unresolved = build_incidents(findings, checks)

        # Should be filtered out because active session and clean shutdown have no events
        self.assertEqual(len(incidents), 0)

        # Wayland error during shutdown should be suppressed
        wayland_finding = next((f for f in findings if f["id"] == "wayland"), None)
        self.assertIsNone(wayland_finding)

        overall, hyps = build_overall(incidents, warnings)
        self.assertEqual(overall["title"], "No leading cause identified")

    def test_recurring_stability_warnings_remain(self):
        checks = {
            "journal_boots": check("boots", "0 00000000000000000000000000000000 2026-07-29 10:00:00 2026-07-29 11:00:00\n-1 11111111111111111111111111111111 2026-07-29 09:00:00 2026-07-29 09:59:00"),
            "previous_boot_tail": check("tail", "2026-07-29T09:58:00+1000 host systemd[1]: Reached target System Reboot.\n"),
            "display_history": check("history", "2026-07-29T10:15:00+1000 host kernel: i915 atomic update failure"),
        }
        findings, context = analyse(checks)
        incidents, warnings, unresolved = build_incidents(findings, checks)

        overall, hyps = build_overall(incidents, warnings)
        self.assertEqual(overall["title"], "Historical warnings found")
        self.assertIn("not evidence of a current fault", overall["summary"])

    def test_pcie_address_anywhere_is_mapped_to_device(self):
        pci = """0000:02:00.0 Network controller [0280]: Realtek Semiconductor Co., Ltd. RTL8821CE [10ec:c821]\n\tKernel driver in use: rtw88_8821ce\n"""
        logs = """2026-07-29T09:53:40+1000 host kernel: rtw88_8821ce 0000:02:00.0: PCIe Bus Error: severity=Correctable, type=Data Link Layer, (Receiver ID)\n2026-07-29T10:00:00+1000 host kernel: 0000:02:00.0: AER: Corrected error received\n"""
        inventory = parse_lspci_inventory(pci)
        hits = extract_pcie_devices(logs, inventory)
        self.assertIn("0000:02:00.0", hits)
        self.assertEqual(hits["0000:02:00.0"]["driver"], "rtw88_8821ce")
        self.assertIn("RTL8821CE", hits["0000:02:00.0"]["description"])
        self.assertEqual(hits["0000:02:00.0"]["likely_role"], "Wi-Fi card")
        self.assertEqual(hits["0000:02:00.0"]["count"], 2)

    def test_perf_interrupt_message_is_information_not_warning(self):
        checks = {
            "interrupt_latency": check("perf", "2026-07-29 kernel: perf: interrupt took too long (4000 > 3999), lowering kernel.perf_event_max_sample_rate to 50000"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        perf = [f for f in findings if f["id"] == "perf_sampling_adjustment"]
        self.assertEqual(len(perf), 1)
        self.assertEqual(perf[0]["severity"], "info")
        self.assertIn("not a dependable crash predictor", perf[0]["explanation"])

    def test_timeline_marks_last_ten_minutes_as_immediate(self):
        checks = {
            "previous_boot_tail": check("tail", "\n".join([
                "2026-07-29T12:00:00.000000+1000 host kernel: i915: atomic update failure",
                "2026-07-29T12:22:00.000000+1000 host chrome: context provider failed",
                "2026-07-29T12:25:00.000000+1000 host systemd: final ordinary line",
            ]))
        }
        timeline = build_timeline(checks)
        chrome = [item for item in timeline if "context provider" in item["summary"]][0]
        self.assertEqual(chrome["proximity"], "Immediately before crash")
        self.assertEqual(timeline[-1]["category"], "Crash boundary")

    def test_graphics_hypothesis_ranks_above_unsupported_oom(self):
        checks = {
            "previous_errors": check("prev", "2026-07-29T12:26:00+1000 host kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe A"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 1)
        self.assertTrue("Display-stack or KWin Wayland freeze" in incidents[0]["strongest_hypothesis"])

    def test_old_i915_message_unrelated_to_current_incident(self):
        checks = {
            "display_history": check("disp", "2026-07-29T12:26:00+1000 host kernel: i915 atomic update failure on pipe A"),
            "boot_history": check("boot", ""),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        findings[0]["evidence"] = ["2026-07-29T12:26:00+1000 host kernel: i915 atomic update failure on pipe A"]
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 0)

    def test_repeated_correctable_pcie_errors_without_crash(self):
        checks = {
            "hardware_errors_history": check("hw", "2026-07-29T13:26:00+1000 host kernel: pcieport 0000:00:1c.0: AER: Multiple Correctable error message received\n2026-07-29T13:26:00+1000 host kernel: pcieport 0000:00:1c.0: AER: Multiple Correctable error message received\npcieport 0000:00:1c.0: AER: Multiple Correctable error message received"),
            "pci": check("pci", "0000:00:1c.0 PCI bridge [0604]: Intel"),
            "boot_history": check("boot", ""),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 1)
        self.assertTrue("PCIe" in incidents[0]["strongest_hypothesis"])
        self.assertTrue("Active Warning" in incidents[0]["strongest_hypothesis"])

    def test_oom_kill_precedes_frozen_session(self):
        checks = {
            "oom_previous": check("oom", "2026-07-29T12:26:00+1000 host kernel: Out of memory: Killed process"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 2)
        self.assertTrue("Memory/swap exhaustion with swap-I/O thrashing" in incidents[0]["strongest_hypothesis"] or "Memory/swap exhaustion with swap-I/O thrashing" in incidents[1]["strongest_hypothesis"] or "memory-pressure" in incidents[0]["strongest_hypothesis"] or "memory-pressure" in incidents[1]["strongest_hypothesis"])

    def test_multiple_unrelated_warnings_same_boot(self):
        checks = {
            "previous_errors": check("prev", "2026-07-29T13:00:00+1000 host kernel: i915 atomic update failure\n2026-07-29T13:00:00+1000 host kernel: Buffer I/O error on dev sda1"),
            "thermal_previous": check("therm", "2026-07-29T13:00:00+1000 host kernel: cpu clock throttled"),
            "block": check("block", "sda /dev/sda disk 16G usb"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:00:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:01 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertTrue(len([w for w in boot_warnings if w["boot_index"] == "0"]) > 0)

    def test_crash_insufficient_evidence(self):
        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 13:26:00 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 1)
        self.assertTrue("Unknown Kernel, Firmware or Power Failure" in incidents[0]["strongest_hypothesis"])

    def test_storage_finding_dynamically_assigned(self):
        checks = {
            "smart_tests": check("smart", "dummy"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 15:52:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 15:53:00 AEST Wed 2026-07-29 15:55:00 AEST")
        }
        findings, _ = analyse(checks)
        findings.append({"id": "storage_nvme0n1", "title": "Storage error", "category": "Storage", "severity": "critical", "evidence": ["2026-07-29T15:50:00+1000 host kernel: nvme0n1 error"], "boot_index": "-1"})
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertTrue("Storage" in incidents[0]["strongest_hypothesis"])

    def test_thermal_finding_dynamically_assigned(self):
        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 15:52:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 15:53:00 AEST Wed 2026-07-29 15:55:00 AEST")
        }
        findings, _ = analyse(checks)
        findings.append({"id": "thermal", "title": "Thermal protection", "category": "Thermals", "severity": "critical", "evidence": ["2026-07-29T15:50:00+1000 host kernel: critical temperature reached"], "boot_index": "-1"})
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertTrue("Thermal" in incidents[0]["strongest_hypothesis"])

    def test_tasks_use_structured_metadata_to_prevent_spoofing(self):
        tasks = build_tasks("quick")
        for name in ["display_current", "display_previous"]:
            task = next(t for t in tasks if t.key == name)
            self.assertTrue("SYSLOG_IDENTIFIER=kernel" in task.command)
            self.assertTrue("+ _COMM=kwin_wayland" in task.command)
            self.assertTrue("+ _COMM=kwin_x11" in task.command)
        for name in ["oom_previous", "oom_history"]:
            task = next(t for t in tasks if t.key == name)
            self.assertTrue("SYSLOG_IDENTIFIER=kernel" in task.command)
            self.assertTrue("+ _COMM=systemd-oomd" in task.command)
        for name in ["hardware_errors_previous", "hardware_errors_history", "thermal_previous"]:
            task = next(t for t in tasks if t.key == name)
            self.assertTrue("-k" in task.command)

    def test_canary_handles_null_desktop_heartbeat_age(self):
        checks = {
            "canary_log": check("canary", '{"ts":"now","desktop_heartbeat_age_s":null,"kwin_ok":null}\n')
        }
        result = analyse_canary(checks)
        self.assertIn("samples", result)
        self.assertIn("heartbeat", result["interpretation"])


    def test_wayland_crash_is_identified(self):
        checks = {
            "previous_errors": check("prev", "wayland-server: fatal error in compositor"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        wayland = [f for f in findings if f["id"] == "wayland"]
        self.assertEqual(len(wayland), 1)
        self.assertEqual(wayland[0]["severity"], "warning")

    def test_wayland_shutdown_is_ignored(self):
        checks = {
            "previous_errors": check("prev", "wayland-server: error disconnected\nwayland-server: terminate"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        wayland = [f for f in findings if f["id"] == "wayland"]
        self.assertEqual(len(wayland), 0)

    def test_failed_systemd_services_near_crash(self):
        checks = {
            "previous_boot_tail": check("tail", "2026-08-04T12:00:00+1000 host systemd[1]: dbus.service: Failed with result 'exit-code'.\n2026-08-04T12:05:00+1000 host kernel: crash"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        services = [f for f in findings if f["id"] == "failed_services"]
        self.assertEqual(len(services), 1)

    def test_failed_systemd_services_far_from_crash_ignored(self):
        checks = {
            "previous_boot_tail": check("tail", "2026-08-04T10:00:00+1000 host systemd[1]: dbus.service: Failed with result 'exit-code'.\n2026-08-04T12:05:00+1000 host kernel: crash"),
            "boot_history": check("boot", ""),
            "pstore": check("pstore", "No pstore crash records found."),
            "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        services = [f for f in findings if f["id"] == "failed_services"]
        self.assertEqual(len(services), 0)

    def test_repeated_system_disk_errors_are_critical(self):
        checks = {
            "previous_errors": check("prev", "I/O error on dev nvme0n1\nI/O error on dev nvme0n1\nI/O error on dev nvme0n1"),
            "block": check("block", "nvme0n1 /dev/nvme0n1 disk 256G nvme"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_nvme0n1"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "critical")
        self.assertIn("Attribute the physical device", storage[0]["explanation"])

    def test_single_removable_drive_error_is_info(self):
        checks = {
            "previous_errors": check("prev", "I/O error on dev sda1"),
            "block": check("block", "sda /dev/sda disk 16G usb"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_sda1"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "info")

    def test_unsafe_removal_is_info(self):
        checks = {
            "previous_errors": check("prev", "USB disconnect\nI/O error on dev sda1 write"),
            "block": check("block", "sda /dev/sda disk 16G usb"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_sda1"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "info")
        self.assertIn("unsafe removal", storage[0]["explanation"])

    def test_smart_failure_is_critical(self):
        checks = {
            "previous_errors": check("prev", "SMART overall-health self-assessment test result: FAILED! on dev sda"),
            "block": check("block", "sda /dev/sda disk 1000G sata"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_sda"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "critical")

    def test_unidentified_device_error(self):
        checks = {
            "previous_errors": check("prev", "I/O error occurred"),
            "boot_history": check("boot", ""), "pstore": check("pstore", ""), "pci": check("pci", ""),
        }
        findings, _ = analyse(checks)
        storage = [f for f in findings if f["id"] == "storage_unknown"]
        self.assertEqual(len(storage), 1)
        self.assertEqual(storage[0]["severity"], "warning")



    def test_crash_from_boot_minus_3_not_assigned_to_minus_1(self):
        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Sun Jul 26 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-3 e2110b7c6f7e4e72afca6dfe736dbfb8 Sun 2026-07-26 12:26:00 AEST Sun 2026-07-26 15:51:00 AEST\n-1 aec9240f60294f9d8207a3caadb072f1 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        inc_minus_1 = [i for i in incidents if i["boot_index"] == "-1"]
        inc_minus_3 = [i for i in incidents if i["boot_index"] == "-3"]
        self.assertEqual(len(inc_minus_1), 0)
        self.assertEqual(len(inc_minus_3), 1)
        self.assertEqual(inc_minus_3[0]["failure_boundary"], "unclean shutdown")

    def test_multiple_crash_records_map_to_respective_boots(self):
        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Sun Jul 26 12:26 - crash  (03:25)\nreboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-3 e2110b7c6f7e4e72afca6dfe736dbfb8 Sun 2026-07-26 12:26:00 AEST Sun 2026-07-26 15:51:00 AEST\n-1 aec9240f60294f9d8207a3caadb072f1 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 15:51:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 2)

    def test_crash_record_without_year_unresolved_when_ambiguous(self):
        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Sun Jul 26 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-2 e2110b7c6f7e4e72afca6dfe736dbfb8 Sun 2025-07-26 12:26:00 AEST Sun 2025-07-26 15:51:00 AEST\n-1 aec9240f60294f9d8207a3caadb072f1 Sun 2026-07-26 12:26:00 AEST Sun 2026-07-26 15:51:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 0)

    def test_yearless_last_timestamp_parser(self):
        parsed = parse_last_crash_time_without_year("Wed Jul 29 12:26")
        self.assertEqual(parsed, {"month": 7, "day": 29, "hour": 12, "minute": 26})
        self.assertIsNone(parse_last_crash_time_without_year("not a crash timestamp"))

    def test_build_tasks_has_unique_keys(self):
        for mode in ("quick", "full"):
            keys = [task.key for task in build_tasks(mode)]
            self.assertEqual(len(keys), len(set(keys)))

    def test_adjacent_boots_do_not_receive_same_event(self):
        checks = {
            "previous_errors": check("prev", "2026-07-26T15:50:00+1000 host kernel: i915 atomic update failure"),
            "journal_boots": check("boots", "-2 e2110b7c6f7e4e72afca6dfe736dbfb8 Sun 2026-07-26 12:26:00 AEST Sun 2026-07-26 15:51:00 AEST\n-1 aec9240f60294f9d8207a3caadb072f1 Sun 2026-07-26 15:52:00 AEST Sun 2026-07-26 18:51:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        warnings_minus_2 = [w for w in boot_warnings if w["boot_index"] == "-2"]
        warnings_minus_1 = [w for w in boot_warnings if w["boot_index"] == "-1"]
        self.assertEqual(len(warnings_minus_2), 1)
        self.assertEqual(len(warnings_minus_1), 0)

    def test_crash_outside_available_boot_history_unresolved(self):
        checks = {
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Sun Jul 20 12:26 - crash  (03:25)"),
            "journal_boots": check("boots", "-1 aec9240f60294f9d8207a3caadb072f1 Sun 2026-07-26 12:26:00 AEST Sun 2026-07-26 15:51:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, boot_warnings, unresolved = build_incidents(findings, checks)
        self.assertEqual(len(incidents), 0)



    def test_overall_no_incidents(self):
        overall, hypotheses = build_overall([])
        self.assertEqual(overall["title"], "No leading cause identified")
        self.assertEqual(hypotheses, [])

    def test_overall_incidents_no_hypotheses(self):
        incidents = [{"boot_index": "0", "sort_key": 0, "failure_boundary": "active session", "hypotheses": []}]
        overall, hypotheses = build_overall(incidents)
        self.assertEqual(overall["title"], "No leading cause identified")
        self.assertEqual(hypotheses, [])

    def test_overall_only_boot_warnings(self):
        incidents = []
        overall, hypotheses = build_overall(incidents)
        self.assertEqual(overall["title"], "No leading cause identified")
        self.assertEqual(hypotheses, [])

    def test_overall_only_unresolved_evidence(self):
        incidents = []
        overall, hypotheses = build_overall(incidents)
        self.assertEqual(overall["title"], "No leading cause identified")
        self.assertEqual(hypotheses, [])

    def test_oom_five_minutes_before_crash(self):
        checks = {
            "oom_previous": check("oom", "2026-07-29T12:21:00+1000 host kernel: Out of memory: Killed process"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:00 - crash  (00:26)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:00:00 AEST Wed 2026-07-29 12:26:00 AEST\n0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:01 AEST Wed 2026-07-29 13:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _, _ = build_incidents(findings, checks)

        self.assertEqual(len(incidents), 2)
        oom_inc = next(i for i in incidents if i["failure_boundary"] == "OOM event")
        crash_inc = next(i for i in incidents if i["failure_boundary"] == "unclean shutdown")

        # The OOM event at 12:21 should be in the OOM window (12:06 to 12:22)
        self.assertTrue(any("Out of memory" in e["line"] for e in oom_inc["incident_evidence"]))

        # The OOM event at 12:21 should ALSO be in the crash window (12:11 to 12:27)
        self.assertTrue(any("Out of memory" in e["line"] for e in crash_inc["incident_evidence"]))

        self.assertEqual(crash_inc["strongest_hypothesis"], "Memory/swap exhaustion with swap-I/O thrashing")

    def test_wayland_crash_before_unclean_shutdown(self):
        checks = {
            "previous_errors": check("prev", "2026-07-29T12:21:00+1000 host wayland-server: fatal error in compositor"),
            "boot_history": check("boot", "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:00 - crash  (00:26)"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:00:00 AEST Wed 2026-07-29 12:26:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _, _ = build_incidents(findings, checks)

        self.assertEqual(len(incidents), 2)
        wayland_inc = next(i for i in incidents if i["failure_boundary"] == "compositor crash")
        crash_inc = next(i for i in incidents if i["failure_boundary"] == "unclean shutdown")

        self.assertTrue(any("wayland-server" in e["line"] for e in wayland_inc["incident_evidence"]))
        self.assertTrue(any("wayland-server" in e["line"] for e in crash_inc["incident_evidence"]))

    def test_two_unrelated_boundaries_overlap(self):
        checks = {
            "previous_errors": check("prev", "2026-07-29T12:21:00+1000 host wayland-server: fatal error in compositor"),
            "oom_previous": check("oom", "2026-07-29T12:22:00+1000 host kernel: Out of memory: Killed process"),
            "journal_boots": check("boots", "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:00:00 AEST Wed 2026-07-29 12:30:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _, _ = build_incidents(findings, checks)

        self.assertEqual(len(incidents), 2)
        wayland_inc = next(i for i in incidents if i["failure_boundary"] == "compositor crash")
        oom_inc = next(i for i in incidents if i["failure_boundary"] == "OOM event")

        # Wayland event is in both
        self.assertTrue(any("wayland-server" in e["line"] for e in wayland_inc["incident_evidence"]))
        self.assertTrue(any("wayland-server" in e["line"] for e in oom_inc["incident_evidence"]))

        # OOM event is in both
        self.assertTrue(any("Out of memory" in e["line"] for e in wayland_inc["incident_evidence"]))
        self.assertTrue(any("Out of memory" in e["line"] for e in oom_inc["incident_evidence"]))

    def test_incidents_different_order_identical_output(self):
        # build_overall sorts by sort_key, order shouldn't matter
        inc1 = {"boot_index": "0", "sort_key": 1, "failure_boundary": "active session", "hypotheses": [{"title": "A", "confidence": "high"}]}
        inc2 = {"boot_index": "0", "sort_key": 2, "failure_boundary": "active session", "hypotheses": [{"title": "B", "confidence": "high"}]}

        out1, hyp1 = build_overall([inc1, inc2])
        out2, hyp2 = build_overall([inc2, inc1])

        self.assertEqual(out1, out2)
        self.assertEqual(hyp1, hyp2)
        self.assertEqual(out1["title"], "B")

    def test_overall_build_with_missing_boot_key(self):
        # Regression test for KeyError: 'boot'
        # incidents didn't have 'boot' but had 'boot_index'
        inc1 = {"boot_index": "-1", "sort_key": 1, "failure_boundary": "unclean shutdown", "hypotheses": [{"title": "A", "confidence": "high"}]}
        try:
            out, hyp = build_overall([inc1])
            self.assertEqual(out["title"], "A")
        except KeyError as e:
            self.fail(f"build_overall raised KeyError: {e}")

    def test_wayland_crash_in_current_boot_is_captured(self):
        # Regression test for current-boot Wayland segfault not being captured
        checks = {
            "display_current": check("curr", "2026-08-27T08:43:11.136497+10:00 host kwin_wayland[8851]: segfault at address 0x0"),
            "boot_history": check("boot", ""),
            "journal_boots": check("boots", "0 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-08-27 08:00:00 AEST Wed 2026-08-27 09:00:00 AEST")
        }
        findings, _ = analyse(checks)
        incidents, _, _ = build_incidents(findings, checks)

        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["boot_index"], "0")
        self.assertEqual(incidents[0]["failure_boundary"], "compositor crash")
        self.assertTrue(any("segfault" in e["line"] for e in incidents[0]["incident_evidence"]))




    def test_readiness_journal_no_previous(self):
        from collector import assess_readiness
        checks = {"journal_dir": {"returncode": 0, "output": "/var/log/journal"}, "journal_boots": {"output": "0 boot current"}}
        res = assess_readiness(checks)
        j = next(s for s in res["sources"] if s["name"] == "Persistent Journal")
        self.assertEqual(j["status"], "unverified")

    def test_readiness_pstore_command_failure(self):
        from collector import assess_readiness
        checks = {"pstore": {"returncode": 1, "output": "ls: cannot access /sys/fs/pstore"}}
        res = assess_readiness(checks)
        p = next(s for s in res["sources"] if s["name"] == "EFI pstore")
        self.assertEqual(p["status"], "error")

    def test_readiness_pstore_unverified(self):
        from collector import assess_readiness
        checks = {"pstore": {"returncode": 0, "output": "No pstore crash records found"}}
        res = assess_readiness(checks)
        p = next(s for s in res["sources"] if s["name"] == "EFI pstore")
        self.assertEqual(p["status"], "unverified")

    def test_readiness_kdump_no_reservation(self):
        from collector import assess_readiness
        checks = {"kdump_package": {"returncode": 0}, "kdump_service": {"output": "active"}, "crashkernel_mem": {"output": "root=UUID"}}
        res = assess_readiness(checks)
        k = next(s for s in res["sources"] if s["name"] == "Kdump Infrastructure")
        self.assertEqual(k["status"], "missing_reservation")

    def test_readiness_kdump_not_loaded(self):
        from collector import assess_readiness
        checks = {"kdump_package": {"returncode": 0}, "kdump_service": {"output": "active"}, "crashkernel_mem": {"output": "crashkernel=512M"}, "kexec_loaded": {"output": "0"}}
        res = assess_readiness(checks)
        k = next(s for s in res["sources"] if s["name"] == "Kdump Infrastructure")
        self.assertEqual(k["status"], "kernel_not_loaded")

    def test_readiness_kdump_target_missing(self):
        from collector import assess_readiness
        checks = {"kdump_package": {"returncode": 0}, "kdump_service": {"output": "active"}, "crashkernel_mem": {"output": "crashkernel=512M"}, "kexec_loaded": {"output": "1"}, "kdump_target_space": {"returncode": 1, "output": "No such file or directory"}}
        res = assess_readiness(checks)
        k = next(s for s in res["sources"] if s["name"] == "Kdump Infrastructure")
        self.assertEqual(k["status"], "target_missing")

    def test_readiness_panic_disabled_intentionally(self):
        from collector import assess_readiness
        checks = {"sysctl_panic": {"output": "kernel.panic_on_oops = 0"}}
        res = assess_readiness(checks)
        s = next(s for s in res["sources"] if s["name"] == "Kernel Panic Settings")
        self.assertEqual(s["status"], "disabled_intentionally")

    def test_readiness_kernel_panic_zero(self):
        from collector import assess_readiness
        checks = {"sysctl_panic": {"output": "kernel.panic = 0"}}
        res = assess_readiness(checks)
        s = next(s for s in res["sources"] if s["name"] == "Kernel Panic Settings")
        self.assertEqual(s["status"], "disabled_intentionally")

    def test_readiness_canary_stale(self):
        import time
        from collector import assess_readiness
        checks = {"canary_service": {"output": "active"}, "canary_stat": {"output": str(int(time.time() - 300))}}
        res = assess_readiness(checks)
        c = next(s for s in res["sources"] if s["name"] == "System Canary")
        self.assertEqual(c["status"], "stale")

    def test_readiness_fully_verified(self):
        import time
        from collector import assess_readiness
        checks = {
            "journal_dir": {"returncode": 0}, "journal_boots": {"output": "-1 boot\n0 boot"},
            "pstore": {"returncode": 0, "output": "panic record"},
            "sysctl_panic": {"output": "kernel.panic = 10\nkernel.panic_on_oops = 1\nkernel.softlockup_panic = 1\nkernel.nmi_watchdog = 1\nkernel.hardlockup_panic = 1"},
            "kdump_package": {"returncode": 0}, "kdump_service": {"output": "active"}, "crashkernel_mem": {"output": "crashkernel=512M"}, "kexec_loaded": {"output": "1"}, "kdump_target_space": {"returncode": 0, "output": "100G avail"},
            "canary_service": {"output": "active"}, "canary_stat": {"output": str(int(time.time()))}
        }
        res = assess_readiness(checks)
        for s in res["sources"]:
            self.assertIn(s["status"], ["verified_persistent", "available_with_records", "verified_ready", "ready", "verified_active"])


if __name__ == "__main__":
    unittest.main()
