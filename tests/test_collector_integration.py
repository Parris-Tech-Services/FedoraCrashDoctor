import pytest
import collector
import shutil


def test_collector_includes_normalized_coredumps_in_report(monkeypatch, sydney_host_tz):
    # The boot window below is journalctl text in AEST; the coredump epoch is
    # 2026-08-31 10:55 AEST, so the host must be on Sydney time to match it.
    import json
    
    # Mock get_systemd_coredumps to return a structured kwin_wayland crash
    def mock_get_coredumps(*args, **kwargs):
        return [{
            "incident_source": "systemd-coredump",
            "boot_id": "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1",
            "timestamp": 1788137700.0,
            "pid": 9999,
            "signal": 11,
            "signal_name": "SIGSEGV",
            "executable": "/usr/bin/kwin_wayland",
            "core_available": True,
            "raw_source_hash": "abc"
        }]
        
    monkeypatch.setattr("coredump_adapter.get_systemd_coredumps", mock_get_coredumps)
    
    # Mock runner and boots to create a clean environment
    class MockRunner:
        def __init__(self, *args, **kwargs):
            self.cancelled = False
        def execute(self):
            return {
                "journal_boots": {"output": " 0 b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1 Mon 2026-08-31 10:00:00 AEST—Mon 2026-08-31 11:00:00 AEST"}
            }
            
    monkeypatch.setattr("collector.CheckRunner", MockRunner)
    
    # Mock validate_report so we don't need a full valid report schema
    monkeypatch.setattr("collector.validate_report", lambda x: None)
    
    report = collector.collect("quick")
    incidents = report.get("incidents", [])
    
    # We should have an active session incident for boot 0 (b1) 
    assert len(incidents) >= 1
    kwin_incident = next(i for i in incidents if i["boot_id"] == "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1")
    
    # Verify coredump is attached to the incident
    assert "coredumps" in kwin_incident
    assert len(kwin_incident["coredumps"]) == 1
    core = kwin_incident["coredumps"][0]
    
    assert core["pid"] == 9999
    assert core["executable"] == "/usr/bin/kwin_wayland"
    assert core["signal"] == 11
    assert core["boot_id"] == "b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1b1"


def test_collect_attaches_explainable_confidence_to_every_incident(monkeypatch):
    """collect() must actually call confidence_explanation.explain_incident()
    for the real pipeline, not just leave it as a tested-but-unused library --
    this is a regression test for that wiring, independent of any GUI code."""
    class MockRunner:
        def __init__(self, *args, **kwargs):
            self.cancelled = False

        def execute(self):
            return {
                "previous_errors": {
                    "title": "prev", "category": "Software", "status": "ok",
                    "returncode": 0, "duration_seconds": 0, "command": "test",
                    "output": "2026-07-29T12:26:00+1000 host kernel: i915 0000:00:02.0: [drm] *ERROR* Atomic update failure on pipe A",
                },
                "boot_history": {
                    "title": "boot", "category": "Software", "status": "ok",
                    "returncode": 0, "duration_seconds": 0, "command": "test",
                    "output": "reboot   system boot  7.1.5-200.fc44.x Wed Jul 29 12:26 - crash  (03:25)",
                },
                "journal_boots": {
                    "title": "boots", "category": "Software", "status": "ok",
                    "returncode": 0, "duration_seconds": 0, "command": "test",
                    "output": "-1 e2110b7c6f7e4e72afca6dfe736dbfb8 Wed 2026-07-29 12:26:00 AEST Wed 2026-07-29 12:26:00 AEST",
                },
            }

    monkeypatch.setattr("collector.CheckRunner", MockRunner)
    monkeypatch.setattr("coredump_adapter.get_systemd_coredumps", lambda *a, **k: [])
    monkeypatch.setattr("collector.validate_report", lambda x: None)

    report = collector.collect("quick")
    incidents = report.get("incidents", [])
    assert len(incidents) >= 1

    incident = incidents[0]
    assert "hypothesis_explanations" in incident
    explanations = incident["hypothesis_explanations"]
    assert len(explanations) == len(incident.get("hypotheses", []))
    if explanations:
        assert "mechanism" in explanations[0]
        assert "missing_evidence" in explanations[0]
        assert explanations[0]["recurrence_context"] is None  # single-scan collect() has no history


def test_analyse_identifies_node_heap_abort_and_coredump_storm():
    checks = {
        "coredumps_json": {"structured_evidence": [
            {"executable": "/home/josh/.local/bin/node", "command": "next-server", "signal_name": "SIGABRT", "pid": 10, "timestamp": 1},
            {"executable": "/home/josh/.local/bin/node", "command": "next-server FatalProcessOutOfMemory", "signal_name": "SIGABRT", "pid": 11, "timestamp": 2},
        ]},
    }
    findings, _ = collector.analyse(checks)
    ids = {finding["id"] for finding in findings}
    assert "node_heap_crash" in ids
    assert "coredump_storm" in ids


def test_tail_files_preserves_rotated_canary_order(tmp_path):
    paths = []
    for suffix, text in ((".3", "old"), (".2", "middle"), (".1", "newer"), ("", "active")):
        path = tmp_path / f"canary.log{suffix}"
        path.write_text(text)
        paths.append(path)

    output = collector.tail_files(paths, 1200)
    assert output.index("old") < output.index("middle") < output.index("newer") < output.index("active")
