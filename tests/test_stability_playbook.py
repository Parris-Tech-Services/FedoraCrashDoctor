from stability_playbook import build_playbook


def finding(finding_id):
    return {"id": finding_id, "severity": "warning"}


def test_graphics_playbook_contains_controlled_ab_tests():
    actions = build_playbook([finding("intel_display")])
    ids = {item["id"] for item in actions}
    assert "graphics_one_monitor_ab" in ids
    assert "graphics_disable_app_acceleration" in ids
    assert all(item["requires_confirmation"] for item in actions)
    assert not any(item["automatic_action_taken"] for item in actions)


def test_node_and_coredump_findings_get_workload_and_core_guidance():
    actions = build_playbook([finding("node_heap_crash"), finding("coredump_storm")])
    ids = {item["id"] for item in actions}
    assert {"memory_attribute_workload", "coredump_limits", "update_graphics_kernel"} <= ids


def test_playbook_always_offers_silent_mode():
    actions = build_playbook([])
    assert actions[-1]["id"] == "silent_background_mode"
