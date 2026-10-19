#!/usr/bin/env python3
"""Small built-in report contract for Fedora Crash Doctor.

The project intentionally avoids requiring jsonschema at runtime. This module
implements a strict-enough structural validator that protects the collector,
GUI, exports and historical fixtures from drifting apart.
"""
from __future__ import annotations

from typing import Any

REPORT_SCHEMA_VERSION = 1
CHECK_STATES = {
    "pending",
    "running",
    "completed",
    "failed",
    "timed_out",
    "cancelled",
    "skipped",
    "unavailable",
    "permission_denied",
}
REQUIRED_REPORT_KEYS = {
    "schema",
    "schema_version",
    "metadata",
    "counts",
    "overall",
    "categories",
    "freeze_classes",
    "readiness",
    "findings",
    "timeline",
    "checks",
    "test_targets",
    "limitations",
}


class ReportSchemaError(ValueError):
    pass


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise ReportSchemaError(message)


def validate_report(report: dict[str, Any], allow_future_fields: bool = True) -> None:
    _require(isinstance(report, dict), "report must be an object")
    missing = REQUIRED_REPORT_KEYS - set(report)
    _require(not missing, f"report missing required keys: {', '.join(sorted(missing))}")
    _require(report.get("schema_version") == REPORT_SCHEMA_VERSION, "unsupported report schema_version")
    _require(isinstance(report.get("metadata"), dict), "metadata must be an object")
    _require(isinstance(report.get("counts"), dict), "counts must be an object")
    _require(isinstance(report.get("overall"), dict), "overall must be an object")
    _require(isinstance(report.get("categories"), dict), "categories must be an object")
    _require(isinstance(report.get("freeze_classes"), list), "freeze_classes must be a list")
    _require(isinstance(report.get("readiness"), dict), "readiness must be an object")
    _require(isinstance(report.get("findings"), list), "findings must be a list")
    _require(isinstance(report.get("timeline"), list), "timeline must be a list")
    _require(isinstance(report.get("checks"), dict), "checks must be an object")
    _require(isinstance(report.get("test_targets"), dict), "test_targets must be an object")
    _require(isinstance(report.get("limitations"), list), "limitations must be a list")

    for key in ("generated", "mode", "version"):
        _require(key in report["metadata"], f"metadata.{key} is required")
    _require(report["metadata"]["mode"] in {"quick", "full", "deep", "manual-mark"}, "metadata.mode is invalid")

    for key in ("critical", "warning", "info"):
        _require(isinstance(report["counts"].get(key), int), f"counts.{key} must be an integer")

    for check_id, check in report["checks"].items():
        _require(isinstance(check_id, str) and check_id, "check id must be a non-empty string")
        _require(isinstance(check, dict), f"check {check_id} must be an object")
        for key in ("title", "category", "command", "status", "state", "returncode", "duration_seconds", "output"):
            _require(key in check, f"check {check_id} missing {key}")
        _require(check["state"] in CHECK_STATES, f"check {check_id} has invalid state {check['state']!r}")
        _require(isinstance(check["duration_seconds"], (int, float)), f"check {check_id} duration must be numeric")
        _require(isinstance(check["output"], str), f"check {check_id} output must be a string")

    for finding in report["findings"]:
        _require(isinstance(finding, dict), "finding must be an object")
        for key in ("id", "severity", "category", "title", "explanation", "evidence"):
            _require(key in finding, f"finding missing {key}")
        _require(finding["severity"] in {"critical", "warning", "info"}, "finding severity is invalid")
        _require(isinstance(finding["evidence"], list), "finding evidence must be a list")

    if not allow_future_fields:
        extra = set(report) - REQUIRED_REPORT_KEYS - {"incidents", "boot_warnings", "unresolved_evidence", "hypotheses", "canary", "partial", "cancelled"}
        _require(not extra, f"unknown report keys: {', '.join(sorted(extra))}")


def migrate_report(report: dict[str, Any]) -> dict[str, Any]:
    """Return a schema-versioned report while preserving older report fields."""
    if "schema_version" not in report:
        report = dict(report)
        report["schema_version"] = REPORT_SCHEMA_VERSION
    return report
