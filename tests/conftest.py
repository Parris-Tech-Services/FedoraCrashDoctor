import os

# Tests must never open visible Fedora Crash Doctor windows.
# This prevents disruptive popup windows during automated testing.
os.environ["QT_QPA_PLATFORM"] = "offscreen"

import time

import pytest


def _set_host_tz(value: str | None) -> None:
    if value is None:
        os.environ.pop("TZ", None)
    else:
        os.environ["TZ"] = value
    time.tzset()


@pytest.fixture
def host_tz():
    """Set the host's local timezone for the duration of one test.

    Incident windows come from journal text, which is naive host-local time,
    while canary samples carry an explicit offset. Tests whose fixtures are
    written in a specific local zone must say so instead of relying on the
    machine running them being in that zone.
    """
    original = os.environ.get("TZ")
    yield _set_host_tz
    _set_host_tz(original)


@pytest.fixture
def sydney_host_tz(host_tz):
    """Host-local time is Australia/Sydney (fixtures use AEST / +10:00)."""
    host_tz("Australia/Sydney")
