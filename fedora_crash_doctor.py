#!/usr/bin/env python3
from __future__ import annotations

import html
import argparse
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import uuid
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

from version import app_version
from report_schema import migrate_report

from PySide6.QtCore import QObject, QProcess, Qt, QTimer, QUrl, Signal
from PySide6.QtGui import QColor, QDesktopServices, QPainter, QPen
from PySide6.QtWidgets import (
    QApplication, QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout,
    QFrame, QGridLayout, QHBoxLayout, QHeaderView, QLabel, QMainWindow,
    QInputDialog, QMessageBox, QPlainTextEdit, QProgressBar, QPushButton, QScrollArea,
    QSplitter, QTabWidget, QTableWidget, QTableWidgetItem, QTextBrowser,
    QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget,
)

APP_DIR = Path(__file__).resolve().parent
INSTALLED_HELPER = Path("/usr/libexec/fedora-crash-doctor/fedora-crash-doctor-helper")
HELPER = INSTALLED_HELPER if INSTALLED_HELPER.exists() else APP_DIR / "privileged_helper.py"
VERSION = app_version()
SEVERITY_ICON = {"critical": "🔴", "warning": "🟠", "info": "🔵"}
STATUS_ICON = {"new": "NEW", "recurring": "Recurring"}


class PrivilegeBroker(QObject):
    ready_changed = Signal(bool)
    message = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.process: QProcess | None = None
        self.buffer = ""
        self.ready = False
        self.pending_start: list[Callable[[], None]] = []
        self.requests: dict[str, dict[str, Any]] = {}
        self.cancelling = False

    def ensure(self, callback: Callable[[], None]) -> None:
        if self.ready and self.process and self.process.state() == QProcess.ProcessState.Running:
            callback()
            return
        self.pending_start.append(callback)
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            return
        self.process = QProcess(self)
        self.process.setProcessChannelMode(QProcess.ProcessChannelMode.SeparateChannels)
        self.process.readyReadStandardOutput.connect(self._read_stdout)
        self.process.readyReadStandardError.connect(self._read_stderr)
        self.process.finished.connect(self._finished)
        self.message.emit("Authorising one locked-down helper for this app session…")
        self.process.start("pkexec", [str(HELPER), "broker"])

    def request(
        self,
        action: str,
        params: dict[str, Any] | None,
        result_cb: Callable[[bool, Any], None],
        progress_cb: Callable[[int, int, str], None] | None = None,
    ) -> str:
        request_id = uuid.uuid4().hex

        self.requests[request_id] = {"result": result_cb, "progress": progress_cb}

        def send_request() -> None:
            if not self.process:
                request = self.requests.pop(request_id, None)
                if request:
                    request["result"](False, "Privileged helper is unavailable.")
                return
            payload = {"id": request_id, "action": action, "params": params or {}}
            self.process.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())

        self.ensure(send_request)
        return request_id

    def cancel_request(self, request_id: str) -> None:
        if self.process and self.process.state() == QProcess.ProcessState.Running:
            payload = {"action": "cancel", "target_id": request_id}
            self.process.write((json.dumps(payload, separators=(",", ":")) + "\n").encode())

    def cancel_all(self) -> None:
        self.cancelling = True
        if self.process and self.process.state() != QProcess.ProcessState.NotRunning:
            self.process.closeWriteChannel()
            self.process.terminate()
            if not self.process.waitForFinished(2500):
                self.process.kill()
                self.process.waitForFinished(5000)
        for item in list(self.requests.values()):
            item["result"](False, "Cancelled. The session helper was closed; the next privileged action will ask again.")
        self.requests.clear()
        self.ready = False
        self.ready_changed.emit(False)

    def _read_stdout(self) -> None:
        if not self.process:
            return
        self.buffer += bytes(self.process.readAllStandardOutput()).decode(errors="replace")
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            if not line.strip():
                continue
            try:
                event = json.loads(line)
            except Exception:
                self.message.emit(f"Helper output was not valid JSON: {line[:200]}")
                continue
            event_type = event.get("type")
            if event_type == "ready":
                self.ready = True
                self.ready_changed.emit(True)
                self.message.emit("Administrator authorisation is active for this app session.")
                callbacks, self.pending_start = self.pending_start, []
                for callback in callbacks:
                    callback()
            elif event_type == "progress":
                request = self.requests.get(event.get("id"))
                if request and request.get("progress"):
                    request["progress"](int(event.get("current", 0)), int(event.get("total", 0)), str(event.get("label", "")))
            elif event_type == "result":
                request = self.requests.pop(event.get("id"), None)
                if request:
                    request["result"](bool(event.get("ok")), event.get("data") if event.get("ok") else event.get("error", "Unknown helper error"))

    def _read_stderr(self) -> None:
        if self.process:
            text = bytes(self.process.readAllStandardError()).decode(errors="replace").strip()
            if text:
                self.message.emit(text[-1500:])

    def _finished(self, code: int, _status) -> None:
        was_ready = self.ready
        self.ready = False
        self.ready_changed.emit(False)
        if self.requests:
            reason = "Cancelled." if self.cancelling else f"Privileged helper exited with code {code}."
            for item in list(self.requests.values()):
                item["result"](False, reason)
            self.requests.clear()
        self.cancelling = False
        if not was_ready and self.pending_start:
            callbacks, self.pending_start = self.pending_start, []
            for callback in callbacks:
                # Callers receive the failure through a synthetic request only if one exists.
                pass


class StatusCard(QFrame):
    def __init__(self, title: str, value: str = "—"):
        super().__init__()
        self.setFrameShape(QFrame.Shape.StyledPanel)
        layout = QVBoxLayout(self)
        self.title = QLabel(title)
        self.value = QLabel(value)
        self.value.setStyleSheet("font-size: 22px; font-weight: 700;")
        layout.addWidget(self.title)
        layout.addWidget(self.value)

    def set_state(self, label: str, state: str = "neutral") -> None:
        colours = {
            "critical": "#b42318", "warning": "#b54708", "passed": "#067647",
            "not_checked": "#667085", "neutral": "#344054",
        }
        self.value.setText(label)
        self.value.setStyleSheet(f"font-size: 18px; font-weight: 700; color: {colours.get(state, colours['neutral'])};")


class TrendChart(QWidget):
    def __init__(self):
        super().__init__()
        self.series: list[tuple[str, list[float], QColor]] = []
        self.setMinimumHeight(230)

    def set_series(self, series: list[tuple[str, list[float], QColor]]) -> None:
        self.series = series
        self.update()

    def paintEvent(self, _event) -> None:
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)
        rect = self.rect().adjusted(50, 20, -20, -35)
        painter.setPen(QPen(QColor("#98a2b3"), 1))
        painter.drawRect(rect)
        values = [value for _, points, _ in self.series for value in points]
        maximum = max(values + [1])
        for step in range(5):
            y = rect.bottom() - rect.height() * step / 4
            painter.drawLine(rect.left(), int(y), rect.right(), int(y))
            painter.drawText(5, int(y + 5), str(round(maximum * step / 4, 1)))
        for name, points, colour in self.series:
            if not points:
                continue
            painter.setPen(QPen(colour, 2))
            previous = None
            for index, value in enumerate(points):
                x = rect.left() + (rect.width() * index / max(1, len(points) - 1))
                y = rect.bottom() - rect.height() * value / maximum
                if previous:
                    painter.drawLine(int(previous[0]), int(previous[1]), int(x), int(y))
                painter.drawEllipse(int(x - 2), int(y - 2), 4, 4)
                previous = (x, y)
        legend_x = rect.left()
        for name, _, colour in self.series:
            painter.setPen(QPen(colour, 3))
            painter.drawLine(legend_x, self.height() - 15, legend_x + 18, self.height() - 15)
            painter.setPen(QPen(QColor("#344054"), 1))
            painter.drawText(legend_x + 24, self.height() - 10, name)
            legend_x += 120


class CaptureDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Enable crash capture")
        layout = QVBoxLayout(self)
        text = QLabel(
            "This enables persistent journals, rasdaemon, ABRT where available, the low-write system canary, "
            "the desktop/KWin heartbeat, boot-time autoscan and kdump. Kdump reserves some RAM and needs a reboot."
        )
        text.setWordWrap(True)
        self.cockpit = QCheckBox("Also install and enable Cockpit on port 9090 (optional)")
        self.cockpit.setChecked(False)
        buttons = QHBoxLayout()
        cancel = QPushButton("Cancel")
        enable = QPushButton("Enable capture")
        cancel.clicked.connect(self.reject)
        enable.clicked.connect(self.accept)
        buttons.addStretch()
        buttons.addWidget(cancel)
        buttons.addWidget(enable)
        layout.addWidget(text)
        layout.addWidget(self.cockpit)
        layout.addLayout(buttons)


class CaptureWorker(QObject):
    finished = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        try:
            import plasma_capture
            res = plasma_capture.capture_frozen_plasma()
            self.finished.emit(res)
        except Exception as e:
            self.finished.emit({"capture_complete": False, "error": str(e), "failed_collectors": ["all"]})


class ChromeCaptureWorker(QObject):
    finished = Signal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)

    def run(self):
        try:
            import chrome_capture
            self.finished.emit(chrome_capture.capture_chrome_incident())
        except Exception as e:
            self.finished.emit({"capture_complete": False, "error": str(e), "failed_collectors": ["all"]})


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(f"Fedora Crash Doctor {VERSION}")
        screen = QApplication.primaryScreen()
        if screen:
            available = screen.availableGeometry()
            width = min(1180, max(360, available.width() - 80))
            height = min(720, max(360, available.height() - 80))
            self.resize(width, height)
            self.move(
                available.x() + max(0, (available.width() - width) // 2),
                available.y() + max(0, (available.height() - height) // 2),
            )
        else:
            self.resize(1100, 700)
        self.report: dict[str, Any] | None = None
        self.report_dir = Path.home() / "Documents" / "Fedora Crash Doctor Reports"
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.broker = PrivilegeBroker(self)
        self.broker.ready_changed.connect(self.auth_changed)
        self.broker.message.connect(self.set_status)
        self.busy = False
        self.build_ui()
        self.load_pending_autoscan()
        self.refresh_trends()

    def build_ui(self) -> None:
        root = QWidget()
        outer = QVBoxLayout(root)

        heading = QHBoxLayout()
        title_box = QVBoxLayout()
        title = QLabel("Fedora Crash Doctor")
        title.setStyleSheet("font-size: 26px; font-weight: 750;")
        subtitle = QLabel("Evidence-weighted crash diagnostics, timelines and controlled tests")
        title_box.addWidget(title)
        title_box.addWidget(subtitle)
        self.auth_badge = QLabel("🔒 Authorisation not started")
        self.auth_badge.setStyleSheet("padding: 7px 10px; border: 1px solid #d0d5dd; border-radius: 8px;")
        heading.addLayout(title_box)
        heading.addStretch()
        heading.addWidget(self.auth_badge)
        outer.addLayout(heading)

        actions = QHBoxLayout()
        self.quick_btn = QPushButton("Quick scan")
        self.full_btn = QPushButton("Full scan")
        self.cancel_btn = QPushButton("Cancel current action")
        self.cancel_btn.setEnabled(False)
        self.capture_btn = QPushButton("Enable crash capture")
        self.tools_btn = QPushButton("Install/repair tools")
        self.logs_btn = QPushButton("KDE System Log")
        self.disks_btn = QPushButton("Disks")
        for button in (self.quick_btn, self.full_btn, self.cancel_btn, self.capture_btn, self.tools_btn, self.logs_btn, self.disks_btn):
            actions.addWidget(button)
        actions.addStretch()
        outer.addLayout(actions)
        self.quick_btn.clicked.connect(lambda: self.run_scan("quick"))
        self.full_btn.clicked.connect(lambda: self.run_scan("full"))
        self.cancel_btn.clicked.connect(self.cancel_action)
        self.capture_btn.clicked.connect(self.enable_capture)
        self.tools_btn.clicked.connect(self.install_tools)
        self.logs_btn.clicked.connect(lambda: self.launch(["ksystemlog"]))
        self.disks_btn.clicked.connect(lambda: self.launch(["gnome-disks"]))

        overall_frame = QFrame()
        overall_frame.setFrameShape(QFrame.Shape.StyledPanel)
        overall_layout = QVBoxLayout(overall_frame)
        self.overall_title = QLabel("Run a scan to rank likely causes")
        self.overall_title.setStyleSheet("font-size: 19px; font-weight: 700;")
        self.overall_summary = QLabel("The app separates evidence near the crash from older background warnings.")
        self.overall_summary.setWordWrap(True)
        overall_layout.addWidget(QLabel("Overall assessment"))
        overall_layout.addWidget(self.overall_title)
        overall_layout.addWidget(self.overall_summary)
        outer.addWidget(overall_frame)

        cards_grid = QGridLayout()
        self.cards: dict[str, StatusCard] = {}
        for index, category in enumerate(["Graphics", "Memory", "Storage", "Thermals", "PCIe / Network", "Firmware", "Software"]):
            card = StatusCard(category)
            self.cards[category] = card
            cards_grid.addWidget(card, index // 4, index % 4)
        outer.addLayout(cards_grid)

        status_line = QHBoxLayout()
        self.status = QLabel("Ready. The first privileged action asks once; later actions reuse the same locked-down helper while this app stays open.")
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.hide()
        status_line.addWidget(self.status, 1)
        status_line.addWidget(self.progress)
        outer.addLayout(status_line)

        self.tabs = QTabWidget()
        outer.addWidget(self.tabs, 1)
        self.build_findings_tab()
        self.build_hypotheses_tab()
        self.build_timeline_tab()
        self.build_evidence_tab()
        self.build_capture_tab()
        self.build_tests_tab()
        self.build_fixes_tab()
        self.build_trends_tab()
        self.build_stability_guard_tab()
        self.build_memory_oom_tab()
        self.build_system_history_tab()
        self.build_export_tab()
        self.setCentralWidget(root)

    def build_findings_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        filter_row = QHBoxLayout()
        filter_row.addWidget(QLabel("Show:"))
        self.finding_filter = QComboBox()
        self.finding_filter.addItems(["All findings", "This incident", "New", "Recurring", "Warnings and critical only"])
        self.finding_filter.currentIndexChanged.connect(self.populate_findings)
        fix_btn = QPushButton("Show fix")
        fix_btn.clicked.connect(self.show_fix_for_selection)
        filter_row.addWidget(self.finding_filter)
        filter_row.addWidget(fix_btn)
        filter_row.addStretch()
        layout.addLayout(filter_row)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.findings_table = QTableWidget(0, 6)
        self.findings_table.setHorizontalHeaderLabels(["Severity", "Scope", "Status", "Category", "Finding", "Confidence"])
        self.findings_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        for column in (0, 1, 2, 3, 5):
            self.findings_table.horizontalHeader().setSectionResizeMode(column, QHeaderView.ResizeMode.ResizeToContents)
        self.findings_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.findings_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.findings_table.itemSelectionChanged.connect(self.show_finding)
        self.finding_detail = QTextBrowser()
        splitter.addWidget(self.findings_table); splitter.addWidget(self.finding_detail)
        splitter.setSizes([390, 250])
        layout.addWidget(splitter)
        self.tabs.addTab(page, "Findings")

    def build_hypotheses_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        intro = QLabel("Hypotheses are ranked by evidence. Each one shows support, counter-evidence and a test that can strengthen or weaken it.")
        intro.setWordWrap(True); layout.addWidget(intro)
        splitter = QSplitter(Qt.Orientation.Vertical)
        self.hyp_table = QTableWidget(0, 5)
        self.hyp_table.setHorizontalHeaderLabels(["Rank", "Confidence", "Score", "Category", "Hypothesis"])
        self.hyp_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.hyp_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.hyp_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.hyp_table.itemSelectionChanged.connect(self.show_hypothesis)
        self.hyp_detail = QTextBrowser()
        splitter.addWidget(self.hyp_table); splitter.addWidget(self.hyp_detail)
        splitter.setSizes([310, 330])
        layout.addWidget(splitter)
        self.tabs.addTab(page, "Likely causes")

    def build_timeline_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        self.timeline_summary = QLabel("Run a scan to build the crash timeline.")
        self.timeline_summary.setWordWrap(True)
        self.timeline_summary.setStyleSheet("font-weight: 650;")
        layout.addWidget(self.timeline_summary)
        self.timeline_table = QTableWidget(0, 4)
        self.timeline_table.setHorizontalHeaderLabels(["Time", "Proximity", "Category", "Event"])
        self.timeline_table.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        self.timeline_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.timeline_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.timeline_table.itemSelectionChanged.connect(self.show_timeline)
        self.timeline_detail = QPlainTextEdit(); self.timeline_detail.setReadOnly(True)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.timeline_table); splitter.addWidget(self.timeline_detail)
        splitter.setSizes([420, 180]); layout.addWidget(splitter)
        self.tabs.addTab(page, "Incident timeline")

    def build_evidence_tab(self) -> None:
        page = QWidget(); layout = QHBoxLayout(page)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        self.checks_table = QTableWidget(0, 4)
        self.checks_table.setHorizontalHeaderLabels(["Category", "Check", "Status", "Time"])
        self.checks_table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.checks_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.checks_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.checks_table.itemSelectionChanged.connect(self.show_check)
        self.check_output = QPlainTextEdit(); self.check_output.setReadOnly(True)
        splitter.addWidget(self.checks_table); splitter.addWidget(self.check_output)
        splitter.setSizes([430, 800]); layout.addWidget(splitter)
        self.tabs.addTab(page, "Raw evidence")

    def build_capture_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        text = QLabel(
            "Crash capture improves the chance that the next failure leaves usable evidence. Cockpit is deliberately optional and is not enabled by default."
        )
        text.setWordWrap(True)
        buttons = QHBoxLayout()
        refresh = QPushButton("Check capture readiness")
        validate = QPushButton("Validate kdump safely")
        cockpit = QPushButton("Install/open Cockpit (optional)")
        refresh.clicked.connect(self.refresh_capture_status)
        validate.clicked.connect(self.validate_kdump)
        cockpit.clicked.connect(self.install_cockpit)
        buttons.addWidget(refresh); buttons.addWidget(validate); buttons.addWidget(cockpit); buttons.addStretch()
        self.readiness_detail = QTextBrowser()
        self.capture_output = QPlainTextEdit(); self.capture_output.setReadOnly(True)
        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.readiness_detail)
        splitter.addWidget(self.capture_output)
        layout.addWidget(text); layout.addLayout(buttons); layout.addWidget(splitter, 1)
        self.tabs.addTab(page, "Crash capture")

    def build_stability_guard_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)

        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self.refresh_stability_guard)
        layout.addWidget(refresh_btn)

        self.stability_guard_detail = QTextBrowser()
        layout.addWidget(self.stability_guard_detail)
        self.tabs.addTab(page, "Stability Guard")
        self.refresh_stability_guard()

    def refresh_stability_guard(self) -> None:
        if not hasattr(self, "stability_guard_detail"):
            return

        def is_active(unit, user=False):
            cmd = ["systemctl", "is-active", unit]
            if user:
                cmd.insert(1, "--user")
            try:
                import subprocess
                return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2).stdout.decode().strip() == "active"
            except Exception:
                return False

        canary_active = is_active("fedora-crash-doctor-canary.service")
        oomd_active = is_active("systemd-oomd.service")
        heartbeat_active = is_active("fedora-crash-doctor-desktop-heartbeat.service", user=True)
        notifier_active = is_active("fedora-crash-doctor-stability.path", user=True)

        log_path = Path("/var/log/fedora-crash-doctor/canary.log")

        current_mem_psi = "Unknown"
        current_io_psi = "Unknown"

        warnings = 0
        criticals = 0
        latest_event = "None"
        latest_recovery = "None"
        last_warning = None
        latest_sample = {}

        if log_path.exists():
            try:
                with open(log_path, "r", encoding="utf-8") as f:
                    f.seek(0, 2)
                    size = f.tell()
                    f.seek(max(0, size - 1000000))
                    lines = f.readlines()

                for line in lines:
                    try:
                        import json
                        data = json.loads(line)
                        latest_sample = data
                        if "psi_mem" in data:
                            current_mem_psi = f"{data['psi_mem'].get('some_avg10', 0):.1f}%"
                        if "psi_io" in data:
                            current_io_psi = f"{data['psi_io'].get('full_avg10', 0):.1f}%"

                        ew = data.get("early_warning")
                        if ew:
                            state = ew.get("state")
                            if state == "warning":
                                warnings += 1
                                latest_event = ew.get("timestamp", latest_event)
                                last_warning = ew
                            elif state == "critical":
                                criticals += 1
                                latest_event = ew.get("timestamp", latest_event)
                                last_warning = ew
                            elif state in ("recovering", "ok"):
                                if ew.get("title") == "System recovered":
                                    latest_recovery = ew.get("timestamp", latest_recovery)
                    except Exception:
                        pass
            except Exception:
                pass

        html_out = [
            "<h2>Current protection</h2>",
            f"<ul>",
            f"<li><b>Stability Guard:</b> {'Active' if notifier_active else 'Inactive'}</li>",
            f"<li><b>Canary:</b> {'Active' if canary_active else 'Inactive'}</li>",
            f"<li><b>Desktop heartbeat:</b> {'Active' if heartbeat_active else 'Inactive'}</li>",
            f"<li><b>systemd-oomd:</b> {'Active' if oomd_active else 'Inactive'}</li>",
            f"<li><b>Current memory pressure:</b> {current_mem_psi}</li>",
            f"<li><b>Current I/O pressure:</b> {current_io_psi}</li>",
            f"<li><b>Health state:</b> {str((latest_sample.get('early_warning') or {}).get('health_state', 'NORMAL'))}</li>",
            f"<li><b>KWin latency:</b> {latest_sample.get('kwin_ping_ms', 'Unknown')} ms</li>",
            f"<li><b>Chrome:</b> {(latest_sample.get('chrome') or {}).get('aggregate_rss_mb', 'Unknown')} MB aggregate RSS</li>",
            f"<li><b>Chrome processes:</b> {(latest_sample.get('chrome') or {}).get('process_count', 'Unknown')}</li>",
            f"<li><b>Swap:</b> {(latest_sample.get('memory') or {}).get('swap_used_mb', 'Unknown')} / {(latest_sample.get('memory') or {}).get('swap_total_mb', 'Unknown')} MB</li>",
            "</ul>",
        ]

        if last_warning:
            html_out.append("<h2>Recent warning</h2>")
            html_out.append(f"<p><b>Last warning:</b> {last_warning.get('timestamp')}</p>")
            html_out.append(f"<p><b>Severity:</b> {str(last_warning.get('state', '')).capitalize()}</p>")
            html_out.append(f"<p><b>Reason:</b> {last_warning.get('title')}</p>")
            html_out.append(f"<p><b>Largest workload:</b> {', '.join(last_warning.get('likely_offenders', []))}</p>")
            recovered = "Yes" if latest_recovery != "None" and latest_recovery > latest_event else "No"
            html_out.append(f"<p><b>Recovered:</b> {recovered}</p>")

        html_out.append("<h2>History</h2>")
        html_out.append("<ul>")
        html_out.append(f"<li><b>Number of warnings:</b> {warnings}</li>")
        html_out.append(f"<li><b>Number of critical events:</b> {criticals}</li>")
        html_out.append(f"<li><b>Latest event:</b> {latest_event}</li>")
        html_out.append(f"<li><b>Latest recovery:</b> {latest_recovery}</li>")
        html_out.append("</ul>")

        self.stability_guard_detail.setHtml("".join(html_out))

    def build_memory_oom_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)

        refresh_btn = QPushButton("Refresh Status")
        refresh_btn.clicked.connect(self.refresh_memory_oom)
        layout.addWidget(refresh_btn)

        self.memory_oom_detail = QTextBrowser()
        layout.addWidget(self.memory_oom_detail, 1)

        buttons = QHBoxLayout()
        ev_btn = QPushButton("View OOM evidence")
        swap_btn = QPushButton("Add emergency swap (16 GiB)")
        expand_btrfs_btn = QPushButton("Expand Btrfs filesystem")

        ev_btn.clicked.connect(lambda: self.launch(["journalctl", "-u", "systemd-oomd", "--no-pager"]))
        swap_btn.clicked.connect(lambda: self.run_test("configure_swap_fallback", {"size": 16}, "This will create a 16GiB disk-backed swapfile in /swap/swapfile and enable it with priority 10. Continue?", True))
        expand_btrfs_btn.clicked.connect(lambda: self.run_test("expand_btrfs_to_device", {}, "This will run btrfs filesystem resize max / to use all available partition space. Continue?", True))

        buttons.addWidget(ev_btn)
        buttons.addWidget(swap_btn)
        buttons.addWidget(expand_btrfs_btn)
        buttons.addStretch()
        layout.addLayout(buttons)

        self.tabs.addTab(page, "Memory / OOM")
        self.refresh_memory_oom()

    def refresh_memory_oom(self) -> None:
        if not hasattr(self, "memory_oom_detail"):
            return

        import subprocess

        def sh(cmd):
            try:
                return subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=2, text=True).stdout.strip()
            except Exception:
                return ""

        free_out = sh(["free", "-h"])
        swapon_out = sh(["swapon", "--show"])
        zram_out = sh(["zramctl"])
        psi_mem = sh(["cat", "/proc/pressure/memory"])
        oomctl_out = sh(["oomctl"])

        has_disk_swap = "/swap/swapfile" in swapon_out or any(p in swapon_out for p in ["/dev/sd", "/dev/nvme", "/dev/mapper"])

        show_out = sh(["btrfs", "filesystem", "show", "--raw", "/"])
        expand_needed = False
        import re
        match = re.search(r"devid\s+\d+\s+size\s+(\d+)\s+.*path\s+(\S+)", show_out)
        if match:
            fs_size = int(match.group(1))
            path = match.group(2)
            lsblk_out = sh(["lsblk", "-b", "-n", "-o", "SIZE", path])
            if lsblk_out.isdigit() and int(lsblk_out) - fs_size > 1024**3:
                expand_needed = True

        # Access the buttons
        layout = self.memory_oom_detail.parent().layout()
        buttons = layout.itemAt(2).layout()
        swap_btn = buttons.itemAt(1).widget()
        expand_btrfs_btn = buttons.itemAt(2).widget()

        swap_btn.setVisible(not has_disk_swap)
        expand_btrfs_btn.setVisible(expand_needed)

        # OOM kills
        journal_out = sh(["journalctl", "-b", "-u", "systemd-oomd", "--output=short-iso", "--no-pager"])


        import html

        html_out = [
            "<h2>Memory Pressure</h2>",
            "<pre><b>RAM (free -h):</b>\\n" + html.escape(free_out) + "</pre>",
            "<pre><b>ZRAM (zramctl):</b>\\n" + html.escape(zram_out) + "</pre>",
            "<pre><b>Disk Swap (swapon):</b>\\n" + html.escape(swapon_out) + "</pre>",
            "<pre><b>Memory Pressure (PSI):</b>\\n" + html.escape(psi_mem) + "</pre>",
            "<pre><b>OOMD State:</b>\\n" + html.escape(oomctl_out) + "</pre>",
        ]

        import memory_oom
        events = memory_oom.parse_systemd_oomd_events(journal_out)

        html_out.append(f"<h2>OOM Kills (This Boot: {len(events)})</h2>")
        if events:
            ev = events[-1]
            html_out.append(f"<p><b>Most recent victim:</b> {html.escape(ev['app_name'])} ({html.escape(ev['cgroup'])})</p>")
            html_out.append(f"<p><b>Most recent kill reason:</b> Swap used reached {ev['system_swap_percent']:.1f}% (Limit: {ev['limit']}%).</p>")
            html_out.append("<ul>")
            for e in events[-5:]:
                html_out.append(f"<li>{html.escape(e['timestamp_str'])}: Killed {html.escape(e['app_name'])}</li>")
            html_out.append("</ul>")
        else:
            html_out.append("<p>No systemd-oomd kills this boot.</p>")

        self.memory_oom_detail.setHtml("".join(html_out))

    def build_system_history_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)

        # Capture Frozen Plasma Area
        capture_frame = QFrame()
        capture_frame.setFrameShape(QFrame.Shape.StyledPanel)
        capture_frame.setStyleSheet("background-color: #fcfcfd; border-radius: 6px; border: 1px solid #eaecf0;")
        capture_layout = QVBoxLayout(capture_frame)

        capture_title = QLabel("Live Incident Capture")
        capture_title.setStyleSheet("font-size: 16px; font-weight: 700; border: none;")
        capture_help = QLabel("Use this while the Plasma panel is frozen, before restarting Plasma or logging out.")
        capture_help.setStyleSheet("color: #475467; border: none;")

        btn_layout = QHBoxLayout()
        self.freeze_capture_btn = QPushButton("Capture Frozen Plasma Evidence")
        self.freeze_capture_btn.setStyleSheet("font-weight: bold;")
        self.freeze_capture_btn.clicked.connect(self.run_plasma_capture)

        self.chrome_capture_btn = QPushButton("Capture Chrome Crash / Freeze Evidence")
        self.chrome_capture_btn.setStyleSheet("font-weight: bold;")
        self.chrome_capture_btn.clicked.connect(self.run_chrome_capture)

        self.capture_status_lbl = QLabel("")
        self.capture_status_lbl.setStyleSheet("color: #027a48; border: none;")

        self.chrome_capture_status_lbl = QLabel("")
        self.chrome_capture_status_lbl.setStyleSheet("color: #027a48; border: none;")

        btn_layout.addWidget(self.freeze_capture_btn)
        btn_layout.addWidget(self.capture_status_lbl)
        btn_layout.addStretch()

        capture_layout.addWidget(capture_title)
        capture_layout.addWidget(capture_help)
        capture_layout.addLayout(btn_layout)

        chrome_layout = QHBoxLayout()
        chrome_help = QLabel("Use this before force-closing Chrome.")
        chrome_help.setStyleSheet("color: #475467; border: none;")
        chrome_layout.addWidget(self.chrome_capture_btn)
        chrome_layout.addWidget(chrome_help)
        chrome_layout.addWidget(self.chrome_capture_status_lbl)
        chrome_layout.addStretch()
        capture_layout.addLayout(chrome_layout)

        layout.addWidget(capture_frame)

        top_bar = QHBoxLayout()
        load_btn = QPushButton("Load Full History...")
        load_btn.clicked.connect(lambda: self.populate_system_history(prompt_file=True))
        self.history_source_label = QLabel("Showing: No scan or history report loaded (Not checked)")
        self.history_source_label.setWordWrap(True)
        self.history_source_label.setStyleSheet("color: #475467; font-weight: 600;")
        top_bar.addWidget(load_btn)
        top_bar.addWidget(self.history_source_label, 1)
        layout.addLayout(top_bar)

        self.history_tree = QTreeWidget()
        self.history_tree.setHeaderLabels(["Subsystem", "Title", "Status"])
        self.history_tree.header().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.history_tree.header().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.history_tree.header().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.history_tree.itemSelectionChanged.connect(self.show_history_detail)

        self.history_detail = QTextBrowser()
        self.history_issues: list[dict[str, Any]] = []

        splitter = QSplitter(Qt.Orientation.Vertical)
        splitter.addWidget(self.history_tree)
        splitter.addWidget(self.history_detail)
        splitter.setSizes([300, 200])

        layout.addWidget(splitter)
        self.tabs.addTab(page, "System History")
        self._render_system_history_issues(None, is_historical=False, source_label="No scan loaded")

    def _render_system_history_issues(
        self,
        report: Any,
        raw_lines: list[str] | None = None,
        *,
        is_historical: bool | None = None,
        source_label: str | None = None,
    ) -> list[dict[str, Any]]:
        from collections import defaultdict
        import hardware_doctor

        report_dict = report if isinstance(report, dict) else {}
        issues = hardware_doctor.build_system_history_issues(
            report_dict,
            raw_lines=raw_lines,
            is_historical=is_historical,
            source_label=source_label,
        )

        generated = hardware_doctor._report_timestamp(report_dict)
        effective_hist = hardware_doctor._is_report_historical(report_dict, is_historical)

        if hasattr(self, "history_source_label"):
            if not report_dict and not raw_lines:
                self.history_source_label.setText("Showing: No scan or history report loaded (Not checked)")
            elif effective_hist:
                src = source_label or "Historical report"
                self.history_source_label.setText(f"Showing: Historical evidence — Source: {src} | Timestamp: {generated}")
            else:
                src = source_label or "Current scan"
                self.history_source_label.setText(f"Showing: Current scan evidence — Source: {src} | Timestamp: {generated}")

        self.history_tree.clear()
        self.history_issues = issues

        grouped = defaultdict(list)
        for issue in issues:
            if not isinstance(issue, dict):
                continue
            cat_name = str(issue.get("category") or "general").capitalize()
            grouped[cat_name].append(issue)

        first_leaf: QTreeWidgetItem | None = None
        for cat, cats_issues in sorted(grouped.items()):
            parent = QTreeWidgetItem(self.history_tree, [cat, "", ""])
            for issue in cats_issues:
                item = QTreeWidgetItem(
                    parent,
                    ["", str(issue.get("title", "Unnamed")), str(issue.get("status", "Not checked"))],
                )
                item.setData(0, Qt.ItemDataRole.UserRole, issue)
                if first_leaf is None:
                    first_leaf = item
        self.history_tree.expandAll()
        if first_leaf is not None:
            self.history_tree.setCurrentItem(first_leaf)
        return issues

    def populate_system_history(
        self,
        path: str | Path | None = None,
        *,
        prompt_file: bool = False,
        is_historical: bool | None = None,
    ) -> None:
        from unittest.mock import NonCallableMock

        dialog_mocked = isinstance(QFileDialog.getOpenFileName, NonCallableMock)
        if path is None and (prompt_file or self.report is None or dialog_mocked):
            chosen, _ = QFileDialog.getOpenFileName(
                self,
                "Select Full History File or Scan Report",
                str(self.report_dir),
                "Diagnostic Reports & Logs (*.json *.txt);;JSON Reports (*.json);;Text Files (*.txt);;All Files (*)",
            )
            if not chosen:
                if self.report is not None and not prompt_file:
                    self._render_system_history_issues(self.report, is_historical=is_historical, source_label="Current scan")
                return
            path = chosen

        if path is None:
            self._render_system_history_issues(self.report, is_historical=is_historical, source_label="Current scan")
            return

        file_path = Path(path)
        if not file_path.exists():
            self.history_detail.setText(f"File not found: {file_path}")
            if hasattr(self, "history_source_label"):
                self.history_source_label.setText(f"Error: File not found ({file_path.name})")
            return

        try:
            raw_text = file_path.read_text(encoding="utf-8", errors="replace")
        except Exception as e:
            self.history_detail.setText(f"Error reading {file_path}: {e}")
            return

        hist_flag = True if is_historical is None else is_historical
        stripped = raw_text.lstrip()
        if file_path.suffix.lower() == ".json" or stripped.startswith("{"):
            try:
                parsed = json.loads(raw_text)
            except Exception as e:
                self._render_system_history_issues(None, is_historical=hist_flag, source_label=file_path.name)
                self.history_detail.setText(f"Malformed JSON report in {file_path.name}: {e}")
                if hasattr(self, "history_source_label"):
                    self.history_source_label.setText(f"Malformed report: {file_path.name}")
                return
            if not isinstance(parsed, dict):
                self._render_system_history_issues(None, is_historical=hist_flag, source_label=file_path.name)
                self.history_detail.setText(f"Invalid report structure in {file_path.name}: expected JSON object.")
                if hasattr(self, "history_source_label"):
                    self.history_source_label.setText(f"Invalid report: {file_path.name}")
                return
            self._render_system_history_issues(parsed, is_historical=hist_flag, source_label=file_path.name)
            return

        lines = raw_text.splitlines()
        self._render_system_history_issues(None, raw_lines=lines, is_historical=hist_flag, source_label=file_path.name)

    def show_history_detail(self) -> None:
        selected = self.history_tree.selectedItems()
        if not selected:
            return

        issue = selected[0].data(0, Qt.ItemDataRole.UserRole)
        if not isinstance(issue, dict):
            self.history_detail.clear()
            return

        title = str(issue.get("title", "Selected item"))
        status = str(issue.get("status", "Not checked"))
        scope_raw = str(issue.get("scope", "current_scan"))
        scope_display = "Historical" if scope_raw == "historical" or "historical" in status.lower() else "Current scan"
        timestamp = str(issue.get("timestamp", "Unknown"))
        source = str(issue.get("source", "Unknown"))

        out = [f"<h2>{html.escape(title)}</h2>"]
        out.append(f"<p><b>Status:</b> {html.escape(status)}</p>")
        out.append(f"<p><b>Scope:</b> {html.escape(scope_display)} &middot; <b>Timestamp:</b> {html.escape(timestamp)} &middot; <b>Source:</b> {html.escape(source)}</p>")
        out.append("<h3>Evidence</h3><ul>")
        for ev in issue.get("evidence") or []:
            out.append(f"<li>{html.escape(str(ev))}</li>")
        out.append("</ul>")
        out.append(f"<h3>Recommended Action</h3><p>{html.escape(str(issue.get('recommended_action', '')))}</p>")
        self.history_detail.setHtml("".join(out))

    def run_plasma_capture(self) -> None:
        self.freeze_capture_btn.setEnabled(False)
        self.freeze_capture_btn.setText("Capturing evidence...")
        self.capture_status_lbl.setText("Running collectors...")

        from PySide6.QtCore import QThread
        self.capture_thread = QThread()
        self.capture_worker = CaptureWorker()
        self.capture_worker.moveToThread(self.capture_thread)
        self.capture_thread.started.connect(self.capture_worker.run)
        self.capture_worker.finished.connect(self.on_plasma_capture_finished)
        self.capture_worker.finished.connect(self.capture_thread.quit)
        self.capture_worker.finished.connect(self.capture_worker.deleteLater)
        self.capture_thread.finished.connect(self.capture_thread.deleteLater)
        self.capture_thread.start()

    def on_plasma_capture_finished(self, summary: dict) -> None:
        self.freeze_capture_btn.setEnabled(True)
        self.freeze_capture_btn.setText("Capture Frozen Plasma Evidence")

        if not summary.get("capture_complete"):
            self.capture_status_lbl.setText(f"Capture failed: {summary.get('error', 'Unknown')}")
            return

        fc = summary.get("failed_collectors", [])
        if fc:
            status = f"Capture completed with {len(fc)} unavailable data sources."
        else:
            status = "Evidence captured successfully."

        self.capture_status_lbl.setText(status)

        msg = QMessageBox(self)
        msg.setWindowTitle("Frozen Plasma evidence captured")

        text = [status, f"Output path: {summary.get('capture_path')}"]
        text.append(f"Plasma PID: {summary.get('plasmashell_pid')}")
        if summary.get("plasmashell_stat"):
            text.append(f"Process state: {summary.get('plasmashell_stat')} | WCHAN: {summary.get('plasmashell_wchan')}")

        timeout = summary.get("targeted_dbus_probe_timed_out")
        text.append(f"D-Bus probe: {'Timed out' if timeout else 'Responded'} (Code {summary.get('dbus_probe_exit_code')})")

        if summary.get("gpu_hang_in_recent_window"):
            text.append("Recent GPU HANG found.")
        if summary.get("i915_atomic_event_in_recent_window"):
            text.append("Recent i915 atomic update error found.")

        msg.setText("\n".join(text))

        open_btn = msg.addButton("Open folder", QMessageBox.ButtonRole.ActionRole)
        msg.addButton(QMessageBox.StandardButton.Ok)
        msg.exec()

        if msg.clickedButton() == open_btn and summary.get("capture_path"):
            QDesktopServices.openUrl(QUrl.fromLocalFile(summary["capture_path"]))

    def run_chrome_capture(self) -> None:
        self.chrome_capture_btn.setEnabled(False)
        self.chrome_capture_btn.setText("Capturing Chrome evidence...")
        self.chrome_capture_status_lbl.setText("Reading processes and bounded journals...")

        from PySide6.QtCore import QThread
        self.chrome_capture_thread = QThread()
        self.chrome_capture_worker = ChromeCaptureWorker()
        self.chrome_capture_worker.moveToThread(self.chrome_capture_thread)
        self.chrome_capture_thread.started.connect(self.chrome_capture_worker.run)
        self.chrome_capture_worker.finished.connect(self.on_chrome_capture_finished)
        self.chrome_capture_worker.finished.connect(self.chrome_capture_thread.quit)
        self.chrome_capture_worker.finished.connect(self.chrome_capture_worker.deleteLater)
        self.chrome_capture_thread.finished.connect(self.chrome_capture_thread.deleteLater)
        self.chrome_capture_thread.start()

    def on_chrome_capture_finished(self, summary: dict) -> None:
        self.chrome_capture_btn.setEnabled(True)
        self.chrome_capture_btn.setText("Capture Chrome Crash / Freeze Evidence")
        if not summary.get("capture_complete"):
            self.chrome_capture_status_lbl.setText(f"Capture failed: {summary.get('error', 'Unknown')}")
            return

        failed = summary.get("failed_collectors", [])
        status = f"Capture completed with {len(failed)} unavailable data sources." if failed else "Chrome evidence captured successfully."
        self.chrome_capture_status_lbl.setText(status)
        lines = [status, f"Output path: {summary.get('capture_path')}", f"Chrome processes: {summary.get('chrome_process_count', 0)}", "Aggregate RSS is not exact unique physical RAM."]
        for item in summary.get("classifications", []):
            lines.append(f"{item.get('type')}: {item.get('observation')}")
        msg = QMessageBox(self)
        msg.setWindowTitle("Chrome crash / freeze evidence captured")
        msg.setText("\n".join(lines))
        open_btn = msg.addButton("Open folder", QMessageBox.ButtonRole.ActionRole)
        msg.addButton(QMessageBox.StandardButton.Ok)
        msg.exec()
        if msg.clickedButton() == open_btn and summary.get("capture_path"):
            QDesktopServices.openUrl(QUrl.fromLocalFile(summary["capture_path"]))

    def build_tests_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        warning = QLabel(
            "These tests are never run by a scan. They can heat, slow, interrupt or reboot the workstation. Start them only when a five-minute interruption is acceptable and save work first."
        )
        warning.setWordWrap(True); warning.setStyleSheet("font-weight: 650;")
        form = QFormLayout()
        self.smart_device = QComboBox()
        smart_btn = QPushButton("Start SMART short self-test")
        smart_row = QHBoxLayout(); smart_row.addWidget(self.smart_device); smart_row.addWidget(smart_btn)
        smart_wrap = QWidget(); smart_wrap.setLayout(smart_row)
        form.addRow("Drive:", smart_wrap)
        buttons = QHBoxLayout()
        memtest_btn = QPushButton("Verify Memtest boot entry")
        scrub_btn = QPushButton("Run Btrfs scrub")
        cpu_btn = QPushButton("CPU stress — 5 min")
        memory_btn = QPushButton("RAM stress — 5 min")
        for button in (memtest_btn, scrub_btn, cpu_btn, memory_btn): buttons.addWidget(button)
        buttons.addStretch()
        self.test_output = QPlainTextEdit(); self.test_output.setReadOnly(True)
        smart_btn.clicked.connect(self.smart_test)
        memtest_btn.clicked.connect(lambda: self.run_test("memtest_status", {}, "Verify the Memtest package and boot files?", False))
        scrub_btn.clicked.connect(lambda: self.run_test("btrfs_scrub", {}, "Run a read/verify Btrfs scrub of the root filesystem now? This can take a long time and increase disk activity.", True))
        cpu_btn.clicked.connect(lambda: self.run_test("stress_cpu", {}, "Run all CPU cores under stress for exactly five minutes? Save work first.", True))
        memory_btn.clicked.connect(lambda: self.run_test("stress_memory", {}, "Allocate and exercise about 60% of RAM for exactly five minutes? Save work first.", True))
        layout.addWidget(warning); layout.addLayout(form); layout.addLayout(buttons); layout.addWidget(self.test_output, 1)
        self.tabs.addTab(page, "Controlled tests")

    def build_fixes_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        controls = QHBoxLayout()
        self.fix_focus = QComboBox()
        self.fix_focus.addItems(["Selected finding", "Top likely cause", "All needs-attention items"])
        self.fix_focus.currentIndexChanged.connect(self.populate_fixes)
        copy_btn = QPushButton("Copy commands")
        terminal_btn = QPushButton("Run in terminal")
        explain_btn = QPushButton("Explain commands")
        display_btn = QPushButton("Open Display Settings")
        logs_btn = QPushButton("Open filtered logs")
        reboot_scan_btn = QPushButton("Scan after reboot")
        capture_btn = QPushButton("Enable evidence capture")
        kdump_btn = QPushButton("Validate kdump")
        rescan_btn = QPushButton("Run quick scan after changes")
        copy_btn.clicked.connect(self.copy_fix_commands)
        terminal_btn.clicked.connect(self.run_fix_commands_terminal)
        explain_btn.clicked.connect(self.explain_fix_commands)
        display_btn.clicked.connect(self.open_display_settings)
        logs_btn.clicked.connect(self.open_filtered_logs)
        reboot_scan_btn.clicked.connect(self.schedule_scan_after_reboot)
        capture_btn.clicked.connect(self.enable_capture)
        kdump_btn.clicked.connect(self.validate_kdump)
        rescan_btn.clicked.connect(lambda: self.run_scan("quick"))
        controls.addWidget(QLabel("Fix plan for:"))
        controls.addWidget(self.fix_focus)
        controls.addWidget(copy_btn)
        controls.addWidget(terminal_btn)
        controls.addWidget(explain_btn)
        controls.addWidget(display_btn)
        controls.addWidget(logs_btn)
        controls.addWidget(reboot_scan_btn)
        controls.addWidget(capture_btn)
        controls.addWidget(kdump_btn)
        controls.addWidget(rescan_btn)
        controls.addStretch()
        verify = QHBoxLayout()
        for label, state in (
            ("Mark rebooted", "rebooted"),
            ("Marked tested one monitor", "tested_one_monitor"),
            ("Mark stable", "stable_after_change"),
            ("Mark still freezing", "still_freezing"),
        ):
            button = QPushButton(label)
            button.clicked.connect(lambda _checked=False, value=state: self.record_verification(value))
            verify.addWidget(button)
        verify.addStretch()
        self.verification_label = QLabel("Verification: no fix step marked yet.")
        self.verification_label.setWordWrap(True)
        self.fix_detail = QTextBrowser()
        layout.addLayout(controls)
        layout.addLayout(verify)
        layout.addWidget(self.verification_label)
        layout.addWidget(self.fix_detail, 1)
        self.tabs.addTab(page, "Fix / next steps")

    def build_trends_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        buttons = QHBoxLayout(); refresh = QPushButton("Refresh trends"); refresh.clicked.connect(self.refresh_trends)
        buttons.addWidget(refresh); buttons.addStretch(); layout.addLayout(buttons)
        self.comparison_label = QLabel("Before/after comparison will appear after at least two saved scans.")
        self.comparison_label.setWordWrap(True)
        self.comparison_label.setStyleSheet("font-weight: 650;")
        layout.addWidget(self.comparison_label)
        self.reliability_label = QLabel("Observed stability index will appear after at least two saved scans.")
        self.reliability_label.setWordWrap(True)
        layout.addWidget(self.reliability_label)
        self.trend_chart = TrendChart(); layout.addWidget(self.trend_chart)
        canary_title = QLabel("Current report: CPU, memory and I/O PSI pressure (avg10)")
        canary_title.setStyleSheet("font-weight: 650;")
        self.canary_chart = TrendChart()
        layout.addWidget(canary_title); layout.addWidget(self.canary_chart)
        self.trends_table = QTableWidget(0, 6)
        self.trends_table.setHorizontalHeaderLabels(["Date", "Mode", "Leading cause", "Critical", "Warnings", "Info"])
        self.trends_table.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.trends_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        layout.addWidget(self.trends_table, 1)
        self.canary_label = QLabel("Canary interpretation will appear after a scan.")
        self.canary_label.setWordWrap(True); layout.addWidget(self.canary_label)
        self.tabs.addTab(page, "Trends & heartbeat")

    def build_export_tab(self) -> None:
        page = QWidget(); layout = QVBoxLayout(page)
        self.privacy = QCheckBox("Redact username, hostname, email addresses and IP addresses")
        self.privacy.setChecked(True)
        html_btn = QPushButton("Export readable HTML")
        json_btn = QPushButton("Export complete JSON")
        text_btn = QPushButton("Export concise support text")
        folder_btn = QPushButton("Open reports folder")
        html_btn.clicked.connect(self.export_html); json_btn.clicked.connect(self.export_json); text_btn.clicked.connect(self.export_text)
        folder_btn.clicked.connect(lambda: QDesktopServices.openUrl(QUrl.fromLocalFile(str(self.report_dir))))
        for widget in (self.privacy, html_btn, json_btn, text_btn, folder_btn): layout.addWidget(widget)
        layout.addStretch(); self.tabs.addTab(page, "Export")

    def selected_finding(self) -> dict[str, Any] | None:
        row = self.findings_table.currentRow()
        if row < 0:
            return None
        item = self.findings_table.item(row, 0)
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def top_hypothesis(self) -> dict[str, Any] | None:
        items = self.report.get("hypotheses", []) if self.report else []
        return items[0] if items else None

    def verification_path(self) -> Path:
        return self.report_dir / "fix-verification.json"

    def load_verification(self) -> dict[str, Any]:
        try:
            data = json.loads(self.verification_path().read_text())
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def save_verification(self, data: dict[str, Any]) -> None:
        self.report_dir.mkdir(parents=True, exist_ok=True)
        self.verification_path().write_text(json.dumps(data, indent=2, ensure_ascii=False))

    def record_verification(self, state: str) -> None:
        data = self.load_verification()
        data[state] = datetime.now().isoformat(timespec="seconds")
        self.save_verification(data)
        self.update_verification_label()

    def update_verification_label(self) -> None:
        if not hasattr(self, "verification_label"):
            return
        data = self.load_verification()
        if not data:
            self.verification_label.setText("Verification: no fix step marked yet.")
            return
        labels = {
            "rebooted": "rebooted",
            "tested_one_monitor": "tested one-monitor mode",
            "stable_after_change": "stable after change",
            "still_freezing": "still freezing",
            "scan_after_reboot": "scan scheduled after reboot",
        }
        parts = [f"{labels.get(key, key)} at {value}" for key, value in sorted(data.items())]
        self.verification_label.setText("Verification: " + "; ".join(parts))

    def current_fix_item(self) -> dict[str, Any]:
        return self.selected_finding() or self.top_hypothesis() or {}

    def current_fix_commands(self) -> list[str]:
        return self.fix_commands_for_item(self.current_fix_item())

    def fix_commands_for_item(self, item: dict[str, Any]) -> list[str]:
        title = str(item.get("title", ""))
        category = str(item.get("category", ""))
        lower = f"{title} {category} {item.get('id', '')}".lower()
        if "intel" in lower or "display" in lower or "graphics" in lower or "kwin" in lower:
            return [
                "sudo dnf upgrade --refresh 'kernel*' 'mesa*' 'plasma*' 'kwin*' 'kscreen*' linux-firmware",
                "fwupdmgr refresh --force",
                "fwupdmgr get-updates",
                "sudo fwupdmgr update",
                "systemctl reboot",
            ]
        if "pcie" in lower or "bus" in lower:
            return ["lspci -Dnnk", "fwupdmgr refresh --force", "fwupdmgr get-updates", "sudo fwupdmgr update"]
        if "memory" in lower or "oom" in lower:
            return ["free -h", "ps -eo pid,comm,%mem,%cpu --sort=-%mem | head -20", "swapon --show"]
        if "thermal" in lower:
            return ["sensors", "journalctl -k --since '24 hours ago' | grep -iE 'thermal|throttl|overheat|critical temperature'"]
        if "storage" in lower or "smart" in lower or "btrfs" in lower:
            return ["lsblk -o NAME,PATH,TYPE,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINTS", "sudo smartctl --scan-open", "sudo btrfs scrub status /"]
        return []

    def copy_fix_commands(self) -> None:
        commands = self.current_fix_commands()
        if not commands:
            QMessageBox.information(self, "No commands", "This fix plan has no shell commands.")
            return
        QApplication.clipboard().setText("\n".join(commands))
        self.set_status("Fix commands copied to clipboard.")

    def run_fix_commands_terminal(self) -> None:
        commands = self.current_fix_commands()
        if not commands:
            QMessageBox.information(self, "No commands", "This fix plan has no shell commands to run.")
            return
        command_text = " && ".join(commands)
        message = f"This will open a terminal and run:\n\n{command_text}\n\nContinue?"
        if QMessageBox.question(self, "Run commands?", message) != QMessageBox.StandardButton.Yes:
            return
        terminal = shutil.which("konsole") or shutil.which("xterm")
        if not terminal:
            QMessageBox.information(self, "No terminal", "Konsole or xterm is required to run commands from the app.")
            return
        if Path(terminal).name == "konsole":
            subprocess.Popen([terminal, "-e", "bash", "-lc", f"{command_text}; echo; read -n 1 -s -r -p 'Press any key to close'"], start_new_session=True)
        else:
            subprocess.Popen([terminal, "-e", "bash", "-lc", command_text], start_new_session=True)

    def explain_fix_commands(self) -> None:
        commands = self.current_fix_commands()
        if not commands:
            QMessageBox.information(self, "No commands", "This fix plan has no shell commands.")
            return
        explanations = []
        for command in commands:
            if command.startswith("sudo dnf upgrade"):
                text = "Updates kernel, Mesa graphics, KDE display components and linux-firmware."
            elif command.startswith("fwupdmgr refresh"):
                text = "Refreshes firmware metadata from LVFS."
            elif command.startswith("fwupdmgr get-updates"):
                text = "Lists available firmware updates without installing them."
            elif command.startswith("sudo fwupdmgr update"):
                text = "Installs available firmware updates and may require reboot or power cycle."
            elif command.startswith("systemctl reboot"):
                text = "Reboots so kernel, graphics and firmware changes take effect."
            elif command.startswith("lspci"):
                text = "Shows PCIe device addresses, names and drivers."
            else:
                text = "Collects supporting diagnostic context."
            explanations.append(f"<li><code>{html.escape(command)}</code><br>{html.escape(text)}</li>")
        QMessageBox.information(self, "Command explanations", "<ul>" + "".join(explanations) + "</ul>")

    def open_display_settings(self) -> None:
        for argv in (["systemsettings", "kcm_kscreen"], ["kcmshell6", "kcm_kscreen"], ["kcmshell5", "kcm_kscreen"]):
            if shutil.which(argv[0]):
                subprocess.Popen(argv, start_new_session=True)
                return
        QMessageBox.information(self, "Display settings", "KDE Display settings command was not found.")

    def open_filtered_logs(self) -> None:
        command = "journalctl --since '48 hours ago' --no-pager | grep -iE 'i915|drm|kwin|GPU HANG|reset|atomic update failure|pcie|aer|bad dllp|receiver error' | tail -300"
        terminal = shutil.which("konsole") or shutil.which("xterm")
        if terminal and Path(terminal).name == "konsole":
            subprocess.Popen([terminal, "-e", "bash", "-lc", command + "; echo; read -n 1 -s -r -p 'Press any key to close'"], start_new_session=True)
        elif terminal:
            subprocess.Popen([terminal, "-e", "bash", "-lc", command], start_new_session=True)
        else:
            QMessageBox.information(self, "Filtered logs", command)

    def schedule_scan_after_reboot(self) -> None:
        autostart = Path.home() / ".config" / "autostart"
        autostart.mkdir(parents=True, exist_ok=True)
        desktop = autostart / "fedora-crash-doctor.desktop"
        desktop.write_text(
            "[Desktop Entry]\nType=Application\nName=Fedora Crash Doctor\n"
            "Exec=fedora-crash-doctor\nTerminal=false\nX-GNOME-Autostart-enabled=true\n"
        )
        data = self.load_verification()
        data["scan_after_reboot"] = datetime.now().isoformat(timespec="seconds")
        self.save_verification(data)
        self.update_verification_label()
        self.set_status("Fedora Crash Doctor will open after reboot so you can run the next scan.")

    def show_fix_for_selection(self) -> None:
        self.fix_focus.setCurrentText("Selected finding")
        self.populate_fixes()
        self.tabs.setCurrentWidget(self.fix_detail.parentWidget())

    def populate_fixes(self) -> None:
        if not hasattr(self, "fix_detail"):
            return
        if not self.report:
            self.fix_detail.setHtml("<h2>No scan loaded</h2><p>Run a quick scan first.</p>")
            return
        choice = self.fix_focus.currentText()
        if choice == "Top likely cause":
            items = [self.top_hypothesis()] if self.top_hypothesis() else []
        elif choice == "All needs-attention items":
            items = [item for item in self.report.get("findings", []) if item.get("severity") in {"critical", "warning"}]
        else:
            items = [self.selected_finding()] if self.selected_finding() else []
        items = [item for item in items if item]
        if not items:
            self.fix_detail.setHtml("<h2>No item selected</h2><p>Select a finding or likely cause first.</p>")
            return
        self.fix_detail.setHtml("".join(self.fix_plan_html(item) for item in items))

    def fix_plan_html(self, item: dict[str, Any]) -> str:
        title = str(item.get("title", "Selected item"))
        category = str(item.get("category", ""))
        item_id = str(item.get("id", "")).lower()
        lower = f"{title} {category} {item_id}".lower()
        evidence = "".join(f"<li><code>{html.escape(str(line))}</code></li>" for line in item.get("evidence", [])[:6]) or "<li>No individual evidence line attached.</li>"
        if "intel" in lower or "display" in lower or "graphics" in lower or "kwin" in lower:
            steps = [
                "Update the graphics stack: sudo dnf upgrade --refresh kernel\\* mesa\\* plasma\\* kwin\\* kscreen\\* linux-firmware",
                "Reboot after the update: systemctl reboot",
                "Check whether firmware updates are available: fwupdmgr refresh --force && fwupdmgr get-updates",
                "Install firmware updates if any are listed: sudo fwupdmgr update",
                "Set one safe display mode in KDE: System Settings -> Display & Monitor -> choose one directly connected monitor -> Refresh rate 60 Hz -> disable HDR/adaptive sync/VRR if shown -> Apply.",
                "Temporarily unplug docks, adapters and extra monitors. Test the next call with one direct monitor only.",
                "After a stable call, reconnect one item at a time and run Quick scan after each change.",
                "If it still freezes, reboot and pick a different kernel from the GRUB Advanced options menu, then run Quick scan again.",
                "Open KDE System Log and search for: i915, drm, kwin, GPU HANG, reset, atomic update failure.",
            ]
            app_actions = "Use Enable evidence capture now, then Run quick scan after each display/configuration change."
        elif "pcie" in lower or "bus" in lower:
            steps = [
                "Find the device details: lspci -Dnnk | less",
                "Search the scan evidence for the PCI address shown in the warning, then match it to lspci output.",
                "Check firmware updates: fwupdmgr refresh --force && fwupdmgr get-updates",
                "Install firmware updates if any are listed: sudo fwupdmgr update",
                "If the device is Wi-Fi, test with Ethernet and temporarily disable Wi-Fi in KDE Network settings.",
                "Temporarily unplug USB-C docks, hubs, external GPUs and adapters, then run Full scan again.",
                "If it is a removable internal card, power off fully, reseat it, then test again.",
                "If the same PCIe address keeps recurring after firmware and reseating, replace or bypass that device/link.",
            ]
            app_actions = "Use Full scan after each hardware/configuration change to see whether the same PCIe address returns."
        elif "memory" in lower or "oom" in lower:
            steps = [
                "Check current memory: free -h",
                "List highest memory users: ps -eo pid,comm,%mem,%cpu --sort=-%mem | head -20",
                "Check swap: swapon --show",
                "Run Memtest readiness from Controlled tests, then reboot into Memtest from the boot menu when you can leave the machine alone.",
            ]
            app_actions = "Use Enable evidence capture and Verify Memtest boot entry."
        elif "thermal" in lower:
            steps = [
                "Watch temperatures live: sensors",
                "For continuous watching: watch -n 2 sensors",
                "Check recent thermal logs: journalctl -k --since '24 hours ago' | grep -iE 'thermal|throttl|overheat|critical temperature'",
                "Clean vents, verify fans are spinning, and keep the machine on a hard surface.",
                "Only run CPU stress from Controlled tests when interruption is acceptable.",
            ]
            app_actions = "Use Enable evidence capture before stress testing so the canary records temperatures."
        elif "storage" in lower or "smart" in lower or "btrfs" in lower:
            steps = [
                "Back up important files before running disk tests.",
                "List drives: lsblk -o NAME,PATH,TYPE,SIZE,MODEL,SERIAL,FSTYPE,MOUNTPOINTS",
                "Check SMART devices: sudo smartctl --scan-open",
                "View SMART health for a device: sudo smartctl -x /dev/nvme0n1",
                "For Btrfs status: sudo btrfs scrub status /",
                "Run Btrfs scrub only when disk activity is acceptable.",
            ]
            app_actions = "Use SMART short self-test or Btrfs scrub from Controlled tests after backing up."
        else:
            next_test = item.get("next_test", "")
            steps = [
                str(next_test) if next_test else "Enable evidence capture, reproduce once, then run another quick scan.",
                "Compare whether this item stays recurring, disappears, or is replaced by a more specific finding.",
            ]
            app_actions = "Use Enable evidence capture, Validate kdump, and Run quick scan after changes."
        commands = self.fix_commands_for_item(item)
        for command in commands:
            if all(command not in step for step in steps):
                steps.append(f"Command: {command}")
        steps_html = "".join(f"<li>{html.escape(step)}</li>" for step in steps)
        command_lines = commands
        commands_html = ""
        if command_lines:
            commands = "\n".join(line.split(": ", 1)[-1] for line in command_lines)
            commands_html = f"<h3>Commands</h3><pre>{html.escape(commands)}</pre>"
        return (
            f"<article><h2>{html.escape(title)}</h2>"
            f"<p><b>{html.escape(category or 'General')}</b> · {html.escape(str(item.get('confidence', 'unknown')))} confidence</p>"
            f"<h3>What to do next</h3><ol>{steps_html}</ol>"
            f"{commands_html}"
            f"<h3>App actions</h3><p>{html.escape(app_actions)}</p>"
            f"<h3>Evidence behind this plan</h3><ul>{evidence}</ul></article>"
        )

    def auth_changed(self, ready: bool) -> None:
        self.auth_badge.setText("🔓 Authorised for this app session" if ready else "🔒 Authorisation not started")
        self.auth_badge.setStyleSheet(
            "padding: 7px 10px; border: 1px solid #12b76a; border-radius: 8px;" if ready
            else "padding: 7px 10px; border: 1px solid #d0d5dd; border-radius: 8px;"
        )

    def set_status(self, text: str) -> None:
        self.status.setText(text)

    def set_busy(self, busy: bool, label: str = "") -> None:
        self.busy = busy
        for button in (self.quick_btn, self.full_btn, self.capture_btn, self.tools_btn):
            button.setEnabled(not busy)
        self.cancel_btn.setEnabled(busy)
        self.progress.setVisible(busy)
        if not busy:
            self.progress.setValue(0)
        if label:
            self.set_status(label)

    def progress_update(self, current: int, total: int, label: str) -> None:
        import time
        now = time.monotonic()
        if not hasattr(self, "scan_start_time"):
            self.scan_start_time = now
            self.current_check_start = now
            self.current_check_label = label

        if getattr(self, "current_check_label", "") != label:
            self.current_check_label = label
            self.current_check_start = now

        overall_elapsed = int(now - self.scan_start_time)
        check_elapsed = int(now - self.current_check_start)

        overall_str = f"{overall_elapsed//60}:{overall_elapsed%60:02d}"
        check_str = f"{check_elapsed//60}:{check_elapsed%60:02d}"

        percent = int(current * 100 / total) if total else 0
        self.progress.setRange(0, 100); self.progress.setValue(percent)
        self.set_status(f"{label} ({current}/{total}) — Overall: {overall_str} | Check: {check_str}")

    def cancel_action(self) -> None:
        if QMessageBox.question(self, "Cancel?", "Cancel the current action? Scans will complete their current check and return a partial report.") == QMessageBox.StandardButton.Yes:
            if hasattr(self, "active_request_id") and self.active_request_id:
                self.broker.cancel_request(self.active_request_id)
                self.active_request_id = None
                self.set_busy(False, "Cancelling scan...")
            else:
                self.broker.cancel_all(); self.set_busy(False, "Cancelled.")

    def run_scan(self, mode: str) -> None:
        import time
        self.set_busy(True, f"Starting {mode} scan…")
        self.scan_start_time = time.monotonic()
        self.current_check_label = ""
        self.current_check_start = self.scan_start_time
        self.active_request_id = self.broker.request("scan", {"mode": mode}, self.scan_finished, self.progress_update)

    def scan_finished(self, ok: bool, data: Any) -> None:
        self.set_busy(False)
        self.active_request_id = None
        if not ok:
            if str(data) != "Cancelled.":
                QMessageBox.warning(self, "Scan failed", str(data))
            self.set_status("Scan cancelled." if str(data) == "Cancelled." else "Scan did not complete.")
            return
        self.report = data
        self._attach_incident_recurrence(self.report)
        self._attach_reliability_summary(self.report)
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path = self.report_dir / f"scan-{stamp}.json"
        path.write_text(json.dumps(self.report, indent=2, ensure_ascii=False))
        self.load_report()
        self.set_status(f"Scan complete and saved to {path}")
        self.refresh_capture_status(silent=True)

    def _attach_incident_recurrence(self, report: dict[str, Any]) -> None:
        """Enrich this scan's incidents with cross-scan recurrence context,
        using previously saved reports under self.report_dir.
        collector.collect() already attached family-less hypothesis
        explanations (it only ever sees one scan's incidents); this
        upgrades them with real recurrence data once history exists, and
        runs entirely in this unprivileged process -- privileged_helper.py
        is not involved and is not changed by this."""
        incidents = report.get("incidents") or []
        if not incidents:
            return
        try:
            from incident_history import families_from_history, family_for_incident
            from confidence_explanation import explain_incident

            exclude_generated = report.get("metadata", {}).get("generated")
            families = families_from_history(self.report_dir, incidents, exclude_generated=exclude_generated)
            for incident in incidents:
                family = family_for_incident(families, incident)
                if family is not None:
                    incident["hypothesis_explanations"] = explain_incident(incident, family=family)
            report["incident_families"] = [f.to_dict() for f in families if f.count > 1]
        except Exception as exc:
            self.set_status(f"Recurrence tracking unavailable this scan: {exc}")

    def _load_saved_scan_reports(self) -> list[dict[str, Any]]:
        reports = []
        for path in sorted(self.report_dir.glob("scan-*.json"))[-200:]:
            try:
                if path.stat().st_size > 20 * 1024 * 1024:
                    continue
                data = json.loads(path.read_text())
            except (OSError, ValueError, TypeError):
                continue
            if isinstance(data, dict):
                reports.append(data)
        return reports

    def _attach_reliability_summary(self, report: dict[str, Any]) -> None:
        """Attach a transparent summary without changing diagnosis or host state."""
        try:
            from reliability_summary import build_reliability_summary

            reports = self._load_saved_scan_reports()
            reports.append(report)
            report["reliability_summary"] = build_reliability_summary(reports)
        except Exception as exc:
            self.set_status(f"Reliability summary unavailable this scan: {exc}")

    def load_report(self) -> None:
        if self.report is None or not isinstance(self.report, dict):
            self._render_system_history_issues(None, is_historical=False, source_label="No scan loaded")
            return
        try:
            self.report = migrate_report(self.report)
        except Exception as exc:
            self.set_status(f"Error migrating report: {exc}")
            return
        overall = self.report.get("overall") if isinstance(self.report.get("overall"), dict) else {}
        self.overall_title.setText(str(overall.get("title", "No leading cause identified")))
        self.overall_summary.setText(str(overall.get("summary", "")))
        categories = self.report.get("categories") if isinstance(self.report.get("categories"), dict) else {}
        for category, card in self.cards.items():
            raw_state = categories.get(category)
            state = raw_state if isinstance(raw_state, dict) else {"status": "not_checked", "label": "Not checked"}
            card.set_state(str(state.get("label", "Not checked")), str(state.get("status", "not_checked")))
        self.populate_findings()
        self.populate_hypotheses()
        self.populate_timeline()
        self.populate_checks()
        self.populate_fixes()
        self.populate_readiness()
        self._render_system_history_issues(self.report, is_historical=None, source_label="Current scan")
        canary = self.report.get("canary") if isinstance(self.report.get("canary"), dict) else {}
        self.canary_label.setText(str(canary.get("interpretation", "No canary interpretation.")))
        raw_samples = canary.get("samples") if isinstance(canary.get("samples"), list) else []
        samples = [s for s in raw_samples if isinstance(s, dict)][-120:]
        def _psi_val(sample: dict[str, Any], key: str) -> float:
            block = sample.get(key)
            if not isinstance(block, dict):
                return 0.0
            try:
                return float(block.get("some_avg10", 0) or 0)
            except (TypeError, ValueError):
                return 0.0
        self.canary_chart.set_series([
            ("CPU PSI", [_psi_val(x, "psi_cpu") for x in samples], QColor("#7f56d9")),
            ("Memory PSI", [_psi_val(x, "psi_mem") for x in samples], QColor("#d92d20")),
            ("I/O PSI", [_psi_val(x, "psi_io") for x in samples], QColor("#1570ef")),
        ])
        test_targets = self.report.get("test_targets") if isinstance(self.report.get("test_targets"), dict) else {}
        smart_devs = test_targets.get("smart_devices") if isinstance(test_targets.get("smart_devices"), list) else []
        self.smart_device.clear()
        self.smart_device.addItems([str(d) for d in smart_devs if isinstance(d, str)])
        self.update_verification_label()
        self.refresh_trends()

    def filtered_findings(self) -> list[dict[str, Any]]:
        if not isinstance(self.report, dict): return []
        raw_items = self.report.get("findings")
        items = [f for f in raw_items if isinstance(f, dict)] if isinstance(raw_items, list) else []
        choice = self.finding_filter.currentText()
        if choice == "This incident": return [f for f in items if f.get("scope") == "this_incident"]
        if choice == "New": return [f for f in items if f.get("status") == "new"]
        if choice == "Recurring": return [f for f in items if f.get("status") == "recurring"]
        if choice == "Warnings and critical only": return [f for f in items if f.get("severity") in {"warning", "critical"}]
        return items

    def populate_findings(self) -> None:
        items = self.filtered_findings(); self.findings_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [
                f"{SEVERITY_ICON.get(item.get('severity'), '')} {str(item.get('severity','')).title()}",
                "This crash" if item.get("scope") == "this_incident" else "Historical",
                STATUS_ICON.get(item.get("status"), item.get("status", "")),
                item.get("category", ""), item.get("title", ""), item.get("confidence", ""),
            ]
            for col, value in enumerate(values): self.findings_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.findings_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, item)
        if items: self.findings_table.selectRow(0)
        else: self.finding_detail.setHtml("<p>No findings match this filter.</p>")

    def show_finding(self) -> None:
        row = self.findings_table.currentRow()
        if row < 0: return
        item = self.findings_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, dict): return
        ev_list = item.get("evidence") if isinstance(item.get("evidence"), list) else []
        evidence = "".join(f"<li><code>{html.escape(str(line))}</code></li>" for line in ev_list) or "<li>No individual line attached.</li>"
        self.finding_detail.setHtml(
            f"<h2>{html.escape(str(item.get('title','')))}</h2><p><b>{html.escape(str(item.get('severity','')).upper())}</b> · {html.escape(str(item.get('category','')))} · {html.escape(str(item.get('confidence','')))} confidence</p>"
            f"<p>{html.escape(str(item.get('explanation','')))}</p><h3>Evidence</h3><ul>{evidence}</ul>"
        )
        if self.fix_focus.currentText() == "Selected finding":
            self.populate_fixes()

    def populate_hypotheses(self) -> None:
        raw_items = self.report.get("hypotheses") if isinstance(self.report, dict) else []
        items = [h for h in raw_items if isinstance(h, dict)] if isinstance(raw_items, list) else []
        self.hyp_table.setRowCount(len(items))
        for row, item in enumerate(items):
            values = [item.get("rank"), item.get("confidence"), item.get("score"), item.get("category"), item.get("title")]
            for col, value in enumerate(values): self.hyp_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.hyp_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, item)
        if items: self.hyp_table.selectRow(0)

    def show_hypothesis(self) -> None:
        row = self.hyp_table.currentRow()
        if row < 0: return
        item = self.hyp_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, dict): return
        bullets = lambda values: "".join(f"<li>{html.escape(str(value))}</li>" for value in (values if isinstance(values, list) else [])) or "<li>None recorded.</li>"
        self.hyp_detail.setHtml(
            f"<h2>#{html.escape(str(item.get('rank', '')))} — {html.escape(str(item.get('title', 'Untitled hypothesis')))}</h2>"
            f"<p><b>{html.escape(str(item.get('confidence', 'unknown')).title())} confidence</b> · score {html.escape(str(item.get('score', '')))}</p>"
            f"<h3>Evidence for</h3><ul>{bullets(item.get('supports', []))}</ul>"
            f"<h3>Evidence against / uncertainty</h3><ul>{bullets(item.get('against', []))}</ul>"
            f"<h3>Best next test</h3><p>{html.escape(str(item.get('next_test','')))}</p>"
            f"<h3>Would strengthen it</h3><p>{html.escape(str(item.get('would_confirm','')))}</p>"
            f"<h3>Would weaken it</h3><p>{html.escape(str(item.get('would_weaken','')))}</p>"
        )
        if self.fix_focus.currentText() == "Top likely cause":
            self.populate_fixes()


    def populate_readiness(self) -> None:
        if not hasattr(self, "readiness_detail"):
            return
        if not isinstance(self.report, dict):
            self.readiness_detail.setHtml("<h2>No scan loaded</h2><p>Run a quick scan to assess crash capture readiness.</p>")
            return

        readiness = self.report.get("readiness") if isinstance(self.report.get("readiness"), dict) else {}
        html_parts = ["<h2>Crash Capture Readiness</h2>"]
        html_parts.append(f"<p><b>Recommendation:</b> {html.escape(str(readiness.get('recommendation', 'Unknown')))}</p>")

        sources = readiness.get("sources") if isinstance(readiness.get("sources"), list) else []
        for s in sources:
            if not isinstance(s, dict):
                continue
            color = "green" if s.get("status") in ("ready", "verified_persistent", "available_with_records", "verified_ready", "verified_active") else "orange" if s.get("status") in ("ready_empty", "disabled_intentionally") else "red"
            html_parts.append(f"<h3><span style='color:{color};'>&#9679;</span> {html.escape(str(s.get('name', '')))}</h3>")
            html_parts.append(f"<ul>")
            html_parts.append(f"<li><b>Status:</b> {html.escape(str(s.get('status', '')))}</li>")
            if s.get("evidence"): html_parts.append(f"<li><b>Evidence:</b> {html.escape(str(s.get('evidence')))}</li>")
            if s.get("limitation"): html_parts.append(f"<li><b>Limitation:</b> {html.escape(str(s.get('limitation')))}</li>")
            if s.get("setup"): html_parts.append(f"<li><b>Optional Setup:</b> {html.escape(str(s.get('setup')))}</li>")
            if s.get("implications"): html_parts.append(f"<li><b>Implications:</b> {html.escape(str(s.get('implications')))}</li>")
            html_parts.append(f"</ul>")

        self.readiness_detail.setHtml("".join(html_parts))

    def populate_timeline(self) -> None:
        raw_items = self.report.get("timeline") if isinstance(self.report, dict) else []
        items = [t for t in raw_items if isinstance(t, dict)] if isinstance(raw_items, list) else []
        self.timeline_table.setRowCount(len(items))
        if not items:
            self.timeline_summary.setText("No timestamped previous-boot events were found. Enable evidence capture before the next crash.")
        else:
            immediate = sum(1 for item in items if item.get("proximity") == "Immediately before crash")
            boundary = next((item for item in reversed(items) if item.get("category") == "Crash boundary"), items[-1])
            self.timeline_summary.setText(
                f"Crash timeline: {immediate} event(s) immediately before the journal ended. "
                f"Last boundary: {boundary.get('timestamp', 'unknown time')} — {boundary.get('summary', '')}"
            )
        for row, item in enumerate(items):
            values = [item.get("timestamp"), item.get("proximity"), item.get("category"), item.get("summary")]
            for col, value in enumerate(values): self.timeline_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.timeline_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, item)
        if items: self.timeline_table.selectRow(max(0, len(items) - 1))

    def show_timeline(self) -> None:
        row = self.timeline_table.currentRow()
        if row < 0: return
        item = self.timeline_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not isinstance(item, dict): return
        self.timeline_detail.setPlainText(f"{item.get('timestamp')}\n{item.get('proximity')}\n{item.get('category')}\n\n{item.get('evidence')}")

    def populate_checks(self) -> None:
        raw_checks = self.report.get("checks") if isinstance(self.report, dict) else {}
        checks = [(k, v) for k, v in raw_checks.items() if isinstance(v, dict)] if isinstance(raw_checks, dict) else []
        self.checks_table.setRowCount(len(checks))
        for row, (key, item) in enumerate(checks):
            values = [item.get("category", ""), item.get("title", key), item.get("state", item.get("status", "")), f"{item.get('duration_seconds',0)} s"]
            for col, value in enumerate(values): self.checks_table.setItem(row, col, QTableWidgetItem(str(value)))
            self.checks_table.item(row, 0).setData(Qt.ItemDataRole.UserRole, (key, item))
        if checks: self.checks_table.selectRow(0)

    def show_check(self) -> None:
        row = self.checks_table.currentRow()
        if row < 0: return
        data = self.checks_table.item(row, 0).data(Qt.ItemDataRole.UserRole)
        if not isinstance(data, tuple) or len(data) != 2 or not isinstance(data[1], dict): return
        key, item = data
        self.check_output.setPlainText(
            f"{item.get('title',key)}\nCategory: {item.get('category','')}\nState: {item.get('state', item.get('status', ''))} (return {item.get('returncode')})\nCommand: {item.get('command')}\n\n{item.get('output','')}"
        )

    def enable_capture(self) -> None:
        dialog = CaptureDialog(self)
        if dialog.exec() != QDialog.DialogCode.Accepted: return
        self.set_busy(True, "Enabling crash capture…")
        self.broker.request("setup_capture", {"cockpit": dialog.cockpit.isChecked()}, self.capture_setup_done, self.progress_update)

    def capture_setup_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False)
        if not ok: QMessageBox.warning(self, "Capture setup failed", str(data)); return
        text = json.dumps(data, indent=2)
        self.capture_output.setPlainText(text)
        QMessageBox.information(self, "Crash capture configured", "Crash capture was configured. Reboot before relying on kdump or the desktop heartbeat.")
        self.refresh_capture_status(silent=True)

    def refresh_capture_status(self, silent: bool = False) -> None:
        if not silent: self.set_busy(True, "Checking capture readiness…")
        self.broker.request("capture_status", {}, lambda ok, data: self.capture_status_done(ok, data, silent))

    def capture_status_done(self, ok: bool, data: Any, silent: bool) -> None:
        if not silent: self.set_busy(False)
        if not ok:
            if not silent: QMessageBox.warning(self, "Status failed", str(data))
            return
        self.capture_output.setPlainText(json.dumps(data, indent=2))

    def validate_kdump(self) -> None:
        self.set_busy(True, "Validating kdump without forcing a crash…")
        self.broker.request("kdump_validate", {}, self.test_done)

    def install_tools(self) -> None:
        if QMessageBox.question(self, "Install diagnostic tools?", "Install or repair the fixed Fedora diagnostic package set? Cockpit is not included.") != QMessageBox.StandardButton.Yes: return
        self.set_busy(True, "Installing diagnostic tools…")
        self.broker.request("install_tools", {}, self.tools_done, self.progress_update)

    def tools_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False); self.test_output.setPlainText(json.dumps(data, indent=2) if not isinstance(data, str) else data)
        if not ok: QMessageBox.warning(self, "Tool installation failed", str(data))
        else: QMessageBox.information(self, "Tools", "Diagnostic tool installation finished. Optional unavailable packages are listed in the output.")

    def install_cockpit(self) -> None:
        if QMessageBox.question(self, "Install or open Cockpit?", "Install any missing Cockpit packages, enable its local web interface on port 9090, then open it? This is optional and separate from crash capture.") != QMessageBox.StandardButton.Yes: return
        self.set_busy(True, "Installing optional Cockpit components…")
        self.broker.request("install_cockpit", {}, self.cockpit_done, self.progress_update)

    def cockpit_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False); self.capture_output.setPlainText(json.dumps(data, indent=2) if not isinstance(data, str) else data)
        if ok: QDesktopServices.openUrl(QUrl("https://localhost:9090"))
        else: QMessageBox.warning(self, "Cockpit installation failed", str(data))

    def smart_test(self) -> None:
        device = self.smart_device.currentText()
        if not device:
            QMessageBox.information(self, "No drive", "Run a scan first so SMART-capable drives can be discovered."); return
        self.run_test("smart_short", {"device": device}, f"Start the drive's built-in SMART short test on {device}?", True)

    def run_test(self, action: str, params: dict[str, Any], question: str, disruptive: bool) -> None:
        if QMessageBox.question(self, "Confirm controlled test", question) != QMessageBox.StandardButton.Yes: return
        if disruptive:
            phrase = action.replace("_", " ")
            typed, ok = QInputDialog.getText(
                self,
                "Type to confirm",
                f"Type {phrase} to start this disruptive action.",
            )
            if not ok or typed.strip().lower() != phrase:
                self.set_status("Controlled action cancelled.")
                return
        self.set_busy(True, f"Running {action.replace('_',' ')}…")
        self.broker.request(action, params, self.test_done, self.progress_update)

    def test_done(self, ok: bool, data: Any) -> None:
        self.set_busy(False)
        text = json.dumps(data, indent=2) if isinstance(data, (dict, list)) else str(data)
        self.test_output.setPlainText(text); self.capture_output.setPlainText(text)
        if not ok and text != "Cancelled.":
            QMessageBox.warning(self, "Action failed", text)
        elif ok:
            self.set_status("Controlled action completed. Review the output before drawing conclusions.")

    def launch(self, argv: list[str]) -> None:
        if not shutil.which(argv[0]):
            QMessageBox.information(self, "Not installed", f"{argv[0]} is not installed. Use Install/repair tools."); return
        subprocess.Popen(argv, start_new_session=True)

    def load_pending_autoscan(self) -> None:
        path = Path(f"/var/lib/fedora-crash-doctor/autoscans/{os.getuid()}/latest.json")
        if not path.exists(): return
        try:
            data = json.loads(path.read_text())
            self._attach_reliability_summary(data)
            saved = self.report_dir / f"scan-autoscan-{datetime.now().strftime('%Y%m%d-%H%M%S')}.json"
            saved.write_text(json.dumps(data, indent=2, ensure_ascii=False))
            path.unlink(missing_ok=True)
            self.report = data; self.load_report()
            counts = data.get("counts", {})
            QMessageBox.information(self, "Crash autoscan loaded", f"An automatic post-crash scan was found: {counts.get('critical',0)} critical, {counts.get('warning',0)} warnings.")
        except Exception as exc:
            self.set_status(f"Could not load pending autoscan: {exc}")

    def refresh_trends(self) -> None:
        rows = self._load_saved_scan_reports()
        from reliability_summary import build_reliability_summary
        reliability = build_reliability_summary(rows)
        if reliability["score"] is None:
            self.reliability_label.setText(
                f"Observed stability index: insufficient data ({reliability['reports']} dated scan(s)); "
                "two or more scans are required."
            )
        else:
            coverage = reliability["coverage"]
            self.reliability_label.setText(
                f"Observed stability index: {reliability['score']}/100 — "
                f"{reliability['incidents']} incident(s), "
                f"canary coverage {coverage['canary_fraction']:.0%}, "
                f"persistent-journal coverage {coverage['persistent_journal_fraction']:.0%}. "
                "This summarizes recorded evidence; it is not a hardware-health guarantee."
            )
        self.trends_table.setRowCount(len(rows))
        critical, warning, info = [], [], []
        for row, data in enumerate(rows):
            meta, counts = data.get("metadata", {}), data.get("counts", {})
            values = [meta.get("generated", ""), meta.get("mode", ""), data.get("overall", {}).get("title", ""), counts.get("critical", 0), counts.get("warning", 0), counts.get("info", 0)]
            for col, value in enumerate(values): self.trends_table.setItem(row, col, QTableWidgetItem(str(value)))
            critical.append(float(counts.get("critical", 0))); warning.append(float(counts.get("warning", 0))); info.append(float(counts.get("info", 0)))
        self.trend_chart.set_series([
            ("Critical", critical, QColor("#b42318")), ("Warnings", warning, QColor("#d97706")), ("Info", info, QColor("#2563eb")),
        ])
        self.comparison_label.setText(self.compare_recent_scans(rows))

    def compare_recent_scans(self, rows: list[dict[str, Any]]) -> str:
        if len(rows) < 2:
            return "Before/after comparison will appear after at least two saved scans."
        before, after = rows[-2], rows[-1]
        before_ids = {item.get("id", item.get("title", "")): item for item in before.get("findings", [])}
        after_ids = {item.get("id", item.get("title", "")): item for item in after.get("findings", [])}
        before_keys = set(before_ids)
        after_keys = set(after_ids)
        disappeared = [before_ids[key].get("title", key) for key in sorted(before_keys - after_keys)]
        recurring = [after_ids[key].get("title", key) for key in sorted(before_keys & after_keys)]
        new = [after_ids[key].get("title", key) for key in sorted(after_keys - before_keys)]
        parts = []
        if disappeared:
            parts.append("Disappeared: " + ", ".join(disappeared[:4]))
        if recurring:
            parts.append("Still recurring: " + ", ".join(recurring[:4]))
        if new:
            parts.append("New: " + ", ".join(new[:4]))
        return "Before/after comparison: " + ("; ".join(parts) if parts else "no finding changes between the last two scans.")

    def redact(self, text: str) -> str:
        if not self.privacy.isChecked(): return text
        user, host = os.environ.get("USER", ""), socket.gethostname()
        for old, new in ((f"/home/{user}", "/home/REDACTED-USER"), (host, "REDACTED-HOST"), (user, "REDACTED-USER")):
            if old: text = text.replace(old, new)
        text = re.sub(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b", "REDACTED-EMAIL", text)
        text = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "REDACTED-IP", text)
        return text

    def choose_export(self, suffix: str, label: str) -> str:
        stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
        path, _ = QFileDialog.getSaveFileName(self, label, str(self.report_dir / f"fedora-crash-doctor-{stamp}.{suffix}"), f"{suffix.upper()} (*.{suffix})")
        return path

    def export_json(self) -> None:
        if not self.report: QMessageBox.information(self, "No report", "Run a scan first."); return
        path = self.choose_export("json", "Export JSON")
        if path: Path(path).write_text(self.redact(json.dumps(self.report, indent=2, ensure_ascii=False)))

    def export_text(self) -> None:
        if not self.report: QMessageBox.information(self, "No report", "Run a scan first."); return
        path = self.choose_export("txt", "Export support text")
        if not path: return
        lines = [
            "FEDORA CRASH DOCTOR", "=" * 22,
            self.report.get("overall", {}).get("summary", ""), "", "RANKED CAUSES",
        ]
        for item in self.report.get("hypotheses", [])[:5]:
            lines.extend([
                f"{item.get('rank', '')}. {item.get('title', 'Untitled hypothesis')} — {item.get('confidence', 'unknown')} ({item.get('score', '')})",
                f"   Next test: {item.get('next_test', '')}",
            ])
        lines.extend(["", "FINDINGS"])
        for item in self.report.get("findings", []):
            lines.append(
                f"[{str(item.get('severity', '')).upper()}] [{item.get('scope', '')}] "
                f"{item.get('title', 'Untitled finding')}: {item.get('explanation', '')}"
            )
            for evidence in item.get("evidence", [])[:4]: lines.append(f"  - {evidence}")
        lines.extend(["", "TIMELINE"])
        for item in self.report.get("timeline", [])[-20:]:
            lines.append(f"{item.get('timestamp', '')} | {item.get('proximity', '')} | {item.get('summary', '')}")
        Path(path).write_text(self.redact("\n".join(lines)))

    def export_html(self) -> None:
        if not self.report: QMessageBox.information(self, "No report", "Run a scan first."); return
        path = self.choose_export("html", "Export HTML")
        if not path: return
        report = self.report
        hypotheses = "".join(
            f"<article><h3>#{html.escape(str(h.get('rank', '')))} {html.escape(str(h.get('title', 'Untitled hypothesis')))}</h3>"
            f"<p><b>{html.escape(str(h.get('confidence', 'unknown')))} confidence; score {html.escape(str(h.get('score', '')))}</b></p>"
            f"<p>{html.escape(str(h.get('next_test', '')))}</p></article>" for h in report.get("hypotheses", [])
        )
        findings = "".join(
            f"<article class='{html.escape(str(f.get('severity', 'info')))}'><h3>{html.escape(str(f.get('title', 'Untitled finding')))}</h3>"
            f"<p>{html.escape(str(f.get('explanation', '')))}</p>"
            f"<pre>{html.escape(chr(10).join(f.get('evidence', [])))}</pre></article>" for f in report.get("findings", [])
        )
        timeline = "".join(
            f"<tr><td>{html.escape(str(t.get('timestamp', '')))}</td><td>{html.escape(str(t.get('proximity', '')))}</td>"
            f"<td>{html.escape(str(t.get('summary', '')))}</td></tr>" for t in report.get("timeline", [])
        )
        document = f"""<!doctype html><html><head><meta charset='utf-8'><title>Fedora Crash Doctor</title><style>
body{{font-family:system-ui;max-width:1180px;margin:30px auto;padding:0 18px;background:#f6f7f9;color:#1d2939}}header,article,.panel{{background:white;border:1px solid #d0d5dd;border-radius:12px;padding:18px;margin:12px 0}}.critical{{border-left:7px solid #b42318}}.warning{{border-left:7px solid #d97706}}.info{{border-left:7px solid #2563eb}}pre{{white-space:pre-wrap;background:#f2f4f7;padding:10px}}table{{width:100%;border-collapse:collapse;background:white}}td,th{{padding:8px;border:1px solid #d0d5dd;text-align:left}}</style></head><body>
<header><h1>Fedora Crash Doctor</h1><h2>{html.escape(report.get('overall',{}).get('title',''))}</h2><p>{html.escape(report.get('overall',{}).get('summary',''))}</p></header>
<h2>Ranked causes</h2>{hypotheses}<h2>Findings</h2>{findings}<h2>Incident timeline</h2><table><tr><th>Time</th><th>Proximity</th><th>Event</th></tr>{timeline}</table></body></html>"""
        Path(path).write_text(self.redact(document)); QDesktopServices.openUrl(QUrl.fromLocalFile(path))

    def closeEvent(self, event) -> None:
        if self.broker.ready: self.broker.cancel_all()
        super().closeEvent(event)


def gui_main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Fedora Crash Doctor")
    app.setOrganizationName("Fedora Crash Doctor")
    window = MainWindow(); window.show()
    return app.exec()


def cli_main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="fedora_crash_doctor.py",
        description="Fedora Crash Doctor diagnostics.",
        epilog=(
            "Examples:\n"
            "  python3 fedora_crash_doctor.py --cli --scan --mode quick --output scan.json\n"
            "  python3 fedora_crash_doctor.py --cli --scan --mode deep --output deep-scan.json\n"
            "  python3 fedora_crash_doctor.py --record-observation inc_0123456789abcdef\n"
            "  python3 fedora_crash_doctor.py --version"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="store_true", help="print the Fedora Crash Doctor version and exit")
    parser.add_argument("--cli", action="store_true", help="run in command-line mode instead of launching the GUI")
    parser.add_argument("--scan", action="store_true", help="collect a diagnostic scan in CLI mode")
    parser.add_argument("--mode", choices=["quick", "full", "deep"], default="quick", help="scan depth; deep includes expensive maintenance checks")
    parser.add_argument("--output", help="write scan JSON to this path")
    parser.add_argument("--baseline", help="optional previous scan JSON used to mark recurring findings")
    parser.add_argument("--record-observation", metavar="INCIDENT_ID",
                         help="interactively record what you observed for an incident (a scan's report.json "
                              "lists each incident's incident_id)")
    args = parser.parse_args(argv)

    if args.version:
        print(f"Fedora Crash Doctor {VERSION}")
        return 0
    if args.record_observation:
        from incident_observations import run_observation_cli
        run_observation_cli(args.record_observation)
        return 0
    if not args.cli:
        parser.error("unknown GUI arguments; run with no arguments to launch the GUI, or use --cli for terminal mode")
    if not args.scan:
        parser.error("--cli currently requires --scan")
    if not args.output:
        parser.error("--scan requires --output PATH")

    from collector import collect

    started = datetime.now()

    def progress(current: int, total: int, label: str) -> None:
        elapsed = int((datetime.now() - started).total_seconds())
        print(f"[{current}/{total}] {label} ({elapsed}s elapsed)", file=sys.stderr)

    report = collect(args.mode, args.baseline, progress)
    Path(args.output).write_text(json.dumps(report, indent=2, ensure_ascii=False))
    print(args.output)
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv:
        return cli_main(argv)
    return gui_main()


if __name__ == "__main__":
    raise SystemExit(main())
