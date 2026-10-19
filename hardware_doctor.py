import re
from datetime import datetime, timezone
from typing import Any
import hashlib

def parse_iso_time(timestamp_str: str) -> datetime | None:
    try:
        return datetime.fromisoformat(timestamp_str)
    except ValueError:
        return None

def extract_timestamp(line: str) -> datetime | None:
    parts = line.split()
    if not parts:
        return None
    return parse_iso_time(parts[0])

def generate_event_id(dt: datetime, normalized_msg: str) -> str:
    base = f"{dt.replace(microsecond=0).isoformat()}_{normalized_msg}"
    return hashlib.md5(base.encode()).hexdigest()

def cluster_events(events: list[dict[str, Any]], window_seconds: int = 60) -> list[list[dict[str, Any]]]:
    if not events:
        return []
    clusters = []
    current_cluster = [events[0]]
    for e in events[1:]:
        if (e["time"] - current_cluster[-1]["time"]).total_seconds() <= window_seconds:
            current_cluster.append(e)
        else:
            clusters.append(current_cluster)
            current_cluster = [e]
    clusters.append(current_cluster)
    return clusters

def analyze_hardware_events(lines: list[str]) -> list[dict[str, Any]]:
    raw_pcie = []
    raw_usb = []
    raw_sda = []
    
    unique_pcie = {}
    unique_usb = {}
    unique_sda = {}
    
    for line in lines:
        dt = extract_timestamp(line)
        if not dt: continue
            
        if "rtw88_8821ce" in line and "PCIe Bus Error" in line:
            raw_pcie.append(line)
            norm = re.sub(r"AVANCE-WS7.*?kernel: ", "", line).strip()
            eid = generate_event_id(dt, norm)
            if eid not in unique_pcie:
                unique_pcie[eid] = {"time": dt, "raw": line, "norm": norm}
                
        elif "usb usb1-port14:" in line and "unable to enumerate USB device" in line:
            raw_usb.append(line)
            norm = "usb usb1-port14 unable to enumerate"
            eid = generate_event_id(dt, norm)
            if eid not in unique_usb:
                unique_usb[eid] = {"time": dt, "raw": line, "norm": norm}
                
        elif "sda" in line and ("Buffer I/O error" in line or "device offline" in line or "EXT4-fs" in line):
            raw_sda.append(line)
            norm = re.sub(r"AVANCE-WS7.*?kernel: ", "", line).strip()
            eid = generate_event_id(dt, norm)
            if eid not in unique_sda:
                unique_sda[eid] = {"time": dt, "raw": line, "norm": norm}

    issues = []
    def create_issue(category, title, status, evidence, action):
        return {
            "category": category,
            "title": title,
            "status": status,
            "evidence": evidence,
            "recommended_action": action,
        }
        
    if unique_pcie:
        pcie_list = sorted(unique_pcie.values(), key=lambda x: x["time"])
        clusters = cluster_events(pcie_list)
        issues.append(create_issue(
            "hardware",
            "Persistent corrected PCIe errors from Realtek Wi-Fi adapter — monitoring recommended.",
            "Monitoring",
            [
                f"Incident clusters: {len(clusters)}",
                f"Unique events: {len(pcie_list)}",
                f"Raw evidence appearances: {len(raw_pcie)}",
                "Errors include Bad DLLP and Replay Timer Timeout.",
                f"First seen: {pcie_list[0]['time']}",
                f"Last seen: {pcie_list[-1]['time']}"
            ],
            "Do not disable AER or ASPM. Monitor for correlation with Wi-Fi dropouts."
        ))
        
    if unique_usb:
        usb_list = sorted(unique_usb.values(), key=lambda x: x["time"])
        clusters = cluster_events(usb_list)
        issues.append(create_issue(
            "hardware",
            "USB port 1-14 (Realtek Bluetooth 4.2 Adapter) repeatedly fails enumeration.",
            "Investigate",
            [
                f"Incident clusters: {len(clusters)}",
                f"Unique events: {len(usb_list)}",
                f"Raw evidence appearances: {len(raw_usb)}",
                f"First seen: {usb_list[0]['time']}",
                f"Last seen: {usb_list[-1]['time']}"
            ],
            "Identify internal connectivity issues for the Bluetooth combo module."
        ))
        
    if unique_sda:
        sda_list = sorted(unique_sda.values(), key=lambda x: x["time"])
        clusters = cluster_events(sda_list, window_seconds=120)
        issues.append(create_issue(
            "storage",
            "Historical external/removable storage I/O failure.",
            "Historical",
            [
                f"Incident clusters: {len(clusters)}",
                f"Unique events: {len(sda_list)}",
                f"Raw evidence appearances: {len(raw_sda)}",
                "Errors include Buffer I/O errors and device offline events.",
                "This does NOT attribute to the internal NVMe boot drive.",
                f"First seen: {sda_list[0]['time']}",
                f"Last seen: {sda_list[-1]['time']}"
            ],
            "Confirm if a failing USB drive or external enclosure was attached around these dates."
        ))
        
    return issues


_FAILED_CHECK_STATUSES = {"error", "failed", "timeout", "timed_out", "cancelled", "not_available", "unavailable", "permission_denied", "skipped"}


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _as_list(value: Any) -> list[Any]:
    return value if isinstance(value, list) else []


def _format_status(base_status: str, is_historical: bool) -> str:
    if is_historical and "historical" not in base_status.lower():
        return f"Historical — {base_status}"
    return base_status


def _is_report_historical(report: dict[str, Any] | None, explicit_historical: bool | None = None) -> bool:
    if explicit_historical is not None:
        return bool(explicit_historical)
    if not isinstance(report, dict):
        return False
    if report.get("historical") is True:
        return True
    meta = _as_dict(report.get("metadata"))
    if meta.get("is_historical") is True:
        return True
    if str(meta.get("scope", "")).lower() == "historical":
        return True
    return False


def _report_timestamp(report: dict[str, Any] | None) -> str:
    rep = _as_dict(report)
    meta = _as_dict(rep.get("metadata"))
    gen = meta.get("generated") or rep.get("generated")
    return str(gen).strip() if isinstance(gen, str) and gen.strip() else "Unknown"


def _check_output(check: dict[str, Any]) -> str:
    if not isinstance(check, dict):
        return ""
    out = check.get("output")
    if out is None:
        out = check.get("stdout")
    err = check.get("stderr")
    out_str = str(out) if out is not None else ""
    if err and isinstance(err, str) and err.strip() and err.strip() not in out_str:
        out_str = f"{out_str}\n{err}".strip()
    return out_str


def _check_command(check: dict[str, Any], fallback: str = "") -> str:
    if not isinstance(check, dict):
        return fallback
    cmd = check.get("command")
    if cmd is None:
        cmd = check.get("cmd")
    if isinstance(cmd, list):
        return " ".join(str(x) for x in cmd).strip() or fallback
    if isinstance(cmd, str) and cmd.strip():
        return cmd.strip()
    title = check.get("title")
    if isinstance(title, str) and title.strip():
        return title.strip()
    return fallback


def _check_succeeded(check: dict[str, Any]) -> bool:
    if not isinstance(check, dict):
        return False
    if check.get("ok") is False:
        return False
    status = str(check.get("status", "ok")).lower()
    state = str(check.get("state", "completed")).lower()
    rc = check.get("returncode", 0)
    output = _check_output(check)
    if status in _FAILED_CHECK_STATUSES or state in _FAILED_CHECK_STATUSES:
        return False
    if rc not in (0, None):
        return False
    lower_out = output.lower()
    if "permission denied" in lower_out or "command is not installed" in lower_out:
        return False
    return bool(output.strip())


def evaluate_nvme_health(
    report: dict[str, Any] | None = None,
    raw_lines: list[str] | None = None,
    *,
    is_historical: bool = False,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Evaluate Internal NVMe health strictly from collected SMART / NVMe evidence."""
    report_dict = _as_dict(report)
    checks = _as_dict(report_dict.get("checks"))
    findings = [f for f in _as_list(report_dict.get("findings")) if isinstance(f, dict)]
    timestamp = _report_timestamp(report_dict)

    cand_keys = sorted(
        k for k in checks
        if isinstance(k, str) and (k.startswith("smart") or k.startswith("nvme"))
    )
    nvme_checks: list[tuple[str, dict[str, Any]]] = []
    for k in cand_keys:
        c = _as_dict(checks.get(k))
        title_cmd = f"{c.get('title', '')} {_check_command(c)}".lower()
        # Exclude explicit non-NVMe /dev/sd* SMART checks if other checks exist
        if k.startswith("smart") and ("/dev/sd" in title_cmd or "usb" in title_cmd) and len(cand_keys) > 1:
            continue
        nvme_checks.append((k, c))

    nvme_findings = []
    for f in findings:
        fid = str(f.get("id", "")).lower()
        cat = str(f.get("category", "")).lower()
        title = str(f.get("title", "")).lower()
        expl = str(f.get("explanation", "")).lower()
        raw_ev = f.get("evidence")
        ev_items = raw_ev if isinstance(raw_ev, list) else ([raw_ev] if isinstance(raw_ev, str) else [])
        ev_text = " ".join(str(x) for x in ev_items).lower()
        if (
            fid.startswith("storage_nvme")
            or ("storage" in cat and ("nvme" in title or "internal system disk" in title or "smart" in expl or "nvme" in ev_text or "smart" in ev_text))
        ):
            nvme_findings.append(f)

    item_historical = is_historical or (
        not nvme_checks
        and bool(nvme_findings)
        and all(str(f.get("scope", "")).lower() == "historical" for f in nvme_findings)
    )

    valid_sources: list[str] = []
    failed_notes: list[str] = []
    combined_texts: list[str] = []
    any_check_succeeded = False

    for key, c in nvme_checks:
        out = _check_output(c)
        cmd_desc = _check_command(c, key)
        src_desc = f"{key} ({cmd_desc})" if cmd_desc != key else key
        if str(c.get("scope", "")).lower() == "historical":
            item_historical = True
        if _check_succeeded(c):
            any_check_succeeded = True
            valid_sources.append(src_desc)
            combined_texts.append(out)
        else:
            # Even if smartctl returned a non-zero exit code, it may contain failure telemetry
            if re.search(r"SMART overall-health|SMART Health Status|critical_warning|Critical Warning|media_errors|Media and Data Integrity Errors", out, re.I):
                valid_sources.append(src_desc)
                combined_texts.append(out)
            first_line = next((ln.strip() for ln in out.splitlines() if ln.strip()), c.get("state") or c.get("status") or "unavailable")
            failed_notes.append(f"{key}: {first_line[:160]}")

    if raw_lines:
        raw_joined = "\n".join(str(ln) for ln in raw_lines if isinstance(ln, str))
        if re.search(r"SMART overall-health|SMART Health Status|Smart Log for NVME|critical_warning\s*:|Media and Data Integrity Errors", raw_joined, re.I):
            combined_texts.append(raw_joined)
            valid_sources.append(source_label or "loaded history log")
            if "permission denied" not in raw_joined.lower():
                any_check_succeeded = True

    full_text = "\n".join(combined_texts)

    smart_passed: bool | None = None
    if re.search(r"SMART overall-health self-assessment test result:\s*(?:FAILED|BAD)|SMART Health Status:\s*(?:BAD|FAILED)", full_text, re.I):
        smart_passed = False
    elif re.search(r"SMART overall-health self-assessment test result:\s*PASSED|SMART Health Status:\s*OK", full_text, re.I):
        smart_passed = True

    crit_match = re.search(r"(?:critical_warning|Critical Warning)\s*:\s*(0x[0-9a-fA-F]+|\d+)", full_text)
    critical_warning = int(crit_match.group(1), 0) if crit_match else None

    media_match = re.search(r"(?:media_errors|Media and Data Integrity Errors)\s*:\s*([\d,]+)", full_text)
    media_errors = int(media_match.group(1).replace(",", "")) if media_match else None

    err_match = re.search(r"(?:num_err_log_entries|Error Information Log Entries)\s*:\s*([\d,]+)", full_text)
    err_log_entries = int(err_match.group(1).replace(",", "")) if err_match else None

    temp_match = re.search(r"(?:temperature|Temperature)\s*:\s*(-?\d+)\s*(?:°\s*C|Celsius|\bC\b)", full_text, re.I)
    temperature_c = int(temp_match.group(1)) if temp_match else None

    warn_temp_match = re.search(r"Warning\s+Comp\.\s+Temp\.\s+Threshold:\s*(\d+)\s*Celsius", full_text, re.I)
    warn_temp_c = int(warn_temp_match.group(1)) if warn_temp_match else 78

    crit_temp_match = re.search(r"Critical\s+Comp\.\s+Temp\.\s+Threshold:\s*(\d+)\s*Celsius", full_text, re.I)
    crit_temp_c = int(crit_temp_match.group(1)) if crit_temp_match else 82

    wear_match = re.search(r"(?:percentage_used|Percentage Used)\s*:\s*(\d+)\s*%", full_text, re.I)
    percentage_used = int(wear_match.group(1)) if wear_match else None

    spare_match = re.search(r"(?:available_spare|Available Spare)\s*:\s*(\d+)\s*%", full_text, re.I)
    available_spare = int(spare_match.group(1)) if spare_match else None

    spare_thresh_match = re.search(r"(?:available_spare_threshold|Available Spare Threshold)\s*:\s*(\d+)\s*%", full_text, re.I)
    spare_threshold = int(spare_thresh_match.group(1)) if spare_thresh_match else None

    model_match = re.search(r"Model Number:\s*(.+)", full_text)
    model = model_match.group(1).strip() if model_match else None

    local_time_match = re.search(r"Local Time is:\s*(.+)", full_text)
    if local_time_match and timestamp == "Unknown":
        timestamp = local_time_match.group(1).strip()

    raw_nvme_err_lines: list[str] = []
    if raw_lines:
        for ln in raw_lines:
            if isinstance(ln, str) and re.search(r"\bnvme\d*\S*:.*(?:I/O error|timeout|resetting|critical_warning|device offline|FAILED)", ln, re.I):
                raw_nvme_err_lines.append(ln.strip())

    has_critical_finding = any(str(f.get("severity", "")).lower() == "critical" for f in nvme_findings)
    has_warning_finding = any(str(f.get("severity", "")).lower() == "warning" for f in nvme_findings)

    is_failing = (
        smart_passed is False
        or (critical_warning is not None and critical_warning > 0)
        or (media_errors is not None and media_errors > 0)
        or (available_spare is not None and spare_threshold is not None and available_spare < spare_threshold)
        or (available_spare is not None and spare_threshold is None and available_spare < 10)
        or (temperature_c is not None and temperature_c >= crit_temp_c)
        or has_critical_finding
    )

    is_warning = not is_failing and (
        (percentage_used is not None and percentage_used >= 100)
        or (temperature_c is not None and temperature_c >= warn_temp_c)
        or (err_log_entries is not None and err_log_entries > 0)
        or has_warning_finding
        or bool(raw_nvme_err_lines)
    )

    has_positive_health = any_check_succeeded and (
        smart_passed is True
        or (critical_warning == 0 and (media_errors is None or media_errors == 0))
    )

    evidence: list[str] = []
    if model:
        evidence.append(f"Model: {model}")
    if smart_passed is True:
        evidence.append("SMART: Passed")
    elif smart_passed is False:
        evidence.append("SMART: FAILED")
    elif critical_warning == 0 and any_check_succeeded:
        evidence.append("SMART: Passed (critical_warning: 0)")

    if critical_warning is not None:
        evidence.append(f"Critical warning: 0x{critical_warning:02x}" if critical_warning > 0 else "Critical warning: 0")
    if media_errors is not None:
        evidence.append(f"Media errors: {media_errors}")
    if err_log_entries is not None:
        evidence.append(f"NVMe error-log entries: {err_log_entries}")
    if temperature_c is not None:
        temp_state = "Normal" if temperature_c < warn_temp_c else ("Critical" if temperature_c >= crit_temp_c else "Elevated")
        evidence.append(f"Temperature: {temperature_c} °C ({temp_state})")
    if percentage_used is not None:
        evidence.append(f"Wear used: {percentage_used}%")
    if available_spare is not None:
        thresh_note = f" (threshold: {spare_threshold}%)" if spare_threshold is not None else ""
        evidence.append(f"Available spare: {available_spare}%{thresh_note}")

    for f in nvme_findings:
        evidence.append(f"Finding [{f.get('severity', 'info')}]: {f.get('title', '')}")
        for ev_line in _as_list(f.get("evidence"))[:3]:
            evidence.append(f"Log: {ev_line}")
    for ln in raw_nvme_err_lines[:3]:
        evidence.append(f"Log: {ln}")

    if is_failing:
        base_status = "Failing"
        action = "Back up important data immediately and inspect full SMART/NVMe telemetry."
    elif is_warning:
        base_status = "Warning"
        action = "Back up important data and monitor NVMe error logs, wear, and temperatures."
    elif has_positive_health:
        base_status = "Healthy"
        action = "No action required."
    elif any_check_succeeded and full_text.strip():
        base_status = "Insufficient evidence"
        evidence.append("Check output did not contain recognizable SMART or NVMe health fields.")
        action = "Run a privileged scan with smartmontools and nvme-cli installed to verify NVMe health."
    else:
        base_status = "Not checked"
        evidence.append("No verified SMART or NVMe health telemetry is available in this report.")
        for note in failed_notes[:2]:
            evidence.append(f"Unverified check ({note})")
        action = "Run a privileged Quick or Full scan to collect SMART and NVMe health logs."

    source_summary = ", ".join(valid_sources) if valid_sources else (source_label or ("unverified (" + ", ".join(k for k, _ in nvme_checks) + ")" if nvme_checks else "none"))
    scope_str = "Historical" if item_historical else "Current scan"
    evidence.append(f"Evidence source: {source_summary}")
    evidence.append(f"Timestamp: {timestamp}")
    evidence.append(f"Scope: {scope_str}")

    return {
        "category": "storage",
        "title": "Internal NVMe",
        "status": _format_status(base_status, item_historical),
        "scope": "historical" if item_historical else "current_scan",
        "timestamp": timestamp,
        "source": source_summary,
        "evidence": evidence,
        "recommended_action": action,
    }


def evaluate_btrfs_health(
    report: dict[str, Any] | None = None,
    raw_lines: list[str] | None = None,
    *,
    is_historical: bool = False,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Evaluate Btrfs health strictly from collected btrfs_stats / btrfs_scrub evidence."""
    report_dict = _as_dict(report)
    checks = _as_dict(report_dict.get("checks"))
    findings = [f for f in _as_list(report_dict.get("findings")) if isinstance(f, dict)]
    timestamp = _report_timestamp(report_dict)

    stats_check = _as_dict(checks.get("btrfs_stats"))
    scrub_check = _as_dict(checks.get("btrfs_scrub"))
    stats_ok = _check_succeeded(stats_check)
    scrub_ok = _check_succeeded(scrub_check)
    stats_out = _check_output(stats_check)
    scrub_out = _check_output(scrub_check)

    btrfs_findings = [
        f for f in findings
        if "btrfs" in str(f.get("title", "")).lower()
        or "btrfs" in str(f.get("explanation", "")).lower()
        or any("btrfs" in str(x).lower() for x in _as_list(f.get("evidence")))
    ]

    raw_btrfs_errs: list[str] = []
    if raw_lines:
        for ln in raw_lines:
            if isinstance(ln, str) and re.search(r"BTRFS.*(?:error|corrupt|readonly|abort)", ln, re.I):
                raw_btrfs_errs.append(ln.strip())

    counters: dict[str, int] = {}
    if stats_ok:
        for m in re.finditer(r"\[(?P<dev>[^\]]+)\]\.(?P<metric>\w+_errs)\s+(?P<val>\d+)", stats_out):
            metric = m.group("metric")
            counters[metric] = counters.get(metric, 0) + int(m.group("val"))

    scrub_errors = False
    scrub_summary = "Scrub status: not checked"
    if scrub_ok:
        err_m = re.search(r"Error summary:\s*(.+)", scrub_out, re.I)
        err_text = err_m.group(1).strip() if err_m else ""
        if err_text and err_text.lower() != "no errors found":
            scrub_errors = True
            scrub_summary = f"Scrub error summary: {err_text}"
        elif "no stats available" in scrub_out.lower():
            scrub_summary = "Scrub status: no scrub run recorded (no stats available)"
        elif err_text.lower() == "no errors found":
            started_m = re.search(r"Scrub started:\s*(.+)", scrub_out, re.I)
            started_note = f" ({started_m.group(1).strip()})" if started_m else ""
            scrub_summary = f"Scrub completed with no errors{started_note}"
        else:
            scrub_summary = "Scrub status: inspected"
    elif scrub_check:
        first_line = next((ln.strip() for ln in scrub_out.splitlines() if ln.strip()), "unavailable")
        scrub_summary = f"Scrub status: unverified ({first_line[:120]})"

    io_errs = sum(counters.get(k, 0) for k in ("write_io_errs", "read_io_errs", "flush_io_errs"))
    corrupt_errs = sum(counters.get(k, 0) for k in ("corruption_errs", "generation_errs"))

    evidence: list[str] = []
    sources: list[str] = []
    if stats_ok:
        sources.append("btrfs_stats (btrfs device stats /)")
    if scrub_ok:
        sources.append("btrfs_scrub (btrfs scrub status /)")

    if counters:
        evidence.append(f"Read/write/flush errors: {io_errs}")
        evidence.append(f"Corruption/generation errors: {corrupt_errs}")
    evidence.append(scrub_summary)

    for f in btrfs_findings:
        evidence.append(f"Finding [{f.get('severity', 'info')}]: {f.get('title', '')}")
    for ln in raw_btrfs_errs[:3]:
        evidence.append(f"Log: {ln}")

    if corrupt_errs > 0 or io_errs > 0 or scrub_errors or any(f.get("severity") == "critical" for f in btrfs_findings):
        base_status = "Failing"
        action = "Back up data immediately and inspect Btrfs device stats and scrub output."
    elif btrfs_findings or raw_btrfs_errs:
        base_status = "Warning"
        action = "Inspect Btrfs logs and run a verified Btrfs scrub when convenient."
    elif stats_ok and counters:
        base_status = "Healthy"
        action = "No action required."
    elif stats_ok or scrub_ok:
        base_status = "Insufficient evidence"
        action = "Run a privileged scan to verify Btrfs device error counters."
    else:
        base_status = "Not checked"
        evidence.insert(0, "No verified Btrfs device stats were collected in this report.")
        action = "Run a scan on a Btrfs root filesystem to verify device counters."

    source_summary = ", ".join(sources) if sources else (source_label or "none")
    scope_str = "Historical" if is_historical else "Current scan"
    evidence.append(f"Evidence source: {source_summary}")
    evidence.append(f"Timestamp: {timestamp}")
    evidence.append(f"Scope: {scope_str}")

    return {
        "category": "storage",
        "title": "Btrfs",
        "status": _format_status(base_status, is_historical),
        "scope": "historical" if is_historical else "current_scan",
        "timestamp": timestamp,
        "source": source_summary,
        "evidence": evidence,
        "recommended_action": action,
    }


def evaluate_ram_cpu_health(
    report: dict[str, Any] | None = None,
    raw_lines: list[str] | None = None,
    *,
    is_historical: bool = False,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Evaluate RAM / CPU Hardware health strictly from RAS/EDAC/MCE/kernel evidence."""
    report_dict = _as_dict(report)
    checks = _as_dict(report_dict.get("checks"))
    findings = [f for f in _as_list(report_dict.get("findings")) if isinstance(f, dict)]
    timestamp = _report_timestamp(report_dict)

    ras_check = _as_dict(checks.get("ras_errors"))
    edac_check = _as_dict(checks.get("edac"))
    hw_prev = _as_dict(checks.get("hardware_errors_previous"))
    hw_hist = _as_dict(checks.get("hardware_errors_history"))
    cur_kern = _as_dict(checks.get("current_kernel_errors"))

    ras_ok = _check_succeeded(ras_check)
    edac_ok = _check_succeeded(edac_check) and "no memory controller data found" not in _check_output(edac_check).lower()
    kern_ok = any(_check_succeeded(c) for c in (hw_prev, hw_hist, cur_kern))

    hw_findings = [
        f for f in findings
        if str(f.get("id", "")) == "uncorrectable_hardware"
        or any(
            re.search(r"mce:|machine check|memory-failure|uncorrectable.*hardware|edac.*error", str(ev), re.I)
            for ev in _as_list(f.get("evidence"))
        )
    ]

    combined_kern = "\n".join(
        _check_output(c) for c in (hw_prev, hw_hist, cur_kern) if isinstance(c, dict)
    )
    if raw_lines:
        combined_kern += "\n" + "\n".join(str(ln) for ln in raw_lines if isinstance(ln, str))

    mce_lines = [
        ln.strip()
        for ln in combined_kern.splitlines()
        if re.search(r"mce:.*(?:hardware error|fatal|uncorrected)|machine check.*(?:fatal|error)|memory-failure:|EDAC.*(?:UE|CE\b.*[1-9])", ln, re.I)
    ]

    ras_out = _check_output(ras_check)
    ras_has_mem_errors = ras_ok and "no memory errors" not in ras_out.lower() and bool(re.search(r"memory.*error|mc_event", ras_out, re.I))

    sources: list[str] = []
    if ras_ok:
        sources.append("ras_errors (ras-mc-ctl --errors)")
    if edac_ok:
        sources.append("edac (edac-util -v)")
    for key, c in (("current_kernel_errors", cur_kern), ("hardware_errors_previous", hw_prev), ("hardware_errors_history", hw_hist)):
        if _check_succeeded(c):
            sources.append(key)

    evidence: list[str] = []
    if hw_findings or mce_lines or ras_has_mem_errors:
        base_status = "Failing"
        for f in hw_findings:
            evidence.append(f"Finding [{f.get('severity', 'critical')}]: {f.get('title', '')}")
        for ln in mce_lines[:4]:
            evidence.append(f"Kernel log: {ln}")
        if ras_has_mem_errors:
            evidence.append("rasdaemon recorded memory controller events.")
        action = "Test RAM with Memtest86+ and inspect CPU/motherboard machine-check logs."
    elif ras_ok or edac_ok or kern_ok:
        if ras_ok and "no memory errors" in ras_out.lower():
            evidence.append("RAS daemon memory errors: 0 (No Memory errors)")
        elif not ras_ok:
            evidence.append("RAS daemon database: unverified / inactive")
        if edac_ok:
            evidence.append("EDAC memory-controller counters: verified")
        else:
            evidence.append("EDAC memory-controller counters: unavailable on this platform")
        if kern_ok:
            evidence.append("Kernel MCE / memory-failure events in collected logs: 0")
        base_status = "Healthy" if (ras_ok or edac_ok) and kern_ok else ("Healthy" if ras_ok else "Insufficient evidence")
        action = "No action required." if base_status == "Healthy" else "Enable rasdaemon via Crash Capture to record hardware memory counters."
    else:
        base_status = "Not checked"
        evidence.append("No verified RAS, EDAC, or kernel MCE check outputs were collected in this report.")
        action = "Run a Quick or Full scan to check kernel MCE and RAS logs."

    source_summary = ", ".join(sources) if sources else (source_label or "none")
    scope_str = "Historical" if is_historical else "Current scan"
    evidence.append(f"Evidence source: {source_summary}")
    evidence.append(f"Timestamp: {timestamp}")
    evidence.append(f"Scope: {scope_str}")

    return {
        "category": "hardware",
        "title": "RAM / CPU Hardware",
        "status": _format_status(base_status, is_historical),
        "scope": "historical" if is_historical else "current_scan",
        "timestamp": timestamp,
        "source": source_summary,
        "evidence": evidence,
        "recommended_action": action,
    }


def evaluate_temperature_health(
    report: dict[str, Any] | None = None,
    raw_lines: list[str] | None = None,
    *,
    is_historical: bool = False,
    source_label: str | None = None,
) -> dict[str, Any]:
    """Evaluate Temperatures strictly from collected sensors and thermal log evidence."""
    report_dict = _as_dict(report)
    checks = _as_dict(report_dict.get("checks"))
    findings = [f for f in _as_list(report_dict.get("findings")) if isinstance(f, dict)]
    timestamp = _report_timestamp(report_dict)

    sensors_check = _as_dict(checks.get("sensors"))
    therm_prev = _as_dict(checks.get("thermal_previous"))
    sensors_ok = _check_succeeded(sensors_check)
    sensors_out = _check_output(sensors_check)

    if raw_lines and not sensors_ok:
        raw_joined = "\n".join(str(ln) for ln in raw_lines if isinstance(ln, str))
        if re.search(r"(?:Package id \d+|Composite|Tctl|Core \d+):\s*\+?-?\d+(?:\.\d+)?\s*°C", raw_joined):
            sensors_out = raw_joined
            sensors_ok = True

    thermal_findings = [
        f for f in findings
        if str(f.get("id", "")).startswith("thermal") or str(f.get("category", "")).lower() == "thermals"
    ]

    therm_log_lines = [
        ln.strip()
        for ln in _check_output(therm_prev).splitlines()
        if re.search(r"critical temperature|overheat|thermal.*shutdown|temperature above threshold|throttl", ln, re.I)
    ]
    if raw_lines:
        for ln in raw_lines:
            if isinstance(ln, str) and re.search(r"critical temperature|overheat|thermal.*shutdown|temperature above threshold", ln, re.I):
                therm_log_lines.append(ln.strip())

    parsed_Readings: list[str] = []
    over_crit = False
    over_high = False

    if sensors_ok:
        for line in sensors_out.splitlines():
            m = re.match(r"^\s*([^:]+):\s*\+?(-?\d+(?:\.\d+)?)\s*°C(.*)$", line)
            if not m:
                continue
            label, val_str, rest = m.group(1).strip(), m.group(2), m.group(3)
            temp_val = float(val_str)
            high_m = re.search(r"high\s*=\s*\+?(-?\d+(?:\.\d+)?)\s*°C", rest)
            crit_m = re.search(r"crit\s*=\s*\+?(-?\d+(?:\.\d+)?)\s*°C", rest)
            high_val = float(high_m.group(1)) if high_m else None
            crit_val = float(crit_m.group(1)) if crit_m else None

            if (crit_val and temp_val >= crit_val) or temp_val >= 95.0:
                over_crit = True
            elif (high_val and temp_val >= high_val) or temp_val >= 85.0:
                over_high = True

            if label.lower().startswith(("package id", "tctl", "tdie", "composite", "temp1", "core 0")):
                parsed_Readings.append(line.strip())

    sources: list[str] = []
    if sensors_ok:
        sources.append("sensors")
    if _check_succeeded(therm_prev):
        sources.append("thermal_previous")

    evidence: list[str] = []
    for reading in parsed_Readings[:6]:
        evidence.append(reading)
    for f in thermal_findings:
        evidence.append(f"Finding [{f.get('severity', 'warning')}]: {f.get('title', '')}")
    for ln in therm_log_lines[:3]:
        evidence.append(f"Thermal log: {ln}")

    if over_crit or any(f.get("severity") == "critical" for f in thermal_findings):
        base_status = "Failing"
        action = "Check cooling, fans, and heatsinks immediately; critical temperatures were recorded."
    elif over_high or thermal_findings or therm_log_lines:
        base_status = "Warning"
        action = "Monitor cooling and airflow under load; elevated temperatures or thermal events were recorded."
    elif sensors_ok and parsed_Readings:
        base_status = "Healthy"
        action = "No action required."
    elif sensors_ok:
        base_status = "Insufficient evidence"
        evidence.append("Sensors check ran but reported no recognizable temperature readings.")
        action = "Verify lm_sensors configuration."
    else:
        base_status = "Not checked"
        evidence.append("No verified temperature sensor readings were collected in this report.")
        action = "Run a Quick or Full scan with lm_sensors installed to inspect temperatures."

    source_summary = ", ".join(sources) if sources else (source_label or "none")
    scope_str = "Historical" if is_historical else "Current scan"
    evidence.append(f"Evidence source: {source_summary}")
    evidence.append(f"Timestamp: {timestamp}")
    evidence.append(f"Scope: {scope_str}")

    return {
        "category": "hardware",
        "title": "Temperatures",
        "status": _format_status(base_status, is_historical),
        "scope": "historical" if is_historical else "current_scan",
        "timestamp": timestamp,
        "source": source_summary,
        "evidence": evidence,
        "recommended_action": action,
    }


def build_system_history_issues(
    report: dict[str, Any] | None = None,
    raw_lines: list[str] | None = None,
    *,
    is_historical: bool | None = None,
    source_label: str | None = None,
) -> list[dict[str, Any]]:
    """Build all System History subsystem items from real diagnostic evidence without hardcoded health claims."""
    import graphics_doctor
    import app_crash_doctor
    import dadlan_doctor

    report_dict = _as_dict(report)
    checks = _as_dict(report_dict.get("checks"))
    meta = _as_dict(report_dict.get("metadata"))
    historical = _is_report_historical(report_dict, is_historical)
    timestamp = _report_timestamp(report_dict)
    boot_id = str(meta.get("boot_id") or "").strip() or None

    log_lines: list[str] = []
    if raw_lines:
        log_lines.extend(str(ln) for ln in raw_lines if isinstance(ln, str))
    elif checks:
        for key in (
            "display_current", "display_previous", "display_history",
            "hardware_errors_previous", "hardware_errors_history",
            "previous_errors", "current_kernel_errors", "previous_boot_tail",
            "coredumps",
        ):
            out = _check_output(_as_dict(checks.get(key)))
            if out.strip():
                log_lines.extend(out.splitlines())

    issues: list[dict[str, Any]] = []
    if log_lines:
        try:
            issues.extend(graphics_doctor.analyze_graphics_events(log_lines, current_boot_id=None if historical else boot_id))
        except Exception:
            pass
        try:
            issues.extend(app_crash_doctor.analyze_app_crashes(log_lines))
        except Exception:
            pass
        try:
            issues.extend(analyze_hardware_events(log_lines))
        except Exception:
            pass

    failed_unit_lines: list[str] = []
    if raw_lines:
        failed_unit_lines = [str(ln) for ln in raw_lines if isinstance(ln, str)]
    else:
        fu_out = _check_output(_as_dict(checks.get("failed_units")))
        if fu_out:
            failed_unit_lines = fu_out.splitlines()
    if failed_unit_lines:
        try:
            issues.extend(dadlan_doctor.analyze_dadlan(failed_unit_lines))
        except Exception:
            pass

    for item in issues:
        if not isinstance(item, dict):
            continue
        item_hist = historical or "historical" in str(item.get("status", "")).lower()
        item["status"] = _format_status(str(item.get("status", "Unknown")), item_hist)
        item.setdefault("scope", "historical" if item_hist else "current_scan")
        item.setdefault("timestamp", timestamp)
        item.setdefault("source", source_label or ("report checks" if checks else "history log"))

    issues.append(evaluate_nvme_health(report_dict, raw_lines, is_historical=historical, source_label=source_label))
    issues.append(evaluate_btrfs_health(report_dict, raw_lines, is_historical=historical, source_label=source_label))
    issues.append(evaluate_ram_cpu_health(report_dict, raw_lines, is_historical=historical, source_label=source_label))
    issues.append(evaluate_temperature_health(report_dict, raw_lines, is_historical=historical, source_label=source_label))

    return issues
