import json
import hashlib
import subprocess
from typing import Any, Optional

def _get_package_info(executable: str) -> dict[str, str]:
    if not executable or not executable.startswith("/"):
        return {}
    
    try:
        # Query RPM for the package owning the file
        result = subprocess.run(
            ["rpm", "-qf", "--queryformat", "%{NAME}\\n%{VERSION}-%{RELEASE}\\n%{ARCH}", executable],
            capture_output=True,
            text=True,
            timeout=2
        )
        if result.returncode == 0:
            lines = result.stdout.strip().split("\\n")
            if len(lines) == 3:
                return {
                    "package": lines[0],
                    "package_version": lines[1],
                    "architecture": lines[2],
                }
    except Exception:
        pass
    return {}

def _safe_int(value: Any) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None


def parse_systemd_coredump_json(lines: list[str], resolve_packages: bool = True) -> list[dict[str, Any]]:
    """Parse structured JSON lines from journalctl -t systemd-coredump -o json"""
    incidents = []
    
    # Cache package info to avoid redundant rpm calls
    pkg_cache = {}
    
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue
            
        # Ignore entries that aren't actual coredumps (e.g., just general log messages)
        # Usually they have COREDUMP_PID or MESSAGE="Process... dumped core."
        if "COREDUMP_PID" not in entry and "COREDUMP_EXE" not in entry:
            continue
            
        exe = entry.get("COREDUMP_EXE") or entry.get("_EXE")
        
        incident = {
            "incident_source": "systemd-coredump",
            "boot_id": entry.get("_BOOT_ID"),
            "timestamp": _safe_int(entry.get("__REALTIME_TIMESTAMP")) / 1000000.0 if _safe_int(entry.get("__REALTIME_TIMESTAMP")) is not None else None,
            "pid": _safe_int(entry.get("COREDUMP_PID")),
            "uid": _safe_int(entry.get("COREDUMP_UID")),
            "gid": _safe_int(entry.get("COREDUMP_GID")),
            "signal": _safe_int(entry.get("COREDUMP_SIGNAL")),
            "signal_name": entry.get("COREDUMP_SIGNAL_NAME"),
            "executable": exe,
            "command": entry.get("COREDUMP_CMDLINE"),
            "comm": entry.get("COREDUMP_COMM"),
            "unit": entry.get("COREDUMP_UNIT") or entry.get("_SYSTEMD_UNIT"),
            "user_unit": entry.get("COREDUMP_USER_UNIT"),
            "hostname": entry.get("_HOSTNAME"),
            
            "storage": {
                "present": "COREDUMP_FILENAME" in entry,
                "location": entry.get("COREDUMP_FILENAME"),
            },
            
            "core_available": "unknown", # Changed per requirements
            "metadata_available": True,
            "journal_cursor": entry.get("__CURSOR"),
            
            "package": None,
            "package_version": None,
            "architecture": None,
            "build_id": None,
        }
        
        # We can extract build_id if it's in the metadata. (Often systemd-coredump doesn't expose it directly in the journal, but we can leave it None and populate later if we do symbolisation).
        
        if resolve_packages and exe:
            if exe not in pkg_cache:
                pkg_cache[exe] = _get_package_info(exe)
            
            pkg_info = pkg_cache[exe]
            incident.update(pkg_info)
            
        canonical = {
            "boot_id": incident["boot_id"],
            "timestamp": incident["timestamp"],
            "pid": incident["pid"],
            "executable": incident["executable"],
            "signal": incident["signal"],
            "hostname": incident["hostname"]
        }
        raw_hash = hashlib.sha256(json.dumps(canonical, sort_keys=True).encode("utf-8")).hexdigest()
        incident["raw_source_hash"] = raw_hash
        
        incidents.append(incident)
        
    return incidents

def get_systemd_coredumps(since: str = "30 days ago", max_records: int = 1000, max_bytes: int = 10 * 1024 * 1024) -> list[dict[str, Any]]:
    """Fetch structured coredump evidence directly from the systemd journal with bounded memory and process streaming."""
    fields = [
        "__CURSOR", "__REALTIME_TIMESTAMP", "_BOOT_ID", "COREDUMP_PID", "COREDUMP_UID",
        "COREDUMP_GID", "COREDUMP_SIGNAL", "COREDUMP_SIGNAL_NAME", "COREDUMP_EXE", "_EXE",
        "COREDUMP_CMDLINE", "COREDUMP_COMM", "COREDUMP_UNIT", "_SYSTEMD_UNIT", "COREDUMP_USER_UNIT",
        "_HOSTNAME", "COREDUMP_FILENAME"
    ]
    
    cmd = ["journalctl", "-t", "systemd-coredump", "-o", "json", "--since", since, f"--output-fields={','.join(fields)}"]
    
    incidents = []
    total_bytes = 0
    
    import time
    import select
    
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL
        )
        
        start_time = time.time()
        timeout = 20
        
        while True:
            if time.time() - start_time > timeout:
                proc.kill()
                break
                
            # Use select to wait for data up to 1 second, so we can enforce overall timeout
            ready, _, _ = select.select([proc.stdout], [], [], 1.0)
            if not ready:
                continue
                
            # Read up to 200KB per line safely
            line_bytes = proc.stdout.readline(200000)
            if not line_bytes:
                break
                
            line_len = len(line_bytes)
            if total_bytes + line_len > max_bytes:
                proc.kill()
                break
                
            total_bytes += line_len
            line = line_bytes.decode('utf-8', errors='replace').strip()
            
            if not line:
                continue
            
            # parse line individually
            parsed = parse_systemd_coredump_json([line], resolve_packages=True)
            incidents.extend(parsed)
            
            if len(incidents) >= max_records:
                proc.kill()
                break
                
        proc.wait(timeout=2)
    except Exception:
        if 'proc' in locals():
            proc.kill()
    finally:
        if 'proc' in locals() and proc.stdout is not None:
            try:
                proc.stdout.close()
            except OSError:
                pass

    return incidents
