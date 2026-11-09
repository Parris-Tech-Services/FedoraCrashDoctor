#!/usr/bin/env python3
"""RuneScape (RS2) client crash and freeze diagnosis.

Read-only: this module only reads logs, journals and process information. It
never terminates processes or changes system configuration. Launching and
restarting the client lives in runescape_watchdog.py.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

ERROR_PREFIX = "[ERROR]"
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "info": 3}
JOURNAL_RE = re.compile(
    r"\bjava\b|kwin|drm|amdgpu|i915|nvidia|NVRM|nouveau|oom|Xid|segfault|GPU HANG", re.I
)


@dataclass
class Finding:
    id: str
    severity: str
    title: str
    explanation: str
    fix: str
    evidence: str = ""
    source: str = ""


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str
    title: str
    pattern: str
    explanation: str
    fix: str
    sources: tuple = ("*",)


# Sources: client (stdout/stderr log), hs_err (JVM fatal error report), journal,
# coredump (coredumpctl list java), threads (jcmd Thread.print taken during a freeze).
RULES: tuple[Rule, ...] = (
    Rule(
        "java-heap-oom", "high", "Client ran out of Java heap memory",
        r"java\.lang\.OutOfMemoryError|OutOfMemoryError: Java heap space",
        "The JVM hit its heap limit, which usually shows up as a freeze and then a crash.",
        "Give the client more heap (add -Xmx1024m to extra JVM args) and close memory-hungry apps. "
        "If the machine is tight on RAM, try the low-memory profile instead.",
        ("client", "hs_err", "threads"),
    ),
    Rule(
        "kernel-oom-killer", "critical", "Linux killed the client for using too much system memory",
        r"Out of memory: Killed process \d+ \(java\)|oom-kill:.*\bjava\b|oom_reaper: reaped process \d+ \(java\)",
        "The kernel's OOM killer ended the Java process. The client vanishes with no error of its own.",
        "Free RAM before playing, check `free -h`, and confirm zram/swap is active. "
        "A leak elsewhere (browser, other Java apps) is often the real culprit.",
        ("journal",),
    ),
    Rule(
        "jvm-fatal-error", "critical", "JVM crashed with a native fatal error",
        r"A fatal error has been detected by the Java Runtime Environment|\bSIGSEGV\b|\bSIGBUS\b",
        "The Java runtime itself crashed (not a normal Java exception). That points at a native library, "
        "usually graphics, or at the JVM build.",
        "Open the hs_err_pid log and look at the 'Problematic frame'. Try the stable-graphics or "
        "xwayland-safe profile first.",
        ("client", "hs_err"),
    ),
    Rule(
        "native-gfx-frame", "critical", "Crash happened inside a graphics/X11 library",
        r"^#\s+[CV]\s+\[(?:libGL|libGLX|libEGL|libGLdispatch|libnvidia|libgallium|libX11|libxcb|libXrender|libXext|[^\]\s]*_dri)[^\]]*\]",
        "The 'Problematic frame' is in a GL/X11/Mesa/NVIDIA library, so a graphics driver or "
        "X server interaction is the likely cause.",
        "Use the software profile to confirm. If it stops crashing, update Mesa/NVIDIA via dnf "
        "or try an X11 session instead of Wayland.",
        ("hs_err", "client"),
    ),
    Rule(
        "x11-gl-error", "high", "X11/GLX/Mesa error reported",
        r"X Error of failed request:\s+(?:BadMatch|BadAlloc|BadDrawable|BadWindow|BadAccess|GLXBadContext)"
        r"|GLXBadContext|libGL error:|MESA: error|failed to load driver",
        "The client hit a display or GL driver error. These commonly precede freezes or hard crashes.",
        "Try stable-graphics (disables Java2D OpenGL/XRender). Check Mesa is up to date: "
        "`sudo dnf upgrade 'mesa-*'`.",
        ("client", "hs_err", "journal"),
    ),
    Rule(
        "no-display", "high", "Client could not reach a display",
        r"Can't connect to X11 window server|HeadlessException|No X11 DISPLAY variable",
        "Java could not find an X display. Common when launched from a service, over SSH, or "
        "when XWayland isn't running.",
        "Launch from your desktop session and check `echo $DISPLAY` is set.",
        ("client",),
    ),
    Rule(
        "missing-native-lib", "high", "A native library is missing",
        r"UnsatisfiedLinkError|cannot open shared object file",
        "Java or the client needs a shared library that isn't installed.",
        "Run `sudo dnf provides '*/<libname>'` using the library named in the evidence and install it.",
        ("client", "hs_err"),
    ),
    Rule(
        "java-version-mismatch", "high", "Java version is incompatible with the client",
        r"UnsupportedClassVersionError|Unsupported major\.minor version",
        "The client jar was built for a different Java version than the one running it.",
        "Install a matching JDK (`sudo dnf install java-17-openjdk` or similar) and point java_path at it.",
        ("client",),
    ),
    Rule(
        "java-deadlock", "high", "Client threads are deadlocked",
        r"Found one Java-level deadlock",
        "The thread dump taken during the freeze shows a genuine Java deadlock. That is a client bug, "
        "not your system.",
        "Keep the saved thread dump; restarting is the only fix. If it repeats, the client build is the problem.",
        ("threads",),
    ),
    Rule(
        "network-drop", "medium", "Network errors around the time of the problem",
        r"UnknownHostException|SocketTimeoutException|ConnectException|Connection reset|Broken pipe",
        "Connection errors can look like a freeze or disconnect. They don't normally crash the client by themselves.",
        "Check your connection and DNS. If these only appear alongside the freeze, the network is a suspect "
        "rather than the graphics stack.",
        ("client",),
    ),
    Rule(
        "gpu-hang", "critical", "GPU driver reported a hang or reset",
        r"i915.*GPU HANG|\[drm:i915.*\*ERROR\*.*(?:hang|reset)|amdgpu.*(?:ring \S+ timeout|GPU reset)|NVRM: Xid|nouveau.*(?:fifo|timeout)",
        "The kernel logged a GPU hang. A GPU reset can freeze or kill every graphical app, including the client.",
        "Update kernel and firmware (`sudo dnf upgrade 'kernel*' linux-firmware`). On NVIDIA check the driver "
        "matches your kernel. Try an X11 session to compare.",
        ("journal",),
    ),
    Rule(
        "kernel-segfault-java", "critical", "Kernel logged a segfault in java",
        r"\bjava\[\d+\]: segfault at|\bjava\[\d+\].*general protection",
        "The Java process faulted at the kernel level. Repeated segfaults in different places can also point at "
        "flaky RAM or an overclock.",
        "Check the faulting library in the line. If it varies run to run, run a memory test (memtest86+ "
        "from the boot menu).",
        ("journal",),
    ),
    Rule(
        "compositor-gl", "medium", "Compositor reported a GL problem",
        r"kwin_\w+.*(?:GL_CONTEXT_LOST|graphics reset|OpenGL.*(?:lost|reset|fail))",
        "KWin logged an OpenGL issue around the time of the problem, which may be related to a frozen window.",
        "Try toggling the compositor (Alt+Shift+F12) while the client runs to see whether freezes stop.",
        ("journal",),
    ),
    Rule(
        "java-coredump", "medium", "Systemd recorded Java core dumps",
        r"\bjava\b",
        "coredumpctl has stored crash dumps for java, so the JVM has been dying hard.",
        "Run `coredumpctl info java` for the signal and timestamp, and match it against the client logs.",
        ("coredump",),
    ),
)


def _evidence(text: str, match: re.Match) -> str:
    start = text.rfind("\n", 0, match.start()) + 1
    end = text.find("\n", match.end())
    line = text[start:] if end == -1 else text[start:end]
    return line.strip()[:220]


def _sysinfo_findings(sysinfo: dict[str, Any]) -> list[Finding]:
    found: list[Finding] = []
    if str(sysinfo.get("session_type") or "").lower() == "wayland":
        found.append(Finding(
            "wayland-session", "info", "Running under a Wayland session",
            "Java AWT clients run through XWayland on Wayland. Freezes and input glitches are more common "
            "there than on a native X11 session.",
            "Try the xwayland-safe profile, or log into a Plasma X11 session to compare behaviour.",
            evidence=f"XDG_SESSION_TYPE={sysinfo.get('session_type')}", source="system",
        ))
    avail = sysinfo.get("mem_available_mb")
    if isinstance(avail, int) and avail < 1000:
        found.append(Finding(
            "low-free-memory", "medium", "Very little free memory right now",
            "Under 1 GB is available, which makes heap exhaustion and OOM kills far more likely.",
            "Close other apps, and consider the low-memory profile.",
            evidence=f"MemAvailable={avail} MB, SwapTotal={sysinfo.get('swap_total_mb')} MB", source="system",
        ))
    major = sysinfo.get("java_major")
    if isinstance(major, int) and major >= 21:
        found.append(Finding(
            "very-new-java", "info", f"Running Java {major}",
            "Older AWT-based clients can misbehave on very recent JVMs. This is a possibility to test, "
            "not a confirmed cause.",
            "If crashes persist after trying the graphics profiles, try a Java 17 or 11 JDK via java_path.",
            evidence=str(sysinfo.get("java_version_line", "")), source="system",
        ))
    if sysinfo.get("java_version_line") == "":
        found.append(Finding(
            "java-missing", "high", "Java wasn't found",
            "The configured java binary couldn't be run.",
            "Install one: `sudo dnf install java-17-openjdk`, or set java_path in the config.",
            source="system",
        ))
    return found


def diagnose(sources: dict[str, str], sysinfo: dict[str, Any] | None = None) -> list[Finding]:
    """Run all rules. One finding per rule, most severe first."""
    findings: list[Finding] = []
    seen: set[str] = set()
    for rule in RULES:
        if rule.id in seen:
            continue
        regex = re.compile(rule.pattern, re.I | re.M)
        for name, text in sources.items():
            if not text:
                continue
            if "*" not in rule.sources and name not in rule.sources:
                continue
            match = regex.search(text)
            if match:
                findings.append(Finding(
                    rule.id, rule.severity, rule.title, rule.explanation, rule.fix,
                    evidence=_evidence(text, match), source=name,
                ))
                seen.add(rule.id)
                break
    if sysinfo:
        findings.extend(_sysinfo_findings(sysinfo))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return findings


# --- collectors (all read-only, all bounded) -------------------------------------------------

def state_dir() -> Path:
    base = os.environ.get("XDG_STATE_HOME") or str(Path.home() / ".local/state")
    path = Path(base) / "fedora-crash-doctor" / "runescape"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _run(command: list[str], timeout: float = 8.0) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        return result.stdout + (result.stderr or "")
    except subprocess.TimeoutExpired:
        return f"{ERROR_PREFIX} collector timeout: {' '.join(command)}"
    except (FileNotFoundError, OSError) as exc:
        return f"{ERROR_PREFIX} collector unavailable: {exc}"


def _read_text(path: str | Path, max_bytes: int = 20000) -> str:
    try:
        with open(path, "rb") as handle:
            return handle.read(max_bytes).decode("utf-8", "replace")
    except OSError:
        return ""


def _tail(path: str | Path, max_bytes: int = 200_000) -> str:
    try:
        with open(path, "rb") as handle:
            handle.seek(0, os.SEEK_END)
            size = handle.tell()
            handle.seek(max(0, size - max_bytes))
            return handle.read().decode("utf-8", "replace")
    except OSError:
        return ""


def collect_sysinfo(java_path: str = "java") -> dict[str, Any]:
    info: dict[str, Any] = {
        "session_type": os.environ.get("XDG_SESSION_TYPE", ""),
        "desktop": os.environ.get("XDG_CURRENT_DESKTOP", ""),
        "java_path": java_path,
    }
    meminfo = _read_text("/proc/meminfo", 8192)
    for key, name in (("MemAvailable", "mem_available_mb"), ("MemTotal", "mem_total_mb"), ("SwapTotal", "swap_total_mb")):
        match = re.search(rf"^{key}:\s+(\d+) kB", meminfo, re.M)
        if match:
            info[name] = int(match.group(1)) // 1024
    out = _run([java_path, "-version"])
    if out.startswith(ERROR_PREFIX):
        info["java_version_line"] = ""
    else:
        line = next((ln.strip() for ln in out.splitlines() if "version" in ln), "unknown")
        info["java_version_line"] = line
        match = re.search(r'version "(\d+)(?:\.(\d+))?', line)
        if match:
            major = int(match.group(1))
            if major == 1 and match.group(2):
                major = int(match.group(2))
            info["java_major"] = major
    gpu = _run(["lspci", "-mm"])
    if not gpu.startswith(ERROR_PREFIX):
        info["gpu"] = [ln for ln in gpu.splitlines() if re.search(r"vga|3d|display", ln, re.I)][:3]
    return info


def collect_journal(hours: int = 24, max_lines: int = 5000) -> str:
    since = f"{hours} hours ago"
    kernel = _run(["journalctl", "-k", "--no-pager", "-q", "--since", since, "-n", str(max_lines)], timeout=20)
    system = _run(["journalctl", "--no-pager", "-q", "--since", since, "-n", str(max_lines)], timeout=20)
    if kernel.startswith(ERROR_PREFIX) and system.startswith(ERROR_PREFIX):
        return kernel
    lines: list[str] = []
    for blob in (kernel, system):
        if blob.startswith(ERROR_PREFIX):
            continue
        lines.extend(ln for ln in blob.splitlines() if JOURNAL_RE.search(ln))
    return "\n".join(dict.fromkeys(lines))


def collect_coredumps() -> str:
    out = _run(["coredumpctl", "list", "--no-pager", "--no-legend", "java"])
    if "No coredumps found" in out:
        return ""
    return out


def find_hs_err(extra_dirs: Iterable[str | Path] = (), days: int = 7, limit: int = 3) -> list[Path]:
    dirs = [Path.cwd(), Path.home(), Path("/tmp"), *[Path(d) for d in extra_dirs]]
    cutoff = time.time() - days * 86400
    found: dict[Path, float] = {}
    for directory in dirs:
        try:
            for path in directory.glob("hs_err_pid*.log"):
                mtime = path.stat().st_mtime
                if mtime >= cutoff:
                    found[path.resolve()] = mtime
        except OSError:
            continue
    return [p for p, _ in sorted(found.items(), key=lambda kv: kv[1], reverse=True)[:limit]]


def latest_client_log() -> Path | None:
    logs = sorted(state_dir().glob("client-*.log"), key=lambda p: p.stat().st_mtime)
    return logs[-1] if logs else None


# --- report + capture ------------------------------------------------------------------------

def render_report(findings: list[Finding], sysinfo: dict[str, Any]) -> str:
    lines = ["RuneScape client diagnosis", "=" * 26, ""]
    lines.append(f"Session: {sysinfo.get('session_type') or 'unknown'} / {sysinfo.get('desktop') or 'unknown'}")
    lines.append(f"Java: {sysinfo.get('java_version_line') or 'not found'}")
    if sysinfo.get("mem_available_mb") is not None:
        lines.append(f"Memory: {sysinfo.get('mem_available_mb')} MB available of {sysinfo.get('mem_total_mb')} MB")
    for gpu in sysinfo.get("gpu", []):
        lines.append(f"GPU: {gpu}")
    lines.append("")
    if not findings:
        lines.append("No known cause matched the evidence. Raw excerpts were saved alongside this report.")
    for number, finding in enumerate(findings, 1):
        lines.append(f"{number}. [{finding.severity.upper()}] {finding.title}")
        lines.append(f"   Why: {finding.explanation}")
        if finding.evidence:
            lines.append(f"   Evidence ({finding.source}): {finding.evidence}")
        lines.append(f"   Try: {finding.fix}")
        lines.append("")
    return "\n".join(lines)


def _make_capture_dir(base: Path, now: datetime) -> Path:
    base.mkdir(parents=True, exist_ok=True)
    stem = f"runescape-{now:%Y%m%dT%H%M%SZ}"
    for suffix in ("", *[f"-{n}" for n in range(1, 50)]):
        candidate = base / f"{stem}{suffix}"
        try:
            candidate.mkdir(mode=0o700)
            return candidate
        except FileExistsError:
            continue
    raise OSError("could not create a unique capture directory")


def _write_private(path: Path, text: str) -> None:
    path.write_text(text)
    os.chmod(path, 0o600)


def capture_runescape_incident(
    base: Path | None = None,
    client_log: str | Path | None = None,
    thread_dump: str | None = None,
    hours: int = 24,
    java_path: str = "java",
    extra_dirs: Iterable[str | Path] = (),
    now: datetime | None = None,
) -> dict[str, Any]:
    """Collect evidence, diagnose it, and save a capture folder. Never raises on collector failure."""
    now = now or datetime.now(timezone.utc)
    base = base or (Path.home() / ".local/share/FedoraCrashDoctor/captures")
    failed: list[str] = []
    sources: dict[str, str] = {}

    sysinfo = collect_sysinfo(java_path)

    journal = collect_journal(hours)
    if journal.startswith(ERROR_PREFIX):
        failed.append("journal")
    elif journal:
        sources["journal"] = journal

    coredumps = collect_coredumps()
    if coredumps.startswith(ERROR_PREFIX):
        failed.append("coredumpctl")
    elif coredumps:
        sources["coredump"] = coredumps

    hs_files = find_hs_err(extra_dirs)
    if hs_files:
        sources["hs_err"] = "\n".join(_read_text(p) for p in hs_files)

    log_path = Path(client_log) if client_log else latest_client_log()
    if log_path and log_path.exists():
        sources["client"] = _tail(log_path)
    else:
        failed.append("client-log")

    if thread_dump:
        sources["threads"] = thread_dump

    findings = diagnose(sources, sysinfo)
    capture_dir = _make_capture_dir(base, now)
    summary: dict[str, Any] = {
        "capture_complete": True,
        "capture_time": now.isoformat(),
        "capture_path": str(capture_dir),
        "client_log": str(log_path) if log_path else None,
        "hs_err_files": [str(p) for p in hs_files],
        "failed_collectors": failed,
        "sysinfo": sysinfo,
        "findings": [asdict(f) for f in findings],
    }
    _write_private(capture_dir / "report.json", json.dumps(summary, indent=2))
    _write_private(capture_dir / "report.txt", render_report(findings, sysinfo))
    for name, text in sources.items():
        _write_private(capture_dir / f"{name}.txt", text)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diagnose RuneScape client crashes and freezes (read-only).")
    parser.add_argument("--log", help="client log to analyse (default: newest watchdog log)")
    parser.add_argument("--hours", type=int, default=24, help="journal look-back window")
    parser.add_argument("--java", default="java", help="java binary")
    args = parser.parse_args(argv)
    summary = capture_runescape_incident(client_log=args.log, hours=args.hours, java_path=args.java)
    print((Path(summary["capture_path"]) / "report.txt").read_text())
    print(f"Saved to: {summary['capture_path']}")
    if summary["failed_collectors"]:
        print(f"Unavailable data sources: {', '.join(summary['failed_collectors'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
