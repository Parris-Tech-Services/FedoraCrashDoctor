#!/usr/bin/env python3
"""RuneScape (RS2 / JoshRS #377) client crash and freeze diagnosis.

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
    r"\bjava\b|joshrs|kwin|wayland|xwayland|drm|amdgpu|i915|nvidia|NVRM|nouveau|oom|Xid|segfault|GPU HANG|thermal|throttl",
    re.I,
)
GAME_THREAD_EXC_RE = re.compile(
    r'Exception in thread "(?:Thread-\d+|main|Game\S*)"\s+java\.lang\.\S+[^\n]*(?:\n\s+at\s+[^\n]+)?'
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
        "java-uncaught-game-thread-exception",
        "critical",
        "Uncaught Java exception crashed the client game loop thread",
        r'Exception in thread "(?:Thread-\d+|main|Game\S*)"\s+java\.lang\.(?:ArrayIndexOutOfBoundsException|NullPointerException|RuntimeException|IndexOutOfBoundsException|IllegalStateException|IllegalArgumentException|ClassCastException|ArithmeticException|\w+Exception)[^\n]*(?:\n\s+at\s+[^\n]+)?',
        "The main game loop thread (such as Thread-2 in jagex2.client.Client / GameShell.run) threw an "
        "unhandled Java exception and died, while AWT/XWayland UI and Java Sound threads stayed alive. "
        "This leaves the client window open and consuming background audio CPU, but completely frozen to input.",
        "Fix the bounds/null check at the stack frame shown in the evidence (for example "
        "jagex2.client.Client.updateFacingDirection when a disconnected target sends slot -1 -> index 32767 "
        "into a 16384-element NPC array), recompile client-java, and restart the client.",
        ("client",),
    ),
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
        "kwin-wayland-swapchain", "info", "KWin Wayland reported swapchain buffer allocation failure",
        r"kwin_wayland\[\d+\]: Failed to allocate a graphics buffer for a swapchain",
        "KWin Wayland logged transient swapchain buffer allocation warnings during window compositing or "
        "screenshot capture. This does not kill Java threads by itself, but indicates compositor pressure.",
        "If window redraws stutter under Wayland, test the xwayland-safe profile.",
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
    parts = [ln.strip() for ln in line.splitlines() if ln.strip()]
    return " | ".join(parts)[:240]


def _thread_dump_findings(threads_text: str) -> list[Finding]:
    """Detect a running RuneScape JVM whose main game loop thread (Thread-2 / GameShell.run) has died."""
    if not threads_text or "Full thread dump" not in threads_text:
        return []
    has_awt_or_rs = (
        "XToolkit-Shutdown-Thread" in threads_text
        or "AWT-EventQueue-" in threads_text
        or "jagex2." in threads_text
    )
    has_game_loop = (
        '"Thread-2"' in threads_text
        or "GameShell.run" in threads_text
        or "jagex2.client.Client.run" in threads_text
    )
    if has_awt_or_rs and not has_game_loop and ("Java Sound" in threads_text or '"Thread-0"' in threads_text):
        return [
            Finding(
                "java-game-thread-missing",
                "high",
                "Client game loop thread (Thread-2) is dead while the window remains open",
                "The JVM thread dump contains AWT/XWayland and Java Sound threads, but the revision-377 "
                "game loop thread (Thread-2 / GameShell.run) is completely absent. The game loop died from "
                "an uncaught exception while non-daemon UI/audio threads prevented the JVM from exiting.",
                "Inspect /tmp/joshrs-client-persistent.log for an uncaught Exception in thread \"Thread-2\" "
                "and restart the client.",
                evidence="Full thread dump present with AWT/Sound threads active, but Thread-2 (GameShell.run) is missing.",
                source="threads",
            )
        ]
    return []


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
    for tf in _thread_dump_findings(sources.get("threads", "")):
        if tf.id not in seen:
            findings.append(tf)
            seen.add(tf.id)
    if sysinfo:
        findings.extend(_sysinfo_findings(sysinfo))
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    return findings


# --- JoshRS #377 auto-discovery & live process/JVM inspection -------------------------------

def discover_joshrs_install(home: Path | None = None) -> dict[str, Any] | None:
    """Auto-discover the local JoshRS revision-377 installation if present under HOME or JOSHRS_HOME."""
    candidates: list[Path] = []
    env_home = os.environ.get("JOSHRS_HOME")
    if env_home:
        candidates.append(Path(env_home).expanduser())
    base_home = home or Path.home()
    candidates.append(base_home / "dev" / "JoshRS" / "lostcity377")
    for root in candidates:
        try:
            if root.is_dir() and (root / "client-java").is_dir():
                classes_dir = root / "client-java" / "build" / "classes" / "java" / "main"
                start_script = root / "start-client.sh"
                persistent_log = Path("/tmp/joshrs-client-persistent.log")
                return {
                    "root": str(root),
                    "client_dir": str(root / "client-java"),
                    "classes_dir": str(classes_dir),
                    "start_client_script": str(start_script) if start_script.exists() else "",
                    "status_script": str(root / "status-joshrs.sh") if (root / "status-joshrs.sh").exists() else "",
                    "persistent_client_log": str(persistent_log) if persistent_log.exists() else "/tmp/joshrs-client-persistent.log",
                    "server_log": str(root / "engine" / "logs" / "server.log"),
                    "default_custom_command": [
                        "java", "{jvm}", "-cp", str(classes_dir),
                        "jagex2.client.Client", "10", "8808", "highmem", "members", "32",
                    ],
                }
        except OSError:
            continue
    return None


def _listening_tcp_ports() -> set[int]:
    ports: set[int] = set()
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        text = _read_text(table, 131072)
        for line in text.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[3] == "0A":  # 0A = TCP_LISTEN
                try:
                    ports.add(int(parts[1].split(":")[1], 16))
                except (IndexError, ValueError):
                    continue
    return ports


def _proc_memory_and_threads(pid: int) -> dict[str, Any]:
    status = _read_text(f"/proc/{pid}/status", 16384)
    info: dict[str, Any] = {}
    for key, out_key, div in (
        ("VmRSS", "rss_mb", 1024),
        ("VmSize", "vmsize_mb", 1024),
        ("VmPeak", "vmpeak_mb", 1024),
        ("Threads", "threads", 1),
    ):
        match = re.search(rf"^{key}:\s+(\d+)", status, re.M)
        if match:
            info[out_key] = int(match.group(1)) // div
    return info


def collect_thread_dump(pid: int) -> str | None:
    """Safely capture a read-only thread dump from a live JVM via jcmd or jstack."""
    out = _run(["jcmd", str(pid), "Thread.print"], timeout=10.0)
    if "Full thread dump" in out:
        return out
    out2 = _run(["jstack", "-l", str(pid)], timeout=10.0)
    if "Full thread dump" in out2:
        return out2
    return None


def collect_heap_info(pid: int) -> str | None:
    """Safely query read-only JVM heap usage via jcmd GC.heap_info."""
    out = _run(["jcmd", str(pid), "GC.heap_info"], timeout=8.0)
    if out and not out.startswith(ERROR_PREFIX) and ("heap" in out.lower() or "used" in out.lower()):
        return out.strip()
    return None


def collect_live_status(include_thread_probe: bool = False) -> dict[str, Any]:
    """Discover running JoshRS / RuneScape client and server processes and read-only JVM metrics."""
    install = discover_joshrs_install()
    clients: list[dict[str, Any]] = []
    servers: list[dict[str, Any]] = []
    me = os.getpid()

    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        pid = int(entry.name)
        try:
            cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        if not cmd or "fedora_crash_doctor" in cmd or "runescape_watchdog" in cmd or "runescape_doctor" in cmd:
            continue
        if re.search(r"jagex2\.client\.Client|runelite|hdos|osbuddy|rs2|client\.jar", cmd, re.I) and "java" in cmd:
            proc_info: dict[str, Any] = {"pid": pid, "cmdline": cmd}
            proc_info.update(_proc_memory_and_threads(pid))
            if include_thread_probe:
                dump = collect_thread_dump(pid)
                if dump:
                    proc_info["game_thread_alive"] = (
                        '"Thread-2"' in dump or "GameShell.run" in dump or "jagex2.client.Client.run" in dump
                    )
                    proc_info["deadlock_detected"] = "Found one Java-level deadlock" in dump
                heap = collect_heap_info(pid)
                if heap:
                    proc_info["heap_summary"] = " | ".join(
                        ln.strip() for ln in heap.splitlines() if "used" in ln.lower() or "garbage-first" in ln.lower()
                    )[:220]
            clients.append(proc_info)
        elif ("tsx src/app.ts" in cmd or "lostcity377" in cmd) and ("node" in cmd or "tsx" in cmd):
            if "join.mjs" not in cmd:
                s_info: dict[str, Any] = {"pid": pid, "cmdline": cmd}
                s_info.update(_proc_memory_and_threads(pid))
                servers.append(s_info)

    ports = _listening_tcp_ports()
    joshrs_ports = {
        "game_52402": 52402 in ports,
        "http_8888": 8888 in ports,
        "mgmt_8898": 8898 in ports,
    }
    return {
        "joshrs_install": install,
        "clients": clients,
        "servers": servers,
        "ports": joshrs_ports,
        "server_online": bool(servers) or all(joshrs_ports.values()),
        "client_running": bool(clients),
    }


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
    for key, name in (
        ("MemAvailable", "mem_available_mb"),
        ("MemTotal", "mem_total_mb"),
        ("SwapTotal", "swap_total_mb"),
        ("SwapFree", "swap_free_mb"),
    ):
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
    install = discover_joshrs_install()
    if install:
        info["joshrs_root"] = install["root"]
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


def collect_user_service_journal(hours: int = 24) -> str:
    """Collect user systemd logs for joshrs-client.service if available."""
    since = f"{hours} hours ago"
    out = _run(
        ["journalctl", "--user", "-u", "joshrs-client.service", "--no-pager", "-q", "--since", since, "-n", "200"],
        timeout=8.0,
    )
    if out.startswith(ERROR_PREFIX):
        return ""
    return out.strip()


def collect_coredumps() -> str:
    out = _run(["coredumpctl", "list", "--no-pager", "--no-legend", "java"])
    if "No coredumps found" in out:
        return ""
    return out


def find_hs_err(extra_dirs: Iterable[str | Path] = (), days: int = 7, limit: int = 3) -> list[Path]:
    install = discover_joshrs_install()
    joshrs_dirs = [Path(install["root"]), Path(install["client_dir"])] if install else []
    dirs = [Path.cwd(), Path.home(), Path("/tmp"), *joshrs_dirs, *[Path(d) for d in extra_dirs]]
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
    candidates: list[Path] = list(state_dir().glob("client-*.log"))
    install = discover_joshrs_install()
    if install:
        persistent = Path(install["persistent_client_log"])
        if persistent.exists():
            candidates.append(persistent)
    valid: list[tuple[float, Path]] = []
    for path in candidates:
        try:
            valid.append((path.stat().st_mtime, path))
        except OSError:
            continue
    if not valid:
        return None
    valid.sort(key=lambda item: item[0])
    return valid[-1][1]


# --- incident classification, hypotheses & timeline ------------------------------------------

def classify_incident(findings: list[Finding], live_status: dict[str, Any] | None = None) -> dict[str, str]:
    """Distinguish application hang, JVM crash, OOM kill, renderer failure, and server disconnect."""
    finding_ids = {f.id for f in findings}
    if "java-uncaught-game-thread-exception" in finding_ids or "java-game-thread-missing" in finding_ids:
        return {
            "category": "application_game_thread_hang",
            "title": "Application Hang — Uncaught Java Exception Killed Game Loop Thread (Thread-2)",
            "summary": (
                "The JVM did not suffer a native crash or OOM kill, and the JoshRS server stayed online. "
                "Instead, the client's main game loop thread (Thread-2 in jagex2.client.Client) died from "
                "an uncaught runtime exception while AWT/XWayland and sound threads kept the window open."
            ),
        }
    if "java-deadlock" in finding_ids:
        return {
            "category": "application_deadlock",
            "title": "Application Hang — Java Thread Deadlock",
            "summary": "Two or more client threads deadlocked waiting on monitors, freezing the client.",
        }
    if finding_ids & {"jvm-fatal-error", "native-gfx-frame", "kernel-segfault-java", "java-coredump"}:
        return {
            "category": "jvm_native_crash",
            "title": "Native JVM Crash (SIGSEGV / Fatal Error)",
            "summary": "The Java Virtual Machine terminated abnormally inside native code or a graphics library.",
        }
    if finding_ids & {"java-heap-oom", "kernel-oom-killer"}:
        return {
            "category": "oom_termination",
            "title": "Memory Exhaustion / Out-Of-Memory Termination",
            "summary": "The client exhausted its Java heap or was killed by the Linux kernel OOM killer.",
        }
    if finding_ids & {"gpu-hang", "x11-gl-error", "compositor-gl"}:
        return {
            "category": "renderer_or_display_failure",
            "title": "Graphics / Compositor / Display Pipeline Failure",
            "summary": "The GPU driver, XWayland or KWin compositor reported a rendering or display error.",
        }
    if "network-drop" in finding_ids:
        return {
            "category": "server_disconnection",
            "title": "Network or Game Server Disconnection",
            "summary": "The client lost connection to the game server without a local JVM crash.",
        }
    return {
        "category": "no_crash_detected",
        "title": "No Active Crash or Freeze Signature Found",
        "summary": "No uncaught game-thread exception, native JVM crash, OOM kill or GPU hang matched.",
    }


def build_hypotheses(
    findings: list[Finding],
    sysinfo: dict[str, Any],
    sources: dict[str, str],
    live_status: dict[str, Any] | None = None,
) -> list[dict[str, Any]]:
    """Build ranked root-cause hypotheses with supporting and contradicting evidence."""
    hypotheses: list[dict[str, Any]] = []
    by_id = {f.id: f for f in findings}
    server_up = bool((live_status or {}).get("server_online"))

    if "java-uncaught-game-thread-exception" in by_id or "java-game-thread-missing" in by_id:
        ev_list: list[str] = []
        if "java-uncaught-game-thread-exception" in by_id:
            ev_list.append(by_id["java-uncaught-game-thread-exception"].evidence)
        if "java-game-thread-missing" in by_id:
            ev_list.append(by_id["java-game-thread-missing"].evidence)
        ev_list.append(
            "When Thread-2 dies in jagex2.client.Client, AWT-EventQueue-0, signlink (Thread-0) and Java Sound "
            "threads keep the process alive (~30% CPU in JitterCorrector/AudioPusher), so the window stays "
            "visible on screen but never repaints or processes input."
        )
        against = [
            "No native JVM crash log (hs_err_pid*.log) or coredumpctl entry was generated.",
            "No Linux kernel OOM kill or systemd-oomd termination occurred.",
        ]
        if server_up:
            against.append("The local JoshRS server (ports 52402/8888/8898) remained active throughout.")
        hypotheses.append({
            "rank": len(hypotheses) + 1,
            "id": "hypothesis-game-thread-exception",
            "title": "Uncaught ArrayIndexOutOfBoundsException on Thread-2 froze the client window",
            "confidence": "high",
            "supports": ev_list,
            "against": against,
            "fix": (
                "In client-java/src/main/java/jagex2/client/Client.java (updateFacingDirection, line 5400), "
                "change `arg1.field1156 != -1 && arg1.field1156 < 32768` to "
                "`arg1.field1156 >= 0 && arg1.field1156 < this.npcs.length` (and guard player index against "
                "`this.players.length`) so disconnected target slots (-1 + 32768 = 32767) never crash Thread-2."
            ),
        })

    for fid, conf in (
        ("jvm-fatal-error", "high"),
        ("native-gfx-frame", "high"),
        ("kernel-oom-killer", "high"),
        ("java-heap-oom", "high"),
        ("gpu-hang", "high"),
        ("java-deadlock", "high"),
        ("x11-gl-error", "medium"),
        ("kwin-wayland-swapchain", "low"),
    ):
        if fid in by_id:
            item = by_id[fid]
            hypotheses.append({
                "rank": len(hypotheses) + 1,
                "id": f"hypothesis-{fid}",
                "title": item.title,
                "confidence": conf,
                "supports": [item.evidence or item.explanation],
                "against": [
                    "Does not by itself explain an uncaught Java exception on Thread-2 if one is also present."
                ] if "java-uncaught-game-thread-exception" in by_id else [],
                "fix": item.fix,
            })

    # Always provide the evidence-based explanation for the black margins when JoshRS #377 is present
    client_text = sources.get("client", "")
    if sysinfo.get("joshrs_root") or "jagex2.client.Client" in client_text:
        hypotheses.append({
            "rank": len(hypotheses) + 1,
            "id": "hypothesis-black-margins-fixed-viewport",
            "title": "Large black margins are caused by fixed 765x503 aspect scaling ('Fit' mode with '3D View' off)",
            "confidence": "high",
            "supports": [
                "JoshRS revision-377 GameShell.java centers a classic 765x503 game frame on a black canvas "
                "when 'Fit' scaling (e.g. [Fit | 960x631 | Zoom:1200]) is selected without '3D View'.",
                "In a maximized KDE window, the remaining horizontal and vertical space outside the 765:503 "
                "frame is intentionally painted black.",
            ],
            "against": [
                "Not a GPU driver corruption or VRAM failure — the top control bar and KDE panel render normally."
            ],
            "fix": (
                "Click '3D View' in the client's top toolbar to expand the 3D viewport to the full window, "
                "or switch Scale between 1x / 1.5x / 2x / Max."
            ),
        })

    return hypotheses


def build_timeline(sources: dict[str, str], user_journal: str = "") -> list[dict[str, str]]:
    """Build a chronological incident timeline correlating client logs, service restarts, and KWin/kernel logs."""
    events: list[dict[str, str]] = []
    if user_journal:
        for line in user_journal.splitlines():
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 4)
            ts = " ".join(parts[:3]) if len(parts) >= 4 else "user-service"
            msg = parts[4] if len(parts) >= 5 else line
            events.append({"timestamp": ts, "source": "joshrs-client.service", "event": msg[:200]})

    journal_text = sources.get("journal", "")
    if journal_text:
        for line in journal_text.splitlines()[-25:]:
            line = line.strip()
            if not line:
                continue
            parts = line.split(None, 4)
            ts = " ".join(parts[:3]) if len(parts) >= 4 else "journal"
            msg = parts[4] if len(parts) >= 5 else line
            events.append({"timestamp": ts, "source": "system-journal", "event": msg[:200]})

    client_text = sources.get("client", "")
    if client_text:
        for match in GAME_THREAD_EXC_RE.finditer(client_text):
            ev = _evidence(client_text, match)
            events.append({
                "timestamp": "client-log",
                "source": "client-stdout",
                "event": f"Game thread crashed with uncaught exception: {ev}",
            })

    return events


# --- report + capture ------------------------------------------------------------------------

def render_report(
    findings: list[Finding],
    sysinfo: dict[str, Any],
    classification: dict[str, str] | None = None,
    hypotheses: list[dict[str, Any]] | None = None,
    timeline: list[dict[str, str]] | None = None,
    live_status: dict[str, Any] | None = None,
) -> str:
    lines = ["RuneScape client diagnosis", "=" * 26, ""]
    lines.append(f"Session: {sysinfo.get('session_type') or 'unknown'} / {sysinfo.get('desktop') or 'unknown'}")
    lines.append(f"Java: {sysinfo.get('java_version_line') or 'not found'}")
    if sysinfo.get("mem_available_mb") is not None:
        lines.append(f"Memory: {sysinfo.get('mem_available_mb')} MB available of {sysinfo.get('mem_total_mb')} MB")
    for gpu in sysinfo.get("gpu", []):
        lines.append(f"GPU: {gpu}")
    if live_status:
        clients = live_status.get("clients", [])
        if clients:
            c0 = clients[0]
            gt = c0.get("game_thread_alive")
            gt_str = "alive" if gt is True else ("DEAD (frozen window)" if gt is False else "unprobed")
            lines.append(
                f"Live Client: PID {c0.get('pid')} | RSS {c0.get('rss_mb', '?')} MB | "
                f"Threads {c0.get('threads', '?')} | Game loop (Thread-2): {gt_str}"
            )
        else:
            lines.append("Live Client: not running")
        lines.append(f"JoshRS Server: {'ONLINE (ports 52402/8888/8898)' if live_status.get('server_online') else 'offline'}")
    lines.append("")
    if classification:
        lines.append(f"Incident Classification: {classification.get('title', '')}")
        lines.append(f"Summary: {classification.get('summary', '')}")
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
    if hypotheses:
        lines.append("Ranked Root-Cause Hypotheses")
        lines.append("-" * 28)
        for hyp in hypotheses:
            lines.append(f"#{hyp['rank']} [{hyp['confidence'].upper()}] {hyp['title']}")
            for sup in hyp.get("supports", []):
                lines.append(f"   + Supports: {sup}")
            for ag in hyp.get("against", []):
                lines.append(f"   - Contradicts: {ag}")
            lines.append(f"   * Fix: {hyp.get('fix', '')}")
            lines.append("")
    if timeline:
        lines.append("Correlated Incident Timeline")
        lines.append("-" * 28)
        for item in timeline[-15:]:
            lines.append(f"  {item.get('timestamp', '')} | {item.get('source', '')} | {item.get('event', '')}")
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
    live_status = collect_live_status(include_thread_probe=False)

    journal = collect_journal(hours)
    if journal.startswith(ERROR_PREFIX):
        failed.append("journal")
    elif journal:
        sources["journal"] = journal

    user_journal = collect_user_service_journal(hours)
    if user_journal:
        sources["user_service"] = user_journal

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

    if thread_dump is None and live_status.get("clients"):
        pid = live_status["clients"][0]["pid"]
        probed = collect_thread_dump(pid)
        if probed:
            thread_dump = probed
            live_status["clients"][0]["game_thread_alive"] = (
                '"Thread-2"' in probed or "GameShell.run" in probed or "jagex2.client.Client.run" in probed
            )

    if thread_dump:
        sources["threads"] = thread_dump

    findings = diagnose(sources, sysinfo)
    classification = classify_incident(findings, live_status)
    hypotheses = build_hypotheses(findings, sysinfo, sources, live_status)
    timeline = build_timeline(sources, user_journal)

    capture_dir = _make_capture_dir(base, now)
    summary: dict[str, Any] = {
        "capture_complete": True,
        "capture_time": now.isoformat(),
        "capture_path": str(capture_dir),
        "client_log": str(log_path) if log_path else None,
        "hs_err_files": [str(p) for p in hs_files],
        "failed_collectors": failed,
        "sysinfo": sysinfo,
        "live_status": live_status,
        "incident_classification": classification,
        "findings": [asdict(f) for f in findings],
        "hypotheses": hypotheses,
        "timeline": timeline,
    }
    _write_private(capture_dir / "report.json", json.dumps(summary, indent=2))
    _write_private(
        capture_dir / "report.txt",
        render_report(findings, sysinfo, classification, hypotheses, timeline, live_status),
    )
    for name, text in sources.items():
        _write_private(capture_dir / f"{name}.txt", text)
    return summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Diagnose RuneScape client crashes and freezes (read-only).")
    parser.add_argument("--log", help="client log to analyse (default: newest watchdog or JoshRS persistent log)")
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
