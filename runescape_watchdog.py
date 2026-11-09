#!/usr/bin/env python3
"""RuneScape (RS2 / JoshRS #377) client launcher and watchdog.

Launches the client under a chosen profile, watches it for crashes and freezes,
saves a diagnosis (see runescape_doctor.py) and restarts it.

Unlike the read-only capture modules, this one starts and stops processes. It only
ever touches the RuneScape client you configured (or the single PID you point it at),
never anything else on the system.

Freeze detection combines two signals:
1. CPU-idle freeze: a JVM that uses no CPU at all for `freeze_seconds`
   (deadlock, blocked I/O, stopped GPU wait).
2. Dead game-loop thread: in revision-377 clients (`jagex2.client.Client`), an
   uncaught exception on `Thread-2` kills the game loop while Java Sound threads
   keep advancing process CPU ticks. The watchdog watches the client log for an
   uncaught game-thread exception so it catches this freeze mode too.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field, fields
from datetime import datetime
from pathlib import Path
from typing import Any, Callable

import runescape_doctor

Emit = Callable[[str, str], None]


class ConfigError(Exception):
    """Raised when the client launch command can't be built."""


def config_path() -> Path:
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "fedora-crash-doctor" / "runescape.json"


# Commonly used mitigations for Java AWT/Swing clients freezing or crashing on Linux graphics
# stacks. They are not guaranteed fixes; the watchdog can step through them automatically.
PROFILES: dict[str, dict] = {
    "default": {
        "desc": "No extra flags.",
        "jvm": [],
        "env": {},
    },
    "stable-graphics": {
        "desc": "Turn off Java2D OpenGL and XRender pipelines.",
        "jvm": ["-Dsun.java2d.opengl=false", "-Dsun.java2d.xrender=false"],
        "env": {},
    },
    "xwayland-safe": {
        "desc": "Stable-graphics plus non-reparenting WM hint, often helps under XWayland/KWin.",
        "jvm": ["-Dsun.java2d.opengl=false", "-Dsun.java2d.xrender=false", "-Dsun.java2d.pmoffscreen=false"],
        "env": {"_JAVA_AWT_WM_NONREPARENTING": "1"},
    },
    "software": {
        "desc": "Everything above plus forced Mesa software rendering. Slow, but isolates GPU driver bugs.",
        "jvm": ["-Dsun.java2d.opengl=false", "-Dsun.java2d.xrender=false", "-Dsun.java2d.pmoffscreen=false"],
        "env": {"_JAVA_AWT_WM_NONREPARENTING": "1", "LIBGL_ALWAYS_SOFTWARE": "1"},
    },
    "low-memory": {
        "desc": "Small fixed heap and serial GC for tight-RAM machines. Not part of auto-escalation.",
        "jvm": ["-Xms64m", "-Xmx512m", "-XX:+UseSerialGC"],
        "env": {},
    },
}

# Order the watchdog walks through when the client keeps failing.
ESCALATION = ["default", "stable-graphics", "xwayland-safe", "software"]
STABLE_RUN_SECONDS = 180


def next_profile(current: str) -> str:
    if current in ESCALATION:
        return ESCALATION[min(ESCALATION.index(current) + 1, len(ESCALATION) - 1)]
    return current


@dataclass
class Config:
    java_path: str = "java"
    jar_path: str = ""
    client_args: list[str] = field(default_factory=list)
    # Full custom command. The literal token "{jvm}" is replaced by the profile's JVM flags.
    custom_command: list[str] = field(default_factory=list)
    profile: str = "default"
    extra_jvm_args: list[str] = field(default_factory=list)
    freeze_seconds: int = 45
    poll_seconds: float = 2.0
    max_restarts: int = 5
    restart_delay: float = 3.0
    auto_escalate: bool = True
    kill_frozen: bool = True

    def has_client(self) -> bool:
        return bool(self.jar_path or self.custom_command)


def load_config(path: Path | None = None) -> Config:
    path = path or config_path()
    cfg = Config()
    try:
        data = json.loads(path.read_text())
    except (OSError, ValueError):
        return cfg
    if not isinstance(data, dict):
        return cfg
    known = {f.name for f in fields(Config)}
    for key, value in data.items():
        if key in known:
            setattr(cfg, key, value)
    return cfg


def discover_joshrs_config(cfg: Config | None = None) -> Config:
    """Return cfg with auto-discovered JoshRS #377 launch command if no client is explicitly configured."""
    cfg = cfg or load_config()
    if cfg.has_client():
        return cfg
    install = runescape_doctor.discover_joshrs_install()
    if install and install.get("default_custom_command"):
        cfg.custom_command = list(install["default_custom_command"])
    return cfg


def save_config(cfg: Config, path: Path | None = None) -> Path:
    path = path or config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(cfg), indent=2) + "\n")
    return path


def build_command(cfg: Config, profile: str | None = None) -> tuple[list[str], dict[str, str]]:
    """Return (argv, env) for launching the client under the given profile."""
    prof = PROFILES.get(profile or cfg.profile, PROFILES["default"])
    env = dict(os.environ)
    env.update(prof["env"])
    jvm = [*prof["jvm"], *cfg.extra_jvm_args]
    if cfg.custom_command:
        argv: list[str] = []
        for token in cfg.custom_command:
            if token == "{jvm}":
                argv.extend(jvm)
            else:
                argv.append(token)
        return argv, env
    if not cfg.jar_path:
        raise ConfigError(
            "No client configured. Set one with `runescape_watchdog.py config --jar /path/to/client.jar` "
            "or use 'Set Client .jar...' in the app."
        )
    jar = str(Path(cfg.jar_path).expanduser())
    return [cfg.java_path, *jvm, "-jar", jar, *cfg.client_args], env


def client_dirs(cfg: Config) -> list[Path]:
    if cfg.jar_path:
        return [Path(cfg.jar_path).expanduser().parent]
    install = runescape_doctor.discover_joshrs_install()
    if install:
        return [Path(install["client_dir"]), Path(install["root"])]
    return []


def discover_joshrs_server_launcher(install: dict[str, Any] | None = None) -> Path | None:
    """Locate an EXISTING original server launcher, never construct a new world."""
    install = install or runescape_doctor.discover_joshrs_install()
    if not install:
        return None
    root = Path(install["root"])
    if not root.is_dir():
        return None
    for relative in (
        "start-server.sh",
        "start-joshrs-server.sh",
        "engine/start-server.sh",
        "engine/run-server.sh",
    ):
        path = root / relative
        # Don't execute arbitrary symlink targets or guess Node/DB flags.
        if path.is_file() and not path.is_symlink():
            return path
    return None


def start_joshrs_server() -> tuple[bool, str]:
    """Opt-in start of the EXISTING offline server via its original launcher.

    Refuses partial startups, occupied ports, missing scripts and all uncertain
    states; does not restart clients, kill any process, edit saves/DB, or try to
    install the observer/MCP. Must never be invoked by the background watchdog.
    """
    live = runescape_doctor.collect_live_status(include_thread_probe=False)
    if not live.get("joshrs_install"):
        return False, "No local JoshRS installation identified; no action taken."
    if live.get("server_online"):
        return True, "JoshRS game server is already online; no new world started."
    if live.get("servers") or any((live.get("ports") or {}).values()):
        return False, (
            "Refusing to start a second world: a server process or a JoshRS port is already "
            "present. Diagnose this partial start and its logs first."
        )
    script = discover_joshrs_server_launcher(live["joshrs_install"])
    if not script:
        return False, (
            "Server is offline, but the original server launcher was not found. "
            "No generic Node command was guessed, no world started, and no saves changed. "
            "Check the existing JoshRS server startup script/service and logs."
        )
    root = Path(live["joshrs_install"]["root"])
    log_path = runescape_doctor.state_dir() / "server-start.log"
    try:
        # Private log for diagnosis, no secrets/arguments in GUI responses.
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        os.fchmod(fd, 0o600)
        try:
            process = subprocess.Popen(
                ["bash", str(script)],
                cwd=str(root),
                stdin=subprocess.DEVNULL,
                stdout=fd,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        finally:
            os.close(fd)
        # A launcher can detach immediately, or remain running in foreground.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            state = runescape_doctor.collect_live_status(include_thread_probe=False)
            if state.get("server_online"):
                return True, (
                    "Original JoshRS server launcher started the game listener. "
                    "Confirm player login and saved progress in the existing client."
                )
            if process.poll() is not None:
                break
            time.sleep(0.4)
        return False, (
            "The existing launcher was invoked, but server readiness is unverified. "
            f"Read the private log {log_path}; do not launch another copy."
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return False, f"Could not start the existing JoshRS server launcher: {type(exc).__name__}. No retry."


def start_joshrs_client() -> tuple[bool, str]:
    """Start the JoshRS client using its existing start-client.sh launcher if available."""
    live = runescape_doctor.collect_live_status(include_thread_probe=False)
    if live.get("clients"):
        pid = live["clients"][0]["pid"]
        return True, f"JoshRS client is already running (PID {pid})."
    install = live.get("joshrs_install") or runescape_doctor.discover_joshrs_install()
    if install and install.get("start_client_script"):
        script = install["start_client_script"]
        try:
            res = subprocess.run(
                [script],
                cwd=install["root"],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if res.returncode == 0:
                deadline = time.monotonic() + 12.0
                while time.monotonic() < deadline:
                    now_live = runescape_doctor.collect_live_status(include_thread_probe=False)
                    if now_live.get("clients"):
                        pid = now_live["clients"][0]["pid"]
                        return True, f"Started JoshRS client via start-client.sh (PID {pid})."
                    time.sleep(0.4)
                return True, (res.stdout.strip() or "Started JoshRS client via start-client.sh (building classes in background).")
            return False, f"start-client.sh exited with {res.returncode}: {(res.stderr or res.stdout).strip()}"
        except (OSError, subprocess.SubprocessError) as exc:
            return False, f"Failed to execute {script}: {exc}"
    cfg = discover_joshrs_config()
    try:
        argv, env = build_command(cfg)
        proc = subprocess.Popen(
            argv,
            env=env,
            cwd=install["client_dir"] if install else None,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            start_new_session=True,
        )
        return True, f"Launched client PID {proc.pid}: {shlex.join(argv)}"
    except (ConfigError, OSError) as exc:
        return False, str(exc)


def stop_joshrs_client() -> tuple[bool, str]:
    """Gracefully stop only the running RuneScape Java client process. Never touches the server."""
    live = runescape_doctor.collect_live_status(include_thread_probe=False)
    clients = live.get("clients", [])
    if not clients:
        return True, "No running RuneScape client process found."
    # Stop user systemd unit if active, then signal only the discovered client PIDs
    subprocess.run(
        ["systemctl", "--user", "stop", "joshrs-client.service"],
        capture_output=True,
        text=True,
        timeout=8,
    )
    stopped_pids: list[int] = []
    for item in clients:
        pid = item["pid"]
        try:
            os.kill(pid, signal.SIGTERM)
            stopped_pids.append(pid)
        except ProcessLookupError:
            stopped_pids.append(pid)
        except PermissionError as exc:
            return False, f"Not permitted to stop client PID {pid}: {exc}"
    deadline = time.monotonic() + 4.0
    while time.monotonic() < deadline:
        if all(read_proc_stat(pid) is None for pid in stopped_pids):
            break
        time.sleep(0.15)
    return True, f"Stopped RuneScape client PID(s): {', '.join(str(p) for p in stopped_pids)} (game server untouched)."


# --- process helpers -------------------------------------------------------------------------

def read_proc_stat(pid: int) -> tuple[int, str] | None:
    """Return (utime+stime ticks, state letter) for a PID, or None if it's gone."""
    try:
        data = Path(f"/proc/{pid}/stat").read_text()
        rest = data.rsplit(")", 1)[1].split()
        return int(rest[11]) + int(rest[12]), rest[0]
    except (OSError, IndexError, ValueError):
        return None


def find_pids(pattern: str) -> list[tuple[int, str]]:
    regex = re.compile(pattern)
    me = os.getpid()
    found: list[tuple[int, str]] = []
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit() or int(entry.name) == me:
            continue
        try:
            cmd = (entry / "cmdline").read_bytes().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            continue
        if cmd and regex.search(cmd) and "runescape_watchdog" not in cmd and "fedora_crash_doctor" not in cmd:
            found.append((int(entry.name), cmd))
    return found


def describe_exit(rc: int | None) -> str:
    if rc is None:
        return "unknown exit status"
    if rc < 0:
        try:
            return f"killed by {signal.Signals(-rc).name}"
        except ValueError:
            return f"killed by signal {-rc}"
    return f"exit code {rc}"


def log_has_game_thread_exception(log_path: Path | None, start_offset: int = 0) -> bool:
    """Check whether the client log since start_offset contains an uncaught game-thread exception."""
    if not log_path or not log_path.exists():
        return False
    try:
        with open(log_path, "rb") as handle:
            handle.seek(start_offset)
            text = handle.read(65536).decode("utf-8", "replace")
        return bool(runescape_doctor.GAME_THREAD_EXC_RE.search(text))
    except OSError:
        return False


class FreezeDetector:
    """Flags a process whose CPU time hasn't advanced for freeze_seconds."""

    def __init__(self, freeze_seconds: float, max_gap: float = 30.0):
        self.freeze_seconds = freeze_seconds
        self.max_gap = max_gap
        self._ticks: int | None = None
        self._progress_at = 0.0
        self._last_now: float | None = None

    def update(self, now: float, ticks: int, state: str) -> bool:
        if self._last_now is not None and now - self._last_now > self.max_gap:
            self._progress_at = now  # long gap (suspend/resume): don't count it as a freeze
        self._last_now = now
        if self._ticks is None or ticks != self._ticks or state == "T":
            self._ticks = ticks
            self._progress_at = now
            return False
        return now - self._progress_at >= self.freeze_seconds


class RestartPolicy:
    def __init__(self, cfg: Config):
        self.cfg = cfg
        self.failures = 0

    def record_failure(self, ran_seconds: float, profile: str) -> tuple[bool, str, float]:
        """Return (should_restart, profile_for_next_run, delay_seconds)."""
        if ran_seconds >= STABLE_RUN_SECONDS:
            self.failures = 0
        self.failures += 1
        if self.failures > self.cfg.max_restarts:
            return False, profile, 0.0
        nxt = profile
        if self.cfg.auto_escalate and self.failures >= 2:
            nxt = next_profile(profile)
        return True, nxt, self.cfg.restart_delay * min(self.failures, 5)


def _print_event(kind: str, message: str) -> None:
    print(f"[{kind}] {message}", flush=True)


class Supervisor:
    def __init__(self, cfg: Config, emit: Emit | None = None):
        self.cfg = cfg
        self.emit: Emit = emit or _print_event
        self._stop = threading.Event()

    def stop(self) -> None:
        """Stop watching. A running client is left alone."""
        self._stop.set()

    def _cwd(self) -> str | None:
        dirs = client_dirs(self.cfg)
        return str(dirs[0]) if dirs and dirs[0].is_dir() else None

    def _new_log(self) -> Path:
        directory = runescape_doctor.state_dir()
        logs = sorted(directory.glob("client-*.log"), key=lambda p: p.stat().st_mtime)
        for old in logs[:-19]:
            try:
                old.unlink()
            except OSError:
                pass
        return directory / f"client-{datetime.now():%Y%m%d-%H%M%S-%f}.log"

    def _monitor(
        self,
        pid: int,
        proc: subprocess.Popen | None = None,
        log_path: Path | None = None,
        log_offset: int = 0,
    ) -> tuple[str, int | None]:
        detector = FreezeDetector(self.cfg.freeze_seconds, max_gap=max(30.0, self.cfg.poll_seconds * 5))
        while not self._stop.is_set():
            if proc is not None:
                rc = proc.poll()
                if rc is not None:
                    return "exited", rc
            stat = read_proc_stat(pid)
            if stat is None or stat[1] == "Z":
                return "exited", (proc.poll() if proc is not None else None)
            if log_has_game_thread_exception(log_path, log_offset):
                return "frozen", None
            if detector.update(time.monotonic(), stat[0], stat[1]):
                return "frozen", None
            self._stop.wait(self.cfg.poll_seconds)
        return "stopped", None

    def _thread_dump(self, pid: int) -> str | None:
        out = runescape_doctor._run(["jcmd", str(pid), "Thread.print"], timeout=15)
        return out if "Full thread dump" in out else None

    def _terminate(self, pid: int, group: bool, proc: subprocess.Popen | None = None) -> None:
        def send(sig: int) -> None:
            try:
                if group:
                    os.killpg(pid, sig)
                else:
                    os.kill(pid, sig)
            except ProcessLookupError:
                pass
            except PermissionError as exc:
                self.emit("error", f"Not allowed to signal process {pid}: {exc}")

        send(signal.SIGTERM)
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if proc is not None:
                if proc.poll() is not None:
                    return
            else:
                stat = read_proc_stat(pid)
                if stat is None or stat[1] == "Z":
                    return
            time.sleep(0.2)
        send(signal.SIGKILL)
        if proc is not None:
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

    def _incident(self, log_path: Path | None, dump: str | None) -> None:
        try:
            summary = runescape_doctor.capture_runescape_incident(
                client_log=log_path, thread_dump=dump,
                java_path=self.cfg.java_path, extra_dirs=client_dirs(self.cfg),
            )
        except Exception as exc:  # diagnosis must never take the watchdog down
            self.emit("error", f"Diagnosis failed: {exc}")
            return
        findings = summary["findings"][:3]
        for item in findings:
            self.emit("finding", f"[{item['severity']}] {item['title']} - {item['fix']}")
        if not findings:
            self.emit("finding", "No known cause matched. Raw evidence was saved for review.")
        self.emit("report", summary["capture_path"])

    def run(self) -> int:
        """Launch the client and keep it alive. Returns 0 on a clean finish, 1 on giving up, 2 on config error."""
        policy = RestartPolicy(self.cfg)
        profile = self.cfg.profile
        while not self._stop.is_set():
            try:
                argv, env = build_command(self.cfg, profile)
            except ConfigError as exc:
                self.emit("error", str(exc))
                return 2
            log_path = self._new_log()
            self.emit("start", f"Launching with profile '{profile}': {shlex.join(argv)}")
            started = time.monotonic()
            try:
                with open(log_path, "wb") as log_file:
                    proc = subprocess.Popen(
                        argv, stdout=log_file, stderr=subprocess.STDOUT, env=env,
                        cwd=self._cwd(), start_new_session=True,
                    )
            except OSError as exc:
                self.emit("error", f"Could not start client: {exc}")
                return 2

            outcome, rc = self._monitor(proc.pid, proc, log_path=log_path, log_offset=0)
            dump = None
            if outcome == "stopped":
                self.emit("stop", "Watchdog stopped. The client was left running.")
                return 0
            if outcome == "frozen":
                self.emit("frozen", f"Client stopped responding (CPU idle for {self.cfg.freeze_seconds}s or game loop thread crashed).")
                dump = self._thread_dump(proc.pid)
                if not self.cfg.kill_frozen:
                    self.emit("frozen", "Leaving the frozen client running (kill_frozen is off).")
                    self._incident(log_path, dump)
                    return 1
                self._terminate(proc.pid, True, proc)
            elif rc == 0:
                self.emit("exit", "Client closed normally. Watchdog finished.")
                return 0
            else:
                self.emit("crash", f"Client exited abnormally ({describe_exit(rc)}).")

            self._incident(log_path, dump)
            restart, profile, delay = policy.record_failure(time.monotonic() - started, profile)
            if not restart:
                self.emit("giveup", f"Giving up after {policy.failures} failures in a row. "
                                    "Check the saved report for the likely cause.")
                return 1
            self.emit("restart", f"Restarting in {delay:.0f}s with profile '{profile}'.")
            self._stop.wait(delay)
        return 0

    def watch_pid(self, pid: int) -> int:
        """Watch an already-running client. Relaunches only after a freeze it had to kill."""
        self.emit("attach", f"Watching existing process {pid}.")
        outcome, _ = self._monitor(pid)
        if outcome == "stopped":
            return 0
        dump = None
        killed = False
        if outcome == "frozen":
            self.emit("frozen", f"No CPU activity for {self.cfg.freeze_seconds}s, treating the client as frozen.")
            dump = self._thread_dump(pid)
            if self.cfg.kill_frozen:
                self._terminate(pid, False)
                killed = True
        else:
            self.emit("exit", "The watched process ended. When attaching, a clean quit and a crash look the same.")
        self._incident(None, dump)
        if killed and self.cfg.has_client() and not self._stop.is_set():
            self.emit("restart", "Relaunching the configured client under the watchdog.")
            return self.run()
        return 1 if outcome == "frozen" else 0


# --- CLI -------------------------------------------------------------------------------------

def _pick_pid(args: argparse.Namespace) -> int | None:
    if args.pid:
        return args.pid
    pattern = args.match or r"(jagex2\.client\.Client|runelite|hdos|osbuddy|rs2|(^|/)java( |$))"
    candidates = find_pids(pattern)
    if len(candidates) == 1:
        return candidates[0][0]
    if not candidates:
        print(f"No running process matched {pattern!r}.", file=sys.stderr)
    else:
        print("More than one process matched. Pick one with --pid:", file=sys.stderr)
        for pid, cmd in candidates:
            print(f"  {pid}  {cmd[:120]}", file=sys.stderr)
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Launch and watch the RuneScape client.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_run = sub.add_parser("run", help="launch the client and restart it when it crashes or freezes")
    p_run.add_argument("--profile", choices=sorted(PROFILES))
    p_run.add_argument("--no-escalate", action="store_true", help="don't step through graphics profiles")
    p_run.add_argument("--max-restarts", type=int)
    p_run.add_argument("--freeze-seconds", type=int)
    p_run.add_argument("--no-kill", action="store_true", help="report freezes but don't kill the client")

    p_watch = sub.add_parser("watch", help="watch an already-running client")
    p_watch.add_argument("--pid", type=int)
    p_watch.add_argument("--match", help="regex for the client's command line (default: RuneScape / java process)")
    p_watch.add_argument("--freeze-seconds", type=int)
    p_watch.add_argument("--no-kill", action="store_true")

    p_diag = sub.add_parser("diagnose", help="diagnose the latest crash or freeze (read-only)")
    p_diag.add_argument("--log")
    p_diag.add_argument("--hours", type=int, default=24)

    sub.add_parser("status", help="show live JoshRS client, JVM and server status (read-only)")

    p_cfg = sub.add_parser("config", help="show or change the saved configuration")
    p_cfg.add_argument("--jar")
    p_cfg.add_argument("--java")
    p_cfg.add_argument("--profile", choices=sorted(PROFILES))
    p_cfg.add_argument("--client-arg", action="append", help="replaces the saved list; repeat for several")
    p_cfg.add_argument("--jvm-arg", action="append", help="replaces the saved list; repeat for several")

    sub.add_parser("profiles", help="list launch profiles")

    args = parser.parse_args(argv)
    cfg = load_config()

    if args.cmd == "profiles":
        for name, prof in PROFILES.items():
            marker = "*" if name in ESCALATION else " "
            print(f"{marker} {name:16} {prof['desc']}")
        print("\n* = used by auto-escalation, in this order: " + " -> ".join(ESCALATION))
        return 0

    if args.cmd == "status":
        print(json.dumps(runescape_doctor.collect_live_status(include_thread_probe=True), indent=2))
        return 0

    if args.cmd == "config":
        changed = False
        for attr, value in (("jar_path", args.jar), ("java_path", args.java), ("profile", args.profile),
                            ("client_args", args.client_arg), ("extra_jvm_args", args.jvm_arg)):
            if value is not None:
                setattr(cfg, attr, value)
                changed = True
        if changed:
            print(f"Saved to {save_config(cfg)}")
        print(json.dumps(asdict(cfg), indent=2))
        return 0

    if args.cmd == "diagnose":
        extra = ["--log", args.log] if args.log else []
        return runescape_doctor.main([*extra, "--hours", str(args.hours), "--java", cfg.java_path])

    cfg = discover_joshrs_config(cfg)
    if args.no_kill:
        cfg.kill_frozen = False
    if getattr(args, "freeze_seconds", None):
        cfg.freeze_seconds = args.freeze_seconds
    supervisor = Supervisor(cfg)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: supervisor.stop())

    if args.cmd == "watch":
        pid = _pick_pid(args)
        return 2 if pid is None else supervisor.watch_pid(pid)

    if args.profile:
        cfg.profile = args.profile
    if args.no_escalate:
        cfg.auto_escalate = False
    if args.max_restarts is not None:
        cfg.max_restarts = args.max_restarts
    return supervisor.run()


if __name__ == "__main__":
    sys.exit(main())
