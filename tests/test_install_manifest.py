"""Installed-tree packaging regression tests.

These tests derive, from the actual source tree and the actual packaging
scripts (install.sh, packaging/fedora-crash-doctor.spec), whether every
module reachable from the shipped entry points would really be present on
a machine that only has the *installed* tree -- not the source checkout.

This exists because both install.sh and the RPM spec have independently
drifted out of sync with the application's imports before (missing
app_crash_doctor/coredump_adapter/graphics_doctor/hardware_doctor/
memory_oom/dadlan_doctor). A bare `import fedora_crash_doctor` from the
source checkout does not catch this, because several of the missing
modules are imported lazily inside function bodies rather than at module
top level. These tests statically discover every local import (at any
nesting depth) transitively reachable from the real entry points, then
physically stage the installer's file manifest into an isolated directory
and prove those modules actually import from that directory alone.
"""
from __future__ import annotations

import ast
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
INSTALL_SH = ROOT / "install.sh"
SPEC = ROOT / "packaging" / "fedora-crash-doctor.spec"

# Entry points that are known, by construction, to be installed directly
# into the shared datadir tree and run as standalone scripts (systemd
# ExecStart targets, the CLI/GUI wrapper, and host_stability_audit.py's
# own CLI). Used only as a non-empty sanity floor -- the real entry-point
# set is derived from the source tree and the installers below.
EXPECTED_DATADIR_ENTRY_POINTS = {
    "fedora_crash_doctor",
    "host_stability_audit",
    "canary",
    "desktop_heartbeat",
    "autoscan",
    "collector",
}


def _tracked_root_py_stems() -> set[str]:
    """Root-level first-party modules.

    From a git checkout this is the tracked set, so stray scratch files are
    ignored. A release tarball or rpmbuild tree has no git metadata; there
    the files present *are* the shipped source, so every root *.py counts.
    """
    try:
        out = subprocess.run(
            ["git", "ls-files", "--", "*.py"],
            cwd=ROOT, capture_output=True, text=True, check=True,
        )
        lines = out.stdout.splitlines()
    except (OSError, subprocess.CalledProcessError):
        lines = []
    if not lines:
        lines = [p.name for p in ROOT.glob("*.py")]
    stems = set()
    for line in lines:
        if "/" not in line:
            stems.add(line[:-3])
    return stems


def _has_main_block(path: Path) -> bool:
    return 'if __name__ == "__main__"' in path.read_text(encoding="utf-8")


def _local_imports(path: Path, local: set[str]) -> set[str]:
    """All first-party module names imported anywhere in `path`, at any nesting depth."""
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                name = alias.name.split(".")[0]
                if name in local:
                    found.add(name)
        elif isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                name = node.module.split(".")[0]
                if name in local:
                    found.add(name)
    return found


def _transitive_closure(entry_stems: set[str], local: set[str]) -> set[str]:
    seen: set[str] = set()
    queue = list(entry_stems)
    while queue:
        stem = queue.pop()
        if stem in seen:
            continue
        seen.add(stem)
        path = ROOT / f"{stem}.py"
        if not path.exists():
            continue
        for dep in _local_imports(path, local):
            if dep not in seen:
                queue.append(dep)
    return seen


def _parse_install_sh_datadir_manifest() -> set[str]:
    """Modules install.sh copies into $SHARE_DIR (the app's shared datadir)."""
    text = INSTALL_SH.read_text(encoding="utf-8")
    modules = set()
    for line in text.splitlines():
        line = line.strip()
        if '"$SHARE_DIR/"' not in line or "install -m" not in line:
            continue
        for token in line.split():
            if token.startswith('"$SOURCE_DIR/') and token.endswith('.py"'):
                modules.add(token.split("/")[-1][:-len('.py"')])
    return modules


def _parse_spec_datadir_manifest() -> set[str]:
    """Modules the RPM spec's %install copies into %{_datadir}/fedora-crash-doctor/."""
    text = SPEC.read_text(encoding="utf-8")
    modules = set()
    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("install -m"):
            continue
        if "%{buildroot}%{_datadir}/fedora-crash-doctor/" not in line:
            continue
        for token in line.split():
            if token.endswith(".py"):
                modules.add(token[:-len(".py")])
    return modules


def _entry_points(local: set[str], manifest: set[str]) -> set[str]:
    main_modules = {s for s in local if _has_main_block(ROOT / f"{s}.py")}
    return main_modules & manifest


@pytest.fixture(scope="module")
def local_modules() -> set[str]:
    return _tracked_root_py_stems()


@pytest.fixture(scope="module")
def install_sh_manifest() -> set[str]:
    return _parse_install_sh_datadir_manifest()


@pytest.fixture(scope="module")
def spec_manifest() -> set[str]:
    return _parse_spec_datadir_manifest()


def _required_modules(local_modules: set[str], manifest: set[str]) -> set[str]:
    entry_points = _entry_points(local_modules, manifest)
    assert EXPECTED_DATADIR_ENTRY_POINTS <= entry_points, (
        "Entry-point discovery found fewer scripts than expected -- "
        f"got {sorted(entry_points)}, expected at least "
        f"{sorted(EXPECTED_DATADIR_ENTRY_POINTS)}. This usually means "
        "install.sh/the RPM spec no longer install one of the known "
        "entry-point scripts, or the __main__ detection broke."
    )
    closure = _transitive_closure(entry_points, local_modules)
    # privileged_helper.py and stability_notifier.py are installed to
    # libexec (not datadir) but privileged_helper.py resolves `collector`
    # via an explicit sys.path.insert onto the datadir at runtime, so its
    # own direct imports must also be satisfiable from the datadir manifest.
    for extra in ("privileged_helper", "stability_notifier"):
        path = ROOT / f"{extra}.py"
        if path.exists():
            closure |= _local_imports(path, local_modules)
    return closure


def test_install_sh_manifest_covers_every_reachable_module(local_modules, install_sh_manifest):
    required = _required_modules(local_modules, install_sh_manifest)
    missing = required - install_sh_manifest
    assert not missing, (
        f"install.sh does not install these modules that are reachable from "
        f"its shipped entry points, so an install.sh-installed system would "
        f"raise ImportError: {sorted(missing)}"
    )


def test_spec_manifest_covers_every_reachable_module(local_modules, spec_manifest):
    required = _required_modules(local_modules, spec_manifest)
    missing = required - spec_manifest
    assert not missing, (
        f"packaging/fedora-crash-doctor.spec does not install these modules "
        f"that are reachable from its shipped entry points, so an "
        f"RPM-installed system would raise ImportError: {sorted(missing)}"
    )


def _stage_and_import(tmp_path: Path, manifest: set[str], required: set[str]) -> None:
    stage_dir = tmp_path / "staged"
    stage_dir.mkdir()
    for stem in manifest:
        src = ROOT / f"{stem}.py"
        if src.exists():
            shutil.copy2(src, stage_dir / f"{stem}.py")

    import_lines = "\n".join(f"import {name}" for name in sorted(required))
    check_lines = "\n".join(
        f'assert {name}.__file__.startswith(staged), '
        f'f"{name} resolved outside the staged tree: {{{name}.__file__}}"'
        for name in sorted(required)
    )
    script = (
        "import os\n"
        "staged = os.environ['STAGED_DIR']\n"
        f"{import_lines}\n"
        f"{check_lines}\n"
        "print('OK')\n"
    )

    env = dict(os.environ)
    env["PYTHONPATH"] = str(stage_dir)
    env["STAGED_DIR"] = str(stage_dir)
    env["QT_QPA_PLATFORM"] = "offscreen"
    result = subprocess.run(
        [sys.executable, "-c", script],
        cwd=str(stage_dir),
        env=env,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, (
        f"Importing the staged tree failed.\nstdout: {result.stdout}\n"
        f"stderr: {result.stderr}"
    )
    assert "OK" in result.stdout


def test_install_sh_staged_tree_imports_in_isolation(tmp_path, local_modules, install_sh_manifest):
    entry_points = _entry_points(local_modules, install_sh_manifest)
    closure = _transitive_closure(entry_points, local_modules)
    # Only assert import success for modules the manifest actually claims to
    # ship; manifest completeness is covered separately above.
    required = closure & install_sh_manifest
    _stage_and_import(tmp_path, install_sh_manifest, required)


def test_spec_staged_tree_imports_in_isolation(tmp_path, local_modules, spec_manifest):
    entry_points = _entry_points(local_modules, spec_manifest)
    closure = _transitive_closure(entry_points, local_modules)
    required = closure & spec_manifest
    _stage_and_import(tmp_path, spec_manifest, required)
