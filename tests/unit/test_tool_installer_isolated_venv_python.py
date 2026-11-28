"""An isolated venv built by another Python is rebuilt, not reused (#1695).

Measured 2026-11-25 on a clean Debian container: `uv tool install` put JMo on
Python 3.15, where checkov's dependency pycares 4.11.0 has no wheel, so
`jmo tools install` failed to build it. After `uv tool install --force
--python 3.12`, `jmo tools install --yes --force checkov` failed the same way:
`_isolated_pip_install` created `~/.jmo/tools/venvs/checkov` only when it was
absent, so the 3.15 venv was kept and pip ran on 3.15 again. Only deleting the
venv by hand recovered it, while `--force`'s help says it repairs an install.

The reverse must not break: a venv on the Python checkov installs on (3.12),
after JMo moved to one it does not (3.15), is put back and installed into when
the rebuild fails, rather than deleted.

These tests drive the real `_isolated_pip_install` with its subprocess calls
faked, so they read what it does with a venv already on disk.
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

import pytest

from scripts.cli import tool_installer
from scripts.cli.tool_installer import ToolInstaller, _venv_reusable

THIS_PYTHON = f"{sys.version_info.major}.{sys.version_info.minor}"
OTHER_PYTHON = f"{sys.version_info.major}.{sys.version_info.minor + 1}"
BIN = "Scripts" if sys.platform == "win32" else "bin"
EXE = ".exe" if sys.platform == "win32" else ""


def _venv(home: Path) -> Path:
    return home / ".jmo" / "tools" / "venvs" / "checkov"


def _make_venv(venv: Path, cfg: str | bytes | None, pip: bool = True) -> None:
    (venv / BIN).mkdir(parents=True)
    (venv / BIN / f"python{EXE}").touch()
    if pip:
        (venv / BIN / f"pip{EXE}").touch()
    if isinstance(cfg, bytes):
        (venv / "pyvenv.cfg").write_bytes(cfg)
    elif cfg is not None:
        (venv / "pyvenv.cfg").write_text(cfg, encoding="utf-8")


@pytest.fixture
def run(tmp_path, monkeypatch):
    """Fake subprocess for the installer: records each command, makes the files
    a real venv creation and pip install would leave behind, and fails the
    pip install on this Python when `fail_here` is set."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    fake = types.SimpleNamespace(calls=[], fail_here=False)

    def fake_run(cmd, **_kwargs):
        fake.calls.append([str(c) for c in cmd])
        rc = 0
        if cmd[1:3] == ["-m", "venv"]:
            _make_venv(Path(cmd[3]), f"version = {THIS_PYTHON}.0\n")
        elif "install" in cmd and cmd[-1].startswith("checkov=="):
            venv = Path(cmd[0]).parent.parent
            built_here = THIS_PYTHON in (venv / "pyvenv.cfg").read_text("utf-8")
            if fake.fail_here and built_here:
                rc = 1  # as pycares fails to build on 3.15
            else:
                (venv / BIN / f"checkov{EXE}").touch()
        return subprocess.CompletedProcess(cmd, rc, stdout="3.4.6\n", stderr="")

    # Replace the module's `subprocess` name, not `subprocess.run` itself:
    # patching the attribute would patch the shared module for every thread.
    monkeypatch.setattr(
        tool_installer,
        "subprocess",
        types.SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired),
    )
    return fake


def _created_a_venv(calls: list[list[str]]) -> bool:
    return any(c[1:3] == ["-m", "venv"] for c in calls)


def _install(tmp_path: Path):
    installer = ToolInstaller(install_dir=tmp_path / ".jmo" / "bin")
    return installer._isolated_pip_install("checkov", "checkov==3.4.6")


def _no_leftovers(tmp_path: Path) -> bool:
    return [p.name for p in _venv(tmp_path).parent.iterdir()] == ["checkov"]


@pytest.mark.parametrize(
    ("cfg", "pip"),
    [
        (f"home = /x\nversion = {OTHER_PYTHON}.2\n", True),  # CPython's venv
        (f"home = /x\nversion_info = {OTHER_PYTHON}\n", True),  # uv's venv
        ("home = /x\n", True),  # no interpreter recorded
        (None, True),  # no pyvenv.cfg at all
        (b"version = \xff\xfe\n", True),  # a pyvenv.cfg that is not UTF-8
        (f"version = {THIS_PYTHON}.0\n", False),  # an interrupted creation
    ],
    ids=["cpython-other", "uv-other", "no-version", "no-cfg", "not-utf8", "no-pip"],
)
def test_a_venv_not_shown_to_be_reusable_is_rebuilt(cfg, pip, run, tmp_path):
    venv = _venv(tmp_path)
    _make_venv(venv, cfg, pip=pip)
    (venv / "left-by-the-old-python").touch()

    result = _install(tmp_path)

    assert _created_a_venv(run.calls), "the old venv was reused, so pip runs on it"
    assert not (venv / "left-by-the-old-python").exists()
    assert _no_leftovers(tmp_path), "the old venv was not cleaned up"
    assert result.success, result.message


def test_a_rebuild_that_fails_puts_the_old_venv_back_and_installs_there(run, tmp_path):
    # The reverse of #1695: the old venv is on the Python checkov installs on,
    # and this one cannot build it. Deleting the old venv first would leave
    # checkov missing where it had worked.
    venv = _venv(tmp_path)
    _make_venv(venv, f"version = {OTHER_PYTHON}.2\n")
    (venv / BIN / f"checkov{EXE}").touch()
    run.fail_here = True

    result = _install(tmp_path)

    assert _created_a_venv(run.calls), "a rebuild was not attempted"
    assert OTHER_PYTHON in (venv / "pyvenv.cfg").read_text("utf-8")
    assert (venv / BIN / f"checkov{EXE}").exists()
    assert _no_leftovers(tmp_path)
    assert result.success, result.message


@pytest.mark.parametrize(
    "cfg",
    [f"version = {THIS_PYTHON}.9\n", f"version_info = {THIS_PYTHON}\n"],
    ids=["cpython", "uv"],
)
def test_a_venv_built_on_this_python_is_kept(cfg, run, tmp_path):
    # Rebuilding every time would re-download checkov's ~100 packages on each
    # `jmo tools install`, so a matching venv must survive.
    venv = _venv(tmp_path)
    _make_venv(venv, cfg)
    (venv / "kept").touch()

    result = _install(tmp_path)

    assert not _created_a_venv(run.calls)
    assert (venv / "kept").exists()
    assert result.success, result.message


def test_an_absent_venv_is_created(run, tmp_path):
    result = _install(tmp_path)

    assert _created_a_venv(run.calls)
    assert result.success, result.message


def test_a_real_venv_records_the_key_the_check_reads(tmp_path):
    # The fakes above write the key the check expects; this asks CPython's own
    # venv module, so a renamed key would show here, not as a rebuild on every
    # install. --without-pip keeps it fast; the pip file stands in for pip.
    venv = tmp_path / "v"
    subprocess.run(
        [sys.executable, "-m", "venv", "--without-pip", str(venv)],
        check=True,
        capture_output=True,
        timeout=120,
    )
    (venv / BIN / f"pip{EXE}").touch()

    assert _venv_reusable(venv)
