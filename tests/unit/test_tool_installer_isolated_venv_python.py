"""An isolated venv built by another Python is rebuilt, not reused (#1695).

Measured 2026-11-25 on a clean Debian container: `uv tool install` put JMo on
Python 3.15, where checkov's dependency pycares 4.11.0 has no wheel, so
`jmo tools install` failed to build it. After `uv tool install --force
--python 3.12`, `jmo tools install --yes --force checkov` failed the same way:
`_isolated_pip_install` created `~/.jmo/tools/venvs/checkov` only when it was
absent, so the 3.15 venv was kept and pip ran on 3.15 again. Only deleting the
venv by hand recovered it, while `--force`'s help says it repairs an install.

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
from scripts.cli.tool_installer import ToolInstaller

THIS_PYTHON = f"{sys.version_info.major}.{sys.version_info.minor}"
OTHER_PYTHON = f"{sys.version_info.major}.{sys.version_info.minor + 1}"
BIN = "Scripts" if sys.platform == "win32" else "bin"
EXE = ".exe" if sys.platform == "win32" else ""


def _venv(home: Path) -> Path:
    return home / ".jmo" / "tools" / "venvs" / "checkov"


def _make_venv(venv: Path, cfg: str | None) -> None:
    (venv / BIN).mkdir(parents=True)
    for name in ("python", "pip"):
        (venv / BIN / f"{name}{EXE}").touch()
    if cfg is not None:
        (venv / "pyvenv.cfg").write_text(cfg, encoding="utf-8")


@pytest.fixture
def run(tmp_path, monkeypatch):
    """Fake subprocess for the installer: records each command and makes the
    files a real venv creation and pip install would leave behind."""
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    calls: list[list[str]] = []

    def fake_run(cmd, **_kwargs):
        calls.append([str(c) for c in cmd])
        if cmd[1:3] == ["-m", "venv"]:
            _make_venv(Path(cmd[3]), f"version = {THIS_PYTHON}.0\n")
        elif "install" in cmd and cmd[-1].startswith("checkov=="):
            (_venv(tmp_path) / BIN / f"checkov{EXE}").touch()
        return subprocess.CompletedProcess(cmd, 0, stdout="3.4.6\n", stderr="")

    # Replace the module's `subprocess` name, not `subprocess.run` itself:
    # patching the attribute would patch the shared module for every thread.
    monkeypatch.setattr(
        tool_installer,
        "subprocess",
        types.SimpleNamespace(run=fake_run, TimeoutExpired=subprocess.TimeoutExpired),
    )
    return calls


def _created_a_venv(calls: list[list[str]]) -> bool:
    return any(c[1:3] == ["-m", "venv"] for c in calls)


def _install(tmp_path: Path):
    installer = ToolInstaller(install_dir=tmp_path / ".jmo" / "bin")
    return installer._isolated_pip_install("checkov", "checkov==3.4.6")


@pytest.mark.parametrize(
    "cfg",
    [
        f"home = /x\nversion = {OTHER_PYTHON}.2\n",  # CPython's venv
        f"home = /x\nversion_info = {OTHER_PYTHON}\n",  # uv's venv
        "home = /x\n",  # no interpreter recorded
        None,  # no pyvenv.cfg at all
    ],
    ids=["cpython-other", "uv-other", "no-version", "no-cfg"],
)
def test_a_venv_not_shown_to_be_built_here_is_rebuilt(cfg, run, tmp_path):
    venv = _venv(tmp_path)
    _make_venv(venv, cfg)
    (venv / "left-by-the-old-python").touch()

    result = _install(tmp_path)

    assert _created_a_venv(run), "the old venv was reused, so pip runs on it again"
    assert not (venv / "left-by-the-old-python").exists()
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

    assert not _created_a_venv(run)
    assert (venv / "kept").exists()
    assert result.success, result.message


def test_an_absent_venv_is_created(run, tmp_path):
    result = _install(tmp_path)

    assert _created_a_venv(run)
    assert result.success, result.message
