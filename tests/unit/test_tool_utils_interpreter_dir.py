"""`find_tool()` looks beside the interpreter only for a pip-installed tool (#1288).

The fallback exists because pip puts a tool's script next to the interpreter
that installed it, a directory that is on PATH only when its venv is
activated. Before #1288 it answered for every name: under an interpreter in
`/usr/bin` (a system Python on Linux or WSL, Homebrew's on macOS),
`find_tool("docker")` found `/usr/bin/docker` whatever PATH said, and the six
tests that hide docker, curl or wget by patching `shutil.which` failed there.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

from scripts.core import tool_utils
from scripts.core.install_config import ISOLATED_TOOLS


@pytest.fixture
def interpreter_dir(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An interpreter's directory, as `/usr/bin` is, and nothing on PATH or
    under ~/.jmo."""
    bindir = tmp_path / "usr-bin"
    bindir.mkdir()
    monkeypatch.setattr(tool_utils.sys, "executable", str(bindir / "python3"))
    monkeypatch.setattr(tool_utils.shutil, "which", lambda _name: None)
    monkeypatch.setattr(tool_utils, "get_isolated_tool_path", lambda _name: None)
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path / "home"))
    return bindir


def _plant(directory: Path, name: str) -> Path:
    path = directory / (f"{name}.exe" if sys.platform == "win32" else name)
    path.write_bytes(b"")
    return path


@pytest.mark.parametrize("name", ["docker", "curl", "wget", "git"])
def test_a_system_binary_beside_the_interpreter_is_not_found(
    interpreter_dir: Path, name: str
) -> None:
    _plant(interpreter_dir, name)

    assert tool_utils.find_tool(name) is None


def test_a_pip_installed_scanner_beside_the_interpreter_is_found(
    interpreter_dir: Path,
) -> None:
    # What the fallback is for: `uv tool install jmo-security --with checkov`,
    # or a pip install into JMo's own environment, puts checkov's script here.
    assert "checkov" in ISOLATED_TOOLS
    planted = _plant(interpreter_dir, "checkov")

    assert tool_utils.find_tool("checkov") == str(planted)
