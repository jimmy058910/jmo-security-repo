"""`find_tool()` must prefer a JMo-managed isolated venv over a PATH copy, so
the scanner runs the binary `jmo tools check` reports (#1101).

Measured 2026-09-02 with semgrep 1.172.0 in `~/.jmo/tools/venvs/semgrep/` and
a stale user-site 1.161.0 on PATH: `tool_manager._find_binary()` checks the
isolated venv first, so `tools check` printed OK 1.172.0, while
`tool_utils.find_tool()` checked `shutil.which` first and handed the scanner
1.161.0. Two resolvers, two answers, one tool name -- the shape #1093 was
filed on. `find_tool`'s own comment already said "check isolated venv paths
first"; the code did it third.
"""

from __future__ import annotations

from pathlib import Path

from scripts.core import tool_utils


def _venv_exe(tmp_path: Path, tool: str) -> Path:
    exe = tmp_path / "venvs" / tool / "Scripts" / f"{tool}.exe"
    exe.parent.mkdir(parents=True)
    exe.write_bytes(b"")
    return exe


def test_isolated_venv_wins_over_a_path_copy(tmp_path, monkeypatch):
    venv_exe = _venv_exe(tmp_path, "semgrep")
    stale = str(tmp_path / "stale" / "semgrep.EXE")
    monkeypatch.setattr(tool_utils.shutil, "which", lambda _name: stale)
    monkeypatch.setattr(
        tool_utils,
        "get_isolated_tool_path",
        lambda name: venv_exe if name == "semgrep" else None,
    )

    assert tool_utils.find_tool("semgrep") == str(venv_exe)


def test_a_path_copy_is_still_found_when_no_isolated_venv_exists(tmp_path, monkeypatch):
    on_path = str(tmp_path / "bin" / "trivy")
    monkeypatch.setattr(tool_utils.shutil, "which", lambda _name: on_path)
    monkeypatch.setattr(tool_utils, "get_isolated_tool_path", lambda _name: None)

    assert tool_utils.find_tool("trivy") == on_path


def test_the_two_resolvers_agree_on_an_isolated_tool(tmp_path, monkeypatch):
    """`tool_manager._find_binary` and `tool_utils.find_tool` return one path."""
    from scripts.cli.tool_manager import ToolManager
    from scripts.core import paths

    venv_exe = _venv_exe(tmp_path, "semgrep")
    stale = str(tmp_path / "stale" / "semgrep.EXE")
    resolver = lambda name: venv_exe if name == "semgrep" else None  # noqa: E731
    monkeypatch.setattr(tool_utils.shutil, "which", lambda _name: stale)
    monkeypatch.setattr(tool_utils, "get_isolated_tool_path", resolver)
    monkeypatch.setattr(paths, "get_isolated_tool_path", resolver)

    via_manager = ToolManager()._find_binary("semgrep")
    via_utils = tool_utils.find_tool("semgrep")

    assert via_manager == via_utils == str(venv_exe)
