"""`find_tool` must return a launcher this platform can actually execute.

The Java-based tools ship a POSIX `.sh` and a Windows `.bat` **side by side in
the same directory**::

    ~/.jmo/bin/dependency-check/bin/dependency-check.sh
    ~/.jmo/bin/dependency-check/bin/dependency-check.bat
    ~/.jmo/bin/zap/zap.sh
    ~/.jmo/bin/zap/zap.bat

`find_tool` hardcoded the `.sh` for both, on every platform. Handing Windows a
`.sh` does not fail as "not found" - `subprocess` raises

    [WinError 193] %1 is not a valid Win32 application

which reads like a corrupt binary rather than the wrong file, and is why the
cause was not obvious from the message.

It is the same defect twice over. `tool_manager.py`'s ``VERSION_COMMANDS``
already maps both tools per platform (`{"windows": [...bat], "default":
[...sh]}`), so `jmo tools check` resolved `dependency-check.bat` and reported
the tool healthy in the same run where the scanner resolved
`dependency-check.sh` and died. That is exactly the two-resolvers-disagree
failure `tool_utils.py` already documents for checkov, and the one that made
`find_tool("yara")` return a pseudo-path.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.core import tool_utils


@pytest.fixture
def jmo_home(tmp_path, monkeypatch):
    """Point Path.home() at tmp_path, and make PATH lookups miss.

    monkeypatch.setenv("HOME", ...) does not work on Windows - see
    .claude/rules/testing.cross-platform.rules.md.
    """
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(tool_utils.shutil, "which", lambda _name: None)
    monkeypatch.setattr(tool_utils, "get_isolated_tool_path", lambda _name: None)
    return tmp_path


def _install_java_tool(root: Path, subdir: str, stem: str, *suffixes: str) -> None:
    d = root / ".jmo" / "bin" / subdir
    d.mkdir(parents=True, exist_ok=True)
    for suffix in suffixes:
        # write_bytes, not write_text: write_text translates LF to CRLF on
        # Windows (newline=None -> os.linesep).
        (d / f"{stem}{suffix}").write_bytes(b"#!/bin/sh\n")


class TestDependencyCheck:
    def test_windows_gets_the_bat_not_the_sh(self, jmo_home, monkeypatch):
        """The .sh is unexecutable on Windows - WinError 193, not 'not found'."""
        monkeypatch.setattr(tool_utils, "_is_windows", lambda: True)
        _install_java_tool(
            jmo_home, "dependency-check/bin", "dependency-check", ".sh", ".bat"
        )

        resolved = tool_utils.find_tool("dependency-check")

        assert resolved is not None
        assert resolved.endswith(".bat"), resolved

    def test_posix_gets_the_sh(self, jmo_home, monkeypatch):
        monkeypatch.setattr(tool_utils, "_is_windows", lambda: False)
        _install_java_tool(
            jmo_home, "dependency-check/bin", "dependency-check", ".sh", ".bat"
        )

        resolved = tool_utils.find_tool("dependency-check")

        assert resolved is not None
        assert resolved.endswith(".sh"), resolved

    def test_windows_without_a_bat_resolves_nothing(self, jmo_home, monkeypatch):
        """Unresolved is honest; a .sh at command[0] is WinError 193.

        `unresolved` is an accounted state the reconciler understands. Returning
        a launcher this platform cannot execute produces a run-time failure that
        looks like a corrupt binary, and - before this branch - was laundered
        into a recorded success by --allow-missing-tools.
        """
        monkeypatch.setattr(tool_utils, "_is_windows", lambda: True)
        _install_java_tool(jmo_home, "dependency-check/bin", "dependency-check", ".sh")

        assert tool_utils.find_tool("dependency-check") is None


class TestZap:
    """zap ships the same pair and had the same latent bug.

    It did not show up in the deep-scan reconciliation only because zap is a URL
    scanner and the fixture is a repository, so its path was never exercised.
    `url_scanner.py:99` calls `_find_tool("zap.sh")`.
    """

    def test_windows_gets_the_bat_not_the_sh(self, jmo_home, monkeypatch):
        monkeypatch.setattr(tool_utils, "_is_windows", lambda: True)
        _install_java_tool(jmo_home, "zap", "zap", ".sh", ".bat")

        resolved = tool_utils.find_tool("zap.sh")

        assert resolved is not None
        assert resolved.endswith(".bat"), resolved

    def test_posix_gets_the_sh(self, jmo_home, monkeypatch):
        monkeypatch.setattr(tool_utils, "_is_windows", lambda: False)
        _install_java_tool(jmo_home, "zap", "zap", ".sh", ".bat")

        resolved = tool_utils.find_tool("zap.sh")

        assert resolved is not None
        assert resolved.endswith(".sh"), resolved


def test_resolvers_agree_on_the_launcher_extension(jmo_home, monkeypatch):
    """The scanner and `jmo tools check` must not pick different files.

    This is the invariant behind three separate bugs now: checkov (check said
    OK, scanner resolved None, 0 IaC findings on 47 .tf files), yara (check said
    OK at 4.5.4, scanner got a pseudo-path) and dependency-check (check resolved
    the .bat and reported healthy, scanner resolved the .sh and died).
    """
    monkeypatch.setattr(tool_utils, "_is_windows", lambda: True)
    _install_java_tool(
        jmo_home, "dependency-check/bin", "dependency-check", ".sh", ".bat"
    )

    scanner_side = tool_utils.find_tool("dependency-check")

    assert scanner_side is not None
    assert Path(scanner_side).suffix == ".bat", (
        "tool_manager's VERSION_COMMANDS maps dependency-check to the .bat on "
        "Windows. find_tool must agree, or the two resolvers disagree again."
    )
