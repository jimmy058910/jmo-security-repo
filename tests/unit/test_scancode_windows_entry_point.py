"""scancode on native Windows: detect the real entry point, and stop attempting
an install that upstream says cannot work (#1091).

Measured 2026-08-31: `jmo tools install scancode` extracted the pre-built
release to `~/.jmo/bin/scancode/` (21 entries, `scancode.bat` among them) and
reported `[FAIL] scancode - Extraction succeeded but tool not detected`,
because detection looked for `scancode` and `scancode.exe` only. The bootstrap
that `scancode.bat` triggers then fails inside scancode's own `configure.bat`
(`ERROR: You must give at least one requirement to install`), and upstream's
banner deprecates native Windows in favour of WSL2
(nexB/scancode-toolkit#2366). Same class as the trufflehog `.exe` omission
that once made a scanner silently inert; here it failed loudly, which is the
better outcome.

Two resolvers answered "scancode" differently before this: `tool_manager
._find_binary` knew the extraction directory and its nested layouts,
`tool_utils.find_tool` only tried `~/.jmo/bin/scancode/scancode`. One helper
now serves both, and it knows about `.bat`.

Also measured, on 2026-09-02: the platform table said shellcheck has "No
Windows build available from upstream", while `BINARY_URLS["shellcheck"]`
carries a Windows zip and this box holds `~/.jmo/bin/shellcheck.exe`, which
only JMo writes. That entry made the wizard skip a tool JMo installs fine, and
with an install-time gate it would have refused a working install. It goes.
"""

from __future__ import annotations

import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.installers.models import InstallResult
from scripts.cli.tool_installer import ToolInstaller
from scripts.cli.tool_manager import ToolManager
from scripts.core import tool_utils
from scripts.core.install_config import BINARY_URLS
from scripts.core.tool_registry import (
    TOOL_PLATFORM_REQUIREMENTS,
    get_platform_status,
    get_tools_for_profile_filtered,
)


class TestPlatformTable:
    def test_scancode_is_linux_and_macos_only_with_wsl2_and_docker_as_the_way_out(self):
        entry = TOOL_PLATFORM_REQUIREMENTS["scancode"]
        assert entry["platforms"] == ["linux", "macos"]
        assert {"wsl2", "docker"} <= set(entry["workarounds"])

        status = get_platform_status("scancode", "windows")
        assert status["supported"] is False
        assert "2366" in status["reason"]
        assert get_platform_status("scancode", "linux")["supported"] is True

    def test_shellcheck_is_not_listed_because_jmo_installs_it_on_windows(self):
        assert "windows" in BINARY_URLS["shellcheck"]
        assert "shellcheck" not in TOOL_PLATFORM_REQUIREMENTS
        assert get_platform_status("shellcheck", "windows")["supported"] is True
        assert "shellcheck" in get_tools_for_profile_filtered("fast", "windows")


@pytest.fixture
def jmo_home(tmp_path, monkeypatch) -> Path:
    # monkeypatch.setenv("HOME", ...) does not work on Windows; patch Path.home.
    monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
    monkeypatch.setattr(tool_utils.shutil, "which", lambda _name: None)
    monkeypatch.setattr(tool_utils, "get_isolated_tool_path", lambda _name: None)
    return tmp_path


def _extract(home: Path, *parts: str) -> Path:
    target = home.joinpath(".jmo", "bin", "scancode", *parts)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(b"")
    return target


def _both_resolvers(name: str = "scancode") -> tuple[str | None, str | None]:
    return tool_utils.find_tool(name), ToolManager()._find_binary(name)


class TestLauncherResolution:
    """`find_tool` and `_find_binary` must return the same launcher."""

    def test_windows_finds_the_bat_once_its_bootstrap_has_completed(
        self, jmo_home, monkeypatch
    ):
        monkeypatch.setattr(sys, "platform", "win32")
        bat = _extract(jmo_home, "scancode.bat")
        _extract(jmo_home, "venv", "Scripts", "scancode.exe")

        assert _both_resolvers() == (str(bat), str(bat))

    def test_the_measured_broken_extraction_is_not_reported_as_a_tool(
        self, jmo_home, monkeypatch
    ):
        """configure.bat + scancode.bat + thirdparty/ + a venv with no
        scancode script: exactly what `jmo tools install scancode` leaves on
        native Windows. The wrapper exits 1 when run. Accepting the `.bat`
        here made `tools check` say OK 32.5.0 (it reads SCANCODE_VERSION, it
        does not run the launcher), which is the silently-inert shape."""
        monkeypatch.setattr(sys, "platform", "win32")
        _extract(jmo_home, "configure.bat")
        _extract(jmo_home, "thirdparty", "README.txt")
        _extract(jmo_home, "venv", "Scripts", "python.exe")
        _extract(jmo_home, "scancode.bat")

        assert _both_resolvers() == (None, None)

    def test_a_bat_in_a_nested_release_needs_its_own_venv_script(
        self, jmo_home, monkeypatch
    ):
        monkeypatch.setattr(sys, "platform", "win32")
        nested = "scancode-toolkit-v32.5.0"
        bat = _extract(jmo_home, nested, "scancode.bat")
        assert _both_resolvers() == (None, None)

        _extract(jmo_home, nested, "venv", "Scripts", "scancode.exe")
        assert _both_resolvers() == (str(bat), str(bat))

    def test_posix_prefers_the_bare_launcher_over_a_bat(self, jmo_home, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        _extract(jmo_home, "scancode.bat")
        launcher = _extract(jmo_home, "scancode")

        assert _both_resolvers() == (str(launcher), str(launcher))

    def test_nested_release_layout(self, jmo_home, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        launcher = _extract(jmo_home, "scancode-toolkit-v32.5.0", "scancode")

        assert _both_resolvers() == (str(launcher), str(launcher))

    def test_bin_subdirectory_layout(self, jmo_home, monkeypatch):
        monkeypatch.setattr(sys, "platform", "linux")
        launcher = _extract(jmo_home, "bin", "scancode")

        assert _both_resolvers() == (str(launcher), str(launcher))

    def test_nothing_extracted_is_nothing_found(self, jmo_home, monkeypatch):
        monkeypatch.setattr(sys, "platform", "win32")

        assert _both_resolvers() == (None, None)


class TestInstallGate:
    """Refuse at the one choke point every install path goes through."""

    @staticmethod
    def _installer(platform: str, installed: bool = False) -> ToolInstaller:
        manager = MagicMock()
        manager.check_tool.return_value = MagicMock(
            installed=installed, installed_version="32.5.0" if installed else None
        )
        installer = ToolInstaller(manager=manager)
        installer.platform = platform
        return installer

    def test_windows_refuses_scancode_with_the_reason_and_the_workarounds(self):
        installer = self._installer("windows")
        with patch.object(installer, "_install_special", MagicMock()) as special:
            result = installer.install_tool("scancode")

        special.assert_not_called()
        assert result.success is False
        assert result.method == "unsupported"
        assert "windows" in result.message
        assert "wsl2" in result.message
        assert "docker" in result.message

    def test_the_update_path_force_reinstall_is_gated_too(self):
        installer = self._installer("windows")
        with patch.object(installer, "_install_special", MagicMock()) as special:
            result = installer.install_tool("scancode", force=True)

        special.assert_not_called()
        assert result.method == "unsupported"

    def test_linux_still_installs_scancode(self):
        installer = self._installer("linux")
        ok = InstallResult(
            tool_name="scancode",
            success=True,
            method="extract_app",
            version_installed="32.5.0",
        )
        with patch.object(
            installer, "_install_special", MagicMock(return_value=ok)
        ) as special:
            result = installer.install_tool("scancode")

        special.assert_called_once()
        assert result.success is True

    def test_noseyparker_on_windows_is_refused_instead_of_a_404(self):
        installer = self._installer("windows")
        with patch.object(installer, "_install_binary", MagicMock()) as binary:
            result = installer.install_tool("noseyparker")

        binary.assert_not_called()
        assert result.method == "unsupported"

    def test_docker_only_tools_keep_their_special_path(self):
        """`platforms: []` means docker-only by design; SPECIAL_INSTALL owns it."""
        installer = self._installer("linux")
        docker = InstallResult(
            tool_name="mobsf", success=False, method="docker", message="use docker"
        )
        with patch.object(
            installer, "_install_special", MagicMock(return_value=docker)
        ) as special:
            result = installer.install_tool("mobsf")

        special.assert_called_once()
        assert result.method == "docker"

    def test_an_installed_tool_is_reported_installed_before_the_gate(self):
        """Someone who installed scancode by hand on Windows keeps it."""
        installer = self._installer("windows", installed=True)

        result = installer.install_tool("scancode")

        assert result.success is True
        assert result.method == "existing"
