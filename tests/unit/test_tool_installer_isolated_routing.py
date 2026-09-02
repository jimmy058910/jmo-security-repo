"""`install_tool()` must honour ISOLATED_TOOLS, and a pinned install whose
resolved binary still reports the old version is a failure (#1101, #1093).

Measured 2026-08-31 and again 2026-09-02: `jmo tools install prowler semgrep
checkov` and `jmo tools update` both loop `install_tool()`, whose pip branch
targets `sys.executable`; only the profile installers split isolated tools
out. prowler landed in the project `.venv` and dragged cryptography
50.0.0 -> 46.0.7 and, via semgrep's `mcp==1.29.0` pin, mcp 2.0.0 -> 1.29.0 off
`uv.lock` -- JMo's own MCP server could not import.

And `_validate_installed_version` only *warned* on a mismatch, so `tools
update` printed `[OK] semgrep (v1.161.0)` two lines after
`expected=1.175.0`, then `All 6 tool(s) updated successfully!` at exit 0. The
old binary, reported as success.

No test touched `install_tool`, `_install_pip`, `_isolated_pip_install` or
`_validate_installed_version` before this file, which is how both survived.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.installers.models import InstallProgress, InstallResult
from scripts.cli.tool_installer import ToolInstaller, print_install_progress
from scripts.core.install_config import ISOLATED_TOOLS

# Spelled out rather than derived from ISOLATED_TOOLS: a parametrize over the
# constant under test cannot fail when that constant empties (#1061). The
# canary below is what fails if the config and this literal drift apart.
ISOLATED = ("prowler", "semgrep", "checkov")


def test_the_literal_matches_the_config():
    assert set(ISOLATED) == set(ISOLATED_TOOLS)


def _installer_with_nothing_installed() -> ToolInstaller:
    manager = MagicMock()
    manager.check_tool.return_value = MagicMock(installed=False)
    installer = ToolInstaller(manager=manager)
    # Windows priorities start with pip, so a pypi tool reaches _install_pip
    # without first probing apt/brew on the host running the test.
    installer.platform = "windows"
    return installer


def _isolated_ok(tool: str, version: str) -> MagicMock:
    return MagicMock(
        return_value=InstallResult(
            tool_name=tool,
            success=True,
            method="isolated_venv",
            version_installed=version,
        )
    )


@pytest.mark.parametrize("tool", ISOLATED)
def test_install_tool_routes_isolated_tools_to_the_isolated_venv(tool):
    installer = _installer_with_nothing_installed()
    pinned = installer.registry.get_tool(tool).version
    package = ISOLATED_TOOLS[tool].get("package", tool)
    isolated = _isolated_ok(tool, pinned)
    plain = MagicMock()

    with (
        patch.object(installer, "_isolated_pip_install", isolated),
        patch.object(installer, "_install_pip", plain),
    ):
        result = installer.install_tool(tool)

    isolated.assert_called_once_with(tool, f"{package}=={pinned}")
    plain.assert_not_called()
    assert result.success
    assert result.method == "isolated_venv"
    assert result.version_installed == pinned


@pytest.mark.parametrize("tool", ISOLATED)
def test_the_update_path_force_reinstall_also_isolates(tool):
    """`jmo tools update` is `install_tool(name, force=True)` per tool."""
    installer = _installer_with_nothing_installed()
    pinned = installer.registry.get_tool(tool).version
    isolated = _isolated_ok(tool, pinned)
    plain = MagicMock()

    with (
        patch.object(installer, "_isolated_pip_install", isolated),
        patch.object(installer, "_install_pip", plain),
    ):
        installer.install_tool(tool, force=True)

    isolated.assert_called_once()
    plain.assert_not_called()


def test_a_regular_pip_tool_still_goes_through_pip():
    installer = _installer_with_nothing_installed()
    pinned = installer.registry.get_tool("bandit").version
    plain = MagicMock(
        return_value=InstallResult(
            tool_name="bandit", success=True, method="pip", version_installed=pinned
        )
    )
    isolated = MagicMock()

    with (
        patch.object(installer, "_install_pip", plain),
        patch.object(installer, "_isolated_pip_install", isolated),
    ):
        result = installer.install_tool("bandit")

    plain.assert_called_once()
    isolated.assert_not_called()
    assert result.success


class TestPinnedInstallVerdict:
    """#1093: the version check decides the verdict, not the installer's exit."""

    @pytest.mark.parametrize("method", ["pip", "isolated_venv", "binary"])
    def test_a_mismatch_after_a_pinned_install_is_a_failure(self, method):
        installer = ToolInstaller(manager=MagicMock())
        result = InstallResult(
            tool_name="semgrep",
            success=True,
            method=method,
            version_installed="1.161.0",
        )

        out = installer._validate_installed_version(result, "1.175.0")

        assert out.success is False
        assert out.version_mismatch is True
        assert "1.161.0" in out.message
        assert "1.175.0" in out.message

    def test_a_mismatch_fails_the_batch_and_prints_fail(self, capsys):
        installer = ToolInstaller(manager=MagicMock())
        result = installer._validate_installed_version(
            InstallResult(
                tool_name="semgrep",
                success=True,
                method="pip",
                version_installed="1.161.0",
            ),
            "1.175.0",
        )
        progress = InstallProgress(total=1)
        progress.add_result(result)

        assert progress.failed == 1
        assert progress.successful == 0

        print_install_progress(progress)
        out = capsys.readouterr().out
        assert "[FAIL] semgrep" in out
        assert "[OK]" not in out

    @pytest.mark.parametrize("method", ["brew", "apt"])
    def test_an_unpinned_package_manager_still_only_warns(self, method):
        """brew/apt install whatever they carry; a mismatch there is not a lie."""
        installer = ToolInstaller(manager=MagicMock())
        out = installer._validate_installed_version(
            InstallResult(
                tool_name="trivy",
                success=True,
                method=method,
                version_installed="0.73.0",
            ),
            "0.74.0",
        )
        assert out.success is True
        assert out.version_mismatch is True

    def test_a_match_is_untouched(self):
        installer = ToolInstaller(manager=MagicMock())
        out = installer._validate_installed_version(
            InstallResult(
                tool_name="semgrep",
                success=True,
                method="pip",
                version_installed="v1.175.0",
            ),
            "1.175.0",
        )
        assert out.success is True
        assert out.version_mismatch is False
