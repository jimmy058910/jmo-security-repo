#!/usr/bin/env python3
"""Tests for scripts/core/tool_registry.py module.

This test suite validates the ToolRegistry class and related utilities:
1. TOOL_MATRIX, POLICY_ENGINE and the tables keyed by tool name
2. ToolInfo dataclass behavior
3. ToolRegistry initialization and loading
4. Platform detection and install hints
5. Every tool JMo installs has an install route on Linux, macOS and Windows

Target Coverage: >= 85%
"""

import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from scripts.core.tool_registry import POLICY_ENGINE, TOOL_MATRIX

# ========== Category 1: The tool matrix and name-keyed tables ==========

V2_PHASE_2_MATRIX = {
    "trufflehog",
    "semgrep",
    "syft",
    "trivy",
    "checkov",
    "hadolint",
    "shellcheck",
    "gosec",
    "yara",
    "grype",
    "zap",
    "nuclei",
}


def test_tool_matrix_is_the_phase_2_set():
    """TOOL_MATRIX is the v2.0.0 Phase 2 scanner set, with no duplicates."""
    assert set(TOOL_MATRIX) == V2_PHASE_2_MATRIX
    assert len(TOOL_MATRIX) == len(set(TOOL_MATRIX))


def test_the_policy_engine_is_not_a_scanner():
    """opa is installed alongside the matrix but scans no target type."""
    from scripts.core.tool_registry import TOOL_SCAN_TYPES

    assert POLICY_ENGINE == "opa"
    assert POLICY_ENGINE not in TOOL_MATRIX
    assert POLICY_ENGINE not in TOOL_SCAN_TYPES["repo"]
    assert [t for t, tools in TOOL_SCAN_TYPES.items() if POLICY_ENGINE in tools] == []


def test_tool_binary_names_mapping():
    """TOOL_BINARY_NAMES maps a tool to its binary where the two differ."""
    from scripts.core.tool_registry import TOOL_BINARY_NAMES

    # zap ships a launcher script, not a `zap` binary
    assert TOOL_BINARY_NAMES.get("zap") == "zap.sh"


def test_tool_execution_commands():
    """Test TOOL_EXECUTION_COMMANDS has execution requirements."""
    from scripts.core.tool_registry import TOOL_EXECUTION_COMMANDS

    assert "zap" in TOOL_EXECUTION_COMMANDS
    assert "zap.sh" in TOOL_EXECUTION_COMMANDS["zap"]
    # Java is the one runtime dependency left, and zap is the tool that needs it
    assert "java" in TOOL_EXECUTION_COMMANDS["zap"]


# ========== Category 2: ToolInfo Dataclass ==========


def test_toolinfo_defaults():
    """Test ToolInfo has correct default values."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="test-tool",
        version="1.0.0",
        description="A test tool",
        category="binary_tools",
    )

    assert tool.name == "test-tool"
    assert tool.version == "1.0.0"
    assert tool.description == "A test tool"
    assert tool.category == "binary_tools"
    assert tool.critical is False
    assert tool.docker_ready is True
    assert tool.pypi_package is None
    assert tool.github_repo is None
    assert tool.platforms == ["linux", "macos", "windows"]


def test_toolinfo_custom_values():
    """Test ToolInfo can be initialized with custom values."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="custom-tool",
        version="2.0.0",
        description="Custom",
        category="python_tools",
        critical=True,
        docker_ready=False,
        pypi_package="custom-package",
        github_repo="org/custom",
        platforms=["linux", "macos"],
    )

    assert tool.critical is True
    assert tool.docker_ready is False
    assert tool.pypi_package == "custom-package"
    assert tool.github_repo == "org/custom"
    assert tool.platforms == ["linux", "macos"]


def test_toolinfo_get_binary_name_default():
    """Test get_binary_name returns tool name when no override."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="trivy",
        version="0.50.0",
        description="Trivy scanner",
        category="binary_tools",
    )

    assert tool.get_binary_name() == "trivy"


def test_toolinfo_get_binary_name_override():
    """Test get_binary_name returns override when set."""
    from scripts.core.tool_registry import ToolInfo

    tool = ToolInfo(
        name="custom-tool",
        version="1.0.0",
        description="Custom",
        category="binary_tools",
        binary_name="custom-bin",
    )

    assert tool.get_binary_name() == "custom-bin"


def test_toolinfo_get_binary_name_from_mapping():
    """Test get_binary_name uses TOOL_BINARY_NAMES mapping."""
    from scripts.core.tool_registry import ToolInfo

    # zap has a binary name mapping to its zap.sh launcher
    tool = ToolInfo(
        name="zap",
        version="2.16.1",
        description="OWASP ZAP",
        category="special_tools",
    )

    assert tool.get_binary_name() == "zap.sh"


# ========== Category 3: ToolRegistry ==========


def test_toolregistry_init_default():
    """Test ToolRegistry initializes with default versions.yaml."""
    from scripts.core.tool_registry import ToolRegistry

    # This should find versions.yaml in the repo
    registry = ToolRegistry()
    assert len(registry.get_all_tools()) > 0


def test_toolregistry_init_custom_path(tmp_path):
    """Test ToolRegistry can load from custom path."""
    from scripts.core.tool_registry import ToolRegistry

    # Create a minimal versions.yaml
    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
python_tools:
  semgrep:
    version: "1.50.0"
    description: "Static analyzer"
    critical: true
    pypi_package: semgrep

binary_tools:
  trivy:
    version: "0.50.0"
    description: "Container scanner"
    github_repo: aquasecurity/trivy
""",
        encoding="utf-8",
    )

    registry = ToolRegistry(versions_path=versions_file)
    tools = registry.get_all_tools()

    # Exactly the two tools the file declares
    tool_names = [t.name for t in tools]
    assert sorted(tool_names) == ["semgrep", "trivy"]


def test_toolregistry_get_tool():
    """Test ToolRegistry.get_tool returns correct tool."""
    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()

    # Get a known tool
    trivy = registry.get_tool("trivy")
    assert trivy is not None
    assert trivy.name == "trivy"

    # Non-existent tool returns None
    assert registry.get_tool("nonexistent-tool") is None


def test_toolregistry_get_critical_tools():
    """Test ToolRegistry.get_critical_tools returns critical tools."""
    from scripts.core.tool_registry import ToolRegistry

    registry = ToolRegistry()
    critical_tools = registry.get_critical_tools()

    # All returned tools should have critical=True
    for tool in critical_tools:
        assert tool.critical is True


def test_toolregistry_registers_every_tool_jmo_installs():
    """Every TOOL_MATRIX tool and the policy engine is in the real registry.

    `jmo tools install` reads each tool's version and package from the
    registry and answers "Unknown tool" for anything missing, so this is the
    set that has to be there -- derived from TOOL_MATRIX, not a count.
    """
    from scripts.core.tool_registry import ToolRegistry

    registered = {t.name for t in ToolRegistry().get_all_tools()}

    assert sorted({*TOOL_MATRIX, POLICY_ENGINE} - registered) == []


def test_toolregistry_handles_missing_versions_file():
    """Test ToolRegistry raises error for missing versions.yaml."""
    from scripts.core.tool_registry import ToolRegistry

    with pytest.raises(FileNotFoundError):
        ToolRegistry(versions_path=Path("/nonexistent/versions.yaml"))


# ========== Category 4: Platform Detection ==========


def test_detect_platform_linux():
    """Test detect_platform returns linux on Linux systems."""
    from scripts.core.tool_registry import detect_platform

    with patch.object(sys, "platform", "linux"):
        assert detect_platform() == "linux"


def test_detect_platform_macos():
    """Test detect_platform returns macos on macOS systems."""
    from scripts.core.tool_registry import detect_platform

    with patch.object(sys, "platform", "darwin"):
        assert detect_platform() == "macos"


def test_detect_platform_windows():
    """Test detect_platform returns windows on Windows systems."""
    from scripts.core.tool_registry import detect_platform

    with patch.object(sys, "platform", "win32"):
        assert detect_platform() == "windows"


# ========== Category 5: Install Hints ==========


def test_get_install_hint_macos_leads_with_jmo_tools_install():
    """macOS gets the pinned `jmo tools install`, never an unpinned brew install."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="trivy",
        version="0.50.0",
        description="Trivy",
        category="binary_tools",
    )

    hint = get_install_hint(tool, platform="macos")
    assert hint.startswith("jmo tools install trivy")
    assert "brew" not in hint


def test_get_install_hint_macos_pip():
    """Test get_install_hint returns pip install for Python tools on macOS."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="semgrep",
        version="1.50.0",
        description="Semgrep",
        category="python_tools",
        pypi_package="semgrep",
    )

    hint = get_install_hint(tool, platform="macos")
    assert "pip install semgrep" in hint


def test_get_install_hint_linux_apt():
    """Test get_install_hint returns apt install for Linux when available."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="shellcheck",
        version="0.9.0",
        description="ShellCheck",
        category="binary_tools",
        apt_package="shellcheck",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "apt install shellcheck" in hint


def test_get_install_hint_linux_pip():
    """Test get_install_hint returns pip install for Python tools on Linux."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="checkov",
        version="3.0.0",
        description="Checkov",
        category="python_tools",
        pypi_package="checkov",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "pip install checkov" in hint


def test_get_install_hint_windows():
    """Test get_install_hint returns pip for Windows Python tools."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="semgrep",
        version="1.50.0",
        description="Semgrep",
        category="python_tools",
        pypi_package="semgrep",
    )

    hint = get_install_hint(tool, platform="windows")
    assert "pip install semgrep" in hint


def test_get_install_hint_without_a_package_names_jmo_tools_install():
    """A tool with no pip or apt package still gets a runnable hint."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="custom-tool",
        version="1.0.0",
        description="Custom",
        category="binary_tools",
        github_repo="org/custom-tool",
    )

    assert get_install_hint(tool, platform="linux") == "jmo tools install custom-tool"


def test_get_install_hint_with_notes():
    """Test get_install_hint includes install notes when present."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="zap",
        version="2.14.0",
        description="OWASP ZAP",
        category="binary_tools",
        install_notes="Requires Java 11+",
    )

    hint = get_install_hint(tool, platform="linux")
    assert "Requires Java 11+" in hint


def test_get_install_hint_auto_detect_platform():
    """Test get_install_hint auto-detects platform when not specified."""
    from scripts.core.tool_registry import ToolInfo, get_install_hint

    tool = ToolInfo(
        name="semgrep",
        version="1.50.0",
        description="Semgrep",
        category="python_tools",
        pypi_package="semgrep",
    )

    # Should not raise, should auto-detect platform. Assert the hint carries a
    # runnable command naming the package -- `len(hint) > 0` passed for any
    # string, including one that had lost the package name entirely, which is
    # the only part of the hint a user actually needs.
    hint = get_install_hint(tool)
    assert "pip install semgrep" in hint


# ========== Category 6: Edge Cases ==========


def test_toolregistry_handles_malformed_yaml(tmp_path):
    """Test ToolRegistry handles malformed YAML gracefully."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text("invalid: yaml: content:", encoding="utf-8")

    with pytest.raises(Exception):
        ToolRegistry(versions_path=versions_file)


def test_toolregistry_handles_empty_yaml(tmp_path):
    """Test ToolRegistry raises error for empty YAML file."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text("", encoding="utf-8")

    # Empty YAML file returns None, which is invalid for a versions file
    with pytest.raises((AttributeError, TypeError)):
        ToolRegistry(versions_path=versions_file)


def test_toolregistry_handles_non_dict_category(tmp_path):
    """Test ToolRegistry handles non-dict category gracefully."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
python_tools:
  - not
  - a
  - dict
binary_tools:
  trivy:
    version: "0.50.0"
    description: "Trivy"
""",
        encoding="utf-8",
    )

    # Should skip the malformed category and load the valid one
    registry = ToolRegistry(versions_path=versions_file)
    tools = registry.get_all_tools()
    tool_names = [t.name for t in tools]
    assert "trivy" in tool_names


def test_toolregistry_handles_non_dict_tool_entry(tmp_path):
    """Test ToolRegistry handles non-dict tool entries gracefully."""
    from scripts.core.tool_registry import ToolRegistry

    versions_file = tmp_path / "versions.yaml"
    versions_file.write_text(
        """
binary_tools:
  invalid_tool: "just a string"
  valid_tool:
    version: "1.0.0"
    description: "Valid tool"
""",
        encoding="utf-8",
    )

    registry = ToolRegistry(versions_path=versions_file)
    tools = registry.get_all_tools()
    tool_names = [t.name for t in tools]

    assert "valid_tool" in tool_names
    assert "invalid_tool" not in tool_names


# ========== Category 7: An install route on every platform ==========
#
# v2.0.0 removed platform gating: every tool `jmo tools install` installs must
# install on Linux, macOS and Windows. (This replaces the shellcheck-on-Windows
# case that lived in the deleted test_scancode_windows_entry_point.py: the
# platform table once said shellcheck had no Windows build while BINARY_URLS
# carried one.)
#
# The route is read off the installer's OWN dispatch rather than a restatement
# of it: ToolInstaller.install_tool runs for real, with each install handler
# swapped for a recorder. binary and extract_app downloads run their real URL
# resolution (the platform key, then "default") and are recorded at
# _get_download_command, so a URL table the installer cannot key for a platform
# records nothing.

_PLATFORMS = ("linux", "macos", "windows")


def _install_routes(tool: str, platform: str, monkeypatch, tmp_path) -> list[str]:
    """Drive `install_tool(tool)` as if on `platform`; return every route reached.

    A route is a handler that would perform the install: pip, apt, an official
    install script, the isolated venv, or a download whose URL the installer
    resolved for `platform`. Every recorder reports failure, so install_tool
    walks its whole priority list and nothing is installed.
    """
    from scripts.cli.installers.models import InstallResult
    from scripts.cli.tool_installer import ToolInstaller

    installer = ToolInstaller(install_dir=tmp_path / "bin")
    installer.platform = platform
    routes: list[str] = []

    def recorder(route: str):
        def handler(tool_name, *_args, **_kwargs):
            routes.append(route)
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method=route,
                message=f"{route} recorded",
            )

        return handler

    def download(url, _output_path):
        routes.append(f"download {url}")
        return None  # "no curl or wget": the handler stops before any network I/O

    monkeypatch.setattr(installer, "_isolated_pip_install", recorder("isolated_venv"))
    monkeypatch.setattr(installer, "_install_pip", recorder("pip"))
    monkeypatch.setattr(installer, "_install_apt", recorder("apt"))
    monkeypatch.setattr(installer, "_install_via_script", recorder("install_script"))
    monkeypatch.setattr(installer, "_get_download_command", download)
    monkeypatch.setattr(installer, "_get_arch", lambda: "x86_64")

    result = installer.install_tool(tool, force=True)
    assert result.success is False  # every handler was a recorder
    return routes


@pytest.mark.parametrize("platform", _PLATFORMS)
@pytest.mark.parametrize("tool", [*TOOL_MATRIX, POLICY_ENGINE])
def test_every_installed_tool_has_an_install_route_on_every_platform(
    tool, platform, monkeypatch, tmp_path
):
    routes = _install_routes(tool, platform, monkeypatch, tmp_path)

    assert routes, f"jmo tools install {tool} has no install route on {platform}"


def test_a_binary_url_the_installer_cannot_key_leaves_no_route(monkeypatch, tmp_path):
    """Negative control: the route check fails when a platform loses its URL.

    hadolint installs only by binary download. With its "default" template
    dropped, the installer has nothing to key Linux or macOS on, so both must
    come back with no route while Windows keeps its own asset.
    """
    from scripts.core.install_config import BINARY_URLS

    monkeypatch.setitem(
        BINARY_URLS, "hadolint", {"windows": BINARY_URLS["hadolint"]["windows"]}
    )

    assert _install_routes("hadolint", "linux", monkeypatch, tmp_path) == []
    assert _install_routes("hadolint", "macos", monkeypatch, tmp_path) == []
    windows = _install_routes("hadolint", "windows", monkeypatch, tmp_path)
    assert len(windows) == 1
    assert windows[0].endswith("/hadolint-Windows-x86_64.exe")
