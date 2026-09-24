#!/usr/bin/env python3
"""Tests for scripts/cli/tool_manager.py module.

This test suite validates the ToolManager class:
1. ToolStatus dataclass behavior
2. ToolManager initialization and tool checking
3. Version parsing and comparison
4. Binary finding
5. Matrix checks and summary functionality (TOOL_MATRIX, or an explicit tool list)
6. Version drift detection
7. Helper functions

Target Coverage: >= 85%
"""

import os
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.core.install_config import ISOLATED_TOOLS
from scripts.core.tool_registry import POLICY_ENGINE, TOOL_MATRIX

# ========== Category 1: VERSION_PATTERNS Constants ==========


def test_version_patterns_default():
    """Test default version pattern exists."""
    from scripts.cli.tool_manager import VERSION_PATTERNS

    assert "default" in VERSION_PATTERNS
    assert isinstance(VERSION_PATTERNS["default"], re.Pattern)


def test_version_patterns_tool_specific():
    """Test tool-specific version patterns exist."""
    from scripts.cli.tool_manager import VERSION_PATTERNS

    important_tools = ["trivy", "grype", "syft", "nuclei", "semgrep", "checkov"]
    for tool in important_tools:
        assert tool in VERSION_PATTERNS or "default" in VERSION_PATTERNS


def test_version_commands_structure():
    """Test VERSION_COMMANDS has correct structure.

    VERSION_COMMANDS can be:
    - list[str]: Universal command (works on all platforms)
    - dict[str, list[str]]: Platform-specific commands with keys like "windows", "default"
      May also include "fallback" key for commands to try if primary fails
    """
    from scripts.cli.tool_manager import VERSION_COMMANDS

    for tool, cmd_config in VERSION_COMMANDS.items():
        if isinstance(cmd_config, dict):
            # Platform-specific commands - validate each variant
            assert "default" in cmd_config or "linux" in cmd_config, (
                f"Platform-specific {tool} must have 'default' or 'linux' key"
            )
            for platform_key, cmd_list in cmd_config.items():
                assert isinstance(cmd_list, list), (
                    f"{tool}[{platform_key}] must be a list"
                )
                assert len(cmd_list) >= 2, (
                    f"{tool}[{platform_key}] must have at least 2 elements"
                )
        else:
            # Universal command
            assert isinstance(cmd_config, list), f"{tool} must be a list"
            assert len(cmd_config) >= 2, f"{tool} must have at least 2 elements"


def test_version_timeouts_reasonable():
    """Test VERSION_TIMEOUTS has reasonable values."""
    from scripts.cli.tool_manager import VERSION_TIMEOUTS

    for tool, timeout in VERSION_TIMEOUTS.items():
        assert 10 <= timeout <= 120


# ========== Category 2: ToolStatus Dataclass ==========


def test_toolstatus_defaults():
    """Test ToolStatus has correct defaults."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(name="test-tool", installed=False)

    assert status.name == "test-tool"
    assert status.installed is False
    assert status.installed_version is None
    assert status.expected_version is None
    assert status.is_outdated is False
    assert status.is_critical is False
    assert status.install_hint == ""
    assert status.binary_path is None
    assert status.execution_ready is True
    assert status.execution_warning is None
    assert status.missing_deps == []


def test_toolstatus_custom_values():
    """Test ToolStatus with custom values."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(
        name="trivy",
        installed=True,
        installed_version="0.49.0",
        expected_version="0.50.0",
        is_outdated=True,
        is_critical=True,
        install_hint="jmo tools install trivy",
        binary_path="/usr/local/bin/trivy",
        execution_ready=True,
    )

    assert status.installed_version == "0.49.0"
    assert status.expected_version == "0.50.0"
    assert status.is_outdated is True
    assert status.is_critical is True


def test_toolstatus_status_icon_missing():
    """Test status_icon returns X for missing tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(name="test", installed=False)
    assert status.status_icon == "X"


def test_toolstatus_status_icon_not_ready():
    """Test status_icon returns ! for not ready tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(name="test", installed=True, execution_ready=False)
    assert status.status_icon == "!"


def test_toolstatus_status_icon_outdated():
    """Test status_icon returns ! for outdated tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(name="test", installed=True, is_outdated=True)
    assert status.status_icon == "!"


def test_toolstatus_status_icon_ok():
    """Test status_icon returns OK for healthy tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(
        name="test", installed=True, execution_ready=True, is_outdated=False
    )
    assert status.status_icon == "OK"


def test_toolstatus_status_text_missing():
    """Test status_text returns MISSING for missing tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(name="test", installed=False)
    assert status.status_text == "MISSING"


def test_toolstatus_status_text_not_ready():
    """Test status_text returns NOT READY for non-executable tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(name="test", installed=True, execution_ready=False)
    assert status.status_text == "NOT READY"


def test_toolstatus_status_text_outdated():
    """Test status_text returns OUTDATED for stale tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(name="test", installed=True, is_outdated=True)
    assert status.status_text == "OUTDATED"


def test_toolstatus_status_text_ok():
    """Test status_text returns OK for healthy tools."""
    from scripts.cli.tool_manager import ToolStatus

    status = ToolStatus(
        name="test", installed=True, execution_ready=True, is_outdated=False
    )
    assert status.status_text == "OK"


# ========== Category 3: ToolManager Initialization ==========


def test_toolmanager_init_defaults():
    """Test ToolManager initializes with defaults."""
    from scripts.cli.tool_manager import ToolManager

    with patch("scripts.cli.tool_manager.ToolRegistry"):
        manager = ToolManager()

    assert manager._registry is None  # Lazy loaded


def test_toolmanager_init_with_registry():
    """Test ToolManager accepts custom registry."""
    from scripts.cli.tool_manager import ToolManager

    mock_registry = MagicMock()

    manager = ToolManager(registry=mock_registry)

    assert manager._registry is mock_registry


def test_toolmanager_registry_lazy_load():
    """Test ToolManager lazy loads registry on access."""
    from scripts.cli.tool_manager import ToolManager

    with patch("scripts.cli.tool_manager.ToolRegistry") as mock_registry_class:
        manager = ToolManager()

        # Access registry property
        _ = manager.registry

        mock_registry_class.assert_called_once()


def test_toolmanager_platform_detected():
    """Test ToolManager detects platform on init."""
    from scripts.cli.tool_manager import ToolManager

    with patch("scripts.cli.tool_manager.detect_platform", return_value="linux"):
        manager = ToolManager()

    assert manager.platform == "linux"


# ========== Category 4: Tool Checking ==========


def test_toolmanager_check_tool_not_found():
    """Test check_tool for tool not in PATH."""
    from scripts.cli.tool_manager import ToolManager

    mock_tool = MagicMock()
    mock_tool.get_binary_name.return_value = "nonexistent"
    mock_tool.version = "1.0.0"
    mock_tool.critical = False

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    manager = ToolManager(registry=mock_registry)

    with patch.object(manager, "_find_binary", return_value=None):
        status = manager.check_tool("nonexistent-tool")

    assert status.installed is False


def test_toolmanager_check_tool_found():
    """Test check_tool for installed tool."""
    from scripts.cli.tool_manager import ToolManager

    mock_tool = MagicMock()
    mock_tool.get_binary_name.return_value = "trivy"
    mock_tool.version = "0.50.0"
    mock_tool.critical = True

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    manager = ToolManager(registry=mock_registry)

    # Note: _get_tool_version now returns (version, error) tuple (Phase 4)
    with patch.object(manager, "_find_binary", return_value="/usr/bin/trivy"):
        with patch.object(manager, "_get_tool_version", return_value=("0.50.0", None)):
            with patch.object(
                manager, "_verify_execution", return_value=(True, None, [])
            ):
                status = manager.check_tool("trivy")

    assert status.installed is True
    assert status.installed_version == "0.50.0"
    assert status.is_critical is True


def test_toolmanager_check_tool_outdated():
    """Test check_tool detects outdated tool."""
    from scripts.cli.tool_manager import ToolManager

    mock_tool = MagicMock()
    mock_tool.get_binary_name.return_value = "trivy"
    mock_tool.version = "0.50.0"
    mock_tool.critical = False

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    manager = ToolManager(registry=mock_registry)

    # Note: _get_tool_version now returns (version, error) tuple (Phase 4)
    with patch.object(manager, "_find_binary", return_value="/usr/bin/trivy"):
        with patch.object(manager, "_get_tool_version", return_value=("0.49.0", None)):
            with patch.object(manager, "_is_version_outdated", return_value=True):
                with patch.object(
                    manager, "_verify_execution", return_value=(True, None, [])
                ):
                    status = manager.check_tool("trivy")

    assert status.is_outdated is True


def test_toolmanager_check_matrix_defaults_to_the_tool_matrix():
    """check_matrix() checks exactly the TOOL_MATRIX, once each, by name."""
    from scripts.cli.tool_manager import ToolManager
    from scripts.core.tool_registry import TOOL_MATRIX

    mock_status = MagicMock()
    mock_status.installed = True

    manager = ToolManager()

    with patch.object(manager, "check_tool", return_value=mock_status) as check:
        statuses = manager.check_matrix()

    assert list(statuses) == list(TOOL_MATRIX)
    assert [c.args[0] for c in check.call_args_list] == list(TOOL_MATRIX)


def test_toolmanager_check_matrix_honours_an_explicit_tool_list():
    """An explicit list narrows the work: only those tools are probed."""
    from scripts.cli.tool_manager import ToolManager

    mock_status = MagicMock()
    mock_status.installed = True

    manager = ToolManager()

    with patch.object(manager, "check_tool", return_value=mock_status) as check:
        statuses = manager.check_matrix(["trivy", "semgrep"])

    assert list(statuses) == ["trivy", "semgrep"]
    assert [c.args[0] for c in check.call_args_list] == ["trivy", "semgrep"]


# ========== Category 5: Version Parsing ==========


def test_parse_version_default_pattern():
    """Test _parse_version with default pattern."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    version = manager._parse_version("unknown-tool", "Version: 1.2.3")

    assert version == "1.2.3"


def test_parse_version_trivy():
    """Test _parse_version for trivy output."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    output = "Version: 0.50.0\nVulnDB: 2024-01-01"
    version = manager._parse_version("trivy", output)

    assert version == "0.50.0"


def test_parse_version_checkov():
    """Test _parse_version for checkov output."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    output = "3.2.1"
    version = manager._parse_version("checkov", output)

    assert version == "3.2.1"


def test_parse_version_empty_output():
    """Test _parse_version with empty output."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    version = manager._parse_version("trivy", "")

    assert version is None


def test_parse_version_no_match():
    """Test _parse_version when no version found."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    version = manager._parse_version("trivy", "Some random text without version")

    assert version is None


# ========== Category 6: Version Comparison ==========


def test_is_version_outdated_same_version():
    """Test _is_version_outdated with same versions."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    result = manager._is_version_outdated("1.0.0", "1.0.0")

    assert result is False


def test_is_version_outdated_older():
    """Test _is_version_outdated when installed is older."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    result = manager._is_version_outdated("1.0.0", "2.0.0")

    assert result is True


def test_is_version_outdated_newer():
    """Test _is_version_outdated when installed is newer."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    result = manager._is_version_outdated("2.0.0", "1.0.0")

    assert result is False


def test_is_version_outdated_patch_difference():
    """Test _is_version_outdated with patch version difference."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    result = manager._is_version_outdated("1.0.0", "1.0.1")

    assert result is True


def test_parse_version_parts():
    """Test _parse_version_parts extracts numeric parts."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    parts = manager._parse_version_parts("v1.2.3-beta")

    assert parts == [1, 2, 3]


def test_parse_version_parts_with_letters():
    """Test _parse_version_parts handles versions like 4.34c."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    parts = manager._parse_version_parts("4.34c")

    assert parts == [4, 34]


# ========== Category 7: Version Direction ==========


def test_compare_version_direction_ahead():
    """Test _compare_version_direction when installed is ahead."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    direction = manager._compare_version_direction("2.0.0", "1.0.0")

    assert direction == "ahead"


def test_compare_version_direction_behind():
    """Test _compare_version_direction when installed is behind."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    direction = manager._compare_version_direction("1.0.0", "2.0.0")

    assert direction == "behind"


def test_compare_version_direction_unknown():
    """Test _compare_version_direction with unparseable versions."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    direction = manager._compare_version_direction(None, "1.0.0")

    assert direction == "unknown"


# ========== Category 8: Binary Finding ==========


def test_find_binary_in_path():
    """Test _find_binary finds tool in PATH."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    with patch("shutil.which", return_value="/usr/bin/trivy"):
        result = manager._find_binary("trivy")

    assert result == "/usr/bin/trivy"


def test_find_binary_not_found():
    """Test _find_binary returns None for missing tool."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    with patch("shutil.which", return_value=None):
        result = manager._find_binary("nonexistent-tool")

    assert result is None


def test_find_binary_zap_special_path(tmp_path):
    """Test _find_binary finds ZAP in special location."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    # Create mock ZAP path
    zap_dir = tmp_path / ".jmo" / "bin" / "zap"
    zap_dir.mkdir(parents=True)
    zap_script = zap_dir / "zap.sh"
    zap_script.touch()

    with patch("shutil.which", return_value=None):
        with patch.object(Path, "home", return_value=tmp_path):
            result = manager._find_binary("zap.sh")

    assert result == str(zap_script)


# ========== Category 9: Matrix Functions ==========


def test_get_missing_tools():
    """Test get_missing_tools returns only missing tools, from the given list."""
    from scripts.cli.tool_manager import ToolManager

    missing_status = MagicMock()
    missing_status.installed = False

    installed_status = MagicMock()
    installed_status.installed = True

    manager = ToolManager()

    with patch.object(
        manager,
        "check_matrix",
        return_value={"trivy": installed_status, "semgrep": missing_status},
    ) as check_matrix:
        missing = manager.get_missing_tools(["trivy", "semgrep"])

    check_matrix.assert_called_once_with(["trivy", "semgrep"])
    assert missing == [missing_status]


def test_get_outdated_tools():
    """Test get_outdated_tools returns only outdated tools among `restrict_to`."""
    from scripts.cli.tool_manager import ToolManager

    outdated_status = MagicMock()
    outdated_status.installed = True
    outdated_status.is_outdated = True

    current_status = MagicMock()
    current_status.installed = True
    current_status.is_outdated = False

    manager = ToolManager()
    by_name = {"trivy": outdated_status, "semgrep": current_status}

    with (
        patch.object(manager, "check_tool", side_effect=by_name.__getitem__) as check,
        patch.object(manager, "check_all_tools") as check_all,
    ):
        outdated = manager.get_outdated_tools(restrict_to=["trivy", "semgrep"])

    assert outdated == [outdated_status]
    # restrict_to narrows the probes, not just the result.
    assert [c.args[0] for c in check.call_args_list] == ["trivy", "semgrep"]
    check_all.assert_not_called()


def test_get_critical_outdated():
    """Test get_critical_outdated filters for critical tools."""
    from scripts.cli.tool_manager import ToolManager

    critical_outdated = MagicMock()
    critical_outdated.installed = True
    critical_outdated.is_outdated = True
    critical_outdated.is_critical = True

    regular_outdated = MagicMock()
    regular_outdated.installed = True
    regular_outdated.is_outdated = True
    regular_outdated.is_critical = False

    manager = ToolManager()

    with patch.object(
        manager,
        "get_outdated_tools",
        return_value=[critical_outdated, regular_outdated],
    ):
        critical = manager.get_critical_outdated()

    assert len(critical) == 1
    assert critical[0].is_critical is True


def test_get_matrix_summary():
    """Test get_matrix_summary returns correct counts for the given tools."""
    from scripts.cli.tool_manager import ToolManager

    installed_status = MagicMock()
    installed_status.installed = True
    installed_status.execution_ready = True
    installed_status.is_outdated = False
    installed_status.is_critical = False

    missing_status = MagicMock()
    missing_status.installed = False
    missing_status.execution_ready = False
    missing_status.is_outdated = False
    missing_status.is_critical = False

    manager = ToolManager()

    with patch.object(
        manager,
        "check_matrix",
        return_value={"trivy": installed_status, "semgrep": missing_status},
    ) as check_matrix:
        summary = manager.get_matrix_summary(["trivy", "semgrep"])

    check_matrix.assert_called_once_with(["trivy", "semgrep"])
    assert summary["total"] == 2
    assert summary["installed"] == 1
    assert summary["missing"] == 1
    assert summary["ready"] is False


# ========== Category 10: Version Drift ==========


def test_get_version_drift_no_drift():
    """Test get_version_drift when all versions match."""
    from scripts.cli.tool_manager import ToolManager

    status = MagicMock()
    status.installed = True
    status.installed_version = "1.0.0"
    status.expected_version = "1.0.0"

    manager = ToolManager()

    with patch.object(
        manager, "check_matrix", return_value={"trivy": status}
    ) as check_matrix:
        drift = manager.get_version_drift(["trivy"])

    check_matrix.assert_called_once_with(["trivy"])
    assert len(drift) == 0


def test_get_version_drift_with_drift():
    """Test get_version_drift detects version mismatch."""
    from scripts.cli.tool_manager import ToolManager

    status = MagicMock()
    status.installed = True
    status.installed_version = "0.49.0"
    status.expected_version = "0.50.0"
    status.is_critical = True

    manager = ToolManager()

    with patch.object(manager, "check_matrix", return_value={"trivy": status}):
        with patch.object(manager, "_compare_version_direction", return_value="behind"):
            drift = manager.get_version_drift(["trivy"])

    assert len(drift) == 1
    assert drift[0]["tool"] == "trivy"
    assert drift[0]["direction"] == "behind"


# ========== Category 11: Execution Verification ==========


def test_verify_execution_success():
    """Test _verify_execution when tool can execute."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    with patch("shutil.which", return_value="/usr/bin/trivy"):
        ready, warning, missing = manager._verify_execution("trivy")

    assert ready is True
    assert warning is None
    assert missing == []


def test_verify_execution_missing_deps():
    """Test _verify_execution detects missing dependencies."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    with patch("shutil.which", return_value=None):
        with patch.object(manager, "_find_binary", return_value=None):
            ready, warning, missing = manager._verify_execution("zap")

    assert ready is False
    assert "Missing" in warning
    assert "java" in missing  # zap requires a Java runtime


# ========== Category 12: Helper Functions ==========


def test_get_remediation_for_tool_known():
    """Test get_remediation_for_tool for known tool."""
    from scripts.cli.tool_manager import get_remediation_for_tool

    result = get_remediation_for_tool("trivy", "linux")

    assert "commands" in result
    assert any("trivy" in cmd for cmd in result["commands"])


def test_get_remediation_for_tool_unknown():
    """Test get_remediation_for_tool for unknown tool."""
    from scripts.cli.tool_manager import get_remediation_for_tool

    result = get_remediation_for_tool("unknown-tool", "linux")

    assert "commands" in result
    assert "jmo tools install unknown-tool" in result["commands"]


def test_get_clean_env():
    """Test _get_clean_env adds custom paths.

    Asserted as a real PATH *entry*, not as the substring ".jmo/bin". That
    substring hardcodes the POSIX separator, so it only ever passed on Windows
    because the code built its paths with f-string forward slashes - producing
    mixed-separator entries, which was part of the defect. A substring check
    also cannot tell "is a PATH entry" from "is buried inside a corrupted one",
    which is exactly what was happening. See TestCleanEnvPathSeparator.
    """
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    env = manager._get_clean_env()

    assert "PATH" in env
    entries = env["PATH"].split(os.pathsep)
    assert str(Path.home() / ".jmo" / "bin") in entries


# ========== Category 13: Print Functions ==========


def test_print_tool_status_table():
    """Test print_tool_status_table outputs formatted table."""
    from scripts.cli.tool_manager import ToolStatus, print_tool_status_table

    statuses = {
        "trivy": ToolStatus(
            name="trivy",
            installed=True,
            installed_version="0.50.0",
            expected_version="0.50.0",
        ),
        "semgrep": ToolStatus(
            name="semgrep",
            installed=False,
            install_hint="pip install semgrep",
        ),
    }

    with patch("builtins.print") as mock_print:
        print_tool_status_table(statuses)

    # Should print header and rows
    assert mock_print.call_count >= 3


def test_get_missing_tools_for_scan():
    """Unavailable tools are returned in the missing list, by name.

    The old body passed the string "fast" -- iterated character by character
    into `for tool in tools` -- and captured the (available, missing) tuple as
    `missing`, so the check was ``len((available, missing)) > 0``, always 2 and
    unfalsifiable (#979). Pass a real list and unpack the tuple.
    """
    from scripts.cli.tool_manager import get_missing_tools_for_scan

    with patch("shutil.which", return_value=None):
        available, missing = get_missing_tools_for_scan(["zzz-not-a-tool", "qqq-nope"])

    assert available == []
    assert {status.name for status in missing} == {"zzz-not-a-tool", "qqq-nope"}


class TestGetRemediationForTool:
    """Tests for get_remediation_for_tool function."""

    def test_get_remediation_with_deps(self):
        """Test remediation commands include dependencies (zap needs Java)."""
        from scripts.cli.tool_manager import (
            REMEDIATION_COMMANDS,
            get_remediation_for_tool,
        )

        result = get_remediation_for_tool("zap", "linux")
        # Should return commands dict
        assert "commands" in result
        assert "manual" in result
        assert "jmo_install" in result
        # The dependency command comes before the tool's own install command.
        java_linux = REMEDIATION_COMMANDS["zap"]["deps"]["java"]["linux"]
        assert result["commands"][0] == java_linux

    def test_get_remediation_windows(self):
        """Test remediation commands for Windows platform."""
        from scripts.cli.tool_manager import get_remediation_for_tool

        result = get_remediation_for_tool("trivy", "windows")
        assert "commands" in result

    def test_get_remediation_darwin(self):
        """Test remediation commands for macOS platform."""
        from scripts.cli.tool_manager import get_remediation_for_tool

        result = get_remediation_for_tool("semgrep", "darwin")
        assert "commands" in result

    def test_get_remediation_unknown_tool(self):
        """Test remediation for unknown tool returns fallback."""
        from scripts.cli.tool_manager import get_remediation_for_tool

        result = get_remediation_for_tool("unknown-tool-xyz", "linux")
        assert "manual" in result


class TestFindBinary:
    """Tests for _find_binary method."""

    def test_find_yara_python_module(self, monkeypatch):
        """Test finding yara as a Python module."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        # Mock importlib to find yara module
        mock_spec = MagicMock()
        mock_spec.origin = "/path/to/yara.py"

        with patch("importlib.util.find_spec", return_value=mock_spec):
            result = manager._find_binary("yara")

        assert result == "/path/to/yara.py"

    def test_find_yara_not_installed(self, monkeypatch):
        """Test yara not found when module not installed."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        with patch("importlib.util.find_spec", return_value=None):
            result = manager._find_binary("yara")

        assert result is None

    def test_find_tool_in_path(self, monkeypatch):
        """Test finding tool in system PATH."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        with patch("shutil.which", return_value="/usr/bin/trivy"):
            result = manager._find_binary("trivy")

        assert result == "/usr/bin/trivy"

    def test_find_zap_special_locations(self, tmp_path, monkeypatch):
        """Test ZAP found in special locations."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        # Create fake ZAP location
        zap_dir = tmp_path / "zap"
        zap_dir.mkdir()
        zap_sh = zap_dir / "zap.sh"
        zap_sh.touch()

        # Mock Path.home() to return tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("shutil.which", return_value=None):
            result = manager._find_binary("zap.sh")

        assert result == str(zap_sh)


class TestGetToolVersion:
    """Tests for _get_tool_version method.

    Note: _get_tool_version now returns a tuple (version, error_reason) for
    Phase 4 startup crash detection. Tests updated accordingly.
    """

    def test_get_version_success(self):
        """Test successful version detection."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_result = MagicMock()
        mock_result.stdout = "trivy version 0.50.0"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            version, error = manager._get_tool_version("trivy", "/usr/bin/trivy")

        assert version == "0.50.0"
        assert error is None

    def test_get_version_from_stderr(self):
        """Test version detection from stderr."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = "semgrep 1.50.0"
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            version, error = manager._get_tool_version("semgrep", "/usr/bin/semgrep")

        assert version == "1.50.0"
        assert error is None

    def test_get_version_timeout(self):
        """Test version detection handles timeout."""
        import subprocess

        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        with patch("subprocess.run", side_effect=subprocess.TimeoutExpired("cmd", 10)):
            version, error = manager._get_tool_version(
                "slow-tool", "/usr/bin/slow-tool"
            )

        assert version is None
        assert error is None  # Timeout is not a crash error

    def test_get_version_file_not_found(self):
        """Test version detection handles FileNotFoundError."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        with patch("subprocess.run", side_effect=FileNotFoundError("Binary not found")):
            version, error = manager._get_tool_version(
                "missing-tool", "/nonexistent/path"
            )

        assert version is None
        assert error is None  # File not found is not a crash error

    def test_get_version_permission_denied(self):
        """Test version detection handles PermissionError."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        with patch("subprocess.run", side_effect=PermissionError("Access denied")):
            version, error = manager._get_tool_version(
                "protected-tool", "/usr/bin/protected"
            )

        assert version is None
        assert error is None  # Permission denied is not a crash error

    def test_get_version_os_error(self):
        """Test version detection handles generic OSError."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        with patch("subprocess.run", side_effect=OSError("Generic error")):
            version, error = manager._get_tool_version("error-tool", "/usr/bin/error")

        assert version is None
        assert error is None  # Generic OS error is not a crash error

    def test_get_version_no_output(self):
        """Test version detection handles empty output."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_result = MagicMock()
        mock_result.stdout = ""
        mock_result.stderr = ""
        mock_result.returncode = 1

        with patch("subprocess.run", return_value=mock_result):
            version, error = manager._get_tool_version("silent-tool", "/usr/bin/silent")

        assert version is None
        assert error is None  # Empty output is not a crash error

    def test_get_version_parse_failure(self):
        """Test version detection handles unparseable output."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_result = MagicMock()
        mock_result.stdout = "Some random output without version"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            version, error = manager._get_tool_version("weird-tool", "/usr/bin/weird")

        # Should return None if version can't be parsed
        assert version is None
        assert error is None  # Parse failure is not a crash error

    def test_get_version_custom_command(self):
        """Test version detection with tool-specific command."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_result = MagicMock()
        mock_result.stdout = "Trivy Version: 0.50.0"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            # Trivy uses custom version command from VERSION_COMMANDS
            version, error = manager._get_tool_version("trivy", "/usr/bin/trivy")

        assert version is not None
        assert error is None


# ========== Category 14: ToolStatusSummary Tests ==========


class TestToolStatusSummary:
    """Tests for ToolStatusSummary dataclass."""

    def test_toolstatussummary_defaults(self):
        """Test ToolStatusSummary keeps every count and list it is given."""
        from scripts.cli.tool_manager import ToolStatusSummary

        summary = ToolStatusSummary(
            total=12,
            installed=10,
            execution_ready=8,
            missing_dependency=["zap"],
            not_installed=["yara", "nuclei"],
            version_issues=["checkov"],
        )

        assert summary.total == 12
        assert summary.installed == 10
        assert summary.execution_ready == 8
        assert summary.missing_dependency == ["zap"]
        assert summary.not_installed == ["yara", "nuclei"]
        assert summary.version_issues == ["checkov"]

    def test_toolstatussummary_needs_attention_count(self):
        """Test needs_attention_count property."""
        from scripts.cli.tool_manager import ToolStatusSummary

        summary = ToolStatusSummary(
            total=12,
            installed=11,
            execution_ready=9,
            missing_dependency=["zap"],
            not_installed=["yara"],
            version_issues=["checkov"],
        )

        # needs_attention = missing_deps(1) + not_installed(1) + version_issues(1) = 3
        assert summary.needs_attention_count == 3

    def test_toolstatussummary_format_status_line_all_ready(self):
        """Test format_status_line when all tools are ready."""
        from scripts.cli.tool_manager import ToolStatusSummary
        from scripts.core.tool_registry import TOOL_MATRIX

        n = len(TOOL_MATRIX)
        summary = ToolStatusSummary(
            total=n,
            installed=n,
            execution_ready=n,
            missing_dependency=[],
            not_installed=[],
            version_issues=[],
        )

        assert summary.format_status_line() == f"All {n} tools ready"

    def test_toolstatussummary_format_status_line_partial(self):
        """Test format_status_line when some tools need attention."""
        from scripts.cli.tool_manager import ToolStatusSummary
        from scripts.core.tool_registry import TOOL_MATRIX

        n = len(TOOL_MATRIX)
        summary = ToolStatusSummary(
            total=n,
            installed=n - 1,
            execution_ready=n - 2,
            missing_dependency=["zap"],
            not_installed=["yara"],
            version_issues=[],
        )

        assert summary.format_status_line() == (
            f"{n - 2}/{n} tools ready (2 need attention)"
        )


class TestGetToolSummary:
    """Tests for get_tool_summary method."""

    @staticmethod
    def _status(installed, execution_ready, version_error=None, missing_deps=()):
        status = MagicMock()
        status.installed = installed
        status.execution_ready = execution_ready
        status.version_error = version_error
        status.missing_deps = list(missing_deps)
        return status

    def test_get_tool_summary_basic(self):
        """Test get_tool_summary counts exactly the tools it is given."""
        from scripts.cli.tool_manager import ToolManager, ToolStatusSummary

        manager = ToolManager()
        installed = self._status(installed=True, execution_ready=True)
        missing = self._status(installed=False, execution_ready=False)
        tools = ["trivy", "semgrep", "checkov", "zap"]

        def mock_check_tool(name):
            return missing if name == "zap" else installed

        with patch.object(manager, "check_tool", side_effect=mock_check_tool) as check:
            summary = manager.get_tool_summary(tools)

        assert isinstance(summary, ToolStatusSummary)
        assert summary.total == 4
        assert summary.installed == 3  # Tools with installed=True
        assert summary.execution_ready == 3  # Tools that are ready
        assert summary.not_installed == ["zap"]
        assert [c.args[0] for c in check.call_args_list] == tools

    def test_get_tool_summary_defaults_to_the_tool_matrix(self):
        """With no list, the summary covers the whole TOOL_MATRIX, once each."""
        from scripts.cli.tool_manager import ToolManager
        from scripts.core.tool_registry import TOOL_MATRIX

        manager = ToolManager()
        ready = self._status(installed=True, execution_ready=True)

        with patch.object(manager, "check_tool", return_value=ready) as check:
            summary = manager.get_tool_summary()

        assert summary.total == len(TOOL_MATRIX)
        assert summary.execution_ready == len(TOOL_MATRIX)
        assert [c.args[0] for c in check.call_args_list] == list(TOOL_MATRIX)

    def test_get_tool_summary_with_version_issues(self):
        """Test get_tool_summary detects version/crash issues."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        ok = self._status(installed=True, execution_ready=True)
        crash = self._status(
            installed=True,
            execution_ready=False,
            version_error="ImportError - pydantic conflict",
        )

        def mock_check_tool(name):
            return crash if name == "checkov" else ok

        with patch.object(manager, "check_tool", side_effect=mock_check_tool):
            summary = manager.get_tool_summary(["trivy", "checkov"])

        assert summary.version_issues == ["checkov"]
        assert summary.execution_ready == 1


class TestCleanEnvPathSeparator:
    r"""`_get_clean_env` must join PATH with the platform's separator.

    It prepended its extra directories with a hardcoded ``":"``::

        env["PATH"] = ":".join(extra_paths) + ":" + current_path

    On POSIX that is correct and the bug is invisible. On Windows the separator
    is ``";"``, so every prepended directory **and the first genuine PATH entry**
    fuse into one nonsensical element:

        'C:\Users\J/.jmo/bin:C:\Users\J/.local/bin:C:\Users\J/.kubescape/bin:C:\real\first\entry'

    Two things are lost. ``~/.jmo/bin`` - the directory JMo installs every tool
    into - is not on the probe's PATH at all, and whatever was first on the real
    PATH is destroyed with it.

    Measured: this is why `dependency-check`'s version probe reported
    ``'java' is not recognized`` on a machine where java was on PATH and
    `shutil.which("java")` found it from the same process. The probe was
    searching a corrupted PATH.

    `tool_manager.py`'s isolated-venv branch already uses ``os.pathsep``
    correctly, so one call site was right and the other was not.
    """

    def test_extra_paths_are_joined_with_os_pathsep(self):
        from scripts.cli.tool_manager import ToolManager

        env = ToolManager()._get_clean_env()
        entries = env["PATH"].split(os.pathsep)

        jmo_bin = str(Path.home() / ".jmo" / "bin")
        normalised = {e.replace("/", os.sep).rstrip(os.sep) for e in entries}

        assert jmo_bin.replace("/", os.sep).rstrip(os.sep) in normalised, (
            "~/.jmo/bin is not a PATH entry - JMo installs its tools there, so "
            f"the probe cannot find any of them. PATH[0] was: {entries[0]!r}"
        )

    def test_the_first_real_path_entry_survives(self, monkeypatch):
        """Prepending must not consume the entry that was already first."""
        from scripts.cli.tool_manager import ToolManager

        sentinel = str(
            Path("C:/sentinel-dir") if os.name == "nt" else Path("/sentinel-dir")
        )
        monkeypatch.setenv("PATH", sentinel + os.pathsep + "other")

        entries = ToolManager()._get_clean_env()["PATH"].split(os.pathsep)

        assert sentinel in entries, (
            f"the pre-existing first PATH entry was swallowed. entries[0]={entries[0]!r}"
        )


# Every tool `jmo tools install` installs, minus the isolated venvs (whose
# case predates #1164 and has its own test below).
_NON_ISOLATED_INSTALLED_TOOLS = [
    t for t in (*TOOL_MATRIX, POLICY_ENGINE) if t not in ISOLATED_TOOLS
]


class TestInstalledToolWithoutAVersionIsNotOK:
    """A version the probe could not read is not evidence the tool works.

    `_get_tool_version` returns `(None, None)` on timeout, on FileNotFoundError,
    on PermissionError and on an unparseable output -- and `_derive_status_type`
    downgrades only on `version_error`, so all four rendered as OK.

    Measured in the 2026-09-02 dogfood, on a machine where checkov could not
    run at all:

        checkov           OK          -             3.3.16

    The dash was the only signal, and the OK beside it overrode it.

    The guard first fired only for ISOLATED_TOOLS. #1164 widened it to every
    installed tool: every tool JMo still installs reports a version, and a
    binary tool that did not (cdxgen under load, in #1164's reproduction)
    printed OK at exit 0 just the same.

    `_verify_execution` is stubbed to "ready" in every case here, so the
    no-version guard is the only thing that can mark a tool not ready.
    """

    @staticmethod
    def _check(monkeypatch, tool, version, error=None):
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        monkeypatch.setattr(
            manager, "_find_binary", lambda name: "/fake/path/" + str(name)
        )
        monkeypatch.setattr(
            manager, "_get_tool_version", lambda *a, **k: (version, error)
        )
        monkeypatch.setattr(manager, "_verify_execution", lambda name: (True, None, []))
        return manager.check_tool(tool)

    def test_isolated_tool_with_no_version_is_not_ok(self, monkeypatch):
        from scripts.cli.tool_manager import ToolStatusType

        status = self._check(monkeypatch, "checkov", None)

        assert status.status_type is not ToolStatusType.OK, (
            "an isolated tool that could not report a version was rendered OK "
            "-- the exact display that hid checkov contributing zero findings "
            "to every Windows scan"
        )
        assert status.execution_ready is False
        assert status.status_text == "NOT READY"
        assert status.execution_warning and "checkov" in status.execution_warning

    def test_isolated_tool_with_a_version_is_still_ok(self, monkeypatch):
        """The guard must not condemn a healthy isolated install."""
        from scripts.cli.tool_manager import ToolStatusType

        status = self._check(monkeypatch, "checkov", "3.3.16")

        assert status.status_type is ToolStatusType.OK
        assert status.execution_ready is True

    @pytest.mark.parametrize("tool", _NON_ISOLATED_INSTALLED_TOOLS)
    def test_a_non_isolated_tool_with_no_version_is_not_ready(self, monkeypatch, tool):
        """#1164: an installed binary that reports no version is not healthy.

        Before #1164 this case was pinned the other way round (a non-isolated
        tool with no version stayed OK). Narrowing the guard back to
        `tool_name in ISOLATED_TOOLS` sends these tools to the stubbed
        `_verify_execution`, which reports them ready with no warning, so
        every assertion below fails.
        """
        from scripts.cli.tool_manager import ToolStatusType

        status = self._check(monkeypatch, tool, None)

        assert status.installed is True
        assert status.execution_ready is False
        assert status.status_type is ToolStatusType.FAILED
        assert status.execution_warning == (
            f"{tool} is installed but did not report a version; it may not "
            f"run. Try: jmo tools install {tool} --force"
        )

    def test_hadolint_is_among_the_newly_guarded_tools(self):
        """The #1164 reproduction's shape: a binary tool never isolated."""
        assert "hadolint" in _NON_ISOLATED_INSTALLED_TOOLS


def test_checkov_version_probe_budget_exceeds_its_measured_startup():
    """checkov's --version straddles the 10s default, so it gets its own.

    Measured on Windows 11 / checkov 3.3.16: 9.1s cold, 11s during a loaded
    scan session, 2.8-6.0s warm. Under the default budget the probe times out
    intermittently and returns `(None, None)`, which -- with the guard above
    now enforcing it -- would flap a healthy install between OK and NOT READY.
    """
    from scripts.cli.tool_manager import VERSION_TIMEOUTS

    assert VERSION_TIMEOUTS.get("checkov", 10) >= 20, (
        "checkov's version probe budget is back at or near its measured "
        "startup cost; the probe will time out at random"
    )


class TestExpectedVersionDisplay:
    """`expected_version_display` shows the pin as it is, or a dash.

    v1 rendered `0.0.0` as "unpinned" for manual-install tools (falco). Those
    tools, and the sentinel, left in v2.0.0: every tool JMo installs now ships
    in the image with a real pin, so there is no convention left to honour.
    """

    @staticmethod
    def _status(name, expected):
        from scripts.cli.tool_manager import ToolStatus

        return ToolStatus(name=name, installed=False, expected_version=expected)

    def test_a_0_0_0_pin_is_shown_verbatim(self):
        """A `0.0.0` pin is a genuinely missing pin, so it must stay visible
        instead of hiding behind a word that reads as deliberate."""
        status = self._status("trivy", "0.0.0")

        assert status.expected_version_display == "0.0.0"

    def test_real_versions_are_untouched(self):
        assert self._status("trivy", "0.74.0").expected_version_display == "0.74.0"
        assert self._status("zap", "2.16.1").expected_version_display == "2.16.1"

    def test_a_missing_expected_version_still_renders_a_dash(self):
        assert self._status("trivy", None).expected_version_display == "-"


class TestNotReadyIsVisibleInTheTable:
    """#1136: `check_tool` has always computed execution readiness and this
    table threw it away.

    `_verify_execution` checks Java for zap and rules for yara. With `java`
    hidden from PATH, a v1 `jmo tools check` printed
    `dependency-check  OK  -  12.1.0` (a Java tool since removed) and exited 0,
    while every scan using it exited 1 and wrote no output. The dash in the
    Installed column was the only evidence on screen, and OK overrode it.
    """

    @staticmethod
    def _status(name, **kw):
        from scripts.cli.tool_manager import ToolStatus

        return ToolStatus(name=name, **kw)

    @staticmethod
    def _render(status, show_hints=True):
        import io
        from contextlib import redirect_stdout

        from scripts.cli.tool_manager import print_tool_status_table

        buf = io.StringIO()
        with redirect_stdout(buf):
            print_tool_status_table({status.name: status}, show_hints=show_hints)
        return buf.getvalue()

    def test_an_installed_tool_that_cannot_run_is_not_ok(self):
        status = self._status(
            "zap",
            installed=True,
            installed_version=None,
            expected_version="2.16.1",
            execution_ready=False,
            execution_warning="Missing: java",
        )

        out = self._render(status)

        assert "NOT READY" in out
        assert "OK" not in out.replace("NOT READY", "")

    def test_the_row_says_why(self):
        """A row that says a tool is not ready and nothing about why sends the
        reader to the installer, which will report it already installed."""
        status = self._status(
            "zap",
            installed=True,
            execution_ready=False,
            execution_warning="Missing: java",
        )

        out = self._render(status)

        assert "Missing: java" in out

    def test_not_ready_outranks_outdated(self):
        """A tool that cannot run at all is a worse problem than an old one."""
        status = self._status(
            "yara",
            installed=True,
            installed_version="4.5.0",
            expected_version="4.5.4",
            is_outdated=True,
            execution_ready=False,
            execution_warning=(
                "No YARA rules installed - yara would report every scan clean. "
                "Run: jmo tools install yara --force"
            ),
        )

        out = self._render(status)

        assert "NOT READY" in out
        assert "OUTDATED" not in out

    def test_a_ready_tool_is_still_ok(self):
        """The regression guard: with its dependency present, nothing changes."""
        status = self._status(
            "zap",
            installed=True,
            installed_version="2.16.1",
            expected_version="2.16.1",
            execution_ready=True,
        )

        out = self._render(status)

        assert "OK" in out
        assert "NOT READY" not in out

    def test_a_missing_tool_is_still_missing_not_not_ready(self):
        """`execution_ready` is False for an uninstalled tool too, so ordering
        the branches wrongly would relabel every MISSING row."""
        status = self._status(
            "grype",
            installed=False,
            execution_ready=False,
            execution_warning="Tool binary not found",
        )

        out = self._render(status)

        assert "MISSING" in out
        assert "NOT READY" not in out
