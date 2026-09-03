#!/usr/bin/env python3
"""Tests for scripts/cli/tool_manager.py module.

This test suite validates the ToolManager class:
1. ToolStatus dataclass behavior
2. ToolManager initialization and tool checking
3. Version parsing and comparison
4. Binary finding
5. Profile and summary functionality
6. Version drift detection
7. Helper functions

Target Coverage: >= 85%
"""

import os
import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

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
            assert (
                "default" in cmd_config or "linux" in cmd_config
            ), f"Platform-specific {tool} must have 'default' or 'linux' key"
            for platform_key, cmd_list in cmd_config.items():
                assert isinstance(
                    cmd_list, list
                ), f"{tool}[{platform_key}] must be a list"
                assert (
                    len(cmd_list) >= 2
                ), f"{tool}[{platform_key}] must have at least 2 elements"
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
        install_hint="brew install trivy",
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


def test_toolmanager_check_profile():
    """Test check_profile checks all tools in profile."""
    from scripts.cli.tool_manager import PROFILE_TOOLS, ToolManager

    mock_status = MagicMock()
    mock_status.installed = True

    manager = ToolManager()

    with patch.object(manager, "check_tool", return_value=mock_status):
        statuses = manager.check_profile("fast")

    # Should check each tool in fast profile
    expected_count = len(PROFILE_TOOLS["fast"])
    assert len(statuses) == expected_count


def test_toolmanager_check_profile_invalid():
    """Test check_profile with invalid profile."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    statuses = manager.check_profile("nonexistent")

    assert statuses == {}


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


def test_find_binary_dependency_check_special_path(tmp_path):
    """Test _find_binary finds dependency-check in special location."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    # Create mock dependency-check path
    dc_dir = tmp_path / ".jmo" / "bin" / "dependency-check" / "bin"
    dc_dir.mkdir(parents=True)
    dc_script = dc_dir / "dependency-check.sh"
    dc_script.touch()

    with patch("shutil.which", return_value=None):
        with patch.object(Path, "home", return_value=tmp_path):
            result = manager._find_binary("dependency-check.sh")

    assert result == str(dc_script)


# ========== Category 9: Profile Functions ==========


def test_get_missing_tools():
    """Test get_missing_tools returns only missing tools."""
    from scripts.cli.tool_manager import ToolManager

    missing_status = MagicMock()
    missing_status.installed = False

    installed_status = MagicMock()
    installed_status.installed = True

    manager = ToolManager()

    with patch.object(
        manager,
        "check_profile",
        return_value={"trivy": installed_status, "semgrep": missing_status},
    ):
        missing = manager.get_missing_tools("fast")

    assert len(missing) == 1
    assert missing[0].installed is False


def test_get_outdated_tools():
    """Test get_outdated_tools returns only outdated tools."""
    from scripts.cli.tool_manager import ToolManager

    outdated_status = MagicMock()
    outdated_status.installed = True
    outdated_status.is_outdated = True

    current_status = MagicMock()
    current_status.installed = True
    current_status.is_outdated = False

    manager = ToolManager()

    with patch.object(
        manager,
        "check_profile",
        return_value={"trivy": outdated_status, "semgrep": current_status},
    ):
        outdated = manager.get_outdated_tools("fast")

    assert len(outdated) == 1
    assert outdated[0].is_outdated is True


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


def test_get_profile_summary():
    """Test get_profile_summary returns correct counts."""
    from scripts.cli.tool_manager import ToolManager

    installed_status = MagicMock()
    installed_status.installed = True
    installed_status.execution_ready = True
    installed_status.is_outdated = False
    installed_status.is_critical = False
    installed_status.manual_install = False

    missing_status = MagicMock()
    missing_status.installed = False
    missing_status.execution_ready = False
    missing_status.is_outdated = False
    missing_status.is_critical = False
    missing_status.manual_install = False

    manager = ToolManager()

    with patch.object(
        manager,
        "check_profile",
        return_value={"trivy": installed_status, "semgrep": missing_status},
    ):
        summary = manager.get_profile_summary("fast")

    assert summary["total"] == 2
    assert summary["installed"] == 1
    assert summary["missing"] == 1


def test_get_profile_summary_distinguishes_manual_install():
    """v1.0.5: get_profile_summary splits missing into real_missing + manual_install_missing."""
    from scripts.cli.tool_manager import ToolManager

    real_miss = MagicMock()
    real_miss.installed = False
    real_miss.execution_ready = False
    real_miss.is_outdated = False
    real_miss.is_critical = False
    real_miss.manual_install = False

    manual_miss = MagicMock()
    manual_miss.installed = False
    manual_miss.execution_ready = False
    manual_miss.is_outdated = False
    manual_miss.is_critical = False
    manual_miss.manual_install = True

    manager = ToolManager()
    with patch.object(
        manager,
        "check_profile",
        return_value={"prowler": real_miss, "akto": manual_miss},
    ):
        summary = manager.get_profile_summary("deep")

    assert summary["missing"] == 2  # union, back-compat
    assert summary["real_missing"] == 1
    assert summary["manual_install_missing"] == 1


# ========== Category 10: Version Drift ==========


def test_get_version_drift_no_drift():
    """Test get_version_drift when all versions match."""
    from scripts.cli.tool_manager import ToolManager

    status = MagicMock()
    status.installed = True
    status.installed_version = "1.0.0"
    status.expected_version = "1.0.0"

    manager = ToolManager()

    with patch.object(manager, "check_profile", return_value={"trivy": status}):
        drift = manager.get_version_drift("fast")

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

    with patch.object(manager, "check_profile", return_value={"trivy": status}):
        with patch.object(manager, "_compare_version_direction", return_value="behind"):
            drift = manager.get_version_drift("fast")

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


def test_verify_execution_cdxgen_node_version():
    """Test _verify_execution checks Node.js version for cdxgen."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    with patch("shutil.which", return_value="/usr/bin/node"):
        with patch.object(manager, "_find_binary", return_value="/usr/bin/cdxgen"):
            with patch.object(manager, "_get_node_version", return_value=(18, 0, 0)):
                ready, warning, missing = manager._verify_execution("cdxgen")

    assert ready is False
    assert "Node.js" in warning


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


def test_get_node_version():
    """Test _get_node_version parses Node.js version."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "v20.10.0\n"

    with patch("subprocess.run", return_value=mock_result):
        version = manager._get_node_version()

    assert version == (20, 10, 0)


def test_get_node_version_not_installed():
    """Test _get_node_version returns None when Node not installed."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()

    with patch("subprocess.run", side_effect=FileNotFoundError):
        version = manager._get_node_version()

    assert version is None


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


def test_print_tool_status_table_renders_manual_state():
    """Manual-install tools render as MANUAL with distinct hint."""
    from scripts.cli.tool_manager import ToolStatus, print_tool_status_table

    statuses = {
        "prowler": ToolStatus(
            name="prowler",
            installed=False,
            install_hint="pip install prowler",
            manual_install=False,
        ),
        "mobsf": ToolStatus(
            name="mobsf",
            installed=False,
            expected_version="4.4.2",
            manual_install=True,
        ),
    }

    captured: list[str] = []
    with patch(
        "builtins.print",
        side_effect=lambda *a, **k: captured.append(" ".join(str(x) for x in a)),
    ):
        print_tool_status_table(statuses, show_hints=True)

    output = "\n".join(captured)
    assert "MANUAL" in output  # status text rendered
    assert "Manual install required" in output  # distinct hint
    assert "docs/MANUAL_INSTALLATION.md" in output
    assert "MISSING" in output  # prowler still rendered as MISSING


def test_tool_status_derives_manual_status_type():
    """ToolStatus(installed=False, manual_install=True) -> ToolStatusType.MANUAL."""
    from scripts.cli.tool_manager import ToolStatus, ToolStatusType

    manual = ToolStatus(name="akto", installed=False, manual_install=True)
    real_missing = ToolStatus(name="prowler", installed=False, manual_install=False)

    assert manual.status_type == ToolStatusType.MANUAL
    assert manual.status_text == "MANUAL"
    assert manual.status_color == "cyan"
    assert real_missing.status_type == ToolStatusType.MISSING
    assert real_missing.status_text == "MISSING"


def test_print_profile_summary():
    """Test print_profile_summary outputs profile info."""
    from scripts.cli.tool_manager import print_profile_summary

    mock_manager = MagicMock()
    mock_manager.get_profile_summary.return_value = {
        "profile": "fast",
        "total": 8,
        "installed": 6,
        "execution_ready": 6,
        "missing": 2,
        "real_missing": 2,
        "manual_install_missing": 0,
        "not_ready": 0,
        "outdated": 0,
        "critical_outdated": 0,
        "ready": False,
        "warnings": [],
    }

    with patch("builtins.print") as mock_print:
        print_profile_summary(mock_manager)

    # Should print summary
    assert mock_print.call_count >= 1


def test_print_profile_summary_renders_manual_split():
    """v1.0.5: deep profile shows 'N missing + M manual' when both exist."""
    from scripts.cli.tool_manager import print_profile_summary

    mock_manager = MagicMock()

    def summary_for(profile: str) -> dict:
        # Only "deep" has manual_install tools in real config; mock that shape.
        if profile == "deep":
            return {
                "profile": "deep",
                "total": 28,
                "installed": 21,
                "execution_ready": 21,
                "missing": 7,
                "real_missing": 3,
                "manual_install_missing": 4,
                "not_ready": 0,
                "outdated": 0,
                "critical_outdated": 0,
                "ready": False,
                "warnings": [],
            }
        return {
            "profile": profile,
            "total": 9,
            "installed": 9,
            "execution_ready": 9,
            "missing": 0,
            "real_missing": 0,
            "manual_install_missing": 0,
            "not_ready": 0,
            "outdated": 0,
            "critical_outdated": 0,
            "ready": True,
            "warnings": [],
        }

    mock_manager.get_profile_summary.side_effect = summary_for

    captured: list[str] = []
    with patch(
        "builtins.print",
        side_effect=lambda *a, **k: captured.append(" ".join(str(x) for x in a)),
    ):
        print_profile_summary(mock_manager)

    output = "\n".join(captured)
    assert "3 missing" in output
    assert "4 manual" in output
    # Non-deep profiles shouldn't have the "+ manual" suffix
    assert "Ready" in output


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
        """Test remediation commands include dependencies."""
        from scripts.cli.tool_manager import get_remediation_for_tool

        result = get_remediation_for_tool("dependency-check", "linux")
        # Should return commands dict
        assert "commands" in result
        assert "manual" in result
        assert "jmo_install" in result

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

    def test_find_dependency_check_special_locations(self, tmp_path, monkeypatch):
        """Test dependency-check found in special locations."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        # Create fake dependency-check location
        dc_dir = tmp_path / "dependency-check" / "bin"
        dc_dir.mkdir(parents=True)
        dc_sh = dc_dir / "dependency-check.sh"
        dc_sh.touch()

        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        with patch("shutil.which", return_value=None):
            result = manager._find_binary("dependency-check.sh")

        assert result == str(dc_sh)


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


# ========== Category 14: Tool-Specific Version Parsing ==========


def test_parse_version_dependency_check():
    """Test dependency-check version parsing with actual output format.

    dependency-check outputs: "Dependency-Check Core version 12.1.0"
    This tests the fixed regex pattern.
    """
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    output = "Dependency-Check Core version 12.1.0"
    version = manager._parse_version("dependency-check", output)

    assert version == "12.1.0"


def test_parse_version_dependency_check_multiline():
    """Test dependency-check version parsing with full multiline output."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    # Simulating full output from dependency-check --version
    output = """Dependency-Check Core version 12.1.0
NVD API Endpoint: https://services.nvd.nist.gov/rest/json/cves/2.0
"""
    version = manager._parse_version("dependency-check", output)

    assert version == "12.1.0"


def test_parse_version_lynis():
    """Test lynis version parsing with actual output format.

    lynis --version outputs: "Lynis 3.1.3"
    """
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    output = "Lynis 3.1.3"
    version = manager._parse_version("lynis", output)

    assert version == "3.1.3"


def test_parse_version_lynis_show_version():
    """Test lynis version parsing with 'lynis show version' output."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    # 'lynis show version' may output just the version number
    output = "3.1.3"
    version = manager._parse_version("lynis", output)

    assert version == "3.1.3"


class TestVersionCommandFallback:
    """Tests for fallback version command functionality."""

    def test_get_version_with_fallback_primary_succeeds(self):
        """Test that fallback is not used when primary command succeeds."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        manager.platform = "linux"

        mock_result = MagicMock()
        mock_result.stdout = "Lynis 3.1.3"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result) as mock_run:
            version, error = manager._get_tool_version("lynis", "/usr/bin/lynis")

        assert version == "3.1.3"
        assert error is None
        # Should only call subprocess.run once (primary command)
        assert mock_run.call_count == 1

    def test_get_version_with_fallback_primary_fails(self):
        """Test that fallback is used when primary command fails to parse version."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        manager.platform = "linux"

        # First call (primary) returns unparseable output
        primary_result = MagicMock()
        primary_result.stdout = "Unknown output format"
        primary_result.stderr = ""
        primary_result.returncode = 0

        # Second call (fallback) returns valid version
        fallback_result = MagicMock()
        fallback_result.stdout = "3.1.3"
        fallback_result.stderr = ""
        fallback_result.returncode = 0

        with patch(
            "subprocess.run", side_effect=[primary_result, fallback_result]
        ) as mock_run:
            version, error = manager._get_tool_version("lynis", "/usr/bin/lynis")

        assert version == "3.1.3"
        assert error is None
        # Should call subprocess.run twice (primary + fallback)
        assert mock_run.call_count == 2

    def test_get_version_fallback_also_fails(self):
        """Test behavior when both primary and fallback fail."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        manager.platform = "linux"

        # Both calls return unparseable output
        mock_result = MagicMock()
        mock_result.stdout = "Unparseable output"
        mock_result.stderr = ""
        mock_result.returncode = 0

        with patch("subprocess.run", return_value=mock_result):
            version, error = manager._get_tool_version("lynis", "/usr/bin/lynis")

        assert version is None
        assert error is None

    def test_lynis_version_commands_structure(self):
        """Test that lynis has both default and fallback commands configured."""
        from scripts.cli.tool_manager import VERSION_COMMANDS

        lynis_config = VERSION_COMMANDS.get("lynis")
        assert lynis_config is not None
        assert isinstance(lynis_config, dict)
        assert "default" in lynis_config
        assert "fallback" in lynis_config
        assert lynis_config["default"] == ["lynis", "--version"]
        assert lynis_config["fallback"] == ["lynis", "show", "version"]


def test_dependency_check_pattern_matches_actual_output():
    """Verify dependency-check regex matches the actual tool output."""
    from scripts.cli.tool_manager import VERSION_PATTERNS

    pattern = VERSION_PATTERNS["dependency-check"]

    # Test actual output format
    actual_output = "Dependency-Check Core version 12.1.0"
    match = pattern.search(actual_output)
    assert match is not None
    assert match.group(1) == "12.1.0"

    # Test with different version numbers
    alt_output = "Dependency-Check Core version 9.0.10"
    match = pattern.search(alt_output)
    assert match is not None
    assert match.group(1) == "9.0.10"


# ========== Category 15: ToolStatusSummary Tests ==========


class TestToolStatusSummary:
    """Tests for ToolStatusSummary dataclass."""

    def test_toolstatussummary_defaults(self):
        """Test ToolStatusSummary with default values."""
        from scripts.cli.tool_manager import ToolStatusSummary

        summary = ToolStatusSummary(
            profile_name="deep",
            profile_total=28,
            platform_applicable=27,
            installed=25,
            execution_ready=22,
            platform_skipped=["falco", "afl++"],
            manual_install=[],
            missing_dependency=["zap"],
            not_installed=["noseyparker"],
            version_issues=["prowler"],
            content_triggered=["mobsf", "akto"],
        )

        assert summary.profile_name == "deep"
        assert summary.profile_total == 28
        assert summary.platform_applicable == 27
        assert summary.installed == 25
        assert summary.execution_ready == 22
        assert len(summary.platform_skipped) == 2
        assert len(summary.content_triggered) == 2

    def test_toolstatussummary_needs_attention_count(self):
        """Test needs_attention_count property."""
        from scripts.cli.tool_manager import ToolStatusSummary

        summary = ToolStatusSummary(
            profile_name="balanced",
            profile_total=18,
            platform_applicable=16,
            installed=14,
            execution_ready=12,
            platform_skipped=["falco", "afl++"],
            manual_install=["mobsf"],
            missing_dependency=["zap"],
            not_installed=[],
            version_issues=["prowler"],
            content_triggered=[],
        )

        # needs_attention = manual(1) + missing_deps(1) + not_installed(0) + version_issues(1) = 3
        assert summary.needs_attention_count == 3

    def test_toolstatussummary_skipped_count(self):
        """Test skipped_count property."""
        from scripts.cli.tool_manager import ToolStatusSummary

        summary = ToolStatusSummary(
            profile_name="deep",
            profile_total=29,
            platform_applicable=27,
            installed=25,
            execution_ready=22,
            platform_skipped=["falco", "afl++"],
            manual_install=["mobsf"],
            missing_dependency=[],
            not_installed=[],
            version_issues=[],
            content_triggered=["akto"],
        )

        # skipped = platform(2) + manual(1) + content_triggered(1) = 4
        assert summary.skipped_count == 4

    def test_toolstatussummary_format_status_line_all_ready(self):
        """Test format_status_line when all tools are ready."""
        from scripts.cli.tool_manager import ToolStatusSummary

        summary = ToolStatusSummary(
            profile_name="fast",
            profile_total=9,
            platform_applicable=9,
            installed=9,
            execution_ready=9,
            platform_skipped=[],
            manual_install=[],
            missing_dependency=[],
            not_installed=[],
            version_issues=[],
            content_triggered=[],
        )

        status_line = summary.format_status_line()
        assert "All 9 tools ready" in status_line

    def test_toolstatussummary_format_status_line_partial(self):
        """Test format_status_line when some tools need attention."""
        from scripts.cli.tool_manager import ToolStatusSummary

        summary = ToolStatusSummary(
            profile_name="balanced",
            profile_total=18,
            platform_applicable=16,
            installed=14,
            execution_ready=12,
            platform_skipped=["falco", "afl++"],
            manual_install=[],
            missing_dependency=["zap"],
            not_installed=[],
            version_issues=[],
            content_triggered=[],
        )

        status_line = summary.format_status_line()
        assert "12/16 tools ready" in status_line
        assert "1 need attention" in status_line


class TestGetToolSummary:
    """Tests for get_tool_summary method."""

    def test_get_tool_summary_basic(self):
        """Test get_tool_summary returns ToolStatusSummary."""
        from scripts.cli.tool_manager import ToolManager, ToolStatusSummary

        manager = ToolManager()

        # Mock check_tool to return predictable results
        mock_status_installed = MagicMock()
        mock_status_installed.installed = True
        mock_status_installed.execution_ready = True
        mock_status_installed.version_error = None
        mock_status_installed.missing_deps = []

        mock_status_missing = MagicMock()
        mock_status_missing.installed = False
        mock_status_missing.execution_ready = False
        mock_status_missing.version_error = None
        mock_status_missing.missing_deps = []

        def mock_check_tool(name):
            if name in ["trivy", "semgrep", "checkov"]:
                return mock_status_installed
            return mock_status_missing

        with patch.object(manager, "check_tool", side_effect=mock_check_tool):
            with patch(
                "scripts.cli.tool_manager.get_tools_for_profile_filtered",
                return_value=["trivy", "semgrep", "checkov"],
            ):
                with patch(
                    "scripts.cli.tool_manager.get_skipped_tools_for_profile",
                    return_value=[("falco", "Linux only")],
                ):
                    with patch(
                        "scripts.cli.tool_manager.PROFILE_TOOLS",
                        {"fast": ["trivy", "semgrep", "checkov", "falco"]},
                    ):
                        summary = manager.get_tool_summary("fast")

        assert isinstance(summary, ToolStatusSummary)
        assert summary.profile_name == "fast"
        assert summary.profile_total == 4  # Total in profile
        assert summary.platform_applicable == 3  # After filtering
        assert summary.installed == 3  # Tools with installed=True
        assert summary.execution_ready == 3  # Tools that are ready
        assert "falco" in summary.platform_skipped

    def test_get_tool_summary_with_content_triggered(self):
        """Test get_tool_summary identifies content-triggered tools."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_status = MagicMock()
        mock_status.installed = True
        mock_status.execution_ready = True
        mock_status.version_error = None
        mock_status.missing_deps = []

        with patch.object(manager, "check_tool", return_value=mock_status):
            with patch(
                "scripts.cli.tool_manager.get_tools_for_profile_filtered",
                return_value=["trivy", "mobsf", "akto"],
            ):
                with patch(
                    "scripts.cli.tool_manager.get_skipped_tools_for_profile",
                    return_value=[],
                ):
                    with patch(
                        "scripts.cli.tool_manager.PROFILE_TOOLS",
                        {"deep": ["trivy", "mobsf", "akto"]},
                    ):
                        with patch(
                            "scripts.cli.tool_manager.CONTENT_TRIGGERED_TOOLS",
                            {"mobsf", "akto"},
                        ):
                            summary = manager.get_tool_summary("deep")

        # mobsf and akto should be in content_triggered
        assert "mobsf" in summary.content_triggered
        assert "akto" in summary.content_triggered
        assert len(summary.content_triggered) == 2

    def test_get_tool_summary_with_version_issues(self):
        """Test get_tool_summary detects version/crash issues."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_status_ok = MagicMock()
        mock_status_ok.installed = True
        mock_status_ok.execution_ready = True
        mock_status_ok.version_error = None
        mock_status_ok.missing_deps = []

        mock_status_crash = MagicMock()
        mock_status_crash.installed = True
        mock_status_crash.execution_ready = False
        mock_status_crash.version_error = "ImportError - pydantic conflict"
        mock_status_crash.missing_deps = []

        def mock_check_tool(name):
            if name == "prowler":
                return mock_status_crash
            return mock_status_ok

        with patch.object(manager, "check_tool", side_effect=mock_check_tool):
            with patch(
                "scripts.cli.tool_manager.get_tools_for_profile_filtered",
                return_value=["trivy", "prowler"],
            ):
                with patch(
                    "scripts.cli.tool_manager.get_skipped_tools_for_profile",
                    return_value=[],
                ):
                    with patch(
                        "scripts.cli.tool_manager.PROFILE_TOOLS",
                        {"balanced": ["trivy", "prowler"]},
                    ):
                        with patch(
                            "scripts.cli.tool_manager.CONTENT_TRIGGERED_TOOLS",
                            set(),
                        ):
                            summary = manager.get_tool_summary("balanced")

        assert "prowler" in summary.version_issues

    def test_get_tool_summary_with_manual_install(self):
        """Test get_tool_summary identifies manual install tools."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        mock_status_ok = MagicMock()
        mock_status_ok.installed = True
        mock_status_ok.execution_ready = True
        mock_status_ok.version_error = None
        mock_status_ok.missing_deps = []

        mock_status_missing = MagicMock()
        mock_status_missing.installed = False
        mock_status_missing.execution_ready = False
        mock_status_missing.version_error = None
        mock_status_missing.missing_deps = []

        def mock_check_tool(name):
            if name == "mobsf":
                return mock_status_missing
            return mock_status_ok

        with patch.object(manager, "check_tool", side_effect=mock_check_tool):
            with patch(
                "scripts.cli.tool_manager.get_tools_for_profile_filtered",
                return_value=["trivy", "mobsf"],
            ):
                with patch(
                    "scripts.cli.tool_manager.get_skipped_tools_for_profile",
                    return_value=[],
                ):
                    with patch(
                        "scripts.cli.tool_manager.PROFILE_TOOLS",
                        {"deep": ["trivy", "mobsf"]},
                    ):
                        with patch(
                            "scripts.cli.tool_manager.CONTENT_TRIGGERED_TOOLS",
                            set(),
                        ):
                            with patch(
                                "scripts.cli.tool_manager.MANUAL_INSTALL_TOOLS",
                                {"mobsf"},
                            ):
                                summary = manager.get_tool_summary("deep")

        # mobsf not installed and in MANUAL_INSTALL_TOOLS
        assert "mobsf" in summary.manual_install

    def test_get_tool_summary_invalid_profile(self):
        """Test get_tool_summary with invalid profile."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()

        with patch(
            "scripts.cli.tool_manager.PROFILE_TOOLS",
            {"fast": ["trivy"]},
        ):
            summary = manager.get_tool_summary("nonexistent")

        assert summary.profile_total == 0
        assert summary.platform_applicable == 0


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

        assert (
            sentinel in entries
        ), f"the pre-existing first PATH entry was swallowed. entries[0]={entries[0]!r}"


class TestVariantExecutionReadiness:
    """`_verify_execution` must resolve a variant to its parent binary.

    `semgrep-secrets`, `trivy-rbac` and `checkov-cicd` are TOOL_VARIANTS: they
    run their parent's executable, which is why TOOL_BINARY_NAMES maps each to
    it. `check_tool`'s installed check and version lookup both resolved that;
    `_verify_execution` did not, so it probed for a binary literally named
    `semgrep-secrets`, never found one, and reported the tool as installed-but-
    not-executable in the same run that listed it OK.

    Measured on the deep profile before the fix: `execution_ready` 18 of 21
    installed, `not_ready` 3, and three warnings reading `Missing: <variant>`.
    After: 21 / 0 / none.

    The pre-existing tests in this file all patch `_verify_execution` out, so
    nothing exercised this path.
    """

    @pytest.mark.parametrize(
        "variant,parent",
        [
            ("semgrep-secrets", "semgrep"),
            ("trivy-rbac", "trivy"),
            ("checkov-cicd", "checkov"),
        ],
    )
    def test_variant_is_ready_when_only_the_parent_binary_exists(self, variant, parent):
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        with (
            patch(
                "scripts.cli.tool_manager.tool_exists",
                side_effect=lambda cmd, warn=False: cmd == parent,
            ),
            patch.object(manager, "_find_binary", return_value=None),
        ):
            ready, warning, missing = manager._verify_execution(variant)

        assert ready is True, f"{variant} reported not-ready though {parent} exists"
        assert warning is None, f"unexpected warning for {variant}: {warning}"
        assert missing == []

    def test_a_genuinely_absent_tool_is_still_reported_missing(self):
        """The fix must not turn the check into an unconditional pass."""
        from scripts.cli.tool_manager import ToolManager

        manager = ToolManager()
        with (
            patch("scripts.cli.tool_manager.tool_exists", return_value=False),
            patch.object(manager, "_find_binary", return_value=None),
        ):
            ready, warning, missing = manager._verify_execution("semgrep-secrets")

        assert ready is False
        assert warning and "Missing" in warning
        assert missing == ["semgrep"], "should name the binary it actually probed"


class TestIsolatedToolWithoutAVersionIsNotOK:
    """A version the probe could not read is not evidence the tool works.

    An isolated venv is built by pip from a pinned requirement, so its version
    is always knowable. `_get_tool_version` nonetheless returns `(None, None)`
    on timeout, on FileNotFoundError, on PermissionError and on an unparseable
    output -- and `_derive_status_type` downgraded only on `version_error`, so
    all four rendered as OK.

    Measured in the 2026-09-02 dogfood, on a machine where checkov could not
    run at all:

        checkov           OK          -             3.3.16
        checkov-cicd      OK          3.3.16        3.3.16

    Same binary, same table, two probes. The dash was the only signal, and the
    OK beside it overrode it.
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

    def test_a_variant_resolves_to_its_parent_for_the_isolated_check(self, monkeypatch):
        """`checkov-cicd` is not itself in ISOLATED_TOOLS; its parent is.

        Keying the check on the variant name would leave the variant rows OK
        while only the base row was downgraded -- half a fix, and the more
        confusing half, since the two rows describe one binary.
        """
        from scripts.cli.tool_manager import ToolStatusType

        status = self._check(monkeypatch, "checkov-cicd", None)

        assert status.status_type is not ToolStatusType.OK
        assert status.execution_ready is False

    def test_a_non_isolated_tool_with_no_version_is_unaffected(self, monkeypatch):
        """Plenty of tools legitimately decline to print a version.

        Scoping this to isolated venvs is deliberate: widening it to every
        tool would turn a silent-failure guard into a wall of false NOT READY.
        """
        from scripts.cli.tool_manager import ToolStatusType

        status = self._check(monkeypatch, "trivy", None)

        assert status.status_type is ToolStatusType.OK
        assert status.execution_ready is True


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


class TestUnpinnedSentinelIsNotShownAsAVersion:
    """`0.0.0` in versions.yaml means "nothing to pin", not release 0.0.0.

    A MANUAL_INSTALL tool ships in no Docker image, so no release of it is
    baked anywhere. `update_versions.py --validate` has read `0.0.0` that way
    since #935 and prints `falco: unpinned (manual install, no image)` --
    but the sentinel was defined only in that dev script, so the CLI printed
    it verbatim:

        falco             UNSUPPORTED    -             0.0.0

    falco is the only entry carrying it (afl++, akto and mobsf all have real
    versions), so it reads as a data error rather than a convention.
    """

    @staticmethod
    def _status(name, expected):
        from scripts.cli.tool_manager import ToolStatus

        return ToolStatus(name=name, installed=False, expected_version=expected)

    def test_a_manual_tool_carrying_the_sentinel_reads_unpinned(self):
        from scripts.cli.tool_manager import UNPINNED_SENTINEL

        status = self._status("falco", UNPINNED_SENTINEL)

        assert status.expected_version_display == "unpinned"
        assert UNPINNED_SENTINEL not in status.expected_version_display

    def test_the_raw_value_survives_for_machine_readers(self):
        """Display only -- `tools check --json` must not move."""
        from scripts.cli.tool_manager import UNPINNED_SENTINEL

        status = self._status("falco", UNPINNED_SENTINEL)

        assert status.expected_version == UNPINNED_SENTINEL

    def test_a_non_manual_tool_carrying_0_0_0_still_shows_it(self):
        """The control that matters.

        The sentinel is honoured only for MANUAL_INSTALL_TOOLS, exactly as
        `_validate_one` honours it. A `0.0.0` on a tool that *does* ship in an
        image is a genuinely missing pin, and rendering that as "unpinned"
        would hide it behind the same word that means "deliberate" elsewhere.
        """
        from scripts.cli.tool_manager import UNPINNED_SENTINEL

        status = self._status("trivy", UNPINNED_SENTINEL)

        assert status.expected_version_display == UNPINNED_SENTINEL

    def test_real_versions_are_untouched(self):
        assert self._status("trivy", "0.74.0").expected_version_display == "0.74.0"
        assert self._status("akto", "mini-testing-1.53.7").expected_version_display == (
            "mini-testing-1.53.7"
        )

    def test_a_missing_expected_version_still_renders_a_dash(self):
        assert self._status("trivy", None).expected_version_display == "-"
