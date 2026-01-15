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

import re
from pathlib import Path
from unittest.mock import MagicMock, patch


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
    from scripts.cli.tool_manager import ToolManager, PROFILE_TOOLS

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

    missing_status = MagicMock()
    missing_status.installed = False
    missing_status.execution_ready = False
    missing_status.is_outdated = False
    missing_status.is_critical = False

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
    assert len(missing) > 0


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
    assert len(result["commands"]) > 0


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
    """Test _get_clean_env adds custom paths."""
    from scripts.cli.tool_manager import ToolManager

    manager = ToolManager()
    env = manager._get_clean_env()

    assert "PATH" in env
    assert ".jmo/bin" in env["PATH"]


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


def test_get_missing_tools_for_scan():
    """Test get_missing_tools_for_scan function."""
    from scripts.cli.tool_manager import get_missing_tools_for_scan

    with patch("shutil.which") as mock_which:
        # Make all tools "not found"
        mock_which.return_value = None

        missing = get_missing_tools_for_scan("fast")

    # All fast profile tools should be reported missing
    assert len(missing) > 0


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
