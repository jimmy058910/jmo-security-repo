#!/usr/bin/env python3
"""Tests for scripts/cli/tool_commands.py module.

This test suite validates CLI tool commands:
1. Colors class and colorize function
2. cmd_tools dispatcher
3. cmd_tools_check for status verification
4. cmd_tools_list for tool/profile listing
5. cmd_tools_outdated for detecting stale tools
6. install script generation
7. cmd_tools_debug for version detection debugging

Target Coverage: >= 85%
"""

import argparse
import json
import sys
from unittest.mock import MagicMock, patch


# ========== Category 1: Colors Class ==========


def test_colors_has_expected_constants():
    """Test Colors class has expected color constants."""
    from scripts.cli.tool_commands import Colors

    assert hasattr(Colors, "RED")
    assert hasattr(Colors, "GREEN")
    assert hasattr(Colors, "YELLOW")
    assert hasattr(Colors, "BLUE")
    assert hasattr(Colors, "CYAN")
    assert hasattr(Colors, "NC")


def test_colors_supports_color_non_tty():
    """Test supports_color returns False when not a TTY."""
    from scripts.cli.tool_commands import Colors

    with patch.object(sys.stdout, "isatty", return_value=False):
        assert Colors.supports_color() is False


def test_colors_supports_color_tty_unix():
    """Test supports_color returns True on Unix TTY."""
    from scripts.cli.tool_commands import Colors

    with patch.object(sys.stdout, "isatty", return_value=True):
        with patch.object(sys, "platform", "linux"):
            assert Colors.supports_color() is True


def test_colors_supports_color_windows_with_term():
    """Test supports_color on Windows with TERM set."""
    from scripts.cli.tool_commands import Colors
    import os

    with patch.object(sys.stdout, "isatty", return_value=True):
        with patch.object(sys, "platform", "win32"):
            with patch.dict(os.environ, {"TERM": "xterm-256color"}):
                assert Colors.supports_color() is True


def test_colors_supports_color_windows_with_wt_session():
    """Test supports_color on Windows Terminal."""
    from scripts.cli.tool_commands import Colors
    import os

    with patch.object(sys.stdout, "isatty", return_value=True):
        with patch.object(sys, "platform", "win32"):
            with patch.dict(os.environ, {"WT_SESSION": "123"}, clear=True):
                assert Colors.supports_color() is True


def test_colors_supports_color_windows_no_env():
    """Test supports_color on Windows without terminal env vars."""
    from scripts.cli.tool_commands import Colors
    import os

    with patch.object(sys.stdout, "isatty", return_value=True):
        with patch.object(sys, "platform", "win32"):
            # Clear both TERM and WT_SESSION
            env_copy = {
                k: v for k, v in os.environ.items() if k not in ("TERM", "WT_SESSION")
            }
            with patch.dict(os.environ, env_copy, clear=True):
                assert Colors.supports_color() is False


# ========== Category 2: colorize Function ==========


def test_colorize_no_color_support():
    """Test colorize returns plain text when color not supported."""
    from scripts.cli.tool_commands import colorize, Colors

    with patch.object(Colors, "supports_color", return_value=False):
        result = colorize("test", "red")
        assert result == "test"


def test_colorize_with_color_support():
    """Test colorize returns colored text when supported."""
    from scripts.cli.tool_commands import colorize, Colors

    with patch.object(Colors, "supports_color", return_value=True):
        result = colorize("test", "red")
        assert Colors.RED in result
        assert "test" in result
        assert Colors.NC in result


def test_colorize_green():
    """Test colorize with green color."""
    from scripts.cli.tool_commands import colorize, Colors

    with patch.object(Colors, "supports_color", return_value=True):
        result = colorize("success", "green")
        assert Colors.GREEN in result


def test_colorize_unknown_color():
    """Test colorize with unknown color returns plain text."""
    from scripts.cli.tool_commands import colorize, Colors

    with patch.object(Colors, "supports_color", return_value=True):
        result = colorize("test", "purple")  # Not in color_map
        assert result == "test"


# ========== Category 3: cmd_tools Dispatcher ==========


def test_cmd_tools_no_subcommand():
    """Test cmd_tools with no subcommand defaults to check."""
    from scripts.cli.tool_commands import cmd_tools

    args = argparse.Namespace(tools_command=None)

    with patch(
        "scripts.cli.tool_commands.cmd_tools_check", return_value=0
    ) as mock_check:
        result = cmd_tools(args)

        mock_check.assert_called_once_with(args)
        assert result == 0


def test_cmd_tools_check_subcommand():
    """Test cmd_tools routes to check handler."""
    from scripts.cli.tool_commands import cmd_tools

    args = argparse.Namespace(tools_command="check")

    with patch(
        "scripts.cli.tool_commands.cmd_tools_check", return_value=0
    ) as mock_check:
        result = cmd_tools(args)

        mock_check.assert_called_once_with(args)
        assert result == 0


def test_cmd_tools_install_subcommand():
    """Test cmd_tools routes to install handler."""
    from scripts.cli.tool_commands import cmd_tools

    args = argparse.Namespace(tools_command="install")

    with patch(
        "scripts.cli.tool_commands.cmd_tools_install", return_value=0
    ) as mock_install:
        result = cmd_tools(args)

        mock_install.assert_called_once_with(args)
        assert result == 0


def test_cmd_tools_list_subcommand():
    """Test cmd_tools routes to list handler."""
    from scripts.cli.tool_commands import cmd_tools

    args = argparse.Namespace(tools_command="list")

    with patch("scripts.cli.tool_commands.cmd_tools_list", return_value=0) as mock_list:
        result = cmd_tools(args)

        mock_list.assert_called_once_with(args)
        assert result == 0


def test_cmd_tools_outdated_subcommand():
    """Test cmd_tools routes to outdated handler."""
    from scripts.cli.tool_commands import cmd_tools

    args = argparse.Namespace(tools_command="outdated")

    with patch(
        "scripts.cli.tool_commands.cmd_tools_outdated", return_value=0
    ) as mock_outdated:
        result = cmd_tools(args)

        mock_outdated.assert_called_once_with(args)
        assert result == 0


def test_cmd_tools_debug_subcommand():
    """Test cmd_tools routes to debug handler."""
    from scripts.cli.tool_commands import cmd_tools

    args = argparse.Namespace(tools_command="debug")

    with patch(
        "scripts.cli.tool_commands.cmd_tools_debug", return_value=0
    ) as mock_debug:
        result = cmd_tools(args)

        mock_debug.assert_called_once_with(args)
        assert result == 0


# ========== Category 4: cmd_tools_check ==========


def test_cmd_tools_check_specific_tools():
    """Test cmd_tools_check with specific tools argument."""
    from scripts.cli.tool_commands import cmd_tools_check

    mock_status = MagicMock()
    mock_status.installed = True
    mock_status.installed_version = "1.0.0"
    mock_status.expected_version = "1.0.0"
    mock_status.is_outdated = False
    mock_status.is_critical = False
    mock_status.binary_path = "/usr/bin/tool"

    mock_manager = MagicMock()
    mock_manager.check_tool.return_value = mock_status

    args = argparse.Namespace(
        tools=["trivy", "semgrep"],
        profile=None,
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.print_tool_status_table"):
            with patch("builtins.print"):
                result = cmd_tools_check(args)

    assert mock_manager.check_tool.call_count == 2
    assert result == 0


def test_cmd_tools_check_json_output_profile_summary():
    """Test cmd_tools_check JSON output for profile summary."""
    from scripts.cli.tool_commands import cmd_tools_check

    mock_manager = MagicMock()
    mock_manager.get_profile_summary.return_value = {"installed": 5, "missing": 2}

    args = argparse.Namespace(
        tools=None,
        profile=None,
        json=True,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("builtins.print") as mock_print:
            result = cmd_tools_check(args)

    # Should print JSON
    assert result == 0
    mock_print.assert_called()


def test_cmd_tools_check_missing_tools_returns_error():
    """Test cmd_tools_check returns 1 when tools are missing."""
    from scripts.cli.tool_commands import cmd_tools_check

    mock_status = MagicMock()
    mock_status.installed = False  # Missing
    mock_status.is_outdated = False
    mock_status.is_critical = False

    mock_manager = MagicMock()
    mock_manager.check_tool.return_value = mock_status

    args = argparse.Namespace(
        tools=["missing-tool"],
        profile=None,
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.print_tool_status_table"):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_check(args)

    assert result == 1


# ========== Category 5: cmd_tools_list ==========


def test_cmd_tools_list_all_tools():
    """Test cmd_tools_list shows all tools."""
    from scripts.cli.tool_commands import cmd_tools_list

    mock_tool = MagicMock()
    mock_tool.name = "trivy"
    mock_tool.version = "0.50.0"
    mock_tool.category = "binary_tools"
    mock_tool.critical = False
    mock_tool.description = "Test tool"

    mock_registry = MagicMock()
    mock_registry.get_all_tools.return_value = [mock_tool]

    args = argparse.Namespace(
        profiles=False,
        profile=None,
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_list(args)

    assert result == 0
    mock_registry.get_all_tools.assert_called_once()


def test_cmd_tools_list_profiles():
    """Test cmd_tools_list shows profiles."""
    from scripts.cli.tool_commands import cmd_tools_list

    args = argparse.Namespace(
        profiles=True,
        profile=None,
        json=False,
    )

    with patch("builtins.print") as mock_print:
        result = cmd_tools_list(args)

    assert result == 0
    # Should print profile list
    printed = " ".join(str(call[0][0]) for call in mock_print.call_args_list)
    assert "fast" in printed or "balanced" in printed


def test_cmd_tools_list_profiles_json():
    """Test cmd_tools_list profiles with JSON output."""
    from scripts.cli.tool_commands import cmd_tools_list

    args = argparse.Namespace(
        profiles=True,
        profile=None,
        json=True,
    )

    with patch("builtins.print") as mock_print:
        result = cmd_tools_list(args)

    assert result == 0
    # Should print valid JSON
    output = mock_print.call_args[0][0]
    data = json.loads(output)
    assert "fast" in data
    assert "balanced" in data


def test_cmd_tools_list_for_profile():
    """Test cmd_tools_list for specific profile."""
    from scripts.cli.tool_commands import cmd_tools_list

    mock_tool = MagicMock()
    mock_tool.name = "trivy"
    mock_tool.version = "0.50.0"
    mock_tool.category = "binary_tools"
    mock_tool.critical = True

    mock_registry = MagicMock()
    mock_registry.get_tools_for_profile.return_value = [mock_tool]

    args = argparse.Namespace(
        profiles=False,
        profile="balanced",
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_list(args)

    assert result == 0
    mock_registry.get_tools_for_profile.assert_called_once_with("balanced")


def test_cmd_tools_list_json_output():
    """Test cmd_tools_list with JSON output."""
    from scripts.cli.tool_commands import cmd_tools_list

    mock_tool = MagicMock()
    mock_tool.name = "trivy"
    mock_tool.version = "0.50.0"
    mock_tool.category = "binary_tools"
    mock_tool.critical = True
    mock_tool.description = "Scanner"

    mock_registry = MagicMock()
    mock_registry.get_all_tools.return_value = [mock_tool]

    args = argparse.Namespace(
        profiles=False,
        profile=None,
        json=True,
    )

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        with patch("builtins.print") as mock_print:
            result = cmd_tools_list(args)

    assert result == 0
    output = mock_print.call_args[0][0]
    data = json.loads(output)
    assert len(data) == 1
    assert data[0]["name"] == "trivy"


# ========== Category 6: cmd_tools_outdated ==========


def test_cmd_tools_outdated_no_outdated():
    """Test cmd_tools_outdated when all tools up to date."""
    from scripts.cli.tool_commands import cmd_tools_outdated

    mock_manager = MagicMock()
    mock_manager.get_outdated_tools.return_value = []

    args = argparse.Namespace(
        critical_only=False,
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_outdated(args)

    assert result == 0


def test_cmd_tools_outdated_with_outdated():
    """Test cmd_tools_outdated shows outdated tools."""
    from scripts.cli.tool_commands import cmd_tools_outdated

    mock_status = MagicMock()
    mock_status.name = "trivy"
    mock_status.installed_version = "0.49.0"
    mock_status.expected_version = "0.50.0"
    mock_status.is_critical = False

    mock_manager = MagicMock()
    mock_manager.get_outdated_tools.return_value = [mock_status]

    args = argparse.Namespace(
        critical_only=False,
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_outdated(args)

    # Non-critical outdated returns 0
    assert result == 0


def test_cmd_tools_outdated_critical_returns_error():
    """Test cmd_tools_outdated returns 1 for critical outdated tools."""
    from scripts.cli.tool_commands import cmd_tools_outdated

    mock_status = MagicMock()
    mock_status.name = "trivy"
    mock_status.installed_version = "0.49.0"
    mock_status.expected_version = "0.50.0"
    mock_status.is_critical = True  # Critical!

    mock_manager = MagicMock()
    mock_manager.get_outdated_tools.return_value = [mock_status]

    args = argparse.Namespace(
        critical_only=False,
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_outdated(args)

    assert result == 1


def test_cmd_tools_outdated_critical_only():
    """Test cmd_tools_outdated with --critical-only."""
    from scripts.cli.tool_commands import cmd_tools_outdated

    mock_manager = MagicMock()
    mock_manager.get_critical_outdated.return_value = []

    args = argparse.Namespace(
        critical_only=True,
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_outdated(args)

    mock_manager.get_critical_outdated.assert_called_once()
    assert result == 0


def test_cmd_tools_outdated_json_output():
    """Test cmd_tools_outdated with JSON output."""
    from scripts.cli.tool_commands import cmd_tools_outdated

    mock_status = MagicMock()
    mock_status.name = "trivy"
    mock_status.installed_version = "0.49.0"
    mock_status.expected_version = "0.50.0"
    mock_status.is_critical = False

    mock_manager = MagicMock()
    mock_manager.get_outdated_tools.return_value = [mock_status]

    args = argparse.Namespace(
        critical_only=False,
        json=True,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("builtins.print") as mock_print:
            result = cmd_tools_outdated(args)

    output = mock_print.call_args[0][0]
    data = json.loads(output)
    assert len(data) == 1
    assert data[0]["name"] == "trivy"
    assert result == 0


# ========== Category 7: Install Script Generation ==========


def test_generate_install_script_basic():
    """Test _generate_install_script generates shell script."""
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "trivy"
    mock_status.install_hint = "brew install trivy"

    mock_tool = MagicMock()
    mock_tool.brew_package = "trivy"
    mock_tool.apt_package = None
    mock_tool.pypi_package = None
    mock_tool.npm_package = None

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "macos")

    assert "#!/bin/bash" in script
    assert "brew install trivy" in script


def test_generate_install_script_linux_apt():
    """Test _generate_install_script for Linux with apt."""
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "shellcheck"
    mock_status.install_hint = "apt install shellcheck"

    mock_tool = MagicMock()
    mock_tool.brew_package = None
    mock_tool.apt_package = "shellcheck"
    mock_tool.pypi_package = None
    mock_tool.npm_package = None

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "linux")

    assert "apt-get install -y shellcheck" in script


def test_generate_install_script_pip():
    """Test _generate_install_script for pip packages."""
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "bandit"
    mock_status.install_hint = "pip install bandit"

    mock_tool = MagicMock()
    mock_tool.brew_package = None
    mock_tool.apt_package = None
    mock_tool.pypi_package = "bandit"
    mock_tool.npm_package = None

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "linux")

    assert "pip install bandit" in script


def test_generate_install_script_npm():
    """Test _generate_install_script for npm packages."""
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "cdxgen"
    mock_status.install_hint = "npm install cdxgen"

    mock_tool = MagicMock()
    mock_tool.brew_package = None
    mock_tool.apt_package = None
    mock_tool.pypi_package = None
    mock_tool.npm_package = "@cyclonedx/cdxgen"

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "linux")

    assert "npm install -g @cyclonedx/cdxgen" in script


def test_generate_install_script_unknown_tool():
    """Test _generate_install_script handles unknown tools."""
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "unknown-tool"
    mock_status.install_hint = "Manual installation required"

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = None

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "linux")

    assert "unknown-tool: Unknown tool" in script


# ========== Category 8: cmd_tools_debug ==========


def test_cmd_tools_debug_no_tools():
    """Test cmd_tools_debug returns 1 when no tools specified."""
    from scripts.cli.tool_commands import cmd_tools_debug

    args = argparse.Namespace(tools=[])

    with patch("builtins.print"):
        result = cmd_tools_debug(args)

    assert result == 1


def test_cmd_tools_debug_unknown_tool():
    """Test cmd_tools_debug handles unknown tools."""
    from scripts.cli.tool_commands import cmd_tools_debug

    mock_manager = MagicMock()
    mock_manager.registry.get_tool.return_value = None
    mock_manager._find_binary.return_value = None

    args = argparse.Namespace(tools=["unknown-tool"])

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_debug(args)

    assert result == 0


def test_cmd_tools_debug_with_binary():
    """Test cmd_tools_debug shows debug info for found binary."""
    from scripts.cli.tool_commands import cmd_tools_debug

    mock_tool = MagicMock()
    mock_tool.version = "0.50.0"
    mock_tool.get_binary_name.return_value = "trivy"

    mock_manager = MagicMock()
    mock_manager.registry.get_tool.return_value = mock_tool
    mock_manager._find_binary.return_value = "/usr/bin/trivy"
    mock_manager._get_clean_env.return_value = {}

    mock_result = MagicMock()
    mock_result.returncode = 0
    mock_result.stdout = "Trivy Version: 0.50.0"
    mock_result.stderr = ""

    args = argparse.Namespace(tools=["trivy"])

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("subprocess.run", return_value=mock_result):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_debug(args)

    assert result == 0


# ========== Category 9: cmd_tools_install ==========


def test_cmd_tools_install_all_installed():
    """Test cmd_tools_install when all tools already installed."""
    from scripts.cli.tool_commands import cmd_tools_install

    mock_manager = MagicMock()
    mock_manager.get_missing_tools.return_value = []

    args = argparse.Namespace(
        profile="balanced",
        tools=None,
        dry_run=False,
        print_script=False,
        yes=True,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_install(args)

    assert result == 0


def test_cmd_tools_install_print_script():
    """Test cmd_tools_install with --print-script."""
    from scripts.cli.tool_commands import cmd_tools_install

    mock_status = MagicMock()
    mock_status.name = "trivy"
    mock_status.is_critical = False
    mock_status.install_hint = "brew install trivy"

    mock_manager = MagicMock()
    mock_manager.get_missing_tools.return_value = [mock_status]
    mock_manager.platform = "macos"

    args = argparse.Namespace(
        profile="balanced",
        tools=None,
        dry_run=False,
        print_script=True,
        yes=True,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch(
            "scripts.cli.tool_commands._generate_install_script",
            return_value="#!/bin/bash\n",
        ):
            with patch("builtins.print") as mock_print:
                result = cmd_tools_install(args)

    assert result == 0
    # Script should be printed
    mock_print.assert_called()


def test_cmd_tools_install_dry_run():
    """Test cmd_tools_install with --dry-run."""
    from scripts.cli.tool_commands import cmd_tools_install

    mock_status = MagicMock()
    mock_status.name = "trivy"
    mock_status.is_critical = False
    mock_status.install_hint = "brew install trivy"

    mock_manager = MagicMock()
    mock_manager.get_missing_tools.return_value = [mock_status]
    mock_manager.platform = "macos"

    args = argparse.Namespace(
        profile="balanced",
        tools=None,
        dry_run=True,
        print_script=False,
        yes=True,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_install(args)

    assert result == 0
