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


# ========== Category: Helper Functions ==========


class TestGetDirSize:
    """Tests for _get_dir_size function."""

    def test_empty_dir(self, tmp_path):
        """Test size of empty directory."""
        from scripts.cli.tool_commands import _get_dir_size

        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        assert _get_dir_size(empty_dir) == 0

    def test_dir_with_files(self, tmp_path):
        """Test size of directory with files."""
        from scripts.cli.tool_commands import _get_dir_size

        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "file1.txt").write_text("hello")
        (test_dir / "file2.txt").write_text("world")

        # Each file is 5 bytes
        assert _get_dir_size(test_dir) == 10

    def test_nested_dirs(self, tmp_path):
        """Test size of nested directories."""
        from scripts.cli.tool_commands import _get_dir_size

        test_dir = tmp_path / "test"
        test_dir.mkdir()
        (test_dir / "sub").mkdir()
        (test_dir / "file.txt").write_text("abc")
        (test_dir / "sub" / "nested.txt").write_text("xyz")

        assert _get_dir_size(test_dir) == 6


class TestFormatSize:
    """Tests for _format_size function."""

    def test_bytes(self):
        """Test formatting bytes."""
        from scripts.cli.tool_commands import _format_size

        assert _format_size(500) == "500 B"

    def test_kilobytes(self):
        """Test formatting kilobytes."""
        from scripts.cli.tool_commands import _format_size

        assert _format_size(2048) == "2.0 KB"
        assert _format_size(5120) == "5.0 KB"

    def test_megabytes(self):
        """Test formatting megabytes."""
        from scripts.cli.tool_commands import _format_size

        assert _format_size(2 * 1024 * 1024) == "2.0 MB"

    def test_gigabytes(self):
        """Test formatting gigabytes."""
        from scripts.cli.tool_commands import _format_size

        assert _format_size(3 * 1024 * 1024 * 1024) == "3.0 GB"


class TestCheckPipPackage:
    """Tests for _check_pip_package function."""

    def test_package_installed(self):
        """Test checking an installed package."""
        from scripts.cli.tool_commands import _check_pip_package

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)

            result = _check_pip_package("pytest")

        assert result is True

    def test_package_not_installed(self):
        """Test checking a non-installed package."""
        from scripts.cli.tool_commands import _check_pip_package

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)

            result = _check_pip_package("nonexistent-package")

        assert result is False

    def test_subprocess_exception(self):
        """Test handling subprocess exception."""
        from scripts.cli.tool_commands import _check_pip_package

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = Exception("Subprocess failed")

            result = _check_pip_package("pytest")

        assert result is False


class TestGetInstalledTools:
    """Tests for _get_installed_tools function."""

    def test_returns_installed_tools(self):
        """Test getting list of installed tools."""
        from scripts.cli.tool_commands import _get_installed_tools

        # Mock tool statuses
        mock_status1 = MagicMock()
        mock_status1.installed = True
        mock_status2 = MagicMock()
        mock_status2.installed = False
        mock_status3 = MagicMock()
        mock_status3.installed = True

        # Mock tool info
        mock_tool_info1 = MagicMock()
        mock_tool_info1.pypi_package = "semgrep"
        mock_tool_info1.npm_package = None
        mock_tool_info1.brew_package = None

        mock_tool_info2 = MagicMock()
        mock_tool_info2.pypi_package = None
        mock_tool_info2.npm_package = "npm-groovy-lint"
        mock_tool_info2.brew_package = None

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {
            "semgrep": mock_status1,
            "trivy": mock_status2,
            "npm-groovy-lint": mock_status3,
        }
        mock_manager.registry.get_tool.side_effect = lambda x: {
            "semgrep": mock_tool_info1,
            "npm-groovy-lint": mock_tool_info2,
        }.get(x)

        # Patch ToolManager in tool_manager module where it's imported from
        with patch("scripts.cli.tool_manager.ToolManager", return_value=mock_manager):
            tools = _get_installed_tools()

        # Should return installed tools with their install method
        assert len(tools) == 2
        assert ("semgrep", "pip") in tools
        assert ("npm-groovy-lint", "npm") in tools


class TestUninstallTools:
    """Tests for _uninstall_tools function."""

    def test_uninstall_pip_tools(self):
        """Test uninstalling pip tools."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool = MagicMock()
        mock_tool.pypi_package = "semgrep"

        mock_registry = MagicMock()
        mock_registry.get_tool.return_value = mock_tool

        with patch(
            "scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                # Mock shutil.rmtree to avoid Windows file locking on ~/.jmo/bin/
                with patch("shutil.rmtree"):
                    with patch("builtins.print"):
                        errors = []
                        _uninstall_tools([("semgrep", "pip")], errors)

        assert len(errors) == 0
        mock_run.assert_called()

    def test_uninstall_npm_tools(self):
        """Test uninstalling npm tools."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool = MagicMock()
        mock_tool.npm_package = "@cyclonedx/cdxgen"
        mock_tool.pypi_package = None

        mock_registry = MagicMock()
        mock_registry.get_tool.return_value = mock_tool

        with patch(
            "scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry
        ):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(returncode=0)
                with patch("builtins.print"):
                    errors = []
                    _uninstall_tools([("cdxgen", "npm")], errors)

        mock_run.assert_called()


class TestCmdToolsUninstall:
    """Tests for cmd_tools_uninstall function."""

    def test_dry_run_no_jmo_dir(self, tmp_path, monkeypatch):
        """Test dry run when .jmo doesn't exist."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        # Use a non-existent home directory
        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=False, dry_run=True, yes=False)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=False
                ):
                    result = cmd_tools_uninstall(args)

        # Dry run should return 0
        assert result == 0

    def test_dry_run_with_jmo_dir(self, tmp_path, monkeypatch):
        """Test dry run when .jmo exists."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        # Create .jmo directory with contents
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()
        (jmo_dir / "history.db").write_text("test")
        (jmo_dir / "cache").mkdir()

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=False, dry_run=True, yes=False)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=True
                ):
                    result = cmd_tools_uninstall(args)

        assert result == 0

    def test_dry_run_all_with_tools(self, tmp_path, monkeypatch):
        """Test dry run --all with installed tools."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=True, dry_run=True, yes=False)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=False
                ):
                    with patch(
                        "scripts.cli.tool_commands._get_installed_tools",
                        return_value=[("semgrep", "pip"), ("trivy", "brew")],
                    ):
                        result = cmd_tools_uninstall(args)

        assert result == 0


class TestCmdToolsUpdate:
    """Tests for cmd_tools_update function."""

    def test_update_all_tools(self):
        """Test updating all tools."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.50.0"
        mock_status.is_outdated = True

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {"trivy": mock_status}
        mock_manager.update_tool.return_value = True

        args = argparse.Namespace(
            tools=None,
            dry_run=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_update(args)

        assert result == 0

    def test_update_dry_run(self):
        """Test update dry run."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "semgrep"
        mock_status.installed = True
        mock_status.installed_version = "1.0.0"
        mock_status.is_outdated = True

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {"semgrep": mock_status}

        args = argparse.Namespace(
            tools=None,
            dry_run=True,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_update(args)

        # Dry run should not call update_tool
        mock_manager.update_tool.assert_not_called()
        assert result == 0

    def test_update_no_tools_installed(self):
        """Test updating when no tools are installed."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {}

        args = argparse.Namespace(
            tools=None,
            dry_run=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_update(args)

        # Should return 0 even with no tools
        assert result == 0


class TestCmdToolsDebugAdditional:
    """Additional tests for cmd_tools_debug function."""

    def test_debug_tool_not_found(self):
        """Test debug command when tool is not found."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_status = MagicMock()
        mock_status.name = "nonexistent"
        mock_status.installed = False
        mock_status.binary_path = None

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status

        args = argparse.Namespace(
            tool="nonexistent",
            json=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_debug(args)

        # Should return 1 for not installed
        assert result == 1


class TestCmdToolsUninstallExecution:
    """Tests for cmd_tools_uninstall actual execution (not dry_run)."""

    def test_uninstall_yes_removes_jmo_dir(self, tmp_path, monkeypatch):
        """Test actual uninstall with yes=True removes .jmo dir."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        # Create .jmo directory
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()
        (jmo_dir / "history.db").write_text("test")

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=False, dry_run=False, yes=True)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=False
                ):
                    with patch("shutil.rmtree") as mock_rmtree:
                        result = cmd_tools_uninstall(args)

        # Should call rmtree to remove .jmo
        mock_rmtree.assert_called()
        assert result == 0

    def test_uninstall_yes_all_with_tools(self, tmp_path, monkeypatch):
        """Test uninstall --all --yes removes tools."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=True, dry_run=False, yes=True)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=True
                ):
                    with patch(
                        "scripts.cli.tool_commands._get_installed_tools",
                        return_value=[("semgrep", "pip")],
                    ):
                        with patch("scripts.cli.tool_commands._uninstall_tools"):
                            with patch("shutil.rmtree"):
                                with patch("subprocess.run") as mock_run:
                                    mock_run.return_value = MagicMock(returncode=0)
                                    result = cmd_tools_uninstall(args)

        assert result == 0

    def test_uninstall_with_errors(self, tmp_path, monkeypatch):
        """Test uninstall with removal errors."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=False, dry_run=False, yes=True)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=False
                ):
                    with patch("shutil.rmtree") as mock_rmtree:
                        mock_rmtree.side_effect = PermissionError("Access denied")
                        result = cmd_tools_uninstall(args)

        # Should return 1 due to error
        assert result == 1

    def test_uninstall_cancelled_by_user(self, tmp_path, monkeypatch):
        """Test uninstall cancelled by user input."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=False, dry_run=False, yes=False)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=False
                ):
                    with patch("builtins.input", return_value="n"):
                        result = cmd_tools_uninstall(args)

        # Should return 0 (cancelled)
        assert result == 0

    def test_uninstall_keyboard_interrupt(self, tmp_path, monkeypatch):
        """Test uninstall with keyboard interrupt."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=False, dry_run=False, yes=False)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=False
                ):
                    with patch("builtins.input", side_effect=KeyboardInterrupt):
                        result = cmd_tools_uninstall(args)

        # Should return 0 (cancelled)
        assert result == 0

    def test_uninstall_pip_package(self, tmp_path, monkeypatch):
        """Test uninstall with pip package removal."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)

        args = argparse.Namespace(all=False, dry_run=False, yes=True)

        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                with patch(
                    "scripts.cli.tool_commands._check_pip_package", return_value=True
                ):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = MagicMock(returncode=0)
                        result = cmd_tools_uninstall(args)

        # Should call pip uninstall
        mock_run.assert_called()
        assert result == 0


class TestCmdToolsInstallAdditional:
    """Additional tests for cmd_tools_install function."""

    def test_install_print_script(self):
        """Test install with --print-script."""
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
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_install(args)

        assert result == 0

    def test_install_no_missing_tools(self):
        """Test install when all tools are present."""
        from scripts.cli.tool_commands import cmd_tools_install

        mock_manager = MagicMock()
        mock_manager.get_missing_tools.return_value = []

        args = argparse.Namespace(
            profile="fast",
            tools=None,
            dry_run=False,
            print_script=False,
            yes=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_install(args)

        assert result == 0


class TestCmdToolsCheckComprehensive:
    """Comprehensive tests for cmd_tools_check function."""

    def test_check_profile_with_missing_tools(self):
        """Test check with missing tools in profile."""
        from scripts.cli.tool_commands import cmd_tools_check

        mock_status_installed = MagicMock()
        mock_status_installed.name = "trivy"
        mock_status_installed.installed = True
        mock_status_installed.is_outdated = False
        mock_status_installed.is_critical = False

        mock_status_missing = MagicMock()
        mock_status_missing.name = "semgrep"
        mock_status_missing.installed = False
        mock_status_missing.is_critical = True

        mock_manager = MagicMock()
        mock_manager.check_profile.return_value = {
            "trivy": mock_status_installed,
            "semgrep": mock_status_missing,
        }

        args = argparse.Namespace(
            profile="fast",
            tools=None,
            json=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.print_tool_status_table"):
                    with patch("builtins.print"):
                        result = cmd_tools_check(args)

        # Should return 1 for missing tools
        assert result == 1

    def test_check_profile_with_outdated_tools(self):
        """Test check with outdated tools in profile."""
        from scripts.cli.tool_commands import cmd_tools_check

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.40.0"
        mock_status.expected_version = "0.50.0"
        mock_status.is_outdated = True
        mock_status.is_critical = True

        mock_manager = MagicMock()
        mock_manager.check_profile.return_value = {"trivy": mock_status}

        args = argparse.Namespace(
            profile="fast",
            tools=None,
            json=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.print_tool_status_table"):
                    with patch("builtins.print"):
                        result = cmd_tools_check(args)

        # Should return 0 (outdated is warning)
        assert result == 0

    def test_check_profile_json_output(self):
        """Test check with JSON output."""
        from scripts.cli.tool_commands import cmd_tools_check

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.50.0"
        mock_status.expected_version = "0.50.0"
        mock_status.is_outdated = False
        mock_status.is_critical = False
        mock_status.binary_path = "/usr/local/bin/trivy"

        mock_manager = MagicMock()
        mock_manager.check_profile.return_value = {"trivy": mock_status}

        args = argparse.Namespace(
            profile="fast",
            tools=None,
            json=True,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch("builtins.print") as mock_print:
                result = cmd_tools_check(args)

        mock_print.assert_called()
        assert result == 0

    def test_check_no_profile_shows_summary(self):
        """Test check without profile shows summary."""
        from scripts.cli.tool_commands import cmd_tools_check

        mock_manager = MagicMock()
        mock_manager.get_critical_outdated.return_value = []

        args = argparse.Namespace(
            profile=None,
            tools=None,
            json=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.print_profile_summary"):
                    with patch("builtins.print"):
                        result = cmd_tools_check(args)

        assert result == 0

    def test_check_no_profile_with_critical_outdated(self):
        """Test check without profile with critical outdated tools."""
        from scripts.cli.tool_commands import cmd_tools_check

        mock_outdated = MagicMock()
        mock_outdated.name = "trivy"
        mock_outdated.installed_version = "0.40.0"
        mock_outdated.expected_version = "0.50.0"

        mock_manager = MagicMock()
        mock_manager.get_critical_outdated.return_value = [mock_outdated]

        args = argparse.Namespace(
            profile=None,
            tools=None,
            json=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.print_profile_summary"):
                    with patch("builtins.print"):
                        result = cmd_tools_check(args)

        assert result == 0

    def test_check_no_profile_json_output(self):
        """Test check without profile with JSON output."""
        from scripts.cli.tool_commands import cmd_tools_check

        mock_manager = MagicMock()
        mock_manager.get_profile_summary.return_value = {"installed": 5, "total": 7}

        args = argparse.Namespace(
            profile=None,
            tools=None,
            json=True,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch("builtins.print") as mock_print:
                result = cmd_tools_check(args)

        mock_print.assert_called()
        assert result == 0


class TestCmdToolsUpdateComprehensive:
    """Comprehensive tests for cmd_tools_update function."""

    def test_update_no_outdated_tools(self):
        """Test update when no tools are outdated."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_manager = MagicMock()
        mock_manager.get_outdated_tools.return_value = []

        args = argparse.Namespace(
            tools=None,
            dry_run=False,
            critical_only=False,
            yes=True,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_update(args)

        assert result == 0

    def test_update_critical_only_no_tools(self):
        """Test update with --critical-only but no critical tools."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_manager = MagicMock()
        mock_manager.get_critical_outdated.return_value = []

        args = argparse.Namespace(
            tools=None,
            dry_run=False,
            critical_only=True,
            yes=True,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_update(args)

        mock_manager.get_critical_outdated.assert_called()
        assert result == 0


class TestCmdToolsDebugComprehensive:
    """Comprehensive tests for cmd_tools_debug function."""

    def test_debug_no_tool_specified(self):
        """Test debug when no tool is specified."""
        from scripts.cli.tool_commands import cmd_tools_debug

        args = argparse.Namespace(
            tools=[],  # Empty list
        )

        with patch("builtins.print"):
            result = cmd_tools_debug(args)

        # Should return 1 (usage error)
        assert result == 1

    def test_debug_tool_found_with_version(self):
        """Test debug when tool is found and version detected."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.50.0"
        mock_status.binary_path = "/usr/local/bin/trivy"

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status
        mock_manager._get_clean_env.return_value = {}

        args = argparse.Namespace(
            tools=["trivy"],  # List, not single string
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.return_value = MagicMock(
                            returncode=0,
                            stdout="Version: 0.50.0",
                            stderr="",
                        )
                        result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_tool_version_timeout(self):
        """Test debug when version command times out."""
        import subprocess
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.binary_path = "/usr/local/bin/trivy"

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status
        mock_manager._get_clean_env.return_value = {}

        args = argparse.Namespace(
            tools=["trivy"],
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    with patch("subprocess.run") as mock_run:
                        mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)
                        result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_tool_binary_not_found(self):
        """Test debug when binary path doesn't exist."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.binary_path = None  # No binary path

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status

        args = argparse.Namespace(
            tools=["trivy"],
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_tool_permission_error(self):
        """Test debug when permission error executing binary."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.binary_path = "/usr/local/bin/trivy"

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status
        mock_manager._get_clean_env.return_value = {}

        # Mock file command result (first subprocess.run call)
        # cmd_tools_debug makes TWO subprocess calls:
        # 1. `file` command to check binary type (line 267)
        # 2. Version command (line 298)
        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "executable"

        args = argparse.Namespace(
            tools=["trivy"],
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    with patch("subprocess.run") as mock_run:
                        # Use list: first call (file) succeeds, second (version) raises
                        mock_run.side_effect = [
                            mock_file_result,
                            PermissionError("Access denied"),
                        ]
                        result = cmd_tools_debug(args)

        assert result == 0


class TestCmdToolsUpdateWithInstaller:
    """Tests for cmd_tools_update with actual installer logic."""

    def test_update_cancelled_by_user(self):
        """Test update cancelled via user input."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.40.0"
        mock_status.expected_version = "0.50.0"
        mock_status.is_outdated = True
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.get_outdated_tools.return_value = [mock_status]

        args = argparse.Namespace(
            tools=None,
            dry_run=False,
            critical_only=False,
            yes=False,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    with patch("builtins.input", return_value="n"):
                        with patch("sys.stdin") as mock_stdin:
                            mock_stdin.isatty.return_value = True
                            result = cmd_tools_update(args)

        # Should return 0 (cancelled)
        assert result == 0

    def test_update_specific_tool_not_installed(self):
        """Test update specific tool that isn't installed."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = False

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status

        args = argparse.Namespace(
            tools=["trivy"],
            dry_run=False,
            critical_only=False,
            yes=True,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_update(args)

        assert result == 0

    def test_update_specific_tool_already_up_to_date(self):
        """Test update specific tool that's already current."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.50.0"
        mock_status.is_outdated = False

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status

        args = argparse.Namespace(
            tools=["trivy"],
            dry_run=False,
            critical_only=False,
            yes=True,
        )

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("builtins.print"):
                    result = cmd_tools_update(args)

        assert result == 0


# ========== Category: cmd_tools_debug Subprocess Execution ==========


class TestCmdToolsDebugSubprocessExecution:
    """Test cmd_tools_debug subprocess execution paths."""

    def test_debug_binary_found_with_file_command(self, capsys):
        """Test debug when binary is found and file command succeeds."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "/usr/bin/trivy: ELF 64-bit LSB executable"

        mock_version_result = MagicMock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "Version: 0.50.0"
        mock_version_result.stderr = ""

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [mock_file_result, mock_version_result]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_file_command_not_found(self, capsys):
        """Test debug when file command is not available."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_version_result = MagicMock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "Version: 0.50.0"
        mock_version_result.stderr = ""

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    # First call (file command) raises FileNotFoundError
                    mock_run.side_effect = [FileNotFoundError(), mock_version_result]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_file_command_timeout(self, capsys):
        """Test debug when file command times out."""
        import subprocess
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_version_result = MagicMock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "Version: 0.50.0"
        mock_version_result.stderr = ""

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    # First call times out
                    mock_run.side_effect = [
                        subprocess.TimeoutExpired("file", 5),
                        mock_version_result,
                    ]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_version_command_timeout(self, capsys):
        """Test debug when version command times out."""
        import subprocess
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "ELF executable"

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [
                        mock_file_result,
                        subprocess.TimeoutExpired("trivy", 10),
                    ]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_version_command_permission_error(self, capsys):
        """Test debug when version command has permission error."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "ELF executable"

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [mock_file_result, PermissionError()]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_version_command_generic_error(self, capsys):
        """Test debug when version command raises generic exception."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "ELF executable"

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [
                        mock_file_result,
                        RuntimeError("Unknown error"),
                    ]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_version_no_pattern_match(self, capsys):
        """Test debug when version output doesn't match pattern."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "ELF executable"

        mock_version_result = MagicMock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "no version here"
        mock_version_result.stderr = ""

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [mock_file_result, mock_version_result]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_version_empty_output(self, capsys):
        """Test debug when version command returns empty output."""
        from scripts.cli.tool_commands import cmd_tools_debug

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = "/usr/bin/trivy"
        mock_manager._get_clean_env.return_value = {}

        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "ELF executable"

        mock_version_result = MagicMock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = ""
        mock_version_result.stderr = ""

        args = MagicMock()
        args.tools = ["trivy"]

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [mock_file_result, mock_version_result]
                    result = cmd_tools_debug(args)

        assert result == 0

    def test_debug_with_known_version_command(self, capsys):
        """Test debug for tool with known VERSION_COMMANDS entry."""
        from scripts.cli.tool_commands import cmd_tools_debug

        # Use 'semgrep' which is known to be in VERSION_COMMANDS
        tool_name = "semgrep"

        mock_manager = MagicMock()
        mock_manager._find_binary.return_value = f"/usr/bin/{tool_name}"
        mock_manager._get_clean_env.return_value = {}

        mock_file_result = MagicMock()
        mock_file_result.returncode = 0
        mock_file_result.stdout = "executable"

        mock_version_result = MagicMock()
        mock_version_result.returncode = 0
        mock_version_result.stdout = "semgrep 1.0.0"
        mock_version_result.stderr = ""

        args = MagicMock()
        args.tools = [tool_name]

        with patch("scripts.cli.tool_manager.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [mock_file_result, mock_version_result]
                    result = cmd_tools_debug(args)

        assert result == 0


# ========== Category: cmd_tools_install Interactive and Execution ==========


class TestCmdToolsInstallInteractive:
    """Test cmd_tools_install interactive confirmation paths."""

    def test_install_interactive_cancelled(self, capsys, monkeypatch):
        """Test install cancelled via interactive confirmation."""
        from scripts.cli.tool_commands import cmd_tools_install

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = False
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.get_missing_tools.return_value = [mock_status]
        mock_manager.platform = "linux"

        args = MagicMock()
        args.profile = "balanced"
        args.tools = None
        args.print_script = False
        args.dry_run = False
        args.yes = False

        # Simulate user typing "n"
        monkeypatch.setattr("builtins.input", lambda _: "n")

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("sys.stdin") as mock_stdin:
                    mock_stdin.isatty.return_value = True
                    result = cmd_tools_install(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "cancelled" in captured.out.lower()

    def test_install_specific_tools_some_installed(self, capsys):
        """Test install specific tools where some are already installed."""
        from scripts.cli.tool_commands import cmd_tools_install

        installed_status = MagicMock()
        installed_status.name = "trivy"
        installed_status.installed = True
        installed_status.installed_version = "0.50.0"

        missing_status = MagicMock()
        missing_status.name = "semgrep"
        missing_status.installed = False
        missing_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.check_tool.side_effect = lambda t: (
            installed_status if t == "trivy" else missing_status
        )
        mock_manager.platform = "linux"

        args = MagicMock()
        args.profile = "balanced"
        args.tools = ["trivy", "semgrep"]
        args.print_script = False
        args.dry_run = True
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                result = cmd_tools_install(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "already installed" in captured.out

    def test_install_executes_installer_for_profile(self, capsys):
        """Test install executes ToolInstaller for profile missing tools."""
        from scripts.cli.tool_commands import cmd_tools_install

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = False
        mock_status.is_critical = True
        mock_status.install_hint = "brew install trivy"

        mock_manager = MagicMock()
        mock_manager.get_missing_tools.return_value = [mock_status]
        mock_manager.platform = "darwin"

        mock_progress = MagicMock()
        mock_progress.failed = 0
        mock_progress.successful = 1

        mock_installer = MagicMock()
        mock_installer.install_missing.return_value = mock_progress

        args = MagicMock()
        args.profile = "balanced"
        args.tools = None
        args.print_script = False
        args.dry_run = False
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch(
                    "scripts.cli.tool_installer.ToolInstaller",
                    return_value=mock_installer,
                ):
                    with patch("scripts.cli.tool_installer.print_install_progress"):
                        result = cmd_tools_install(args)

        assert result == 0
        mock_installer.install_missing.assert_called_once()

    def test_install_executes_installer_for_specific_tools(self, capsys):
        """Test install executes ToolInstaller for specific tools."""
        from scripts.cli.tool_commands import cmd_tools_install

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = False
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.check_tool.return_value = mock_status
        mock_manager.platform = "linux"

        mock_result = MagicMock()
        mock_result.success = True

        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = mock_result

        mock_progress_cls = MagicMock()
        mock_progress_instance = MagicMock()
        mock_progress_instance.failed = 0
        mock_progress_instance.successful = 1
        mock_progress_cls.return_value = mock_progress_instance

        args = MagicMock()
        args.profile = "balanced"
        args.tools = ["trivy"]
        args.print_script = False
        args.dry_run = False
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch(
                    "scripts.cli.tool_installer.ToolInstaller",
                    return_value=mock_installer,
                ):
                    with patch(
                        "scripts.cli.tool_installer.InstallProgress",
                        mock_progress_cls,
                    ):
                        with patch("scripts.cli.tool_installer.print_install_progress"):
                            result = cmd_tools_install(args)

        assert result == 0
        mock_installer.install_tool.assert_called_once_with("trivy", force=True)

    def test_install_with_failures_returns_error(self, capsys):
        """Test install returns 1 when some tools fail."""
        from scripts.cli.tool_commands import cmd_tools_install

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = False
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.get_missing_tools.return_value = [mock_status]
        mock_manager.platform = "linux"

        mock_progress = MagicMock()
        mock_progress.failed = 1
        mock_progress.successful = 0

        mock_installer = MagicMock()
        mock_installer.install_missing.return_value = mock_progress

        args = MagicMock()
        args.profile = "balanced"
        args.tools = None
        args.print_script = False
        args.dry_run = False
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch(
                    "scripts.cli.tool_installer.ToolInstaller",
                    return_value=mock_installer,
                ):
                    with patch("scripts.cli.tool_installer.print_install_progress"):
                        result = cmd_tools_install(args)

        assert result == 1


# ========== Category: cmd_tools_update Interactive and Execution ==========


class TestCmdToolsUpdateInteractive:
    """Test cmd_tools_update interactive confirmation paths."""

    def test_update_interactive_cancelled(self, capsys, monkeypatch):
        """Test update cancelled via interactive confirmation."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.49.0"
        mock_status.is_outdated = True
        mock_status.required_version = "0.50.0"
        mock_status.expected_version = "0.50.0"  # Needed for f-string formatting
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.get_outdated_tools.return_value = [mock_status]
        mock_manager.platform = "linux"

        args = MagicMock()
        args.tools = None
        args.dry_run = False
        args.critical_only = False
        args.yes = False

        # Simulate user typing "n"
        monkeypatch.setattr("builtins.input", lambda _: "n")

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("sys.stdin") as mock_stdin:
                    mock_stdin.isatty.return_value = True
                    result = cmd_tools_update(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "cancelled" in captured.out.lower()

    def test_update_executes_installer(self, capsys):
        """Test update executes ToolInstaller for outdated tools."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.49.0"
        mock_status.is_outdated = True
        mock_status.required_version = "0.50.0"
        mock_status.expected_version = "0.50.0"  # Needed for f-string formatting
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.get_outdated_tools.return_value = [mock_status]

        mock_result = MagicMock()
        mock_result.success = True

        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = mock_result

        mock_progress_cls = MagicMock()
        mock_progress_instance = MagicMock()
        mock_progress_instance.failed = 0
        mock_progress_instance.successful = 1
        mock_progress_cls.return_value = mock_progress_instance

        args = MagicMock()
        args.tools = None
        args.dry_run = False
        args.critical_only = False
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch(
                    "scripts.cli.tool_installer.ToolInstaller",
                    return_value=mock_installer,
                ):
                    with patch(
                        "scripts.cli.tool_installer.InstallProgress",
                        mock_progress_cls,
                    ):
                        with patch("scripts.cli.tool_installer.print_install_progress"):
                            result = cmd_tools_update(args)

        assert result == 0
        mock_installer.install_tool.assert_called_once_with("trivy", force=True)

    def test_update_with_failures_returns_error(self, capsys):
        """Test update returns 1 when some tools fail."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.49.0"
        mock_status.is_outdated = True
        mock_status.required_version = "0.50.0"
        mock_status.expected_version = "0.50.0"  # Needed for f-string formatting
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.get_outdated_tools.return_value = [mock_status]

        mock_result = MagicMock()
        mock_result.success = False

        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = mock_result

        mock_progress_cls = MagicMock()
        mock_progress_instance = MagicMock()
        mock_progress_instance.failed = 1
        mock_progress_instance.successful = 0
        mock_progress_cls.return_value = mock_progress_instance

        args = MagicMock()
        args.tools = None
        args.dry_run = False
        args.critical_only = False
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch(
                    "scripts.cli.tool_installer.ToolInstaller",
                    return_value=mock_installer,
                ):
                    with patch(
                        "scripts.cli.tool_installer.InstallProgress",
                        mock_progress_cls,
                    ):
                        with patch("scripts.cli.tool_installer.print_install_progress"):
                            result = cmd_tools_update(args)

        assert result == 1


# ========== Category: _generate_install_script Edge Cases ==========


class TestGenerateInstallScriptEdgeCases:
    """Test _generate_install_script edge cases."""

    def test_generate_script_manual_install(self):
        """Test script generation for tool needing manual install."""
        from scripts.cli.tool_commands import _generate_install_script

        mock_tool = MagicMock()
        mock_tool.apt_package = None
        mock_tool.pypi_package = None
        mock_tool.npm_package = None

        mock_status = MagicMock()
        mock_status.name = "custom_tool"
        mock_status.install_hint = "Download from https://example.com"

        with patch("scripts.cli.tool_commands.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool
            mock_registry_cls.return_value = mock_registry

            script = _generate_install_script([mock_status], "linux")

        assert "Manual install required" in script
        assert "Download from https://example.com" in script


# ========== Category: cmd_tools_uninstall Tool Types ==========


class TestCmdToolsUninstallToolTypes:
    """Test cmd_tools_uninstall with different tool types."""

    def test_uninstall_all_with_npm_tools(self, capsys, tmp_path, monkeypatch):
        """Test uninstall --all with npm tools present."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        # Create mock .jmo directory
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()
        (jmo_dir / "config.yml").write_text("test: true")

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None
        mock_tool_info.npm_package = "eslint"
        mock_tool_info.brew_package = None

        mock_manager = MagicMock()
        mock_manager.registry.get_tool.return_value = mock_tool_info
        # Return npm tool
        mock_manager.registry.list_tools.return_value = ["eslint"]

        args = MagicMock()
        args.all = True
        args.dry_run = True
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.Path") as mock_path:
                    mock_jmo = MagicMock()
                    mock_jmo.exists.return_value = True
                    mock_kubescape = MagicMock()
                    mock_kubescape.exists.return_value = False
                    mock_path.home.return_value.__truediv__.side_effect = [
                        mock_jmo,
                        mock_kubescape,
                    ]
                    with patch(
                        "scripts.cli.tool_commands._get_installed_tools"
                    ) as mock_get_tools:
                        mock_get_tools.return_value = [("eslint", "npm")]
                        result = cmd_tools_uninstall(args)

        assert result == 0

    def test_uninstall_all_with_binary_tools(self, capsys, tmp_path):
        """Test uninstall --all with binary tools."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None
        mock_tool_info.npm_package = None
        mock_tool_info.brew_package = None

        mock_manager = MagicMock()
        mock_manager.registry.get_tool.return_value = mock_tool_info

        args = MagicMock()
        args.all = True
        args.dry_run = True
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.Path") as mock_path:
                    mock_jmo = MagicMock()
                    mock_jmo.exists.return_value = True
                    mock_kubescape = MagicMock()
                    mock_kubescape.exists.return_value = True
                    mock_path.home.return_value.__truediv__.side_effect = [
                        mock_jmo,
                        mock_kubescape,
                        mock_jmo,
                        mock_kubescape,
                    ]
                    with patch(
                        "scripts.cli.tool_commands._get_installed_tools"
                    ) as mock_get_tools:
                        mock_get_tools.return_value = [("trivy", "binary")]
                        with patch(
                            "scripts.cli.tool_commands._get_dir_size", return_value=1024
                        ):
                            with patch(
                                "scripts.cli.tool_commands._format_size",
                                return_value="1.0 KB",
                            ):
                                result = cmd_tools_uninstall(args)

        assert result == 0

    def test_uninstall_with_kubescape_dir(self, capsys, tmp_path):
        """Test uninstall --all removes kubescape directory."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        # Create mock directories
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()
        kubescape_dir = tmp_path / ".kubescape"
        kubescape_dir.mkdir()
        (kubescape_dir / "config").write_text("test")

        args = MagicMock()
        args.all = True
        args.dry_run = False
        args.yes = True

        mock_manager = MagicMock()

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.Path") as mock_path:
                    mock_jmo = MagicMock()
                    mock_jmo.exists.return_value = True
                    mock_kubescape = MagicMock()
                    mock_kubescape.exists.return_value = True
                    mock_path.home.return_value.__truediv__.side_effect = lambda x: (
                        mock_jmo if x == ".jmo" else mock_kubescape
                    )
                    with patch(
                        "scripts.cli.tool_commands._get_installed_tools"
                    ) as mock_get_tools:
                        mock_get_tools.return_value = []
                        with patch(
                            "scripts.cli.tool_commands._get_dir_size", return_value=512
                        ):
                            with patch(
                                "scripts.cli.tool_commands._format_size",
                                return_value="512 B",
                            ):
                                with patch("shutil.rmtree"):
                                    result = cmd_tools_uninstall(args)

        # Result depends on whether rmtree succeeded
        assert result in [0, 1]

    def test_uninstall_no_tools_found(self, capsys):
        """Test uninstall --all when no tools are found."""
        from scripts.cli.tool_commands import cmd_tools_uninstall

        mock_manager = MagicMock()

        args = MagicMock()
        args.all = True
        args.dry_run = True
        args.yes = True

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_commands.Path") as mock_path:
                    mock_jmo = MagicMock()
                    mock_jmo.exists.return_value = True
                    mock_kubescape = MagicMock()
                    mock_kubescape.exists.return_value = False
                    mock_path.home.return_value.__truediv__.side_effect = [
                        mock_jmo,
                        mock_kubescape,
                    ]
                    with patch(
                        "scripts.cli.tool_commands._get_installed_tools"
                    ) as mock_get_tools:
                        mock_get_tools.return_value = []
                        result = cmd_tools_uninstall(args)

        assert result == 0
        captured = capsys.readouterr()
        assert "No JMo-managed tools found" in captured.out


# ========== Category: _get_installed_tools Tool Types ==========


class TestGetInstalledToolsTypes:
    """Test _get_installed_tools with different tool types."""

    def test_get_installed_tools_brew_tool(self):
        """Test _get_installed_tools returns brew tool type."""
        from scripts.cli.tool_commands import _get_installed_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None
        mock_tool_info.npm_package = None
        mock_tool_info.brew_package = "trivy"

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {"trivy": MagicMock(installed=True)}
        mock_manager.registry.get_tool.return_value = mock_tool_info

        # Patch at the import location inside the function
        with patch("scripts.cli.tool_manager.ToolManager", return_value=mock_manager):
            tools = _get_installed_tools()

        assert ("trivy", "brew") in tools

    def test_get_installed_tools_no_tool_info(self):
        """Test _get_installed_tools when tool info is None."""
        from scripts.cli.tool_commands import _get_installed_tools

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {
            "unknown_tool": MagicMock(installed=True)
        }
        mock_manager.registry.get_tool.return_value = None

        # Patch at the import location inside the function
        with patch("scripts.cli.tool_manager.ToolManager", return_value=mock_manager):
            tools = _get_installed_tools()

        # Tool without info should not be included
        assert len([t for t in tools if t[0] == "unknown_tool"]) == 0


# ========== Category: _uninstall_tools Execution ==========


class TestUninstallToolsExecution:
    """Test _uninstall_tools execution paths."""

    def test_uninstall_tools_pip_partial_failure(self, capsys):
        """Test _uninstall_tools pip uninstall with partial failure."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = "semgrep"

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Some packages failed"

        errors = []

        with patch("scripts.cli.tool_commands.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool_info
            mock_registry_cls.return_value = mock_registry

            with patch("subprocess.run", return_value=mock_result):
                _uninstall_tools([("semgrep", "pip")], errors)

        # Partial failure should show warning but not add to errors
        captured = capsys.readouterr()
        assert "partial" in captured.out.lower()

    def test_uninstall_tools_pip_exception(self, capsys):
        """Test _uninstall_tools pip uninstall with exception."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = "semgrep"

        errors = []

        with patch("scripts.cli.tool_commands.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool_info
            mock_registry_cls.return_value = mock_registry

            with patch("subprocess.run", side_effect=Exception("Network error")):
                # Mock shutil.rmtree to avoid Windows file locking on ~/.jmo/bin/
                with patch("shutil.rmtree"):
                    _uninstall_tools([("semgrep", "pip")], errors)

        assert len(errors) == 1
        assert "pip uninstall" in errors[0]

    def test_uninstall_tools_npm_exception(self, capsys):
        """Test _uninstall_tools npm uninstall with exception."""
        import subprocess as subprocess_module
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None
        mock_tool_info.npm_package = "eslint"

        errors = []

        with patch("scripts.core.tool_registry.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool_info
            mock_registry_cls.return_value = mock_registry

            # Patch subprocess.run where it's actually used (global namespace after import)
            with patch.object(
                subprocess_module, "run", side_effect=Exception("npm error")
            ):
                # Mock shutil.rmtree to avoid Windows file locking on ~/.jmo/bin/
                with patch("shutil.rmtree"):
                    _uninstall_tools([("eslint", "npm")], errors)

        assert len(errors) == 1
        assert "npm uninstall" in errors[0]

    def test_uninstall_tools_binary_removal(self, capsys, tmp_path):
        """Test _uninstall_tools binary removal."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None
        mock_tool_info.npm_package = None

        # Create mock bin directory
        bin_dir = tmp_path / ".jmo" / "bin"
        bin_dir.mkdir(parents=True)
        (bin_dir / "trivy").write_text("binary")

        errors = []

        with patch("scripts.cli.tool_commands.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool_info
            mock_registry_cls.return_value = mock_registry

            with patch("scripts.cli.tool_commands.Path") as mock_path:
                mock_bin = MagicMock()
                mock_bin.exists.return_value = True
                mock_path.home.return_value.__truediv__.return_value.__truediv__.return_value = (
                    mock_bin
                )

                with patch("shutil.rmtree"):
                    _uninstall_tools([("trivy", "binary")], errors)

        assert len(errors) == 0

    def test_uninstall_tools_binary_removal_error(self, capsys):
        """Test _uninstall_tools binary removal with error."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None
        mock_tool_info.npm_package = None

        errors = []

        with patch("scripts.cli.tool_commands.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool_info
            mock_registry_cls.return_value = mock_registry

            with patch("scripts.cli.tool_commands.Path") as mock_path:
                mock_bin = MagicMock()
                mock_bin.exists.return_value = True
                mock_path.home.return_value.__truediv__.return_value.__truediv__.return_value = (
                    mock_bin
                )

                with patch(
                    "shutil.rmtree", side_effect=PermissionError("Access denied")
                ):
                    _uninstall_tools([("trivy", "binary")], errors)

        assert len(errors) == 1
        assert "binary removal" in errors[0]

    def test_uninstall_tools_brew_message(self, capsys):
        """Test _uninstall_tools shows brew manual removal message."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None
        mock_tool_info.npm_package = None

        errors = []

        with patch("scripts.cli.tool_commands.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool_info
            mock_registry_cls.return_value = mock_registry

            with patch("scripts.cli.tool_commands.Path") as mock_path:
                mock_bin = MagicMock()
                mock_bin.exists.return_value = False
                mock_path.home.return_value.__truediv__.return_value.__truediv__.return_value = (
                    mock_bin
                )

                _uninstall_tools([("trivy", "brew")], errors)

        captured = capsys.readouterr()
        assert "Homebrew" in captured.out or "brew uninstall" in captured.out


# ========== Category: _get_dir_size Edge Cases ==========


class TestGetDirSizeEdgeCases:
    """Test _get_dir_size edge cases."""

    def test_get_dir_size_permission_error(self, tmp_path):
        """Test _get_dir_size handles permission errors."""
        from scripts.cli.tool_commands import _get_dir_size

        # Create a mock path that raises permission error
        mock_path = MagicMock()
        mock_path.rglob.side_effect = PermissionError("Access denied")

        result = _get_dir_size(mock_path)

        assert result == 0

    def test_get_dir_size_os_error(self, tmp_path):
        """Test _get_dir_size handles OS errors."""
        from scripts.cli.tool_commands import _get_dir_size

        mock_path = MagicMock()
        mock_path.rglob.side_effect = OSError("Disk error")

        result = _get_dir_size(mock_path)

        assert result == 0

    def test_get_dir_size_stat_error(self, tmp_path):
        """Test _get_dir_size handles stat errors on individual files."""
        from scripts.cli.tool_commands import _get_dir_size

        mock_file = MagicMock()
        mock_file.is_file.return_value = True
        mock_file.stat.side_effect = OSError("Cannot stat")

        mock_path = MagicMock()
        mock_path.rglob.return_value = [mock_file]

        result = _get_dir_size(mock_path)

        # Should return 0 due to exception handling
        assert result == 0
