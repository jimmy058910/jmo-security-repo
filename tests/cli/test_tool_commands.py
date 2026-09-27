#!/usr/bin/env python3
"""Tests for scripts/cli/tool_commands.py module.

This test suite validates CLI tool commands:
1. Colors class and colorize function
2. cmd_tools dispatcher
3. cmd_tools_check for status verification (the scan matrix plus the policy engine)
4. cmd_tools_list for tool listing
5. cmd_tools_outdated for detecting stale tools
6. install script generation
7. cmd_tools_debug for version detection debugging

Target Coverage: >= 85%
"""

import argparse
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.tool_commands import cmd_tools_uninstall
from scripts.core.tool_registry import POLICY_ENGINE, TOOL_MATRIX

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
    import os

    from scripts.cli.tool_commands import Colors

    with patch.object(sys.stdout, "isatty", return_value=True):
        with patch.object(sys, "platform", "win32"):
            with patch.dict(os.environ, {"TERM": "xterm-256color"}):
                assert Colors.supports_color() is True


def test_colors_supports_color_windows_with_wt_session():
    """Test supports_color on Windows Terminal."""
    import os

    from scripts.cli.tool_commands import Colors

    with patch.object(sys.stdout, "isatty", return_value=True):
        with patch.object(sys, "platform", "win32"):
            with patch.dict(os.environ, {"WT_SESSION": "123"}, clear=True):
                assert Colors.supports_color() is True


def test_colors_supports_color_windows_no_env():
    """Test supports_color on Windows without terminal env vars."""
    import os

    from scripts.cli.tool_commands import Colors

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
    from scripts.cli.tool_commands import Colors, colorize

    with patch.object(Colors, "supports_color", return_value=False):
        result = colorize("test", "red")
        assert result == "test"


def test_colorize_with_color_support():
    """Test colorize returns colored text when supported."""
    from scripts.cli.tool_commands import Colors, colorize

    with patch.object(Colors, "supports_color", return_value=True):
        result = colorize("test", "red")
        assert Colors.RED in result
        assert "test" in result
        assert Colors.NC in result


def test_colorize_green():
    """Test colorize with green color."""
    from scripts.cli.tool_commands import Colors, colorize

    with patch.object(Colors, "supports_color", return_value=True):
        result = colorize("success", "green")
        assert Colors.GREEN in result


def test_colorize_unknown_color():
    """Test colorize with unknown color returns plain text."""
    from scripts.cli.tool_commands import Colors, colorize

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
        json=False,
    )

    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch("scripts.cli.tool_commands.print_tool_status_table"):
            with patch("builtins.print"):
                result = cmd_tools_check(args)

    assert mock_manager.check_tool.call_count == 2
    assert result == 0


def test_cmd_tools_check_json_output_reports_missing_matrix_tools_through_exit_code():
    """The no-argument JSON form still fails when a matrix tool is missing.

    This asserted `result == 0` while mocking two *missing* tools, which pinned
    the defect fixed in #788: the no-argument form returned 0 no matter what it
    found, so `jmo tools check || exit 1` passed with scanners missing. The JSON
    is still printed; the exit code reports the missing tool.

    Real ToolStatus objects, not MagicMocks: a MagicMock's `execution_ready` is
    truthy, and its `installed` is whatever the mock says, so the exit code
    would be an artefact of the mock rather than of the input.
    """
    from scripts.cli.tool_commands import cmd_tools_check

    mock_manager = MagicMock()
    mock_manager.check_matrix.return_value = {
        "trivy": _status("trivy"),
        "semgrep": _status("semgrep", installed=False, installed_version=None),
    }
    mock_manager.check_tool.return_value = _status(POLICY_ENGINE)

    args = argparse.Namespace(tools=None, json=True)

    captured: list[str] = []
    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch(
            "builtins.print",
            side_effect=lambda *a, **k: captured.append(" ".join(str(x) for x in a)),
        ):
            result = cmd_tools_check(args)

    payload = json.loads("\n".join(captured))
    assert payload["tools"]["semgrep"]["installed"] is False
    assert payload["tools"]["trivy"]["installed"] is True
    assert result == 1


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


def test_cmd_tools_check_json_for_named_tools_keys_each_tool_under_tools():
    """`jmo tools check <names> --json` reports each named tool, and only those.

    Named tools get no policy-engine entry: the engine is reported only when the
    whole matrix is checked. A missing tool still fails the check.
    """
    from scripts.cli.tool_commands import cmd_tools_check

    statuses = {
        "trivy": _status("trivy", installed_version="0.70.0"),
        "semgrep": _status("semgrep", installed=False, installed_version=None),
    }
    mock_manager = MagicMock()
    mock_manager.check_tool.side_effect = lambda name: statuses[name]

    args = argparse.Namespace(tools=["trivy", "semgrep"], json=True)

    captured: list[str] = []
    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with patch(
            "builtins.print",
            side_effect=lambda *a, **k: captured.append(" ".join(str(x) for x in a)),
        ):
            result = cmd_tools_check(args)

    payload = json.loads("\n".join(captured))
    assert set(payload["tools"]) == {"trivy", "semgrep"}
    assert payload["tools"]["trivy"]["installed_version"] == "0.70.0"
    assert payload["tools"]["semgrep"]["installed"] is False
    assert "policy_engine" not in payload
    assert result == 1  # semgrep still triggers rc=1 (not installed)


def _matrix_check(capsys, json_output=False):
    """Run `jmo tools check` over the real TOOL_MATRIX with every tool OK.

    Only `ToolManager.check_tool` is stubbed, so `check_matrix` and the table
    printer are the real ones.
    """
    from scripts.cli.tool_commands import cmd_tools_check
    from scripts.cli.tool_manager import ToolManager

    checked: list[str] = []

    def ok(_self, name):
        checked.append(name)
        return _status(name)

    with patch.object(ToolManager, "check_tool", ok):
        result = cmd_tools_check(argparse.Namespace(tools=None, json=json_output))
    return result, capsys.readouterr().out, checked


def test_tools_check_lists_each_matrix_tool_once_and_the_policy_engine_below(capsys):
    """The table is the scan matrix; opa gets its own line, not a row.

    opa evaluates policy in the report phase and scans nothing, so it is not
    one of the scanners the table counts - but it is installed and checked, so
    it must be reported somewhere.
    """
    assert TOOL_MATRIX, "an empty matrix would make every assertion below vacuous"

    result, out, checked = _matrix_check(capsys)

    lines = out.splitlines()
    rule = next(i for i, line in enumerate(lines) if line and set(line) == {"-"})
    rows = []
    for line in lines[rule + 1 :]:
        if not line.strip():
            break
        rows.append(line.split()[0])

    assert sorted(rows) == sorted(TOOL_MATRIX), rows
    assert len(rows) == len(set(rows)), f"a tool is listed twice: {rows}"
    assert POLICY_ENGINE not in rows, "the policy engine is not a scanner row"
    assert f"Tool Status ({len(TOOL_MATRIX)} scanners)" in out

    engine_lines = [line for line in lines if line.startswith("Policy engine:")]
    assert len(engine_lines) == 1, out
    assert POLICY_ENGINE in engine_lines[0]
    assert "OK" in engine_lines[0]

    assert sorted(checked) == sorted([*TOOL_MATRIX, POLICY_ENGINE])
    assert result == 0
    assert "All tools installed and up to date!" in out


def test_tools_check_json_lists_each_matrix_tool_and_the_policy_engine(capsys):
    """`--json` carries the same split: `tools` is the matrix, and the engine
    is a separate `policy_engine` object."""
    assert TOOL_MATRIX, "an empty matrix would make every assertion below vacuous"

    result, out, _ = _matrix_check(capsys, json_output=True)

    payload = json.loads(out)
    assert sorted(payload["tools"]) == sorted(TOOL_MATRIX)
    assert POLICY_ENGINE not in payload["tools"]
    assert payload["policy_engine"]["name"] == POLICY_ENGINE
    assert payload["policy_engine"]["installed"] is True
    assert payload["policy_engine"]["execution_ready"] is True
    assert result == 0


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

    args = argparse.Namespace(json=False)

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        with patch("scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x):
            with patch("builtins.print"):
                result = cmd_tools_list(args)

    assert result == 0
    mock_registry.get_all_tools.assert_called_once()


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

    args = argparse.Namespace(json=True)

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
    """A tool with neither an apt nor a pip package falls back to `jmo tools install`.

    That is the pinned-binary route on every platform, macOS included: brew
    never honoured the pinned version and is no longer suggested (v2.0.0).
    """
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "trivy"
    mock_status.install_hint = "jmo tools install trivy"

    mock_tool = MagicMock()
    mock_tool.apt_package = None
    mock_tool.pypi_package = None

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "macos")

    assert "#!/bin/bash" in script
    assert "jmo tools install trivy" in script
    assert "brew" not in script


def test_generate_install_script_linux_apt():
    """Test _generate_install_script for Linux with apt."""
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "shellcheck"
    mock_status.install_hint = "apt install shellcheck"

    mock_tool = MagicMock()
    mock_tool.apt_package = "shellcheck"
    mock_tool.pypi_package = None

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "linux")

    assert "apt-get install -y shellcheck" in script


def test_generate_install_script_pip():
    """Test _generate_install_script for pip packages."""
    from scripts.cli.tool_commands import _generate_install_script

    mock_status = MagicMock()
    mock_status.name = "semgrep"
    mock_status.install_hint = "pip install semgrep"

    mock_tool = MagicMock()
    mock_tool.apt_package = None
    mock_tool.pypi_package = "semgrep"

    mock_registry = MagicMock()
    mock_registry.get_tool.return_value = mock_tool

    with patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry):
        script = _generate_install_script([mock_status], "linux")

    assert "pip install semgrep" in script


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
    mock_status.install_hint = "jmo tools install trivy"

    mock_manager = MagicMock()
    mock_manager.get_missing_tools.return_value = [mock_status]
    mock_manager.platform = "macos"

    args = argparse.Namespace(
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
    mock_status.install_hint = "jmo tools install trivy"

    mock_manager = MagicMock()
    mock_manager.get_missing_tools.return_value = [mock_status]
    mock_manager.platform = "macos"

    args = argparse.Namespace(
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

        mock_tool_info2 = MagicMock()
        mock_tool_info2.pypi_package = None

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {
            "semgrep": mock_status1,
            "trivy": mock_status2,
            "trufflehog": mock_status3,
        }
        mock_manager.registry.get_tool.side_effect = lambda x: {
            "semgrep": mock_tool_info1,
            "trufflehog": mock_tool_info2,
        }.get(x)

        # Patch ToolManager in tool_manager module where it's imported from
        with patch("scripts.cli.tool_manager.ToolManager", return_value=mock_manager):
            tools = _get_installed_tools()

        # Should return installed tools with their install method; trivy is
        # not installed, so it is not listed.
        assert len(tools) == 2
        assert ("semgrep", "pip") in tools
        assert ("trufflehog", "binary") in tools


class TestUninstallTools:
    """Tests for _uninstall_tools function."""

    def test_uninstall_pip_tools(self):
        """Test uninstalling pip tools."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool = MagicMock()
        mock_tool.pypi_package = "semgrep"

        mock_registry = MagicMock()
        mock_registry.get_tool.return_value = mock_tool

        with (
            patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            # Mock shutil.rmtree to avoid Windows file locking on ~/.jmo/bin/
            with patch("shutil.rmtree"), patch("builtins.print"):
                errors = []
                _uninstall_tools([("semgrep", "pip")], errors)

        assert len(errors) == 0
        mock_run.assert_called()

    def test_uninstall_binary_tools_removes_the_bin_directory(
        self, tmp_path, monkeypatch
    ):
        """Uninstalling a binary tool removes `~/.jmo/bin`, and spawns nothing.

        `Path.home()` is redirected. `_uninstall_tools` ends with

            jmo_bin = Path.home() / ".jmo" / "bin"
            shutil.rmtree(jmo_bin)

        so without redirection this test **deleted the developer's real
        installed security tools** and still passed. Verified by dropping a
        sentinel file into `~/.jmo/bin` and running this test alone: it passed,
        and the directory was gone.

        Its sibling `test_uninstall_pip_tools` patches `shutil.rmtree` with the
        comment "to avoid Windows file locking on ~/.jmo/bin/" - so the hazard
        was known, fixed in one test, and missed in the adjacent one.

        Redirecting home is preferred over patching `shutil.rmtree`: the real
        deletion still runs and is asserted, just against a temporary tree, so
        the test exercises the code path instead of stubbing it out.
        """
        from scripts.cli.tool_commands import _uninstall_tools

        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))
        jmo_bin = tmp_path / ".jmo" / "bin"
        jmo_bin.mkdir(parents=True)
        (jmo_bin / "trufflehog").write_text("binary", encoding="utf-8")

        mock_tool = MagicMock()
        mock_tool.pypi_package = None

        mock_registry = MagicMock()
        mock_registry.get_tool.return_value = mock_tool

        with (
            patch("scripts.cli.tool_commands.ToolRegistry", return_value=mock_registry),
            patch("subprocess.run") as mock_run,
        ):
            mock_run.return_value = MagicMock(returncode=0)
            with patch("builtins.print"):
                errors = []
                _uninstall_tools([("trufflehog", "binary")], errors)

        # A binary tool has no package manager to call: removal is the rmtree.
        mock_run.assert_not_called()
        assert errors == []
        assert not jmo_bin.exists(), "uninstall must remove the bin directory"


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
                        return_value=[("semgrep", "pip"), ("trivy", "binary")],
                    ):
                        result = cmd_tools_uninstall(args)

        assert result == 0


class TestCmdToolsUpdate:
    """Tests for cmd_tools_update function.

    `cmd_tools_update` asks `get_outdated_tools()`. These tests used to stub
    `check_all_tools()` instead, so the real call returned an unconfigured
    MagicMock - truthy, iterating as empty - and the command went on to build
    a real `ToolInstaller` aimed at the developer's `~/.jmo/bin`. They passed
    only because that empty iteration installed nothing. Every path here now
    either stops before the installer or gets a mock one.
    """

    def test_update_all_tools(self):
        """Every outdated tool is reinstalled with force=True."""
        from scripts.cli.installers.models import InstallResult
        from scripts.cli.tool_commands import cmd_tools_update

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = True
        mock_status.installed_version = "0.50.0"
        mock_status.expected_version = "0.74.0"
        mock_status.is_outdated = True
        mock_status.is_critical = False

        mock_manager = MagicMock()
        mock_manager.get_outdated_tools.return_value = [mock_status]

        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = InstallResult(
            tool_name="trivy", success=True, method="binary", version_installed="0.74.0"
        )

        args = argparse.Namespace(tools=None, critical_only=False, yes=True)

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch(
                    "scripts.cli.tool_installer.ToolInstaller",
                    return_value=mock_installer,
                ):
                    with patch("builtins.print"):
                        result = cmd_tools_update(args)

        mock_installer.install_tool.assert_called_once_with("trivy", force=True)
        assert result == 0

    def test_update_no_tools_installed(self):
        """Nothing outdated: the command stops before building an installer."""
        from scripts.cli.tool_commands import cmd_tools_update

        mock_manager = MagicMock()
        mock_manager.get_outdated_tools.return_value = []

        args = argparse.Namespace(tools=None, critical_only=False, yes=True)

        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("scripts.cli.tool_installer.ToolInstaller") as installer_cls:
                    with patch("builtins.print"):
                        result = cmd_tools_update(args)

        installer_cls.assert_not_called()
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
        mock_status.install_hint = "jmo tools install trivy"

        mock_manager = MagicMock()
        mock_manager.get_missing_tools.return_value = [mock_status]
        mock_manager.platform = "macos"

        args = argparse.Namespace(
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
    """`jmo tools check` over the scan matrix: exit code and summary lines.

    Real ToolStatus objects throughout. A MagicMock's `execution_ready` is a
    truthy Mock, so a mocked status can never reach the not-ready branches, and
    an unset `check_matrix` Mock iterates as empty - which let an earlier version
    of the outdated test below pass while checking nothing at all.
    """

    @staticmethod
    def _run(matrix, json_output=False):
        from scripts.cli.tool_commands import cmd_tools_check

        mock_manager = MagicMock()
        mock_manager.check_matrix.return_value = matrix
        mock_manager.check_tool.return_value = _status(POLICY_ENGINE)

        captured: list[str] = []
        with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch(
                    "builtins.print",
                    side_effect=lambda *a, **k: captured.append(
                        " ".join(str(x) for x in a)
                    ),
                ):
                    result = cmd_tools_check(
                        argparse.Namespace(tools=None, json=json_output)
                    )

        mock_manager.check_tool.assert_called_once_with(POLICY_ENGINE)
        return result, "\n".join(captured)

    def test_check_matrix_with_missing_tools(self):
        """A missing matrix tool fails the check and is counted in the summary."""
        result, out = self._run(
            {
                "trivy": _status("trivy"),
                "semgrep": _status(
                    "semgrep", installed=False, installed_version=None, is_critical=True
                ),
            }
        )

        assert "1 tool(s) missing" in out
        assert result == 1

    def test_check_matrix_with_outdated_tools(self):
        """Outdated is a warning, not a failure: exit 0, with the notice printed."""
        result, out = self._run(
            {
                "trivy": _status(
                    "trivy",
                    installed_version="0.40.0",
                    expected_version="0.50.0",
                    is_outdated=True,
                    is_critical=True,
                )
            }
        )

        assert "1 tool(s) outdated (1 critical)" in out
        assert "jmo tools update" in out
        assert result == 0

    def test_check_matrix_json_output(self):
        """`--json` over the matrix prints parseable JSON with each tool's fields."""
        result, out = self._run(
            {
                "trivy": _status(
                    "trivy",
                    installed_version="0.50.0",
                    expected_version="0.50.0",
                    binary_path="/usr/local/bin/trivy",
                )
            },
            json_output=True,
        )

        payload = json.loads(out)
        assert payload["tools"]["trivy"]["installed_version"] == "0.50.0"
        assert payload["tools"]["trivy"]["binary_path"] == "/usr/local/bin/trivy"
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

    def test_debug_tool_found_with_version(self, capsys):
        """Test debug when tool is found and version detected.

        Patches `ToolManager._find_binary` on the class, not the
        `scripts.cli.tool_commands.ToolManager` module attribute. The attribute
        patch is INERT here: `cmd_tools_debug` does its own
        `from scripts.cli.tool_manager import ToolManager` inside the function
        body, so it never reads the module attribute the patch replaced, and
        the real resolver ran (#1021). The assertion is on OUTPUT, because the
        return code is 0 down every one of these paths.
        """
        from scripts.cli.tool_commands import cmd_tools_debug
        from scripts.cli.tool_manager import ToolManager

        args = argparse.Namespace(tools=["trivy"])

        with patch.object(
            ToolManager, "_find_binary", return_value="/usr/local/bin/trivy"
        ):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.return_value = MagicMock(
                        returncode=0, stdout="Version: 0.50.0", stderr=""
                    )
                    result = cmd_tools_debug(args)

        out = capsys.readouterr().out
        assert result == 0
        assert "Binary path: /usr/local/bin/trivy" in out
        assert "NOT FOUND" not in out, "took the not-found path while claiming found"
        assert "Version: 0.50.0" in out

    def test_debug_tool_version_timeout(self, capsys):
        """Test debug when version command times out."""
        import subprocess

        from scripts.cli.tool_commands import cmd_tools_debug
        from scripts.cli.tool_manager import ToolManager

        args = argparse.Namespace(tools=["trivy"])

        with patch.object(
            ToolManager, "_find_binary", return_value="/usr/local/bin/trivy"
        ):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = subprocess.TimeoutExpired("cmd", 10)
                    result = cmd_tools_debug(args)

        out = capsys.readouterr().out
        assert result == 0
        assert "NOT FOUND" not in out, "took the not-found path while claiming found"
        assert "TIMEOUT" in out.upper(), "the timeout branch never reported itself"

    def test_debug_tool_binary_not_found(self, capsys):
        """Test debug when the binary cannot be resolved at all.

        Regression for #1021. This test used to patch
        `scripts.cli.tool_commands.ToolManager` and set `binary_path = None` on
        a mock whose `check_tool` `cmd_tools_debug` never calls. Both were
        inert, so the command resolved and probed the REAL trivy -- the spawn
        recorder caught `['C:\\\\Users\\\\...\\\\trivy.exe', '--version']` -- and
        the single `result == 0` assertion passed either way. On a machine
        without trivy it exercised the not-found path; on one with trivy, the
        found path. Nothing declared which.

        `NOT FOUND` is the discriminator: it is printed only on the branch this
        test is named for, and that branch `continue`s before any spawn.
        """
        from scripts.cli.tool_commands import cmd_tools_debug
        from scripts.cli.tool_manager import ToolManager

        args = argparse.Namespace(tools=["trivy"])

        with patch.object(ToolManager, "_find_binary", return_value=None):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                result = cmd_tools_debug(args)

        out = capsys.readouterr().out
        assert result == 0
        assert "Binary path: NOT FOUND" in out
        assert "could not be found in PATH" in out
        assert "--- Running version command ---" not in out, (
            "the not-found branch must `continue` before the version probe; "
            "reaching it means a real binary was resolved"
        )

    def test_debug_tool_permission_error(self, capsys):
        """Test debug when permission error executing binary."""
        from scripts.cli.tool_commands import cmd_tools_debug
        from scripts.cli.tool_manager import ToolManager

        # cmd_tools_debug makes TWO subprocess calls: `file` on the binary,
        # then the version command.
        mock_file_result = MagicMock(returncode=0, stdout="executable")

        args = argparse.Namespace(tools=["trivy"])

        with patch.object(
            ToolManager, "_find_binary", return_value="/usr/local/bin/trivy"
        ):
            with patch(
                "scripts.cli.tool_commands.colorize", side_effect=lambda x, _: x
            ):
                with patch("subprocess.run") as mock_run:
                    mock_run.side_effect = [
                        mock_file_result,
                        PermissionError("Access denied"),
                    ]
                    result = cmd_tools_debug(args)

        out = capsys.readouterr().out
        assert result == 0
        assert "NOT FOUND" not in out, "took the not-found path while claiming found"
        assert "PERMISSION" in out.upper(), (
            "the permission branch never reported itself"
        )


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

    def test_install_executes_installer_for_the_matrix_and_policy_engine(self, capsys):
        """A bare `jmo tools install` asks for every scanner plus the policy
        engine, and installs what is missing in parallel.

        opa is in the request because policy evaluation is on by default
        (`jmo.yml policy.auto_evaluate`); a default install without it would
        leave that step nothing to run.
        """
        from scripts.cli.tool_commands import cmd_tools_install

        mock_status = MagicMock()
        mock_status.name = "trivy"
        mock_status.installed = False
        mock_status.is_critical = True
        mock_status.install_hint = "jmo tools install trivy"

        mock_manager = MagicMock()
        mock_manager.get_missing_tools.return_value = [mock_status]
        mock_manager.platform = "macos"

        mock_progress = MagicMock()
        mock_progress.failed = 0
        mock_progress.successful = 1

        mock_installer = MagicMock()
        mock_installer.install_tools_parallel.return_value = mock_progress

        # A Namespace, not a MagicMock: a Mock's `sequential` is truthy, which
        # would route this into the sequential branch.
        args = argparse.Namespace(
            tools=None,
            print_script=False,
            dry_run=False,
            yes=True,
            sequential=False,
            jobs=4,
        )

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
        mock_manager.get_missing_tools.assert_called_once_with(
            [*TOOL_MATRIX, POLICY_ENGINE]
        )
        mock_installer.install_tools_parallel.assert_called_once()
        assert mock_installer.install_tools_parallel.call_args.args[0] == ["trivy"]

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
        mock_installer.install_tools_parallel.return_value = mock_progress

        args = argparse.Namespace(
            tools=None,
            print_script=False,
            dry_run=False,
            yes=True,
            sequential=False,
            jobs=4,
        )

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

        mock_installer.install_tools_parallel.assert_called_once()
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


# ========== Category: cmd_tools_uninstall Tool Types ==========


class TestCmdToolsUninstallToolTypes:
    """`jmo tools uninstall`'s listing, exercised against a real tree.

    These four used to patch `scripts.cli.tool_commands.Path` and assert only
    the return code. **The patch never applied.** `cmd_tools_uninstall` carried
    its own `from pathlib import Path`, which makes `Path` a *local* of the
    function (`"Path" in cmd_tools_uninstall.__code__.co_varnames` is True), so
    the module attribute the patch replaced was never read.

    They passed in CI for the wrong reason: a runner has no `~/.jmo`, so
    `jmo_dir.exists()` was False and the loop under test never ran. On a machine
    that has actually run `jmo tools install`, they walked the real 165,419-file
    tree and tripped `--timeout=60` - and pytest-timeout's `thread` method kills
    the session on Windows, so they took the other 2,153 `tests/cli` tests with
    them (#1207).

    The redundant local import is gone and these now point `Path.home()` at
    `tmp_path` and assert on what is printed.
    """

    @staticmethod
    def _home(tmp_path, monkeypatch):
        """Point `Path.home()` at `tmp_path` and keep the pip probe off the wire."""
        monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path))
        monkeypatch.setattr(
            "scripts.cli.tool_commands._check_pip_package", lambda _pkg: False
        )

    @staticmethod
    def _args(**kw):
        args = argparse.Namespace(all=False, dry_run=True, yes=True)
        for k, v in kw.items():
            setattr(args, k, v)
        return args

    def test_a_directory_is_listed_without_a_size_and_a_file_with_one(
        self, capsys, tmp_path, monkeypatch
    ):
        """The size is what cost 89 s, and only for directories.

        A file's size is one `stat()` and exact, so it stays. A directory's
        meant `rglob("*")` over everything beneath it.
        """
        jmo = tmp_path / ".jmo"
        (jmo / "tools").mkdir(parents=True)
        (jmo / "tools" / "vendored.py").write_text("x" * 100)
        (jmo / "config.yml").write_text("a: 1")
        self._home(tmp_path, monkeypatch)

        assert cmd_tools_uninstall(self._args()) == 0

        out = capsys.readouterr().out
        assert "  - tools/" in out, out
        assert "  - config.yml (4 B)" in out, out
        # The directory's own contents must not be summed into a size.
        assert "tools/ (" not in out, out

    def test_the_listing_never_walks_into_a_directory(
        self, capsys, tmp_path, monkeypatch
    ):
        """Make recursion fatal rather than timing it.

        Asserting on wall-clock would be a benchmark, and a benchmark taken on
        one machine is the mistake #1120 was about - it would pass on a CI
        runner with an empty `~/.jmo` no matter what the code did. This asserts
        the *mechanism*: if the listing ever recurses again, `rglob` raises and
        this fails in milliseconds, on any machine.
        """
        jmo = tmp_path / ".jmo"
        (jmo / "tools" / "venvs" / "checkov").mkdir(parents=True)
        (jmo / "tools" / "venvs" / "checkov" / "pkg.py").write_text("x")
        self._home(tmp_path, monkeypatch)

        def _no_recursion(*_a, **_k):
            raise AssertionError(
                "the uninstall listing must not walk directory contents (#1207)"
            )

        monkeypatch.setattr(Path, "rglob", _no_recursion)

        assert cmd_tools_uninstall(self._args()) == 0
        assert "  - tools/" in capsys.readouterr().out

    def test_uninstall_all_groups_installed_tools_by_install_method(
        self, capsys, tmp_path, monkeypatch
    ):
        """--all lists what would go, grouped by how it was installed."""
        (tmp_path / ".jmo").mkdir()
        self._home(tmp_path, monkeypatch)
        monkeypatch.setattr(
            "scripts.cli.tool_commands._get_installed_tools",
            lambda: [
                ("trivy", "binary"),
                ("semgrep", "pip"),
                ("trufflehog", "binary"),
                ("checkov", "pip"),
            ],
        )

        assert cmd_tools_uninstall(self._args(all=True)) == 0

        out = capsys.readouterr().out
        assert "binary: trivy, trufflehog" in out, out
        assert "pip: semgrep, checkov" in out, out

    def test_the_function_does_not_shadow_the_module_level_Path(self):
        """A local `from pathlib import Path` silently disables patching.

        This is not style. `cmd_tools_uninstall` used to re-import `Path`
        inside its own body, which makes `Path` a *local* of the function, so
        `patch("scripts.cli.tool_commands.Path")` replaced a module attribute
        the function never read. Four tests in this class were written against
        that patch and asserted only a return code, so they passed everywhere
        while exercising nothing - and on a machine that had actually run
        `jmo tools install` they walked the real 165,419-file `~/.jmo` and
        tripped the 60 s timeout, taking the whole session with them (#1207).

        The tests above are immune because they patch `Path.home` on the class
        rather than the module attribute, which is why a mutation restoring the
        local import survived them. This asserts the shape directly, so the
        next person who adds one is told why not.
        """
        assert "Path" not in cmd_tools_uninstall.__code__.co_varnames, (
            "cmd_tools_uninstall re-imports Path into its own scope; that makes "
            "patch('scripts.cli.tool_commands.Path') a no-op (#1207)"
        )

    def test_uninstall_all_says_so_when_no_tools_are_found(
        self, capsys, tmp_path, monkeypatch
    ):
        (tmp_path / ".jmo").mkdir()
        self._home(tmp_path, monkeypatch)
        monkeypatch.setattr("scripts.cli.tool_commands._get_installed_tools", list)

        assert cmd_tools_uninstall(self._args(all=True)) == 0
        assert "No JMo-managed tools found" in capsys.readouterr().out


# ========== Category: _get_installed_tools Tool Types ==========


class TestGetInstalledToolsTypes:
    """Test _get_installed_tools with different tool types."""

    def test_get_installed_tools_non_pip_tool_is_binary(self):
        """A tool with no PyPI package is JMo's pinned binary download."""
        from scripts.cli.tool_commands import _get_installed_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None

        mock_manager = MagicMock()
        mock_manager.check_all_tools.return_value = {"trivy": MagicMock(installed=True)}
        mock_manager.registry.get_tool.return_value = mock_tool_info

        # Patch at the import location inside the function
        with patch("scripts.cli.tool_manager.ToolManager", return_value=mock_manager):
            tools = _get_installed_tools()

        assert tools == [("trivy", "binary")]

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

    @pytest.fixture(autouse=True)
    def _isolate_home(self, tmp_path, monkeypatch):
        """Keep these tests away from the developer's real installation.

        `_uninstall_tools` ends with
        `shutil.rmtree(Path.home() / ".jmo" / "bin")`. Every test in this class
        calls it, so without redirection the whole class deletes the real tool
        directory - and passes while doing it. Verified by placing a sentinel in
        `~/.jmo/bin` and running this class alone: green, and the directory gone.

        Applied class-wide rather than per test so a test added later is covered
        by construction.

        `monkeypatch.setattr(Path, "home", ...)`, never
        `monkeypatch.setenv("HOME", ...)` - the latter has no effect on
        `Path.home()` on Windows (see
        .claude/rules/testing.cross-platform.rules.md).
        """
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

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

    def test_uninstall_tools_binary_removal(self, capsys, tmp_path):
        """Test _uninstall_tools binary removal."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None

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
                mock_path.home.return_value.__truediv__.return_value.__truediv__.return_value = mock_bin

                with patch("shutil.rmtree"):
                    _uninstall_tools([("trivy", "binary")], errors)

        assert len(errors) == 0

    def test_uninstall_tools_binary_removal_error(self, capsys):
        """Test _uninstall_tools binary removal with error."""
        from scripts.cli.tool_commands import _uninstall_tools

        mock_tool_info = MagicMock()
        mock_tool_info.pypi_package = None

        errors = []

        with patch("scripts.cli.tool_commands.ToolRegistry") as mock_registry_cls:
            mock_registry = MagicMock()
            mock_registry.get_tool.return_value = mock_tool_info
            mock_registry_cls.return_value = mock_registry

            with patch("scripts.cli.tool_commands.Path") as mock_path:
                mock_bin = MagicMock()
                mock_bin.exists.return_value = True
                mock_path.home.return_value.__truediv__.return_value.__truediv__.return_value = mock_bin

                with patch(
                    "shutil.rmtree", side_effect=PermissionError("Access denied")
                ):
                    _uninstall_tools([("trivy", "binary")], errors)

        assert len(errors) == 1
        assert "binary removal" in errors[0]


def test_a_genuinely_missing_tool_still_reports_missing():
    """A tool that is not installed is counted, named with the installer
    command that fixes it, and fails the check."""
    from scripts.cli.tool_commands import cmd_tools_check
    from scripts.cli.tool_manager import ToolStatus, ToolStatusType

    status = ToolStatus(name="trivy", installed=False)
    assert status.status_type is ToolStatusType.MISSING

    mock_manager = MagicMock()
    mock_manager.check_tool.return_value = status
    args = argparse.Namespace(tools=["trivy"], json=False)

    printed = []
    with (
        patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager),
        patch("scripts.cli.tool_commands.print_tool_status_table"),
        patch(
            "builtins.print",
            side_effect=lambda *a, **k: printed.append(" ".join(str(x) for x in a)),
        ),
    ):
        result = cmd_tools_check(args)

    text = chr(10).join(printed)
    assert "1 tool(s) missing" in text
    assert "jmo tools install" in text
    assert result == 1


# ========== #1136: installed-but-unable-to-run reaches the summary ==========


def _check_with(statuses):
    """Run cmd_tools_check over real ToolStatus objects, capturing stdout.

    Real objects, not MagicMocks: a MagicMock's `.execution_ready` is a Mock
    and therefore truthy, so a mocked status can never exercise this path.
    """
    import io
    from contextlib import redirect_stdout

    from scripts.cli.tool_commands import cmd_tools_check

    mock_manager = MagicMock()
    mock_manager.check_tool.side_effect = lambda name: statuses[name]

    args = argparse.Namespace(tools=list(statuses), json=False)

    buf = io.StringIO()
    with patch("scripts.cli.tool_commands.ToolManager", return_value=mock_manager):
        with redirect_stdout(buf):
            result = cmd_tools_check(args)
    return result, buf.getvalue()


def _status(name, **kw):
    from scripts.cli.tool_manager import ToolStatus

    kw.setdefault("installed", True)
    kw.setdefault("installed_version", "1.0.0")
    kw.setdefault("expected_version", "1.0.0")
    return ToolStatus(name=name, **kw)


def test_tools_check_names_a_tool_that_cannot_run():
    """Measured with `java` hidden from PATH: `jmo tools check` printed a
    Java-dependent tool (dependency-check, since removed) as
    `OK  -  12.1.0`, then `All tools installed and up to date!`, and exited 0 -
    while every scan using it exited 1 and wrote no output. zap is the Java
    tool that remains."""
    statuses = {
        "zap": _status(
            "zap",
            installed_version=None,
            expected_version="2.16.1",
            execution_ready=False,
            execution_warning="Missing: java",
        )
    }

    result, out = _check_with(statuses)

    assert "not able to run" in out
    assert "Missing: java" in out
    assert result == 1


def test_tools_check_does_not_claim_all_is_well():
    """The green all-clear must not print over a tool that cannot run."""
    statuses = {
        "zap": _status(
            "zap",
            execution_ready=False,
            execution_warning="Missing: java",
        )
    }

    _, out = _check_with(statuses)

    assert "All tools installed and up to date!" not in out


def test_tools_check_is_unchanged_when_everything_can_run():
    """The regression guard: a fully working install still exits 0 and still
    prints the all-clear."""
    statuses = {"trivy": _status("trivy")}

    result, out = _check_with(statuses)

    assert result == 0
    assert "All tools installed and up to date!" in out
    assert "not able to run" not in out
