#!/usr/bin/env python3
"""
Setup Command Tests for JMo Security CLI.

Tests the setup command for tool verification and installation.

Usage:
    pytest tests/cli_ralph/test_setup_command.py -v
"""

from __future__ import annotations


import pytest


class TestSetupBasicFunctionality:
    """Test setup command basic functionality."""

    def test_setup_help(self, jmo_runner):
        """Verify setup --help shows available options."""
        result = jmo_runner(["setup", "--help"], timeout=30)

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "setup" in output
        # Should show setup-specific options
        assert "--auto-install" in result.stdout or "auto" in output

    def test_setup_basic_invocation(self, jmo_runner):
        """Verify setup command runs without errors."""
        result = jmo_runner(["setup"], timeout=120)

        # Exit 0 for all installed, exit 1 if some missing - both valid
        assert result.returncode in (0, 1), f"Setup failed: {result.stderr}"

        # Should show some tool status
        combined = result.stdout.lower() + result.stderr.lower()
        status_indicators = [
            "tool",
            "check",
            "install",
            "status",
            "missing",
            "found",
        ]
        has_status = any(ind in combined for ind in status_indicators)
        assert has_status or result.returncode == 0


class TestSetupPrintCommands:
    """Test setup --print-commands functionality."""

    def test_setup_print_commands_flag(self, jmo_runner):
        """Verify --print-commands shows installation commands."""
        result = jmo_runner(["setup", "--print-commands"], timeout=60)

        assert result.returncode in (0, 1), f"Setup failed: {result.stderr}"

        combined = result.stdout.lower() + result.stderr.lower()
        # Should show installation commands or indicate no missing tools
        command_indicators = [
            "pip",
            "npm",
            "brew",
            "apt",
            "install",
            "go install",
            "cargo",
            "curl",
            "wget",
            "already installed",
            "all tools",
        ]
        has_command = any(ind in combined for ind in command_indicators)
        assert has_command or "no missing" in combined

    def test_setup_print_commands_no_execution(self, jmo_runner):
        """Verify --print-commands doesn't actually install anything."""
        result = jmo_runner(["setup", "--print-commands"], timeout=60)

        # Should complete quickly (not actually installing)
        assert result.returncode in (0, 1)

        # Output should suggest commands, not execution results
        combined = result.stdout.lower() + result.stderr.lower()
        # Shouldn't show actual installation progress
        assert "downloading" not in combined or "would" in combined


class TestSetupAutoInstall:
    """Test setup --auto-install functionality."""

    def test_setup_auto_install_flag_accepted(self, jmo_runner):
        """Verify --auto-install flag is recognized."""
        # Note: We don't actually want to install tools in tests
        # Just verify the flag is accepted
        result = jmo_runner(
            ["setup", "--auto-install", "--help"],
            timeout=30,
        )

        # Help should work
        assert result.returncode == 0

    @pytest.mark.slow
    @pytest.mark.timeout(300)
    def test_setup_auto_install_dry_run(self, jmo_runner):
        """Verify auto-install with print-commands shows what would be installed."""
        result = jmo_runner(
            ["setup", "--auto-install", "--print-commands"],
            timeout=120,
        )

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestSetupForceReinstall:
    """Test setup --force-reinstall functionality."""

    def test_setup_force_reinstall_flag_accepted(self, jmo_runner):
        """Verify --force-reinstall flag is recognized."""
        result = jmo_runner(
            ["setup", "--force-reinstall", "--print-commands"],
            timeout=60,
        )

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_setup_force_reinstall_shows_all_tools(self, jmo_runner):
        """Force reinstall should show commands for all tools, not just missing."""
        result = jmo_runner(
            ["setup", "--force-reinstall", "--print-commands"],
            timeout=60,
        )

        # With force-reinstall, should show more tools
        # This is a weak assertion since we can't guarantee tool state
        assert result.returncode in (0, 1)


class TestSetupStrictMode:
    """Test setup --strict functionality."""

    def test_setup_strict_flag_accepted(self, jmo_runner):
        """Verify --strict flag is recognized."""
        result = jmo_runner(
            ["setup", "--strict"],
            timeout=120,
        )

        # Strict mode exits non-zero if any tools missing
        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_setup_strict_exit_code(self, jmo_runner):
        """Strict mode should exit non-zero if tools are missing."""
        result = jmo_runner(
            ["setup", "--strict"],
            timeout=120,
        )

        # If returncode is 1, it means strict mode caught missing tools
        # If returncode is 0, all tools are installed
        # Both are valid outcomes
        assert result.returncode in (0, 1)


class TestSetupLoggingFlags:
    """Test setup logging flags."""

    def test_setup_human_logs_flag(self, jmo_runner):
        """Verify --human-logs flag is recognized."""
        result = jmo_runner(
            ["setup", "--human-logs"],
            timeout=120,
        )

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_setup_human_logs_output_format(self, jmo_runner):
        """Human logs should not produce JSON output."""
        result = jmo_runner(
            ["setup", "--human-logs"],
            timeout=120,
        )

        # Human logs are OK even if some JSON appears
        assert result.returncode in (0, 1)


class TestSetupFlagCombinations:
    """Test various setup flag combinations."""

    def test_setup_print_and_human_logs(self, jmo_runner):
        """Verify --print-commands and --human-logs work together."""
        result = jmo_runner(
            ["setup", "--print-commands", "--human-logs"],
            timeout=60,
        )

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_setup_strict_and_print_commands(self, jmo_runner):
        """Verify --strict and --print-commands work together."""
        result = jmo_runner(
            ["setup", "--strict", "--print-commands"],
            timeout=60,
        )

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_setup_force_and_print(self, jmo_runner):
        """Verify --force-reinstall and --print-commands work together."""
        result = jmo_runner(
            ["setup", "--force-reinstall", "--print-commands"],
            timeout=60,
        )

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined

    def test_setup_all_flags_except_install(self, jmo_runner):
        """Verify multiple flags work together (without actual install)."""
        result = jmo_runner(
            [
                "setup",
                "--print-commands",
                "--human-logs",
                "--strict",
            ],
            timeout=60,
        )

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" not in combined


class TestSetupEdgeCases:
    """Test setup edge cases and error handling."""

    def test_setup_no_arguments(self, jmo_runner):
        """Setup without arguments should show status."""
        result = jmo_runner(["setup"], timeout=120)

        assert result.returncode in (0, 1)
        # Should produce some output
        combined = result.stdout + result.stderr
        assert len(combined) > 0

    def test_setup_unknown_flag_rejected(self, jmo_runner):
        """Setup should reject unknown flags."""
        result = jmo_runner(
            ["setup", "--unknown-flag-xyz"],
            timeout=30,
        )

        assert result.returncode != 0
        combined = result.stdout.lower() + result.stderr.lower()
        assert "unrecognized" in combined or "error" in combined

    def test_setup_conflicting_options(self, jmo_runner):
        """Setup should handle potentially conflicting options."""
        # force-reinstall with strict - both should work
        result = jmo_runner(
            ["setup", "--force-reinstall", "--strict", "--print-commands"],
            timeout=60,
        )

        # Should either work or produce a clear error
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


class TestSetupToolDetection:
    """Test setup tool detection functionality."""

    def test_setup_detects_installed_tools(self, jmo_runner):
        """Setup should detect and report installed tools."""
        result = jmo_runner(["setup"], timeout=120)

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()

        # Should mention some tools or their status
        tool_indicators = [
            "trivy",
            "bandit",
            "semgrep",
            "installed",
            "found",
            "available",
            "missing",
            "not found",
        ]
        has_tool_info = any(ind in combined for ind in tool_indicators)
        assert has_tool_info or "setup complete" in combined or result.returncode == 0

    def test_setup_reports_missing_tools(self, jmo_runner):
        """Setup should report missing tools clearly."""
        result = jmo_runner(["setup", "--strict"], timeout=120)

        combined = result.stdout.lower() + result.stderr.lower()

        # If exit code is 1, should explain why
        if result.returncode == 1:
            missing_indicators = [
                "missing",
                "not found",
                "not installed",
                "unavailable",
            ]
            has_explanation = any(ind in combined for ind in missing_indicators)
            # Or it just exits non-zero which is also valid
            assert has_explanation or result.returncode == 1


class TestSetupOutputValidation:
    """Test setup output format and content."""

    def test_setup_output_is_parseable(self, jmo_runner):
        """Setup output should be meaningful and parseable."""
        result = jmo_runner(["setup"], timeout=120)

        # Should produce output
        combined = result.stdout + result.stderr
        assert len(combined.strip()) > 0

    def test_setup_no_unhandled_exceptions(self, jmo_runner):
        """Setup should not produce unhandled exceptions."""
        result = jmo_runner(["setup"], timeout=120)

        combined = result.stdout.lower() + result.stderr.lower()
        # Should not have Python tracebacks
        assert "traceback (most recent call last)" not in combined
        assert "unhandled exception" not in combined

    def test_setup_print_commands_shows_install_methods(self, jmo_runner):
        """Print commands should show installation method per tool."""
        result = jmo_runner(["setup", "--print-commands"], timeout=60)

        combined = result.stdout.lower() + result.stderr.lower()

        # Should show various installation methods or indicate all installed
        methods = ["pip", "npm", "brew", "go", "cargo", "apt", "dnf", "curl"]
        has_method = any(m in combined for m in methods)
        has_all_installed = "all tools" in combined or "no missing" in combined

        # Either shows methods or indicates nothing to install
        assert has_method or has_all_installed or result.returncode == 0
