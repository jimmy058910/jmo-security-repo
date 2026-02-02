#!/usr/bin/env python3
"""
HV: Help and Version Tests for JMo Security CLI.

Tests verify that --version and --help commands work correctly
for all command groups.
"""

from __future__ import annotations

import re


class TestHelpVersion:
    """Test suite for help and version output (HV-001 to HV-008)."""

    def test_hv_001_version_output(self, jmo_runner):
        """HV-001: jmo --version shows version string."""
        result = jmo_runner(["--version"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Version should be in stdout
        version_pattern = r"\d+\.\d+\.\d+"
        assert re.search(
            version_pattern, result.stdout
        ), f"Version pattern not found in output: {result.stdout}"

    def test_hv_002_main_help(self, jmo_runner):
        """HV-002: jmo --help shows all command groups."""
        result = jmo_runner(["--help"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should list main commands
        output = result.stdout.lower()
        assert "scan" in output, "Missing 'scan' in help"
        assert "report" in output, "Missing 'report' in help"
        assert "tools" in output, "Missing 'tools' in help"

    def test_hv_003_scan_help(self, jmo_runner):
        """HV-003: jmo scan --help shows scan options."""
        result = jmo_runner(["scan", "--help"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        # Check for key scan options
        assert "--repo" in output or "repo" in output, "Missing repo option"
        assert "--profile" in output or "profile" in output, "Missing profile option"

    def test_hv_004_report_help(self, jmo_runner):
        """HV-004: jmo report --help shows report options."""
        result = jmo_runner(["report", "--help"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        # Report command shows output directory and policy options
        assert "--out" in output or "--results-dir" in output, "Missing output option"

    def test_hv_005_tools_help(self, jmo_runner):
        """HV-005: jmo tools --help shows tool management commands."""
        result = jmo_runner(["tools", "--help"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        assert "check" in output, "Missing 'check' subcommand"
        assert "list" in output, "Missing 'list' subcommand"
        assert "install" in output, "Missing 'install' subcommand"

    def test_hv_006_history_help(self, jmo_runner):
        """HV-006: jmo history --help shows history commands."""
        result = jmo_runner(["history", "--help"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        assert "list" in output, "Missing 'list' subcommand"

    def test_hv_007_diff_help(self, jmo_runner):
        """HV-007: jmo diff --help shows diff options."""
        result = jmo_runner(["diff", "--help"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        assert "--format" in output or "format" in output, "Missing format option"

    def test_hv_008_policy_help(self, jmo_runner):
        """HV-008: jmo policy --help shows policy commands."""
        result = jmo_runner(["policy", "--help"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        # Policy commands
        assert "list" in output or "validate" in output, "Missing policy subcommands"


class TestHelpOutputQuality:
    """Additional tests for help output quality."""

    def test_help_has_description(self, jmo_runner):
        """Help output includes a description of the tool."""
        result = jmo_runner(["--help"])

        assert result.returncode == 0
        # Should have some description text
        assert len(result.stdout) > 100, "Help output too short"

    def test_help_lists_available_commands(self, jmo_runner):
        """Help output lists available commands."""
        result = jmo_runner(["--help"])

        assert result.returncode == 0
        # Should mention multiple commands
        command_count = sum(
            1
            for cmd in ["scan", "report", "tools", "history", "diff"]
            if cmd in result.stdout.lower()
        )
        assert command_count >= 3, "Not enough commands listed in help"

    def test_version_no_error_output(self, jmo_runner):
        """--version should not produce error output."""
        result = jmo_runner(["--version"])

        assert result.returncode == 0
        # stderr should be empty or only contain warnings
        if result.stderr:
            # Allow deprecation warnings but not errors
            assert (
                "error" not in result.stderr.lower()
            ), f"Error in stderr: {result.stderr}"
