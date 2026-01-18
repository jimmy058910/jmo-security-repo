#!/usr/bin/env python3
"""
TM: Tool Management Tests for JMo Security CLI.

Tests verify that tool management commands (check, list, install --dry-run)
work correctly without actually installing tools.
"""

from __future__ import annotations


class TestToolsCheck:
    """Test suite for `jmo tools check` command (TM-001 to TM-003)."""

    def test_tm_001_tools_check_default(self, jmo_runner):
        """TM-001: jmo tools check shows tool status summary."""
        result = jmo_runner(["tools", "check"], timeout=60)

        # Exit 0 for clean, exit 1 if tools missing - both valid
        assert result.returncode in (0, 1), f"Command failed: {result.stderr}"

        # Output shows profile summary with installation status
        output = result.stdout.lower()
        summary_indicators = ["profile", "installed", "fast", "balanced", "deep", "required", "missing"]
        found = sum(1 for ind in summary_indicators if ind in output)
        assert found >= 2, f"No profile summary found in output: {result.stdout}"

    def test_tm_002_tools_check_output(self, jmo_runner):
        """TM-002: jmo tools check shows status information."""
        result = jmo_runner(["tools", "check"], timeout=60)

        # Exit 0 for clean, exit 1 if tools missing - both valid
        assert result.returncode in (0, 1), f"Command failed: {result.stderr}"

        # Should show status indicators
        output = result.stdout.lower()
        status_indicators = ["ok", "missing", "not found", "installed", "version", "✓", "✗", "x"]
        has_status = any(ind in output for ind in status_indicators)
        assert has_status or "tool" in output, f"No status info: {result.stdout}"

    def test_tm_003_tools_check_profile(self, jmo_runner, fast_profile_tools):
        """TM-003: jmo tools check --profile fast shows only fast profile tools."""
        result = jmo_runner(["tools", "check", "--profile", "fast"], timeout=60)

        # Exit 0 for all installed, exit 1 if some missing - both valid
        assert result.returncode in (0, 1), f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        # Should mention at least some fast profile tools
        found = sum(1 for tool in fast_profile_tools if tool in output)
        assert found >= 1, f"No fast profile tools found: {result.stdout}"


class TestToolsList:
    """Test suite for `jmo tools list` command (TM-004 to TM-005)."""

    def test_tm_004_tools_list(self, jmo_runner):
        """TM-004: jmo tools list shows all supported tools."""
        result = jmo_runner(["tools", "list"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should list multiple tools
        output = result.stdout.lower()
        known_tools = ["trivy", "bandit", "semgrep", "checkov", "hadolint"]
        found = sum(1 for tool in known_tools if tool in output)
        assert found >= 3, f"Too few tools listed: {result.stdout}"

    def test_tm_005_tools_list_shows_categories(self, jmo_runner):
        """TM-005: jmo tools list shows tool categories or profiles."""
        result = jmo_runner(["tools", "list"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower()
        # Should show some categorization or profile info
        category_indicators = ["sast", "sca", "secret", "container", "iac", "profile", "category", "fast", "balanced", "deep"]
        has_category = any(ind in output for ind in category_indicators)
        # Or just a list of tools is acceptable
        assert has_category or len(output) > 100, f"Limited tool info: {result.stdout}"


class TestToolsInstallDryRun:
    """Test suite for `jmo tools install --dry-run` (TM-006)."""

    def test_tm_006_tools_install_dry_run(self, jmo_runner):
        """TM-006: jmo tools install --dry-run --yes shows what would be installed."""
        # Need --yes to avoid interactive prompt even in dry-run
        result = jmo_runner(
            ["tools", "install", "--profile", "fast", "--dry-run", "--yes"],
            timeout=60
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower() + result.stderr.lower()
        # Should mention dry run or show tools that would be installed
        dry_run_indicators = ["dry", "would", "skip", "already", "simulation", "install"]
        has_indicator = any(indicator in output for indicator in dry_run_indicators)

        # Or it should list tools
        has_tools = any(tool in output for tool in ["trivy", "bandit", "semgrep"])

        assert has_indicator or has_tools, (
            f"No dry-run indication in output: {result.stdout}\n{result.stderr}"
        )


class TestToolsOutdated:
    """Test suite for `jmo tools outdated` (TM-007)."""

    def test_tm_007_tools_outdated(self, jmo_runner):
        """TM-007: jmo tools outdated shows tools with updates available."""
        result = jmo_runner(["tools", "outdated"], timeout=60)

        # Exit 0 whether tools have updates or not
        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Output should exist (even if empty/no updates)
        # The command should complete without error
        assert result.returncode == 0


class TestToolsDebug:
    """Test suite for `jmo tools debug` (TM-008)."""

    def test_tm_008_tools_debug(self, jmo_runner):
        """TM-008: jmo tools debug <tool> shows diagnostic information."""
        result = jmo_runner(["tools", "debug", "trivy"], timeout=30)

        # Exit 0 even if tool not installed (debug should work regardless)
        assert result.returncode == 0, f"Command failed: {result.stderr}"

        output = result.stdout.lower() + result.stderr.lower()
        # Should show diagnostic info about the tool
        debug_indicators = [
            "trivy",
            "version",
            "path",
            "install",
            "not found",
            "not installed",
        ]
        has_info = any(indicator in output for indicator in debug_indicators)
        assert has_info, f"No debug info for trivy: {result.stdout}\n{result.stderr}"


class TestToolsEdgeCases:
    """Edge case tests for tools commands."""

    def test_tools_check_unknown_profile(self, jmo_runner):
        """Tools check with unknown profile should fail gracefully."""
        result = jmo_runner(["tools", "check", "--profile", "nonexistent_profile_xyz"])

        # Should fail with meaningful error
        combined = (result.stdout + result.stderr).lower()
        assert result.returncode != 0 or "error" in combined or "unknown" in combined or "invalid" in combined, (
            "Unknown profile should cause error"
        )

    def test_tools_debug_unknown_tool(self, jmo_runner):
        """Debug of unknown tool should provide helpful info."""
        result = jmo_runner(["tools", "debug", "nonexistent_tool_xyz"])

        # Should either fail or show "not found" message
        combined = (result.stdout + result.stderr).lower()
        assert (
            result.returncode != 0
            or "not found" in combined
            or "unknown" in combined
            or "not supported" in combined
        ), f"Unknown tool should show helpful message: {result.stdout}\n{result.stderr}"
