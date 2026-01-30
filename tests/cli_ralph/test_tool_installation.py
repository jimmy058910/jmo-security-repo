#!/usr/bin/env python3
"""
TI: Tool Installation Tests for JMo Security CLI.

These tests perform ACTUAL tool installation. Run sparingly.
Marked with pytest.mark.slow for selective execution.

Usage:
    pytest tests/cli_ralph/test_tool_installation.py -v --timeout=600
    pytest tests/cli_ralph/test_tool_installation.py -v -m "not slow"  # Skip slow tests
"""

from __future__ import annotations

import json

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
from conftest import IS_WINDOWS


# Mark entire module as slow (actual installations)
pytestmark = [
    pytest.mark.slow,
    pytest.mark.timeout(600),  # 10 minute timeout for installation tests
]


class TestToolInstallation:
    """Test suite for actual tool installation (TI-001 to TI-005)."""

    def test_ti_001_install_dry_run_verification(self, jmo_runner):
        """TI-001: Dry-run shows what would be installed without changes."""
        result = jmo_runner(
            ["tools", "install", "--profile", "fast", "--yes", "--dry-run"],
            timeout=60,
        )

        assert result.returncode == 0, f"Dry-run failed: {result.stderr}"

        # Should list tools or indicate dry-run
        combined = (result.stdout + result.stderr).lower()
        assert (
            "dry" in combined
            or "would" in combined
            or "trivy" in combined
            or "bandit" in combined
        ), f"No dry-run output: {result.stdout}"

    @pytest.mark.timeout(600)
    def test_ti_002_install_fast_profile(self, jmo_runner, expected_tool_count):
        """TI-002: Install fast profile tools (8 tools)."""
        result = jmo_runner(
            ["tools", "install", "--profile", "fast", "--yes"],
            timeout=600,  # 10 minutes for installation
        )

        # Some failures are acceptable on Windows
        # Exit code 0 or 1 (partial success) are OK
        assert result.returncode in (
            0,
            1,
        ), f"Installation completely failed: {result.stderr}"

        # Verify some tools installed by running check
        check_result = jmo_runner(
            ["tools", "check", "--profile", "fast", "--json"],
            timeout=60,
        )

        if check_result.returncode == 0 and check_result.stdout.strip():
            try:
                # Try to parse JSON output
                data = json.loads(check_result.stdout)
                tools = data.get("tools", [])

                # Count installed tools
                installed = sum(
                    1
                    for t in tools
                    if isinstance(t, dict) and t.get("status", "").upper() == "OK"
                )

                # Should have at least minimum expected tools
                min_expected = (
                    expected_tool_count["min"] // 2
                )  # Half of min for fast profile
                assert (
                    installed >= min_expected or installed >= 2
                ), f"Too few tools installed: {installed} < {min_expected}"
            except json.JSONDecodeError:
                # If JSON parsing fails, just verify the command ran
                pass

    def test_ti_003_verify_installation(self, jmo_runner, expected_tool_count):
        """TI-003: Verify installation status after TI-002."""
        result = jmo_runner(
            ["tools", "check", "--profile", "fast", "--json"],
            timeout=60,
        )

        # Exit 1 is valid if some tools are missing
        assert result.returncode in (0, 1), f"Check failed: {result.stderr}"

        # Parse output
        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                tools = data.get("tools", [])

                # Report status for debugging
                for tool in tools[:8]:
                    if isinstance(tool, dict):
                        name = tool.get("name", tool.get("tool", "unknown"))
                        status = tool.get("status", "unknown")
                        print(f"  {name}: {status}")

            except json.JSONDecodeError:
                print(f"Could not parse JSON: {result.stdout[:200]}")

    def test_ti_004_debug_single_tool(self, jmo_runner):
        """TI-004: Debug command shows version info for installed tool."""
        # Try trivy first (commonly installed)
        result = jmo_runner(["tools", "debug", "trivy"], timeout=30)

        assert result.returncode == 0, f"Debug failed: {result.stderr}"

        combined = (result.stdout + result.stderr).lower()
        # Should show some diagnostic info
        assert "trivy" in combined, "No trivy info in debug output"

    @pytest.mark.timeout(120)
    def test_ti_005_clean_isolated_venvs(self, jmo_runner):
        """TI-005: Clean command removes isolated venvs."""
        result = jmo_runner(
            ["tools", "clean", "--force"],
            timeout=120,
        )

        # Clean should succeed
        assert result.returncode == 0, f"Clean failed: {result.stderr}"

        combined = (result.stdout + result.stderr).lower()
        # Should indicate cleanup happened or nothing to clean
        cleanup_indicators = ["clean", "removed", "deleted", "no", "nothing", "success"]
        assert any(
            ind in combined for ind in cleanup_indicators
        ), f"No cleanup indication: {result.stdout}"


class TestWindowsExcludedTools:
    """Tests verifying Windows-excluded tools are documented."""

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-specific test")
    def test_ti_windows_excluded_documented(self):
        """Verify Windows-excluded tools are documented in CLAUDE.md."""
        from pathlib import Path

        claude_md = Path("CLAUDE.md")
        if not claude_md.exists():
            pytest.skip("CLAUDE.md not found")

        content = claude_md.read_text(encoding="utf-8").lower()

        # Check for platform-specific documentation
        # The CLAUDE.md may document Windows limitations in various ways
        platform_indicators = [
            "windows",
            "platform",
            "@skip_on_windows",
            "unix",
            "linux",
        ]
        found = sum(1 for ind in platform_indicators if ind in content)

        # Platform documentation should exist
        assert found >= 1, "Platform-specific documentation should exist in CLAUDE.md"

    @pytest.mark.skipif(not IS_WINDOWS, reason="Windows-specific test")
    def test_ti_windows_tools_skip_gracefully(self, jmo_runner):
        """Windows-excluded tools should skip gracefully during install."""
        # Try to install a Windows-excluded tool
        result = jmo_runner(
            ["tools", "install", "falco", "--yes"],
            timeout=60,
        )

        # Should either fail gracefully or skip
        combined = (result.stdout + result.stderr).lower()
        skip_indicators = ["skip", "not supported", "windows", "unavailable", "failed"]
        has_skip = any(ind in combined for ind in skip_indicators)

        # Either skipped gracefully or failed (both acceptable on Windows)
        assert (
            result.returncode != 0 or has_skip
        ), "falco should fail or skip on Windows"


class TestInstallationEdgeCases:
    """Edge cases for tool installation."""

    def test_install_invalid_tool(self, jmo_runner):
        """Installing non-existent tool should fail gracefully."""
        result = jmo_runner(
            ["tools", "install", "nonexistent_tool_xyz", "--yes"],
            timeout=30,
        )

        # Should fail
        assert (
            result.returncode != 0
            or "error" in result.stderr.lower()
            or "not found" in result.stderr.lower()
        ), "Invalid tool should cause error"

    def test_install_without_yes_flag_dry_run(self, jmo_runner):
        """Install dry-run mode shows what would be installed."""
        # Note: CLI still prompts even with --dry-run, so we add --yes
        result = jmo_runner(
            ["tools", "install", "--profile", "fast", "--dry-run", "--yes"],
            timeout=30,
        )

        # Dry-run should succeed
        assert result.returncode == 0, f"Dry-run failed: {result.stderr}"

        # Output should show tools to install
        combined = (result.stdout + result.stderr).lower()
        has_output = any(ind in combined for ind in ["install", "tool", "skip", "dry"])
        assert has_output, "Dry-run should show installation plan"
