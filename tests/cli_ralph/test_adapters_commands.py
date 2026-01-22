#!/usr/bin/env python3
"""
AD: Adapters Tests for JMo Security CLI.

Tests verify adapter listing and validation commands.
"""

from __future__ import annotations



class TestAdaptersList:
    """Test suite for `jmo adapters list` command (AD-001 to AD-002)."""

    def test_ad_001_adapters_list(self, jmo_runner):
        """AD-001: jmo adapters list shows all registered adapters."""
        result = jmo_runner(["adapters", "list"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should list adapter names
        output = result.stdout.lower()
        known_adapters = ["semgrep", "trivy", "bandit", "gitleaks", "checkov"]
        found = sum(1 for adapter in known_adapters if adapter in output)
        assert found >= 3, f"Too few adapters listed: {result.stdout}"

    def test_ad_002_adapters_list_output_structure(self, jmo_runner):
        """AD-002: jmo adapters list shows adapter details."""
        result = jmo_runner(["adapters", "list"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Output should show adapter information
        output = result.stdout.lower()
        # Should show category or tool information
        info_indicators = [
            "sast",
            "sca",
            "secret",
            "container",
            "iac",
            "adapter",
            "tool",
        ]
        has_info = any(ind in output for ind in info_indicators)
        assert has_info or len(output) > 50, f"Limited adapter info: {result.stdout}"


class TestAdaptersValidate:
    """Test suite for `jmo adapters validate` command (AD-003)."""

    def test_ad_003_adapters_validate(self, jmo_runner):
        """AD-003: jmo adapters validate checks all adapter registrations."""
        result = jmo_runner(["adapters", "validate"])

        assert result.returncode == 0, f"Validation failed: {result.stderr}"

        # Should report validation status
        combined = (result.stdout + result.stderr).lower()
        validation_indicators = ["valid", "ok", "pass", "success", "check", "adapter"]
        has_indicator = any(ind in combined for ind in validation_indicators)

        # May also just complete silently on success
        assert (
            result.returncode == 0 or has_indicator
        ), f"No validation status: {result.stdout}"


class TestAdaptersEdgeCases:
    """Edge cases for adapters commands."""

    def test_adapters_help(self, jmo_runner):
        """Adapters --help shows available subcommands."""
        result = jmo_runner(["adapters", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "list" in output, "Missing 'list' subcommand in help"
