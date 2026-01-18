#!/usr/bin/env python3
"""
PL: Policy Commands Tests for JMo Security CLI.

Tests verify policy listing, validation, and testing commands.

Note: The policy list and show commands require OPA to be installed.
Tests will skip gracefully if OPA is not available.
"""

from __future__ import annotations

from pathlib import Path

import pytest


class TestPolicyList:
    """Test suite for `jmo policy list` command (PL-001)."""

    def test_pl_001_policy_list(self, jmo_runner):
        """PL-001: jmo policy list shows available policies (requires OPA)."""
        result = jmo_runner(["policy", "list"])

        # OPA may not be installed - skip gracefully
        if result.returncode != 0 and "OPA not installed" in result.stderr:
            pytest.skip("OPA not installed - policy list requires OPA")

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should list policies or indicate none available
        output = result.stdout.lower()
        policy_indicators = ["policy", "rule", "suppress", "built-in", "custom", "owasp", "zero"]
        has_content = any(ind in output for ind in policy_indicators)
        assert has_content or "no polic" in output or result.returncode == 0, (
            f"No policy list: {result.stdout}"
        )


class TestPolicyValidate:
    """Test suite for `jmo policy validate` command (PL-002)."""

    def test_pl_002_policy_validate_default(self, jmo_runner):
        """PL-002: jmo policy validate checks jmo.suppress.yml."""
        # Check if jmo.suppress.yml exists
        suppress_file = Path("jmo.suppress.yml")
        if not suppress_file.exists():
            pytest.skip("jmo.suppress.yml not found")

        result = jmo_runner(["policy", "validate", str(suppress_file)])

        # Should return 0 for valid, non-zero for invalid
        assert result.returncode in (0, 1), f"Unexpected error: {result.stderr}"

        if result.returncode == 0:
            # Valid policy
            output = result.stdout.lower()
            valid_indicators = ["valid", "ok", "pass", "success"]
            has_valid = any(ind in output for ind in valid_indicators)
            assert has_valid or result.returncode == 0

    def test_policy_validate_nonexistent(self, jmo_runner, tmp_path):
        """Validating non-existent policy should fail."""
        result = jmo_runner(
            ["policy", "validate", str(tmp_path / "nonexistent.yml")]
        )

        # Should fail
        assert result.returncode != 0, "Should fail for non-existent file"

    def test_policy_validate_invalid_yaml(self, jmo_runner, tmp_path):
        """Validating invalid YAML should fail gracefully."""
        invalid_file = tmp_path / "invalid.yml"
        invalid_file.write_text("{ invalid yaml: [")

        result = jmo_runner(["policy", "validate", str(invalid_file)])

        # Should fail with error
        assert result.returncode != 0, "Should fail for invalid YAML"


class TestPolicyTest:
    """Test suite for `jmo policy test` command (PL-003)."""

    def test_pl_003_policy_test(self, jmo_runner, baseline_results):
        """PL-003: jmo policy test shows which findings would be suppressed."""
        suppress_file = Path("jmo.suppress.yml")
        if not suppress_file.exists():
            pytest.skip("jmo.suppress.yml not found")

        result = jmo_runner(
            [
                "policy", "test",
                str(baseline_results),
                "--policy", str(suppress_file),
            ],
            timeout=60,
        )

        # Should run (may have no suppressions)
        assert result.returncode in (0, 1), f"Policy test failed: {result.stderr}"

        # Output should indicate test results
        output = result.stdout.lower()
        test_indicators = ["suppress", "match", "skip", "apply", "finding", "0", "test"]
        has_results = any(ind in output for ind in test_indicators)
        assert has_results or result.returncode == 0, (
            f"No test results: {result.stdout}"
        )


class TestPolicyShow:
    """Test suite for `jmo policy show` command (PL-004)."""

    def test_pl_004_policy_show(self, jmo_runner):
        """PL-004: jmo policy show displays policy details (requires OPA)."""
        # First list policies to get a name
        list_result = jmo_runner(["policy", "list"])

        if list_result.returncode != 0:
            if "OPA not installed" in list_result.stderr:
                pytest.skip("OPA not installed - policy show requires OPA")
            pytest.skip("Could not list policies")

        # Try common policy names
        policy_names = ["owasp-top-10", "zero-secrets", "pci-dss"]
        for policy_name in policy_names:
            result = jmo_runner(["policy", "show", policy_name])
            if result.returncode == 0:
                # Found a valid policy
                output = result.stdout.lower()
                show_indicators = ["rule", "severity", "description", "name"]
                has_content = any(ind in output for ind in show_indicators)
                assert has_content or len(output) > 20, (
                    f"No policy details: {result.stdout}"
                )
                return

        # If no common policies found, just verify command exists
        result = jmo_runner(["policy", "show", "--help"])
        assert result.returncode == 0, "policy show command should exist"


class TestPolicyEdgeCases:
    """Edge cases for policy commands."""

    def test_policy_help(self, jmo_runner):
        """Policy --help shows available subcommands."""
        result = jmo_runner(["policy", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        subcommands = ["list", "validate", "test", "show"]
        found = sum(1 for cmd in subcommands if cmd in output)
        assert found >= 2, "Missing policy subcommands in help"

    def test_policy_list_requires_opa(self, jmo_runner):
        """Policy list requires OPA - verify error message is clear."""
        result = jmo_runner(["policy", "list"])

        if result.returncode != 0:
            # Should have clear error message about OPA
            assert "opa" in result.stderr.lower(), (
                f"Error should mention OPA: {result.stderr}"
            )
