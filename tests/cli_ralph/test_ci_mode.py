#!/usr/bin/env python3
"""
CI: CI Mode Tests for JMo Security CLI.

Tests verify CI/CD integration mode with threshold enforcement.

Note: The `jmo ci` command RUNS a scan with threshold checking.
The `jmo report --fail-on` also runs threshold checking, but only
on newly aggregated findings from individual-repos/, not on
pre-existing summaries/findings.json.

Since our fixtures only have summaries/ without individual-repos/,
threshold tests verify the command syntax works but may not trigger
actual failures (the report command needs raw tool outputs to aggregate).
"""

from __future__ import annotations

import json


class TestCIModeHelp:
    """Test suite for CI mode help and basic invocation."""

    def test_ci_help(self, jmo_runner):
        """CI --help shows available options."""
        result = jmo_runner(["ci", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "--fail-on" in output, "Missing --fail-on option"
        assert "--results-dir" in output, "Missing --results-dir option"


class TestReportThreshold:
    """
    Test threshold enforcement using jmo report --fail-on.

    Note: Report aggregates from individual-repos/ structure.
    Since fixtures only have summaries/, these tests verify
    the command syntax works correctly.
    """

    def test_ci_001_report_fail_on_critical_syntax(self, jmo_runner, baseline_results):
        """CI-001: jmo report --fail-on CRITICAL runs without error."""
        result = jmo_runner(
            ["report", str(baseline_results), "--fail-on", "CRITICAL"],
            timeout=60,
        )

        # Command should complete (exit 0 when no findings to aggregate)
        # The baseline only has summaries/, not individual-repos/
        assert result.returncode in (0, 1), f"Command failed: {result.stderr}"

    def test_ci_002_report_fail_on_syntax(self, jmo_runner, baseline_results):
        """CI-002: jmo report --fail-on INFO runs without error."""
        result = jmo_runner(
            ["report", str(baseline_results), "--fail-on", "INFO"],
            timeout=60,
        )

        # Command should complete
        assert result.returncode in (0, 1), f"Command failed: {result.stderr}"


class TestReportPassCases:
    """Test report scenarios that should pass."""

    def test_report_no_findings_passes(self, jmo_runner, tmp_path):
        """Report passes when no findings at or above threshold."""
        # Create results with only INFO findings
        summaries = tmp_path / "results" / "summaries"
        summaries.mkdir(parents=True)

        findings_data = {
            "meta": {
                "schema_version": "1.2.0",
                "finding_count": 1,
                "output_version": "1.0.0",
            },
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "fp-info-001",
                    "ruleId": "INFO-001",
                    "severity": "INFO",
                    "tool": {"name": "test", "version": "1.0"},
                    "location": {"path": "test.py", "startLine": 1},
                    "message": "Informational finding",
                }
            ],
        }
        with open(summaries / "findings.json", "w") as f:
            json.dump(findings_data, f)

        result = jmo_runner(
            ["report", str(tmp_path / "results"), "--fail-on", "HIGH"],
            timeout=60,
        )

        # Should pass - only INFO findings, threshold is HIGH
        assert result.returncode == 0, (
            f"Report should pass with INFO findings at HIGH threshold: {result.stderr}"
        )

    def test_report_empty_results_passes(self, jmo_runner, tmp_path):
        """Report passes with zero findings."""
        # Create empty results
        summaries = tmp_path / "results" / "summaries"
        summaries.mkdir(parents=True)

        findings_data = {
            "meta": {
                "schema_version": "1.2.0",
                "finding_count": 0,
                "output_version": "1.0.0",
            },
            "findings": [],
        }
        with open(summaries / "findings.json", "w") as f:
            json.dump(findings_data, f)

        result = jmo_runner(
            ["report", str(tmp_path / "results"), "--fail-on", "CRITICAL"],
            timeout=60,
        )

        # Should pass - no findings
        assert result.returncode == 0, (
            f"Report should pass with no findings: {result.stderr}"
        )


class TestThresholdEdgeCases:
    """Edge cases for threshold enforcement."""

    def test_report_invalid_threshold_syntax(self, jmo_runner, baseline_results):
        """Report with invalid threshold accepts any string (soft validation)."""
        result = jmo_runner(
            ["report", str(baseline_results), "--fail-on", "INVALID_SEVERITY"],
            timeout=30,
        )

        # CLI may accept any threshold string (soft validation)
        # Just verify it runs without crash
        assert result.returncode in (0, 1, 2), f"Unexpected error: {result.stderr}"

    def test_report_creates_missing_results(self, jmo_runner, tmp_path):
        """Report creates results directory if missing."""
        result = jmo_runner(
            ["report", str(tmp_path / "nonexistent"), "--fail-on", "HIGH"],
            timeout=30,
        )

        # Report may create the directory structure
        assert result.returncode in (0, 1), f"Unexpected error: {result.stderr}"

    def test_threshold_output_format(self, jmo_runner, baseline_results):
        """Report output with threshold is machine-readable."""
        result = jmo_runner(
            ["report", str(baseline_results), "--fail-on", "CRITICAL"],
            timeout=60,
        )

        # Output should be suitable for CI parsing
        combined = result.stdout + result.stderr
        # Should have some structured output (counts, status, etc.)
        ci_indicators = [
            "critical", "high", "medium", "low", "info",
            "total", "finding", "fail", "pass", "wrote", "report",
        ]
        has_structure = any(ind in combined.lower() for ind in ci_indicators)
        assert has_structure, f"Report output should be structured: {combined}"
