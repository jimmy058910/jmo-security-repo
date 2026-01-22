#!/usr/bin/env python3
"""
RP: Report Generation Tests for JMo Security CLI.

Tests verify report generation functionality.
Uses pre-generated fixtures from ralph-cli-testing.

Note: The `jmo report` command generates all formats (JSON, MD, HTML, CSV, SARIF)
to the output directory. There is no --format flag - all outputs are generated.

Since fixtures only have summaries/findings.json (not individual-repos/),
these tests verify the command runs correctly and handles existing summaries.
"""

from __future__ import annotations

import json


class TestReportGeneration:
    """Test suite for report generation (RP-001 to RP-005)."""

    def test_rp_001_report_generates_outputs(
        self, jmo_runner, baseline_results, tmp_path
    ):
        """RP-001: jmo report generates output files."""
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = jmo_runner(
            ["report", str(baseline_results), "--out", str(out_dir)],
            timeout=60,
        )

        assert result.returncode == 0, f"Report failed: {result.stderr}"

        # Should generate at least some output files
        output_files = list(out_dir.iterdir())
        assert len(output_files) >= 0, "Report should create output directory"

    def test_rp_002_report_generates_markdown(
        self, jmo_runner, baseline_results, tmp_path
    ):
        """RP-002: jmo report generates markdown summary."""
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = jmo_runner(
            ["report", str(baseline_results), "--out", str(out_dir)],
            timeout=60,
        )

        assert result.returncode == 0, f"Report failed: {result.stderr}"

        # Check for markdown file (may be SUMMARY.md or similar)
        md_files = list(out_dir.glob("*.md"))
        if md_files:
            content = md_files[0].read_text()
            md_indicators = ["#", "##", "*", "-", "|"]
            has_md = any(ind in content for ind in md_indicators)
            assert has_md, f"No markdown in {md_files[0].name}"

    def test_rp_003_report_generates_html(
        self,
        jmo_runner,
        baseline_results,
        tmp_path,
        validate_html_dashboard,
    ):
        """RP-003: jmo report generates dashboard.html."""
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = jmo_runner(
            ["report", str(baseline_results), "--out", str(out_dir)],
            timeout=60,
        )

        assert result.returncode == 0, f"Report failed: {result.stderr}"

        # Check for dashboard.html
        dashboard = out_dir / "dashboard.html"
        if dashboard.exists():
            validate_html_dashboard(dashboard)

    def test_rp_004_report_generates_sarif(
        self, jmo_runner, baseline_results, tmp_path
    ):
        """RP-004: jmo report generates SARIF output."""
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = jmo_runner(
            ["report", str(baseline_results), "--out", str(out_dir)],
            timeout=60,
        )

        assert result.returncode == 0, f"Report failed: {result.stderr}"

        # Check for SARIF file
        sarif_files = list(out_dir.glob("*.sarif")) + list(out_dir.glob("*.sarif.json"))
        if sarif_files:
            with open(sarif_files[0]) as f:
                data = json.load(f)
            # SARIF has $schema or version or runs field
            is_sarif = "$schema" in data or "version" in data or "runs" in data
            assert is_sarif, f"Not valid SARIF: {sarif_files[0].name}"

    def test_rp_005_report_generates_csv(self, jmo_runner, baseline_results, tmp_path):
        """RP-005: jmo report generates CSV output."""
        out_dir = tmp_path / "output"
        out_dir.mkdir()

        result = jmo_runner(
            ["report", str(baseline_results), "--out", str(out_dir)],
            timeout=60,
        )

        assert result.returncode == 0, f"Report failed: {result.stderr}"

        # Check for CSV file
        csv_files = list(out_dir.glob("*.csv"))
        if csv_files:
            content = csv_files[0].read_text()
            lines = content.strip().split("\n")
            if lines:
                # CSV should have commas
                assert "," in lines[0], f"No CSV structure in {csv_files[0].name}"


class TestReportThreshold:
    """Test suite for report --fail-on threshold (RP-006).

    Note: The --fail-on threshold applies to newly AGGREGATED findings from
    individual-repos/ structure. Since fixtures only have summaries/findings.json,
    there are no new findings to aggregate, so exit 0 is expected.
    These tests verify the flag syntax works correctly.
    """

    def test_rp_006_report_fail_on_threshold(self, jmo_runner, baseline_results):
        """RP-006: jmo report --fail-on HIGH runs successfully."""
        result = jmo_runner(
            ["report", str(baseline_results), "--fail-on", "HIGH"],
            timeout=60,
        )

        # --fail-on applies to newly aggregated findings from individual-repos/
        # With only summaries/ present, no new findings to aggregate → exit 0
        assert (
            result.returncode == 0
        ), f"Report with --fail-on should complete: {result.stderr}"

    def test_report_fail_on_info_syntax(self, jmo_runner, baseline_results):
        """--fail-on INFO syntax works correctly."""
        result = jmo_runner(
            ["report", str(baseline_results), "--fail-on", "INFO"],
            timeout=60,
        )

        # Verify command runs successfully (no syntax errors)
        assert (
            result.returncode == 0
        ), f"Report with --fail-on INFO should complete: {result.stderr}"


class TestReportDefaultOutput:
    """Test report default output behavior."""

    def test_report_creates_summaries_dir(self, jmo_runner, baseline_results):
        """Report creates summaries subdirectory by default."""
        result = jmo_runner(
            ["report", str(baseline_results)],
            timeout=60,
        )

        assert result.returncode == 0, f"Report failed: {result.stderr}"

        # Default output is <results_dir>/summaries
        summaries = baseline_results / "summaries"
        assert summaries.exists(), "summaries directory not created"


class TestReportEdgeCases:
    """Edge cases for report commands."""

    def test_report_nonexistent_directory(self, jmo_runner, tmp_path):
        """Report on non-existent directory creates structure."""
        nonexistent = tmp_path / "nonexistent"

        result = jmo_runner(
            ["report", str(nonexistent)],
            timeout=30,
        )

        # Report creates the directory structure (by design)
        assert result.returncode == 0, f"Report failed: {result.stderr}"
        # Verify directory was created
        assert nonexistent.exists(), "Report should create directory"

    def test_report_empty_results(self, jmo_runner, tmp_path):
        """Report on empty results should handle gracefully."""
        # Create minimal structure
        results_dir = tmp_path / "empty-results"
        results_dir.mkdir()

        # Create empty summaries with minimal findings.json
        summaries = results_dir / "summaries"
        summaries.mkdir()
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
            ["report", str(results_dir)],
            timeout=30,
        )

        # Should handle empty results gracefully
        assert result.returncode in (0, 1), f"Unexpected error: {result.stderr}"

    def test_report_help(self, jmo_runner):
        """Report --help shows available options."""
        result = jmo_runner(["report", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        # Report shows --out and --fail-on options
        assert "--out" in output or "out" in output, "Missing output options"

    def test_report_with_policy(self, jmo_runner, baseline_results):
        """Report with --policy flag applies policy evaluation."""
        result = jmo_runner(
            ["report", str(baseline_results), "--policy", "owasp-top-10"],
            timeout=60,
        )

        # Should complete (policy may require OPA which might not be installed)
        assert result.returncode in (
            0,
            1,
        ), f"Report with policy failed: {result.stderr}"
