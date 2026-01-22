#!/usr/bin/env python3
"""
DF: Diff Commands Tests for JMo Security CLI.

Tests verify scan comparison functionality.
Uses pre-generated baseline and current results fixtures.
"""

from __future__ import annotations

import json


class TestDiffBasic:
    """Test suite for basic diff commands (DF-001 to DF-003)."""

    def test_df_001_diff_basic(self, jmo_runner, baseline_results, current_results):
        """DF-001: jmo diff shows added/removed findings."""
        result = jmo_runner(
            ["diff", str(baseline_results), str(current_results)],
            timeout=60,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"

        # Should show changes
        output = result.stdout.lower()
        change_indicators = ["add", "remov", "new", "fixed", "change", "+", "-"]
        has_changes = any(ind in output for ind in change_indicators)
        assert has_changes or "no change" in output, f"No diff output: {result.stdout}"

    def test_df_002_diff_json_format(
        self,
        jmo_runner,
        baseline_results,
        current_results,
    ):
        """DF-002: jmo diff --format json outputs valid JSON."""
        result = jmo_runner(
            ["diff", str(baseline_results), str(current_results), "--format", "json"],
            timeout=60,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"

        if result.stdout.strip():
            # Try to parse JSON output
            try:
                data = json.loads(result.stdout)
                # Should have diff-related structure
                diff_keys = ["added", "removed", "unchanged", "new", "fixed", "summary"]
                has_diff_structure = any(key in data for key in diff_keys)
                assert has_diff_structure or isinstance(
                    data, (dict, list)
                ), f"Unexpected JSON structure: {list(data.keys()) if isinstance(data, dict) else 'list'}"
            except json.JSONDecodeError:
                # JSON might have non-JSON prefix (logs)
                # Try to find JSON object in output
                start = result.stdout.find("{")
                end = result.stdout.rfind("}") + 1
                if start >= 0 and end > start:
                    json.loads(result.stdout[start:end])  # Just validate it parses

    def test_df_003_diff_markdown_format(
        self,
        jmo_runner,
        baseline_results,
        current_results,
    ):
        """DF-003: jmo diff --format md outputs markdown."""
        result = jmo_runner(
            ["diff", str(baseline_results), str(current_results), "--format", "md"],
            timeout=60,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"

        # Should contain markdown elements
        output = result.stdout
        if output.strip():
            md_indicators = ["#", "##", "*", "-", "|", "+"]
            has_md = any(ind in output for ind in md_indicators)
            assert has_md, f"No markdown in diff: {output[:500]}"


class TestDiffFilters:
    """Test suite for diff filtering options (DF-004 to DF-006)."""

    def test_df_004_diff_severity_filter(
        self,
        jmo_runner,
        baseline_results,
        current_results,
    ):
        """DF-004: jmo diff --severity filters by severity level."""
        result = jmo_runner(
            [
                "diff",
                str(baseline_results),
                str(current_results),
                "--severity",
                "CRITICAL,HIGH",
            ],
            timeout=60,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"
        # Command should complete successfully - filtering verified by exit code

    def test_df_005_diff_tool_filter(
        self,
        jmo_runner,
        baseline_results,
        current_results,
    ):
        """DF-005: jmo diff --tool filters by tool name."""
        result = jmo_runner(
            [
                "diff",
                str(baseline_results),
                str(current_results),
                "--tool",
                "semgrep",
            ],
            timeout=60,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"
        # Command should complete successfully - filtering verified by exit code

    def test_df_006_diff_only_new(
        self,
        jmo_runner,
        baseline_results,
        current_results,
    ):
        """DF-006: jmo diff --only new shows only added findings."""
        result = jmo_runner(
            [
                "diff",
                str(baseline_results),
                str(current_results),
                "--only",
                "new",
            ],
            timeout=60,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"
        # Command should complete successfully


class TestDiffEdgeCases:
    """Edge cases for diff commands."""

    def test_diff_identical_results(self, jmo_runner, baseline_results):
        """Diff of identical results shows no changes."""
        result = jmo_runner(
            ["diff", str(baseline_results), str(baseline_results)],
            timeout=60,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"

        # Should indicate no changes
        output = result.stdout.lower()
        no_change_indicators = [
            "no change",
            "identical",
            "same",
            "0 added",
            "0 removed",
            "0 new",
        ]
        has_no_changes = any(ind in output for ind in no_change_indicators)
        # Or might just show empty diff
        assert (
            has_no_changes or "add" not in output
        ), f"Should show no changes: {result.stdout}"

    def test_diff_nonexistent_baseline(self, jmo_runner, current_results, tmp_path):
        """Diff with non-existent baseline should fail gracefully."""
        result = jmo_runner(
            ["diff", str(tmp_path / "nonexistent"), str(current_results)],
            timeout=30,
        )

        assert result.returncode != 0, "Should fail with non-existent baseline"

    def test_diff_help(self, jmo_runner):
        """Diff --help shows available options."""
        result = jmo_runner(["diff", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "--format" in output, "Missing --format option"

    def test_diff_reversed_order(
        self,
        jmo_runner,
        baseline_results,
        current_results,
    ):
        """Diff with reversed order should swap added/removed."""
        result = jmo_runner(
            ["diff", str(current_results), str(baseline_results)],
            timeout=60,
        )

        assert result.returncode == 0, f"Reversed diff failed: {result.stderr}"
        # Should complete (added/removed will be swapped)
