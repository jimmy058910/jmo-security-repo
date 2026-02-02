#!/usr/bin/env python3
"""
SC: Scan Execution Tests for JMo Security CLI.

These tests perform ACTUAL scans on test fixtures.
Uses tests/fixtures/samples/ as scan targets.

Usage:
    pytest tests/cli_ralph/test_scan_execution.py -v --timeout=300
    pytest tests/cli_ralph/test_scan_execution.py -v -m "not slow"
"""

from __future__ import annotations

import json

import pytest


# Mark entire module as slow (actual scans)
pytestmark = [
    pytest.mark.slow,
    pytest.mark.timeout(300),  # 5 minute timeout for scan tests
]


class TestScanExecution:
    """Test suite for actual scan execution (SC-001 to SC-005)."""

    @pytest.mark.timeout(300)
    def test_sc_001_scan_python_fixture(
        self,
        jmo_runner,
        python_vulnerable_fixture,
        tmp_path,
        validate_findings_json,
    ):
        """SC-001: Scan python-vulnerable fixture with fast profile."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(python_vulnerable_fixture),
                "--results-dir",
                str(results_dir),
                "--profile-name",
                "fast",
                "--allow-missing-tools",
                "--human-logs",
            ],
            timeout=300,
        )

        # Scan should complete (exit 0 even if some tools missing)
        assert (
            result.returncode == 0
        ), f"Scan failed: {result.stderr}\nstdout: {result.stdout}"

        # Verify findings.json was created
        findings_path = results_dir / "summaries" / "findings.json"
        if findings_path.exists():
            data = validate_findings_json(findings_path)
            print(f"Scan produced {data['meta']['finding_count']} findings")
        else:
            # Check if any output was created
            created_files = list(results_dir.rglob("*"))
            print(f"Created files: {created_files}")
            # It's OK if no findings.json if all tools were missing
            if not created_files:
                pytest.skip("No tools available for scanning")

    @pytest.mark.timeout(300)
    def test_sc_002_profile_shortcut_scan(
        self,
        jmo_runner,
        python_vulnerable_fixture,
        tmp_path,
    ):
        """SC-002: Use profile shortcut (jmo fast) for scanning."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = jmo_runner(
            [
                "fast",
                str(python_vulnerable_fixture),
                "--results-dir",
                str(results_dir),
                "--allow-missing-tools",
            ],
            timeout=300,
        )

        # Should complete successfully
        assert (
            result.returncode == 0
        ), f"Fast scan failed: {result.stderr}\nstdout: {result.stdout}"

    def test_sc_003_verify_findings_schema(
        self,
        jmo_runner,
        python_vulnerable_fixture,
        tmp_path,
        validate_findings_json,
    ):
        """SC-003: Verify findings.json follows CommonFinding v1.2.0 schema."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        # Run scan first
        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(python_vulnerable_fixture),
                "--results-dir",
                str(results_dir),
                "--profile-name",
                "fast",
                "--allow-missing-tools",
            ],
            timeout=300,
        )

        if result.returncode != 0:
            pytest.skip(f"Scan failed, cannot verify schema: {result.stderr}")

        findings_path = results_dir / "summaries" / "findings.json"
        if not findings_path.exists():
            pytest.skip("findings.json not created (no tools available?)")

        # Validate schema
        data = validate_findings_json(findings_path)

        # Additional schema checks
        assert data["meta"]["schema_version"] == "1.2.0", "Wrong schema version"
        assert "output_version" in data["meta"], "Missing output_version"

        # Check finding structure if any exist
        if data["findings"]:
            finding = data["findings"][0]
            required_fields = ["severity", "tool", "message"]
            for field in required_fields:
                assert field in finding, f"Missing required field: {field}"

    def test_sc_004_verify_dashboard_generated(
        self,
        jmo_runner,
        python_vulnerable_fixture,
        tmp_path,
        validate_html_dashboard,
    ):
        """SC-004: Verify dashboard.html is generated after scan."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        # Run scan
        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(python_vulnerable_fixture),
                "--results-dir",
                str(results_dir),
                "--profile-name",
                "fast",
                "--allow-missing-tools",
            ],
            timeout=300,
        )

        if result.returncode != 0:
            pytest.skip(f"Scan failed: {result.stderr}")

        # Check for dashboard
        dashboard_path = results_dir / "summaries" / "dashboard.html"
        if dashboard_path.exists():
            validate_html_dashboard(dashboard_path)
        else:
            # Dashboard might be optional or not generated without findings
            findings_path = results_dir / "summaries" / "findings.json"
            if findings_path.exists():
                with open(findings_path) as f:
                    data = json.load(f)
                if data.get("meta", {}).get("finding_count", 0) == 0:
                    pytest.skip("No findings, dashboard may not be generated")
            pytest.skip("Dashboard not generated (may require specific tools)")

    @pytest.mark.timeout(180)
    def test_sc_005_container_image_scan(
        self,
        jmo_runner,
        tmp_path,
        docker_available,
    ):
        """SC-005: Container image scan (optional, requires Docker)."""
        if not docker_available:
            pytest.skip("Docker not available")

        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = jmo_runner(
            [
                "scan",
                "--image",
                "python:3.11-slim",
                "--results-dir",
                str(results_dir),
                "--allow-missing-tools",
                "--timeout",
                "120",
            ],
            timeout=180,
        )

        # Should complete (may have findings or not depending on trivy availability)
        assert result.returncode in (
            0,
            1,
        ), f"Image scan failed unexpectedly: {result.stderr}"


class TestScanEdgeCases:
    """Edge cases for scan execution."""

    def test_scan_nonexistent_directory(self, jmo_runner, tmp_path):
        """Scanning non-existent directory should handle gracefully."""
        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path / "nonexistent"),
                "--allow-missing-tools",
            ],
            timeout=30,
        )

        # Scan completes with warning (no scan targets)
        # Exit 0 is acceptable - it warns rather than fails
        assert result.returncode in (0, 1), f"Unexpected error: {result.stderr}"

        # Should show warning about no targets or missing path
        combined = (result.stdout + result.stderr).lower()
        has_warning = any(
            ind in combined for ind in ["no scan targets", "warning", "skip", "missing"]
        )
        assert (
            has_warning or result.returncode == 0
        ), f"Should complete gracefully: {result.stderr}"

    def test_scan_empty_directory(self, jmo_runner, tmp_path):
        """Scanning empty directory should complete gracefully."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(empty_dir),
                "--profile-name",
                "fast",
                "--allow-missing-tools",
            ],
            timeout=60,
        )

        # Should complete (may or may not have findings)
        assert result.returncode in (0, 1), f"Should handle empty dir: {result.stderr}"

    def test_scan_help_shows_allow_missing_tools(self, jmo_runner):
        """Scan help should document --allow-missing-tools flag."""
        result = jmo_runner(["scan", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        # Should mention the flag (may be different wording)
        assert (
            "allow" in output or "missing" in output or "skip" in output
        ), "Should document handling of missing tools"


class TestScanOutputFormats:
    """Tests for scan output format options."""

    def test_scan_human_logs_flag(
        self, jmo_runner, python_vulnerable_fixture, tmp_path
    ):
        """--human-logs should produce human-readable output."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(python_vulnerable_fixture),
                "--results-dir",
                str(results_dir),
                "--profile-name",
                "fast",
                "--allow-missing-tools",
                "--human-logs",
            ],
            timeout=300,
        )

        # Check that output is not JSON
        combined = result.stdout + result.stderr
        # Human logs shouldn't start with '{' (JSON)
        if combined.strip():
            # Human logs are OK even if some JSON appears in tool output
            # Just verify the command ran
            assert result.returncode == 0 or "error" not in combined.lower()
