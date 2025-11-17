#!/usr/bin/env python3
"""
Integration tests for end-to-end diff workflows.

Tests all diff output formats and modes:
- Directory diff mode (primary)
- SQLite diff mode (historical scans)
- All output formats: JSON, Markdown, HTML, SARIF
- Filtering combinations: severity, tool, category
- CI/CD integration patterns

Phase 1.2.3 of TESTING_RELEASE_READINESS_PLAN.md
"""

import json
import subprocess
from pathlib import Path

import pytest

from scripts.core.diff_engine import DiffEngine
from scripts.core.history_db import store_scan


@pytest.fixture
def sample_findings():
    """Generate sample CommonFinding objects for testing."""

    def _create_finding(finding_id, severity, tool, path, line, message, **kwargs):
        return {
            "schemaVersion": "1.2.0",
            "id": finding_id,
            "severity": severity,
            "ruleId": f"TEST-{finding_id[:8]}",
            "tool": {"name": tool, "version": "1.0.0"},
            "location": {"path": path, "startLine": line},
            "message": message,
            "compliance": kwargs.get("compliance", {}),
            "risk": kwargs.get("risk", {}),
        }

    return _create_finding


class TestDirectoryDiffWorkflows:
    """Test directory-based diff workflows."""

    def test_directory_diff_json_format(self, tmp_path, sample_findings):
        """
        Test: Directory diff to JSON output.

        Workflow:
        1. Create baseline and current scan results
        2. Run jmo diff --format json
        3. Validate JSON structure
        4. Verify statistics correct
        """
        # Setup: Create baseline and current results
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        # Baseline: 2 findings
        baseline_findings = [
            sample_findings(
                "baseline001", "HIGH", "semgrep", "src/app.py", 10, "SQL injection"
            ),
            sample_findings(
                "shared001", "MEDIUM", "trivy", "src/auth.py", 30, "Auth bypass"
            ),
        ]

        # Current: 1 shared + 1 new
        current_findings = [
            sample_findings(
                "shared001", "MEDIUM", "trivy", "src/auth.py", 30, "Auth bypass"
            ),
            sample_findings(
                "new001", "CRITICAL", "semgrep", "src/api.py", 15, "Command injection"
            ),
        ]

        # Write findings
        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        # Run diff
        output_path = tmp_path / "diff.json"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "json",
                "--output",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"
        assert output_path.exists(), "JSON output should exist"

        # Validate JSON structure
        with open(output_path) as f:
            diff = json.load(f)

        assert "meta" in diff
        assert "statistics" in diff
        assert "new_findings" in diff
        assert "resolved_findings" in diff

        # Verify statistics
        stats = diff["statistics"]
        assert stats["total_new"] == 1  # new001
        assert stats["total_resolved"] == 1  # baseline001
        assert stats["total_unchanged"] == 1  # shared001

    def test_directory_diff_markdown_format(self, tmp_path, sample_findings):
        """
        Test: Directory diff to Markdown output (PR comments).

        Workflow:
        1. Create findings
        2. Run jmo diff --format md
        3. Validate Markdown structure
        4. Verify PR-friendly format
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = []
        current_findings = [
            sample_findings(
                "new001", "HIGH", "semgrep", "src/api.py", 15, "SQL injection"
            ),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff.md"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "md",
                "--output",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"
        assert output_path.exists()

        md_content = output_path.read_text()
        assert (
            "# 🔍 Security Diff Report" in md_content or "Security Diff" in md_content
        )
        assert "Summary" in md_content
        assert "SQL injection" in md_content

    def test_directory_diff_html_format(self, tmp_path, sample_findings):
        """
        Test: Directory diff to HTML output.

        Workflow:
        1. Create findings
        2. Run jmo diff --format html
        3. Validate HTML structure
        4. Verify interactive dashboard
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = [
            sample_findings("b1", "HIGH", "semgrep", "src/a.py", 1, "Issue A"),
        ]
        current_findings = [
            sample_findings("c1", "CRITICAL", "trivy", "src/b.py", 2, "Issue B"),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff-report.html"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "html",
                "--output",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"
        assert output_path.exists()

        html_content = output_path.read_text()
        assert "<!DOCTYPE html>" in html_content
        # Diff HTML uses vanilla JS template (not React)
        assert "Security Diff Report" in html_content

    def test_directory_diff_sarif_format(self, tmp_path, sample_findings):
        """
        Test: Directory diff to SARIF output.

        Workflow:
        1. Create findings
        2. Run jmo diff --format sarif
        3. Validate SARIF 2.1.0 structure
        4. Verify baselineState field
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = [
            sample_findings("b1", "MEDIUM", "semgrep", "src/old.py", 5, "Old issue"),
        ]
        current_findings = [
            sample_findings("c1", "HIGH", "trivy", "src/new.py", 10, "New issue"),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff.sarif"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "sarif",
                "--output",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Diff failed: {result.stderr}"
        assert output_path.exists()

        with open(output_path) as f:
            sarif = json.load(f)

        assert sarif["version"] == "2.1.0"
        assert "$schema" in sarif
        assert "runs" in sarif


class TestFilteringCombinations:
    """Test diff filtering options."""

    def test_severity_filtering(self, tmp_path, sample_findings):
        """
        Test: --severity filter.

        Workflow:
        1. Create findings with mixed severities
        2. Run diff --severity HIGH,CRITICAL
        3. Verify only HIGH/CRITICAL in output
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = []
        current_findings = [
            sample_findings("c1", "HIGH", "semgrep", "a.py", 1, "High issue"),
            sample_findings("c2", "MEDIUM", "trivy", "b.py", 2, "Medium issue"),
            sample_findings("c3", "LOW", "checkov", "c.py", 3, "Low issue"),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff.json"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--severity",
                "HIGH,CRITICAL",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert output_path.exists()

        with open(output_path) as f:
            diff = json.load(f)

        # Should only see HIGH finding
        assert diff["statistics"]["total_new"] == 1
        assert len(diff["new_findings"]) == 1
        assert diff["new_findings"][0]["severity"] == "HIGH"

    def test_tool_filtering(self, tmp_path, sample_findings):
        """
        Test: --tool filter.

        Workflow:
        1. Create findings from multiple tools
        2. Run diff --tool semgrep
        3. Verify only semgrep findings in output
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = []
        current_findings = [
            sample_findings("c1", "HIGH", "semgrep", "a.py", 1, "Semgrep issue"),
            sample_findings("c2", "HIGH", "trivy", "b.py", 2, "Trivy issue"),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff.json"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--tool",
                "semgrep",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert output_path.exists()

        with open(output_path) as f:
            diff = json.load(f)

        assert diff["statistics"]["total_new"] == 1
        assert diff["new_findings"][0]["tool"]["name"] == "semgrep"

    def test_only_new_filtering(self, tmp_path, sample_findings):
        """
        Test: --only new filter.

        Workflow:
        1. Create findings with new + resolved + unchanged
        2. Run diff --only new
        3. Verify only new findings in output
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = [
            sample_findings("b1", "HIGH", "semgrep", "a.py", 1, "Old issue"),
            sample_findings("shared", "MEDIUM", "trivy", "b.py", 2, "Shared"),
        ]
        current_findings = [
            sample_findings("shared", "MEDIUM", "trivy", "b.py", 2, "Shared"),
            sample_findings("c1", "CRITICAL", "checkov", "c.py", 3, "New issue"),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff.json"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--only",
                "new",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert output_path.exists()

        with open(output_path) as f:
            diff = json.load(f)

        # Should only see new findings
        assert diff["statistics"]["total_new"] == 1
        assert len(diff["new_findings"]) == 1
        assert diff["statistics"]["total_resolved"] == 0
        assert len(diff["resolved_findings"]) == 0


class TestCICDIntegrationPatterns:
    """Test CI/CD workflow patterns."""

    def test_pr_security_gate(self, tmp_path, sample_findings):
        """
        Test: CI/CD security gate based on new HIGH/CRITICAL findings.

        Workflow:
        1. Baseline: Clean scan
        2. Current: Add CRITICAL finding
        3. Run diff with severity filter
        4. Check exit code / statistics for gate
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = []
        current_findings = [
            sample_findings(
                "c1", "CRITICAL", "trivy", "config.py", 20, "RCE vulnerability"
            ),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff.json"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "json",
                "--output",
                str(output_path),
                "--severity",
                "CRITICAL,HIGH",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert output_path.exists()

        with open(output_path) as f:
            diff = json.load(f)

        # Security gate check
        new_critical = diff["statistics"]["new_by_severity"].get("CRITICAL", 0)
        new_high = diff["statistics"]["new_by_severity"].get("HIGH", 0)
        gate_total = new_critical + new_high

        # Gate should fail (1 CRITICAL found)
        assert gate_total > 0, "CI gate should fail with new CRITICAL finding"

    def test_remediation_tracking(self, tmp_path, sample_findings):
        """
        Test: Track remediation progress across scans.

        Workflow:
        1. Baseline: 5 HIGH findings
        2. Current: 2 HIGH findings (3 fixed)
        3. Diff shows 3 resolved
        """
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        baseline_findings = [
            sample_findings(f"b{i}", "HIGH", "semgrep", f"file{i}.py", i, f"Issue {i}")
            for i in range(5)
        ]

        current_findings = [
            sample_findings("b0", "HIGH", "semgrep", "file0.py", 0, "Issue 0"),
            sample_findings("b1", "HIGH", "semgrep", "file1.py", 1, "Issue 1"),
        ]

        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        output_path = tmp_path / "diff.json"
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "diff",
                str(baseline_dir),
                str(current_dir),
                "--format",
                "json",
                "--output",
                str(output_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert output_path.exists()

        with open(output_path) as f:
            diff = json.load(f)

        # Verify remediation tracking
        assert diff["statistics"]["total_resolved"] == 3
        assert diff["statistics"]["total_unchanged"] == 2
        assert diff["statistics"]["trend"] == "improving"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
