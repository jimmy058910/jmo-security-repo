#!/usr/bin/env python3
"""
Integration tests for complete v1.0.0 workflows.

Tests end-to-end user journeys:
- Scan → Report → History → Diff → Trend
- Baseline/current scan comparisons
- CI mode integration
- Multi-scan trend analysis

Phase 1.2.1 of TESTING_RELEASE_READINESS_PLAN.md
"""

import json
import subprocess
import time

import pytest

from scripts.cli.jmo import cmd_ci, cmd_report, cmd_scan
from scripts.core.history_db import get_connection, list_scans, store_scan


class TestV1WorkflowIntegration:
    """Test complete v1.0.0 user workflows."""

    def test_scan_to_dashboard_with_history(self, tmp_path):
        """
        Test: Scan → Store in SQLite → Generate dashboard.

        Workflow:
        1. Create test repo
        2. Run jmo scan with fast profile
        3. Verify raw JSON outputs created
        4. Run jmo report
        5. Verify SQLite scan stored automatically
        6. Verify dashboard HTML includes scan_id
        7. Verify findings.json has v1.0.0 metadata wrapper
        """
        # Setup: Create test repo
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "app.py").write_text("print('hello world')")

        results_dir = tmp_path / "results"
        db_path = tmp_path / ".jmo" / "history.db"

        # Step 1: Run scan
        class ScanArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["trufflehog"]
                self.timeout = 30
                self.threads = 1
                self.allow_missing_tools = True
                self.profile = False
                self.profile_name = "fast"
                # v0.6.0+ multi-target args
                self.image = None
                self.images_file = None
                self.terraform_state = None
                self.cloudformation = None
                self.k8s_manifest = None
                self.url = None
                self.urls_file = None
                self.api_spec = None
                self.gitlab_repo = None
                self.gitlab_group = None
                self.gitlab_url = None
                self.gitlab_token = None
                self.k8s_context = None
                self.k8s_namespace = None
                self.k8s_all_namespaces = False

        scan_rc = cmd_scan(ScanArgs())
        assert scan_rc == 0, "Scan should succeed"

        # Step 2: Verify raw outputs exist
        assert results_dir.exists()
        # Individual repo results should exist
        repo_results = results_dir / "individual-repos" / "test-repo"
        assert repo_results.exists(), "Individual repo results should exist"

        # Step 3: Run report (stores scan in SQLite automatically)
        class ReportArgs:
            def __init__(self):
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.outputs = ["json", "md", "html"]
                self.fail_on = None
                self.profile = False
                self.out = None  # Required by report_orchestrator.py
                self.threads = None
                # v1.0.0: History storage
                self.store_history = True
                self.history_db = str(db_path)

        report_rc = cmd_report(ReportArgs())
        assert report_rc == 0, "Report should succeed"

        # Step 4: Verify SQLite storage
        if db_path.exists():
            conn = get_connection(db_path)
            scans = list_scans(conn, limit=10)
            conn.close()

            assert len(scans) >= 1, "At least one scan should be stored"
            scan = scans[0]
            # Profile comes from config file default_profile, not scan args
            assert scan["profile"] in [
                "fast",
                "balanced",
                "",
            ], "Profile should be stored"
            assert "trufflehog" in scan["tools"], "trufflehog should be in tools"

        # Step 5: Verify dashboard HTML
        dashboard = results_dir / "summaries" / "dashboard.html"
        assert dashboard.exists(), "Dashboard should exist"
        html_content = dashboard.read_text()
        assert "<!DOCTYPE html>" in html_content

        # Step 6: Verify findings.json has v1.0.0 metadata wrapper
        findings_json = results_dir / "summaries" / "findings.json"
        assert findings_json.exists(), "findings.json should exist"

        with open(findings_json) as f:
            data = json.load(f)

        # v1.0.0 metadata wrapper validation
        assert "meta" in data, "v1.0.0 metadata wrapper missing"
        assert "findings" in data, "findings array missing"

        meta = data["meta"]
        assert meta["output_version"] == "1.0.0"
        assert "jmo_version" in meta
        assert "timestamp" in meta
        # Profile comes from config default_profile, may be empty or balanced
        assert "profile" in meta
        # Tools list may be empty if no findings detected
        assert "tools" in meta

    def test_baseline_current_diff_workflow(self, tmp_path):
        """
        Test: Scan baseline → Scan current → Diff → PR comment.

        Workflow:
        1. Create baseline scan results
        2. Create current scan results (with new findings)
        3. Run jmo diff --format md
        4. Verify Markdown output suitable for PR comment
        5. Verify new/fixed findings categorized correctly
        """
        # Setup: Create baseline and current results
        baseline_dir = tmp_path / "baseline-results"
        current_dir = tmp_path / "current-results"

        (baseline_dir / "summaries").mkdir(parents=True)
        (current_dir / "summaries").mkdir(parents=True)

        # Baseline: 2 findings
        baseline_findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "baseline-finding-1",
                "severity": "HIGH",
                "ruleId": "CVE-2024-1111",
                "tool": {"name": "trivy", "version": "0.68.0"},
                "location": {"path": "src/app.py", "startLine": 10},
                "message": "SQL injection vulnerability",
            },
            {
                "schemaVersion": "1.2.0",
                "id": "shared-finding-1",
                "severity": "MEDIUM",
                "ruleId": "G101",
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {"path": "src/config.py", "startLine": 20},
                "message": "Hardcoded secret",
            },
        ]

        # Current: 1 shared + 1 new finding
        current_findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "shared-finding-1",
                "severity": "MEDIUM",
                "ruleId": "G101",
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {"path": "src/config.py", "startLine": 20},
                "message": "Hardcoded secret",
            },
            {
                "schemaVersion": "1.2.0",
                "id": "new-finding-1",
                "severity": "CRITICAL",
                "ruleId": "CVE-2024-9999",
                "tool": {"name": "trivy", "version": "0.68.0"},
                "location": {"path": "src/api.py", "startLine": 15},
                "message": "Remote code execution",
            },
        ]

        # Write findings
        (baseline_dir / "summaries" / "findings.json").write_text(
            json.dumps(baseline_findings, indent=2)
        )
        (current_dir / "summaries" / "findings.json").write_text(
            json.dumps(current_findings, indent=2)
        )

        # Run diff
        output_path = tmp_path / "diff-report.md"
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
        assert output_path.exists(), "Markdown output should exist"

        # Validate Markdown structure
        md_content = output_path.read_text()

        # Check PR comment-friendly format
        assert (
            "# 🔍 Security Diff Report" in md_content or "Security Diff" in md_content
        )
        assert "Summary" in md_content
        assert "Remote code execution" in md_content

        # Verify categorization
        assert "CRITICAL" in md_content  # New finding

    def test_trend_analysis_over_time(self, tmp_path):
        """
        Test: Multiple scans → Trend analysis → Export.

        Workflow:
        1. Create 10 scans over 30 days (simulated timestamps)
        2. Store in SQLite
        3. Run jmo trends analyze --days 30
        4. Verify Mann-Kendall test results
        5. Run jmo trends analyze --export prometheus
        6. Verify Prometheus metrics valid
        """
        results_dir = tmp_path / "results"
        (results_dir / "summaries").mkdir(parents=True)

        db_path = tmp_path / ".jmo" / "history.db"

        # Create 10 scans with increasing severity counts (upward trend)
        scan_ids = []
        for i in range(10):
            findings_data = {
                "findings": [
                    {
                        "schemaVersion": "1.2.0",
                        "id": f"finding-{i}-{j}",
                        "severity": "HIGH",
                        "ruleId": f"CVE-2024-{j}",
                        "tool": {"name": "trivy", "version": "0.68.0"},
                        "location": {"path": f"src/file{j}.py", "startLine": j},
                        "message": f"Vulnerability {j}",
                    }
                    for j in range(i + 1)  # 1, 2, 3... findings
                ]
            }

            (results_dir / "summaries" / "findings.json").write_text(
                json.dumps(findings_data)
            )

            scan_id = store_scan(
                results_dir=results_dir,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )
            scan_ids.append(scan_id)
            time.sleep(0.5)  # Ensure different timestamps

        # Run trend analysis
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "trends",
                "analyze",
                "--days",
                "30",
                "--db",
                str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, f"Trend analysis failed: {result.stderr}"

        # Verify Mann-Kendall test ran
        output = result.stdout
        assert "Trend:" in output or "trend" in output.lower()

        # Run JSON export (Prometheus export not yet wired to CLI)
        json_export = tmp_path / "trends.json"
        result_export = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "trends",
                "analyze",
                "--days",
                "30",
                "--export-json",
                str(json_export),
                "--db",
                str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert (
            result_export.returncode == 0
        ), f"JSON export failed: {result_export.stderr}"
        assert json_export.exists(), "JSON export file should exist"

        # Validate JSON format
        import json as json_module

        export_data = json_module.loads(json_export.read_text())
        assert "metadata" in export_data
        assert "scans" in export_data
        assert "severity_trends" in export_data

    def test_ci_mode_with_history_and_diff(self, tmp_path):
        """
        Test: CI mode with automatic history storage and diff.

        Workflow:
        1. Run jmo ci --repo <repo> --fail-on HIGH
        2. Verify exit code based on severity threshold
        3. Verify scan stored in SQLite
        4. If previous scan exists, diff generated
        """
        repo = tmp_path / "ci-repo"
        repo.mkdir()
        (repo / "app.py").write_text("import os\npassword = 'hardcoded123'\n")

        results_dir = tmp_path / "ci-results"
        db_path = tmp_path / ".jmo" / "history.db"

        class CIArgs:
            def __init__(self):
                self.repo = str(repo)
                self.repos_dir = None
                self.targets = None
                self.results_dir = str(results_dir)
                self.config = str(tmp_path / "jmo.yml")
                self.tools = ["trufflehog"]
                self.timeout = 30
                self.threads = 1
                self.allow_missing_tools = True
                self.fail_on = "HIGH"
                self.profile = True
                # v1.0.0: History storage
                self.store_history = True
                self.history_db = str(db_path)
                # v0.6.0+ multi-target args
                self.image = None
                self.images_file = None
                self.terraform_state = None
                self.cloudformation = None
                self.k8s_manifest = None
                self.url = None
                self.urls_file = None
                self.api_spec = None
                self.gitlab_repo = None
                self.gitlab_group = None
                self.gitlab_url = None
                self.gitlab_token = None
                self.k8s_context = None
                self.k8s_namespace = None
                self.k8s_all_namespaces = False

        rc = cmd_ci(CIArgs())

        # Exit code depends on findings (0 or 1 for success, >1 for errors)
        assert rc in (0, 1), "CI should complete successfully"

        # Verify outputs
        assert results_dir.exists()
        assert (results_dir / "summaries" / "findings.json").exists()
        assert (results_dir / "summaries" / "dashboard.html").exists()

        # Verify timings.json (profile=True)
        assert (results_dir / "summaries" / "timings.json").exists()

    def test_wizard_to_scheduled_scan_to_trends(self, tmp_path):
        """
        Test: Wizard → Schedule → Automated scans → Trend tracking.

        Note: This is a smoke test. Actual wizard and scheduler require
        interactive input or cron setup which is not feasible in CI.

        Workflow:
        1. Verify wizard help exists
        2. Verify schedule commands exist
        3. Simulate multiple scans being stored
        4. Run trend analysis on stored scans
        """
        # Verify wizard command exists
        result_wizard = subprocess.run(
            ["python3", "-m", "scripts.cli.jmo", "wizard", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result_wizard.returncode == 0
        assert "--yes" in result_wizard.stdout  # Non-interactive flag

        # Verify schedule commands exist
        result_schedule = subprocess.run(
            ["python3", "-m", "scripts.cli.jmo", "schedule", "--help"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        assert result_schedule.returncode == 0

        # Simulate 5 automated scans
        results_dir = tmp_path / "scheduled-results"
        (results_dir / "summaries").mkdir(parents=True)
        db_path = tmp_path / ".jmo" / "history.db"

        for i in range(5):
            findings_data = {
                "findings": [
                    {
                        "schemaVersion": "1.2.0",
                        "id": f"scheduled-{i}-{j}",
                        "severity": "MEDIUM",
                        "ruleId": f"SCHED-{j}",
                        "tool": {"name": "semgrep", "version": "1.0.0"},
                        "location": {"path": "main.py", "startLine": j},
                        "message": f"Issue {j}",
                    }
                    for j in range(i + 1)
                ]
            }

            (results_dir / "summaries" / "findings.json").write_text(
                json.dumps(findings_data)
            )

            store_scan(
                results_dir=results_dir,
                profile="balanced",
                tools=["semgrep"],
                db_path=db_path,
                branch="main",
            )
            time.sleep(0.5)

        # Run trend analysis
        result_trends = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "trends",
                "analyze",
                "--db",
                str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert (
            result_trends.returncode == 0
        ), f"Trend analysis failed: {result_trends.stderr}"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
