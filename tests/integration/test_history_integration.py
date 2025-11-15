#!/usr/bin/env python3
"""
Integration tests for SQLite Historical Storage feature.

Tests end-to-end workflows:
- Scan → Store → Query → Retrieve
- Auto-storage via --store-history flag
- CLI commands (history store/list/show/query/prune/stats)
- Multi-scan workflows (trends, comparisons)
"""

import json
import subprocess
import time

import pytest


class TestHistoryWorkflow:
    """Test complete scan → store → query workflow."""

    def test_manual_store_and_retrieve(self, tmp_path):
        """Test manually storing a scan and retrieving it."""
        # Create mock scan results
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "test-finding-1",
                    "severity": "HIGH",
                    "tool": {"name": "trivy", "version": "0.68.0"},
                    "ruleId": "CVE-2024-1234",
                    "location": {"path": "src/app.py", "startLine": 42},
                    "message": "SQL injection vulnerability",
                }
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        db_path = tmp_path / ".jmo" / "history.db"

        # Store scan using history_db module
        from scripts.core.history_db import (
            store_scan,
            get_connection,
            list_scans,
            get_findings_for_scan,
        )

        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
        )

        assert scan_id is not None
        assert len(scan_id) == 36  # UUID format

        # Retrieve scan
        conn = get_connection(db_path)
        scans = list_scans(conn, limit=10)
        assert len(scans) == 1
        assert scans[0]["id"] == scan_id
        assert scans[0]["profile"] == "balanced"
        assert scans[0]["total_findings"] == 1

        # Retrieve findings
        findings = get_findings_for_scan(conn, scan_id)
        conn.close()

        assert len(findings) == 1
        assert findings[0]["fingerprint"] == "test-finding-1"
        assert findings[0]["severity"] == "HIGH"

    def test_multi_scan_trend_analysis(self, tmp_path):
        """Test storing multiple scans and analyzing trends."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        db_path = tmp_path / ".jmo" / "history.db"

        from scripts.core.history_db import store_scan, get_connection, list_scans

        # Store 3 scans with different finding counts
        scan_ids = []
        for i in range(3):
            findings_data = {
                "findings": [
                    {
                        "id": f"finding-{j}",
                        "severity": "HIGH",
                        "tool": {"name": "trivy"},
                        "ruleId": f"CVE-2024-{j}",
                        "location": {"path": "app.py", "startLine": j},
                        "message": f"Issue {j}",
                    }
                    for j in range(i + 1)  # 1, 2, 3 findings
                ]
            }
            summaries_dir.joinpath("findings.json").write_text(
                json.dumps(findings_data)
            )

            scan_id = store_scan(
                results_dir=results_dir,
                profile="fast",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )
            scan_ids.append(scan_id)
            time.sleep(1.1)  # Ensure different timestamps

        # Query scans and verify trend
        conn = get_connection(db_path)
        scans = list_scans(conn, branch="main", limit=10)
        conn.close()

        assert len(scans) == 3
        # Most recent first (DESC)
        assert scans[0]["total_findings"] == 3
        assert scans[1]["total_findings"] == 2
        assert scans[2]["total_findings"] == 1

    def test_prune_old_scans(self, tmp_path):
        """Test pruning old scans from history."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        db_path = tmp_path / ".jmo" / "history.db"

        from scripts.core.history_db import (
            store_scan,
            get_connection,
            list_scans,
            prune_old_scans,
        )

        # Store 2 scans
        store_scan(results_dir, profile="fast", tools=["trivy"], db_path=db_path)
        time.sleep(2)
        store_scan(results_dir, profile="fast", tools=["trivy"], db_path=db_path)

        # Verify 2 scans exist
        conn = get_connection(db_path)
        scans_before = list_scans(conn, limit=10)
        assert len(scans_before) == 2

        # Prune scans older than 1 second (should remove first scan)
        deleted_count = prune_old_scans(conn, older_than_seconds=1)
        assert deleted_count == 1

        # Verify only 1 scan remains
        scans_after = list_scans(conn, limit=10)
        conn.close()

        assert len(scans_after) == 1


class TestHistoryCLI:
    """Test history CLI commands."""

    def test_history_store_command(self, tmp_path):
        """Test 'jmo history store' command."""
        # Create mock scan results
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "cli-finding-1",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-9999",
                    "location": {"path": "main.py", "startLine": 1},
                    "message": "Critical vulnerability",
                }
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        db_path = tmp_path / "history.db"

        # Run history store command
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "history",
                "store",
                "--results-dir",
                str(results_dir),
                "--profile",
                "balanced",
                "--db",
                str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert "Stored scan:" in result.stdout  # Output format: "✅ Stored scan: UUID"
        assert "Database:" in result.stdout

    def test_history_list_command(self, tmp_path):
        """Test 'jmo history list' command."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        db_path = tmp_path / "history.db"

        # Store a scan first
        from scripts.core.history_db import store_scan

        store_scan(results_dir, profile="fast", tools=["trivy"], db_path=db_path)

        # Run history list command
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "history",
                "list",
                "--db",
                str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        assert "fast" in result.stdout  # Profile name
        # Note: Output format depends on whether tabulate is installed
        # Both formats show findings summary (case-insensitive check)
        assert "findings" in result.stdout.lower()
        assert "critical" in result.stdout.lower() or "high" in result.stdout.lower()

    def test_history_stats_command(self, tmp_path):
        """Test 'jmo history stats' command."""
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "stat-finding-1",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "app.py", "startLine": 1},
                    "message": "Test finding",
                }
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        db_path = tmp_path / "history.db"

        # Store a scan
        from scripts.core.history_db import store_scan

        store_scan(results_dir, profile="balanced", tools=["semgrep"], db_path=db_path)

        # Run history stats command
        result = subprocess.run(
            [
                "python3",
                "-m",
                "scripts.cli.jmo",
                "history",
                "stats",
                "--db",
                str(db_path),
            ],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"Command failed: {result.stderr}"
        # Actual output format uses "Scans:" not "Total scans"
        assert "Scans:" in result.stdout
        assert "Findings:" in result.stdout
        assert "balanced" in result.stdout  # Profile name


class TestAutoStorage:
    """Test automatic storage via --store-history flag."""

    def test_scan_with_store_history_flag(self, tmp_path):
        """Test that --store-history automatically stores scan after completion."""
        # This is a smoke test - we can't run a full scan in integration tests
        # but we can verify the flag propagation works

        # Verify the flag is recognized
        result = subprocess.run(
            ["python3", "-m", "scripts.cli.jmo", "scan", "--help"],
            capture_output=True,
            text=True,
            timeout=5,
        )

        assert result.returncode == 0
        assert "--store-history" in result.stdout
        assert "--history-db" in result.stdout


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
