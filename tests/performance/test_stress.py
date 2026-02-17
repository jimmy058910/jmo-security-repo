#!/usr/bin/env python3
"""
Stress Tests for JMo Security.

Tests system behavior under extreme load conditions:
- 100k+ findings processing
- Concurrent scan operations
- Memory pressure scenarios

These tests are marked as 'stress' and should be run separately
as they require significant resources.

Usage:
    pytest tests/performance/test_stress.py -v -m stress
    pytest tests/performance/test_stress.py::TestExtremeLoad -v
"""

from __future__ import annotations

import json
import random
import sqlite3
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


# Mark all tests in this module as stress tests
pytestmark = [
    pytest.mark.stress,
    pytest.mark.slow,
    pytest.mark.timeout(600),  # 10 minute timeout for stress tests
]


# ============================================================================
# Test Data Generators
# ============================================================================


def generate_finding(index: int) -> dict[str, Any]:
    """Generate a realistic finding for stress testing."""
    severities = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    tools = ["semgrep", "trivy", "bandit", "checkov", "hadolint", "grype"]
    rules = [f"CWE-{random.randint(1, 1000)}", f"CVE-2024-{random.randint(1000, 9999)}"]

    return {
        "id": f"fp-stress-{index:08d}",
        "ruleId": random.choice(rules),
        "severity": random.choice(severities),
        "tool": {"name": random.choice(tools), "version": "1.0.0"},
        "location": {
            "path": f"src/module_{index % 100}/file_{index % 1000}.py",
            "startLine": random.randint(1, 500),
            "endLine": random.randint(1, 500),
        },
        "message": f"Finding {index}: "
        + "".join(random.choices(string.ascii_letters, k=50)),
        "title": f"Issue {index}",
    }


def generate_large_findings_file(path: Path, count: int) -> None:
    """Generate a large findings JSON file."""
    findings = [generate_finding(i) for i in range(count)]

    output = {
        "meta": {
            "schema_version": "1.2.0",
            "finding_count": len(findings),
            "output_version": "1.0.0",
        },
        "findings": findings,
    }

    with open(path, "w", encoding="utf-8") as f:
        json.dump(output, f)


# ============================================================================
# Extreme Load Tests
# ============================================================================


class TestExtremeLoad:
    """Test system behavior under extreme load."""

    @pytest.mark.timeout(300)
    @patch("scripts.core.normalize_and_report._enrich_with_priority")
    def test_100k_findings_processing(self, _mock_enrich, tmp_path: Path):
        """Process 100,000 findings without memory issues.

        Note: EPSS/KEV enrichment is patched out because this test measures
        parsing/dedup throughput, not API connectivity. Enrichment performance
        is tested separately in test_prioritization_performance.py.
        """
        from scripts.core.normalize_and_report import gather_results

        # Create results directory structure
        indiv = tmp_path / "individual-repos" / "stress-repo"
        indiv.mkdir(parents=True)

        # Generate findings for multiple tools
        findings_per_tool = 20000  # 20k per tool, 5 tools = 100k
        tools = ["semgrep", "trivy", "bandit", "grype", "checkov"]

        for tool in tools:
            tool_findings = []
            for i in range(findings_per_tool):
                tool_findings.append(
                    {
                        "check_id": f"rule-{i}",
                        "path": f"file_{i % 100}.py",
                        "start": {"line": i % 1000},
                        "extra": {"message": f"Finding {i}", "severity": "LOW"},
                    }
                )

            if tool == "semgrep":
                content = {"results": tool_findings, "version": "1.0.0"}
            elif tool == "trivy":
                content = {
                    "SchemaVersion": 2,
                    "Results": [
                        {
                            "Target": "test",
                            "Vulnerabilities": [
                                {
                                    "VulnerabilityID": f"CVE-{i}",
                                    "PkgName": f"pkg-{i}",
                                    "Severity": "LOW",
                                    "Title": f"Vuln {i}",
                                }
                                for i in range(findings_per_tool)
                            ],
                        }
                    ],
                }
            elif tool == "bandit":
                content = {
                    "results": [
                        {
                            "test_id": f"B{i}",
                            "filename": f"file_{i}.py",
                            "line_number": i,
                            "issue_severity": "LOW",
                            "issue_text": f"Issue {i}",
                        }
                        for i in range(findings_per_tool)
                    ]
                }
            elif tool == "grype":
                content = {
                    "matches": [
                        {
                            "vulnerability": {
                                "id": f"CVE-{i}",
                                "severity": "Low",
                                "description": f"Vuln {i}",
                            },
                            "artifact": {"name": f"pkg-{i}"},
                        }
                        for i in range(findings_per_tool)
                    ]
                }
            else:  # checkov
                content = {
                    "results": {
                        "failed_checks": [
                            {
                                "check_id": f"CKV_{i}",
                                "check_result": {"result": "FAILED"},
                                "file_path": f"file_{i}.tf",
                                "file_line_range": [i, i + 1],
                            }
                            for i in range(findings_per_tool)
                        ]
                    }
                }

            (indiv / f"{tool}.json").write_text(json.dumps(content), encoding="utf-8")

        # Process all findings
        start_time = time.time()
        findings = gather_results(tmp_path)
        elapsed = time.time() - start_time

        # Should complete in reasonable time (<60s)
        assert (
            elapsed < 60
        ), f"Processing 100k findings took {elapsed:.1f}s (target: <60s)"
        assert isinstance(findings, list)
        assert len(findings) > 0

    @pytest.mark.timeout(300)
    @patch("scripts.core.normalize_and_report._enrich_with_priority")
    def test_100k_findings_memory_usage(self, _mock_enrich, tmp_path: Path):
        """Verify memory usage stays under 500MB for 100k findings.

        Note: EPSS/KEV enrichment is patched out — same rationale as
        test_100k_findings_processing above.
        """
        try:
            import psutil
        except ImportError:
            pytest.skip("psutil not installed - required for memory tests")

        from scripts.core.normalize_and_report import gather_results

        # Create findings
        indiv = tmp_path / "individual-repos" / "memory-test"
        indiv.mkdir(parents=True)

        findings_data = {
            "results": [
                {
                    "check_id": f"rule-{i}",
                    "path": f"file_{i % 100}.py",
                    "start": {"line": i % 1000},
                    "extra": {
                        "message": f"Finding {i} " + "x" * 100,
                        "severity": "LOW",
                    },
                }
                for i in range(100000)
            ],
            "version": "1.0.0",
        }
        (indiv / "semgrep.json").write_text(json.dumps(findings_data), encoding="utf-8")

        process = psutil.Process()
        memory_before = process.memory_info().rss

        findings = gather_results(tmp_path)

        memory_after = process.memory_info().rss
        memory_used_mb = (memory_after - memory_before) / (1024 * 1024)

        assert (
            memory_used_mb < 500
        ), f"Memory usage {memory_used_mb:.1f}MB exceeded 500MB limit"
        assert len(findings) > 0


class TestConcurrentOperations:
    """Test concurrent operations for race conditions."""

    @pytest.mark.timeout(180)
    def test_concurrent_scans_sqlite_locking(self, tmp_path: Path):
        """Verify 10 parallel scans don't cause SQLite lock errors."""
        from scripts.core.history_db import init_database

        db_path = tmp_path / "concurrent.db"
        errors = []
        success_count = 0
        lock = threading.Lock()

        # Initialize database
        init_database(db_path)

        def run_scan_operation(scan_id: int):
            nonlocal success_count
            try:
                conn = sqlite3.connect(db_path, timeout=30)
                conn.execute("PRAGMA journal_mode=WAL")
                # Simulate scan insert
                conn.execute(
                    """
                    INSERT INTO scans
                    (id, timestamp, timestamp_iso, profile, tools, targets, target_type, jmo_version)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"scan-{scan_id}",
                        1704067200,
                        "2024-01-01T00:00:00",
                        "fast",
                        "[]",
                        f'["/repo-{scan_id}"]',
                        "repo",
                        "1.0.0",
                    ),
                )
                conn.commit()

                # Simulate some findings
                for i in range(10):
                    conn.execute(
                        """
                        INSERT INTO findings
                        (scan_id, fingerprint, severity, tool, rule_id, path, start_line, message)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            f"scan-{scan_id}",
                            f"fp-{scan_id}-{i}",
                            "HIGH",
                            "test",
                            "CWE-79",
                            f"file_{i}.py",
                            i * 10,
                            f"Finding {i}",
                        ),
                    )
                conn.commit()
                conn.close()

                with lock:
                    success_count += 1
            except Exception as e:
                with lock:
                    errors.append((scan_id, str(e)))

        # Run 10 concurrent "scans"
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(run_scan_operation, i) for i in range(10)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    errors.append(("executor", str(e)))

        # All should succeed (SQLite WAL mode should handle this)
        assert (
            success_count == 10
        ), f"Only {success_count}/10 succeeded. Errors: {errors}"

    @pytest.mark.timeout(120)
    def test_concurrent_file_writes(self, tmp_path: Path):
        """Verify concurrent file writes don't corrupt data."""

        output_dir = tmp_path / "concurrent_outputs"
        output_dir.mkdir()

        errors = []
        success_count = 0
        lock = threading.Lock()

        def write_findings(thread_id: int):
            nonlocal success_count
            try:
                findings_data = {
                    "meta": {"schema_version": "1.2.0", "finding_count": 100},
                    "findings": [
                        {
                            "id": f"fp-{thread_id}-{i}",
                            "severity": "HIGH",
                            "message": f"Thread {thread_id} finding {i}",
                        }
                        for i in range(100)
                    ],
                }

                output_file = output_dir / f"findings_{thread_id}.json"
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(findings_data, f, indent=2)

                # Verify file is valid JSON
                with open(output_file, "r", encoding="utf-8") as f:
                    loaded = json.load(f)
                    assert loaded["meta"]["finding_count"] == 100

                with lock:
                    success_count += 1
            except Exception as e:
                with lock:
                    errors.append((thread_id, str(e)))

        # Run concurrent writes
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [executor.submit(write_findings, i) for i in range(20)]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    errors.append(("executor", str(e)))

        assert (
            success_count == 20
        ), f"Only {success_count}/20 succeeded. Errors: {errors}"


class TestDatabaseStress:
    """Database-specific stress tests."""

    @pytest.mark.timeout(180)
    def test_10k_scans_query_performance(self, tmp_path: Path):
        """Verify queries remain fast with 10k scans in database."""
        from scripts.core.history_db import init_database

        db_path = tmp_path / "large_db.db"

        init_database(db_path)
        conn = sqlite3.connect(db_path)
        conn.execute("PRAGMA journal_mode=WAL")

        # Insert 10k scans
        start_insert = time.time()
        for i in range(10000):
            conn.execute(
                """
                INSERT INTO scans
                (id, timestamp, timestamp_iso, profile, tools, targets, target_type, jmo_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"scan-{i:05d}",
                    1704067200 + i * 86400,
                    f"2024-01-{(i % 28) + 1:02d}T00:00:00",
                    ["fast", "balanced", "deep"][i % 3],
                    "[]",
                    f'["/repo-{i % 100}"]',
                    "repo",
                    "1.0.0",
                ),
            )
        conn.commit()
        _ = time.time() - start_insert  # Track but don't assert on insert time

        # Insert findings for each scan (10 per scan = 100k findings)
        start_findings = time.time()
        for i in range(10000):
            for j in range(10):
                conn.execute(
                    """
                    INSERT INTO findings
                    (scan_id, fingerprint, severity, tool, rule_id, path, start_line, message)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        f"scan-{i:05d}",
                        f"fp-{i:05d}-{j}",
                        ["CRITICAL", "HIGH", "MEDIUM", "LOW"][j % 4],
                        ["semgrep", "trivy", "bandit"][j % 3],
                        f"CWE-{j * 10}",
                        f"file_{j}.py",
                        j * 100,
                        f"Finding {j}",
                    ),
                )
            if i % 1000 == 0:
                conn.commit()
        conn.commit()
        _ = time.time() - start_findings  # Track but don't assert on findings time

        # Test query performance
        # Count query
        start_count = time.time()
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        count_time = time.time() - start_count

        # Recent scans query
        start_recent = time.time()
        conn.execute("SELECT * FROM scans ORDER BY timestamp DESC LIMIT 100")
        recent_time = time.time() - start_recent

        # Severity distribution query
        start_severity = time.time()
        conn.execute("SELECT severity, COUNT(*) FROM findings GROUP BY severity")
        severity_time = time.time() - start_severity

        conn.close()

        # Performance assertions
        assert count == 10000, f"Expected 10000 scans, got {count}"
        assert count_time < 0.1, f"Count query took {count_time:.3f}s (target: <0.1s)"
        assert (
            recent_time < 0.5
        ), f"Recent query took {recent_time:.3f}s (target: <0.5s)"
        assert (
            severity_time < 1.0
        ), f"Severity query took {severity_time:.3f}s (target: <1s)"

    @pytest.mark.timeout(120)
    def test_database_vacuum_under_load(self, tmp_path: Path):
        """Verify VACUUM works correctly after heavy use."""
        from scripts.core.history_db import init_database

        db_path = tmp_path / "vacuum_test.db"

        # Create and populate database
        init_database(db_path)
        conn = sqlite3.connect(db_path)

        for i in range(1000):
            conn.execute(
                """
                INSERT INTO scans
                (id, timestamp, timestamp_iso, profile, tools, targets, target_type, jmo_version)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    f"scan-{i}",
                    1704067200,
                    "2024-01-01",
                    "fast",
                    "[]",
                    "[]",
                    "repo",
                    "1.0.0",
                ),
            )
        conn.commit()

        # Delete half the scans
        conn.execute("DELETE FROM scans WHERE CAST(SUBSTR(id, 6) AS INTEGER) % 2 = 0")
        conn.commit()
        conn.close()

        # Get size before vacuum
        size_before = db_path.stat().st_size

        # Run vacuum
        conn = sqlite3.connect(db_path)
        conn.execute("VACUUM")
        conn.close()

        # Get size after vacuum
        size_after = db_path.stat().st_size

        # Vacuum should reduce size (or at least not crash)
        assert size_after <= size_before


class TestReportGenerationStress:
    """Stress tests for report generation."""

    @pytest.mark.timeout(120)
    def test_html_dashboard_10k_findings(self, tmp_path: Path):
        """Verify HTML dashboard generation with 10k findings."""
        from scripts.core.reporters.html_reporter import write_html

        findings = []
        for i in range(10000):
            findings.append(
                {
                    "id": f"fp-{i:05d}",
                    "ruleId": f"CWE-{i % 100}",
                    "severity": ["CRITICAL", "HIGH", "MEDIUM", "LOW"][i % 4],
                    "tool": {
                        "name": ["semgrep", "trivy", "bandit"][i % 3],
                        "version": "1.0.0",
                    },
                    "location": {
                        "path": f"src/file_{i % 100}.py",
                        "startLine": i % 500,
                    },
                    "message": f"Finding {i}: " + "x" * 100,
                    "title": f"Issue {i}",
                }
            )

        output_path = tmp_path / "dashboard.html"

        start_time = time.time()
        write_html(findings, output_path)
        elapsed = time.time() - start_time

        # Should complete in reasonable time
        assert elapsed < 30, f"Dashboard generation took {elapsed:.1f}s (target: <30s)"
        assert output_path.exists()
        assert output_path.stat().st_size > 0

    @pytest.mark.timeout(60)
    def test_json_export_50k_findings(self, tmp_path: Path):
        """Verify JSON export with 50k findings."""
        findings = [
            {
                "id": f"fp-{i:05d}",
                "severity": "HIGH",
                "message": f"Finding {i}",
            }
            for i in range(50000)
        ]

        output_path = tmp_path / "findings.json"

        start_time = time.time()
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump({"findings": findings}, f)
        elapsed = time.time() - start_time

        assert elapsed < 10, f"JSON export took {elapsed:.1f}s (target: <10s)"
        assert output_path.exists()

        # Verify file is valid JSON
        with open(output_path, "r", encoding="utf-8") as f:
            data = json.load(f)
            assert len(data["findings"]) == 50000
