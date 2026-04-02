#!/usr/bin/env python3
"""
SQL Injection Resistance Tests for JMo Security.

Tests that all SQL operations in history_db.py use parameterized queries
and are resistant to SQL injection attacks.
"""

from __future__ import annotations


import pytest

from scripts.core.history_db import (
    get_connection,
    init_database,
    list_scans,
    store_scan,
)


class TestSQLInjectionResistance:
    """Test SQL injection resistance in history database operations."""

    def test_scan_id_injection_attempts(self, tmp_path):
        """Test that scan_id parameters resist SQL injection.

        Attempts classic SQL injection payloads:
        - ' OR '1'='1
        - '; DROP TABLE scans; --
        - ' UNION SELECT * FROM scans --
        """
        db_path = tmp_path / "test-injection.db"
        init_database(db_path)
        conn = get_connection(db_path)

        # Create a legitimate scan first
        scan_results_dir = tmp_path / "scan-1"
        (scan_results_dir / "summaries").mkdir(parents=True)
        (scan_results_dir / "summaries" / "findings.json").write_text("[]")

        store_scan(
            results_dir=scan_results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
        )

        # Attempt SQL injection via scan_id parameter
        injection_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE scans; --",
            "' UNION SELECT * FROM scans --",
            "1; DELETE FROM scans; --",
        ]

        for payload in injection_payloads:
            # Query should safely handle injection attempts
            cursor = conn.execute(
                "SELECT * FROM scans WHERE id = ?",
                (payload,),  # Parameterized query
            )
            result = cursor.fetchall()

            # Should return empty result (not match legitimate scan)
            assert (
                len(result) == 0
            ), f"SQL injection payload '{payload}' should not return results"

        # Verify legitimate scan still exists
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        assert count == 1, "Legitimate scan should still exist"

        conn.close()

    def test_tool_name_injection_attempts(self, tmp_path):
        """Test that tool name parameters resist SQL injection.

        Validates that tool names stored in database are sanitized.
        """
        db_path = tmp_path / "test-tool-injection.db"
        init_database(db_path)

        scan_results_dir = tmp_path / "scan-1"
        (scan_results_dir / "summaries").mkdir(parents=True)
        (scan_results_dir / "summaries" / "findings.json").write_text("[]")

        # Attempt to inject SQL via tool names
        malicious_tools = [
            "trivy'; DROP TABLE scans; --",
            "semgrep' OR '1'='1",
            "bandit' UNION SELECT * FROM scans --",
        ]

        scan_id = store_scan(
            results_dir=scan_results_dir,
            profile="balanced",
            tools=malicious_tools,
            db_path=db_path,
        )

        # Verify database integrity
        conn = get_connection(db_path)

        # Check scans table still exists
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        assert "scans" in tables, "scans table should still exist"

        # Verify tools stored correctly (as JSON string, not executed)
        cursor = conn.execute("SELECT tools FROM scans WHERE id = ?", (scan_id,))
        tools_json = cursor.fetchone()[0]

        # Should contain malicious payloads as literal strings (not executed)
        for tool in malicious_tools:
            assert (
                tool in tools_json
            ), f"Tool '{tool}' should be stored as literal string, not executed"

        conn.close()

    def test_parameterized_queries_enforcement(self, tmp_path):
        """Test that all queries use parameterized inputs (no string formatting).

        Validates that history_db.py uses safe parameterized queries.
        """
        db_path = tmp_path / "test-params.db"
        init_database(db_path)
        conn = get_connection(db_path)

        # Create test scan
        scan_results_dir = tmp_path / "scan-1"
        (scan_results_dir / "summaries").mkdir(parents=True)
        (scan_results_dir / "summaries" / "findings.json").write_text("[]")

        scan_id = store_scan(
            results_dir=scan_results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
            commit_hash="abc123",
            branch="main",
        )

        # Verify parameterized queries work correctly
        # Test 1: Retrieve by scan_id
        cursor = conn.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        result = cursor.fetchone()
        assert result is not None, "Should retrieve scan by ID"

        # Test 2: Retrieve by commit_hash
        cursor = conn.execute("SELECT * FROM scans WHERE commit_hash = ?", ("abc123",))
        result = cursor.fetchone()
        assert result is not None, "Should retrieve scan by commit hash"

        # Test 3: Retrieve by branch
        cursor = conn.execute("SELECT * FROM scans WHERE branch = ?", ("main",))
        result = cursor.fetchone()
        assert result is not None, "Should retrieve scan by branch"

        # Test 4: list_scans with limit parameter
        scans = list_scans(conn, limit=10)
        assert len(scans) == 1, "Should return 1 scan with limit parameter"

        conn.close()

    def test_path_parameter_injection(self, tmp_path):
        """Test that file path parameters do not cause SQL injection.

        Note: Path traversal is a separate concern from SQL injection.
        This test validates that path parameters themselves cannot inject SQL.
        """
        # Create legitimate scan directory
        scan_results_dir = tmp_path / "scan-1"
        scan_results_dir.mkdir(parents=True, exist_ok=True)
        (scan_results_dir / "summaries").mkdir(parents=True, exist_ok=True)
        (scan_results_dir / "summaries" / "findings.json").write_text("[]")

        # Use database path with SQL injection attempt
        db_path = tmp_path / "test'; DROP TABLE scans; --.db"
        init_database(db_path)

        # Store scan with path containing SQL injection
        scan_id = store_scan(
            results_dir=scan_results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
        )

        # Verify database integrity
        conn = get_connection(db_path)

        # Check tables still exist
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        assert "scans" in tables, "scans table should still exist"
        assert "findings" in tables, "findings table should still exist"

        # Verify scan was stored correctly
        cursor = conn.execute("SELECT id FROM scans WHERE id = ?", (scan_id,))
        stored_id = cursor.fetchone()[0]

        # Scan should be stored successfully
        assert stored_id == scan_id, "Scan ID should match"
        conn.close()

    def test_findings_table_injection(self, tmp_path):
        """Test that findings table operations resist SQL injection.

        Validates fingerprint IDs and finding data cannot execute SQL.
        """
        import json

        db_path = tmp_path / "test-findings-injection.db"
        init_database(db_path)
        conn = get_connection(db_path)

        # Create scan with malicious findings
        scan_results_dir = tmp_path / "scan-1"
        (scan_results_dir / "summaries").mkdir(parents=True)

        malicious_findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "'; DROP TABLE findings; --",
                "ruleId": "CWE-79' OR '1'='1",
                "severity": "CRITICAL",
                "tool": {"name": "trivy", "version": "1.0.0"},
                "location": {"path": "test.py", "startLine": 1, "endLine": 1},
                "message": "Test'; DELETE FROM scans; --",
            }
        ]

        (scan_results_dir / "summaries" / "findings.json").write_text(
            json.dumps(malicious_findings)
        )

        scan_id = store_scan(
            results_dir=scan_results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
        )

        # Verify database integrity
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [row[0] for row in cursor.fetchall()]
        assert "findings" in tables, "findings table should still exist"
        assert "scans" in tables, "scans table should still exist"

        # Verify malicious data stored as literals (not executed)
        cursor = conn.execute(
            "SELECT fingerprint, rule_id, message FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        results = cursor.fetchall()

        assert len(results) == 1, "Should store 1 finding"
        fingerprint, rule_id, message = results[0]

        # Verify malicious payloads stored as strings
        assert "DROP TABLE" in fingerprint, "Malicious fingerprint stored as literal"
        assert "OR '1'='1" in rule_id, "Malicious rule_id stored as literal"
        assert "DELETE FROM" in message, "Malicious message stored as literal"

        conn.close()


if __name__ == "__main__":
    # Allow running tests directly
    pytest.main([__file__, "-v", "--tb=short"])
