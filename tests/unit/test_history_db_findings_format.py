"""
Test that store_scan() handles both list and dict findings formats.

Regression test for Phase 9.1 bug where findings.json contains a list
directly rather than a dict with 'findings' key.
"""

import json
import tempfile
from pathlib import Path

import pytest

from scripts.core.history_db import get_connection, init_database, store_scan


class TestFindingsFormatHandling:
    """Test store_scan() handles both findings.json formats."""

    def test_store_scan_with_list_format_findings(self, tmp_path):
        """Test store_scan() with findings as direct list (current format)."""
        # Setup database
        db_path = tmp_path / "history.db"
        init_database(db_path)

        # Create test results directory
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        summaries = results_dir / "summaries"
        summaries.mkdir()

        # Create findings.json with LIST format (current)
        findings_list = [
            {
                "schemaVersion": "1.2.0",
                "id": "test-finding-1",
                "ruleId": "test-rule",
                "severity": "HIGH",
                "tool": {"name": "test-tool", "version": "1.0"},
                "location": {"path": "test.py", "startLine": 10},
                "message": "Test finding",
            }
        ]
        findings_file = summaries / "findings.json"
        with open(findings_file, "w") as f:
            json.dump(findings_list, f)

        # Store scan (should succeed with list format)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["test-tool"],
            db_path=db_path,
        )

        # Verify scan stored
        assert scan_id is not None
        assert len(scan_id) > 0

        # Verify findings stored
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM findings")
        count = cursor.fetchone()[0]
        assert count == 1

    def test_store_scan_with_dict_format_findings(self, tmp_path):
        """Test store_scan() with findings in dict (legacy format)."""
        # Setup database
        db_path = tmp_path / "history.db"
        init_database(db_path)

        # Create test results directory
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        summaries = results_dir / "summaries"
        summaries.mkdir()

        # Create findings.json with DICT format (legacy)
        findings_dict = {
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "test-finding-2",
                    "ruleId": "test-rule-2",
                    "severity": "MEDIUM",
                    "tool": {"name": "test-tool", "version": "1.0"},
                    "location": {"path": "test2.py", "startLine": 20},
                    "message": "Test finding 2",
                }
            ]
        }
        findings_file = summaries / "findings.json"
        with open(findings_file, "w") as f:
            json.dump(findings_dict, f)

        # Store scan (should succeed with dict format)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["test-tool"],
            db_path=db_path,
        )

        # Verify scan stored
        assert scan_id is not None

        # Verify findings stored
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM findings")
        count = cursor.fetchone()[0]
        assert count == 1

    def test_store_scan_with_empty_list(self, tmp_path):
        """Test store_scan() with empty findings list."""
        # Setup database
        db_path = tmp_path / "history.db"
        init_database(db_path)

        # Create test results directory
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        summaries = results_dir / "summaries"
        summaries.mkdir()

        # Create findings.json with empty list
        findings_file = summaries / "findings.json"
        with open(findings_file, "w") as f:
            json.dump([], f)

        # Store scan (should succeed with 0 findings)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["test-tool"],
            db_path=db_path,
        )

        # Verify scan stored
        assert scan_id is not None

        # Verify 0 findings stored
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM findings")
        count = cursor.fetchone()[0]
        assert count == 0

        # Verify scan metadata shows 0 total findings
        cursor = conn.execute("SELECT total_findings FROM scans WHERE id=?", (scan_id,))
        total = cursor.fetchone()[0]
        assert total == 0

    def test_store_scan_with_malformed_format(self, tmp_path):
        """Test store_scan() handles malformed findings gracefully."""
        # Setup database
        db_path = tmp_path / "history.db"
        init_database(db_path)

        # Create test results directory
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        summaries = results_dir / "summaries"
        summaries.mkdir()

        # Create findings.json with malformed format (string, not list/dict)
        findings_file = summaries / "findings.json"
        with open(findings_file, "w") as f:
            json.dump("malformed", f)

        # Store scan (should handle gracefully with 0 findings)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["test-tool"],
            db_path=db_path,
        )

        # Verify scan stored despite malformed findings
        assert scan_id is not None

        # Verify 0 findings stored
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM findings")
        count = cursor.fetchone()[0]
        assert count == 0
