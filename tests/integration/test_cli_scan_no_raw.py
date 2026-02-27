#!/usr/bin/env python3
"""
Integration tests for --no-store-raw-findings CLI flag (Phase 6 Step 6.1).

Tests that the flag prevents raw finding data from being stored in history database.
"""

from __future__ import annotations

import json


from scripts.core.history_db import get_connection, store_scan


class TestNoStoreRawFindingsFlag:
    """Test --no-store-raw-findings flag behavior in full workflow."""

    def test_scan_no_store_raw_findings_flag(self, tmp_path):
        """
        Test that --no-store-raw-findings flag prevents raw_finding storage.

        Workflow:
        1. Create findings.json with trufflehog findings (secrets)
        2. Store scan with no_store_raw=True
        3. Query database and verify raw_finding is NULL
        """
        # Arrange: Create test results directory with findings.json
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "trufflehog|github|file.py|1|abc123",
                    "tool": {"name": "trufflehog", "version": "3.63.0"},
                    "ruleId": "github",
                    "severity": "CRITICAL",
                    "message": "GitHub Personal Access Token detected",
                    "location": {"path": "file.py", "startLine": 1},
                    "raw": {
                        "DetectorName": "github",
                        "Raw": "ghp_1234567890abcdef",  # SECRET VALUE
                        "Verified": True,
                    },
                },
                {
                    "schemaVersion": "1.2.0",
                    "id": "trivy|CVE-2024-1234|package.json|0|xyz123",
                    "tool": {"name": "trivy", "version": "0.68.0"},
                    "ruleId": "CVE-2024-1234",
                    "severity": "HIGH",
                    "message": "Vulnerability in lodash",
                    "location": {"path": "package.json", "startLine": 0},
                    "raw": {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "lodash",
                    },
                },
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        # Create individual-repos directory (for target type detection)
        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        # Database path
        db_path = tmp_path / "test_history.db"

        # Act: Store scan with no_store_raw=True
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trufflehog", "trivy"],
            db_path=db_path,
            no_store_raw=True,  # ← FLAG UNDER TEST
        )

        # Assert: Verify scan was stored
        assert scan_id is not None
        assert db_path.exists()

        # Assert: Query database and verify raw_finding is NULL for all findings
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT fingerprint, tool, raw_finding FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        rows = cursor.fetchall()

        assert len(rows) == 2  # Both findings stored

        # Check trufflehog finding (should have NULL raw_finding)
        trufflehog_row = [r for r in rows if r[1] == "trufflehog"][0]
        assert trufflehog_row[2] is None  # raw_finding is NULL

        # Check trivy finding (should also have NULL raw_finding)
        trivy_row = [r for r in rows if r[1] == "trivy"][0]
        assert trivy_row[2] is None  # raw_finding is NULL

        conn.close()

    def test_scan_default_stores_raw_findings(self, tmp_path):
        """
        Test that by default (no_store_raw=False), raw findings ARE stored.

        This ensures backward compatibility - default behavior unchanged.
        """
        # Arrange: Create test results directory with findings.json
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "trivy|CVE-2024-1234|package.json|0|xyz123",
                    "tool": {"name": "trivy", "version": "0.68.0"},
                    "ruleId": "CVE-2024-1234",
                    "severity": "HIGH",
                    "message": "Vulnerability in lodash",
                    "location": {"path": "package.json", "startLine": 0},
                    "raw": {
                        "VulnerabilityID": "CVE-2024-1234",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.19",
                    },
                }
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        # Create individual-repos directory
        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        # Database path
        db_path = tmp_path / "test_history.db"

        # Act: Store scan with default (no_store_raw=False)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
            no_store_raw=False,  # ← DEFAULT BEHAVIOR
        )

        # Assert: Verify scan was stored
        assert scan_id is not None

        # Assert: Query database and verify raw_finding IS stored (not NULL)
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT raw_finding FROM findings WHERE scan_id = ? AND tool = ?",
            (scan_id, "trivy"),
        )
        row = cursor.fetchone()

        assert row is not None
        assert row[0] is not None  # raw_finding is NOT NULL
        raw_data = json.loads(row[0])
        assert raw_data["VulnerabilityID"] == "CVE-2024-1234"
        assert raw_data["PkgName"] == "lodash"

        conn.close()

    def test_scan_no_store_raw_with_redaction(self, tmp_path):
        """
        Test interaction between --no-store-raw-findings and secret redaction.

        When both features are used:
        - no_store_raw=True takes precedence (raw_finding = NULL)
        - Redaction is skipped (no need to redact if not storing)
        """
        # Arrange: Create findings with secrets
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "trufflehog|aws|config.py|5|secret123",
                    "tool": {"name": "trufflehog", "version": "3.63.0"},
                    "ruleId": "aws",
                    "severity": "CRITICAL",
                    "message": "AWS Access Key detected",
                    "location": {"path": "config.py", "startLine": 5},
                    "raw": {
                        "DetectorName": "aws",
                        "Raw": "AKIAIOSFODNN7EXAMPLE",  # SECRET
                        "Verified": True,
                    },
                }
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store with no_store_raw=True (should skip redaction and set NULL)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trufflehog"],
            db_path=db_path,
            no_store_raw=True,
        )

        # Assert: raw_finding is NULL (not redacted, just not stored)
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT raw_finding FROM findings WHERE scan_id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row[0] is None  # NULL, not redacted JSON

        conn.close()
