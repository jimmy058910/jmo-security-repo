#!/usr/bin/env python3
"""
Integration tests for --collect-metadata CLI flag (Phase 6 Step 6.3).

Tests that the flag controls privacy-sensitive metadata collection.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from scripts.core.history_db import get_connection, store_scan


class TestCollectMetadataFlag:
    """Test --collect-metadata flag behavior in full workflow."""

    def test_cli_default_privacy_mode(self, tmp_path):
        """
        Test that by default (no --collect-metadata), hostname/username are NOT stored.

        Privacy-first principle: Minimize data collection by default.

        Workflow:
        1. Create findings.json
        2. Store scan WITHOUT collect_metadata flag (default)
        3. Query database and verify hostname/username are NULL
        """
        # Arrange: Create test results directory
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "bandit|B101|test.py|5|xyz123",
                    "tool": {"name": "bandit", "version": "1.7.5"},
                    "ruleId": "B101",
                    "severity": "LOW",
                    "message": "Assert used",
                    "location": {"path": "test.py", "startLine": 5},
                    "raw": {"issue_text": "Use of assert detected", "test_id": "B101"},
                }
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store scan with default (no flag = privacy mode)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["bandit"],
            db_path=db_path,
            # collect_metadata defaults to False
        )

        # Assert: Verify metadata NOT collected
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT hostname, username FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row is not None
        assert row[0] is None, "hostname should be NULL (privacy mode)"
        assert row[1] is None, "username should be NULL (privacy mode)"

        conn.close()

    def test_cli_opt_in_metadata_collection(self, tmp_path):
        """
        Test that --collect-metadata flag enables hostname/username storage.

        When user explicitly opts in, metadata should be collected.

        Workflow:
        1. Create findings.json
        2. Store scan WITH collect_metadata=True (opt-in)
        3. Query database and verify hostname/username are present
        """
        # Arrange: Create test results
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "checkov|CKV_AWS_1|main.tf|12|abc789",
                    "tool": {"name": "checkov", "version": "3.0.0"},
                    "ruleId": "CKV_AWS_1",
                    "severity": "HIGH",
                    "message": "S3 bucket not encrypted",
                    "location": {"path": "main.tf", "startLine": 12},
                    "raw": {"check_id": "CKV_AWS_1", "resource": "aws_s3_bucket.data"},
                }
            ]
        }

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store scan with collect_metadata=True (opt-in)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["checkov"],
            db_path=db_path,
            collect_metadata=True,  # ← OPT-IN FLAG
        )

        # Assert: Verify metadata IS collected
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT hostname, username FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row is not None
        # Hostname and username should be populated
        assert row[0] is not None, "hostname should be collected when opt-in"
        assert row[1] is not None, "username should be collected when opt-in"

        # Verify they are non-empty strings
        assert isinstance(row[0], str) and len(row[0]) > 0
        assert isinstance(row[1], str) and len(row[1]) > 0

        conn.close()

    def test_cli_mixed_privacy_settings_multiple_scans(self, tmp_path):
        """
        Test that multiple scans with different privacy settings are stored correctly.

        Scenario:
        - Scan 1: Privacy mode (default)
        - Scan 2: Metadata collection enabled
        - Scan 3: Privacy mode again

        Expected: Each scan respects its own privacy setting.
        """
        # Arrange: Create test results (reusable)
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {"findings": []}
        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store 3 scans with different privacy settings
        scan_id_1 = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
            collect_metadata=False,  # Privacy mode
        )

        scan_id_2 = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["semgrep"],
            db_path=db_path,
            collect_metadata=True,  # Metadata collection
        )

        scan_id_3 = store_scan(
            results_dir=results_dir,
            profile="deep",
            tools=["trufflehog"],
            db_path=db_path,
            collect_metadata=False,  # Privacy mode
        )

        # Assert: Verify each scan has correct privacy setting
        conn = get_connection(db_path)
        cursor = conn.cursor()

        # Scan 1: Privacy mode (NULL metadata)
        cursor.execute("SELECT hostname, username FROM scans WHERE id = ?", (scan_id_1,))
        row1 = cursor.fetchone()
        assert row1[0] is None and row1[1] is None, "Scan 1 should have NULL metadata"

        # Scan 2: Metadata collection (populated)
        cursor.execute("SELECT hostname, username FROM scans WHERE id = ?", (scan_id_2,))
        row2 = cursor.fetchone()
        assert row2[0] is not None and row2[1] is not None, "Scan 2 should have metadata"

        # Scan 3: Privacy mode (NULL metadata)
        cursor.execute("SELECT hostname, username FROM scans WHERE id = ?", (scan_id_3,))
        row3 = cursor.fetchone()
        assert row3[0] is None and row3[1] is None, "Scan 3 should have NULL metadata"

        conn.close()
