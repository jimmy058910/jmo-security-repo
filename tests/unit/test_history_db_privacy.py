#!/usr/bin/env python3
"""
Unit tests for privacy-aware metadata collection (Phase 6 Step 6.3).

Tests cover:
- Default behavior: hostname/username NOT collected (privacy-first)
- Opt-in behavior: --collect-metadata flag enables collection
- Backward compatibility with existing scans
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.core.history_db import get_connection, store_scan


class TestPrivacyAwareDefaults:
    """Test privacy-aware metadata collection defaults."""

    def test_default_no_metadata_collection(self, tmp_path):
        """
        Test that by default, hostname and username are NOT collected.

        Privacy-first principle: Users must explicitly opt-in to metadata collection.
        Default behavior should minimize data collection.

        Expected: hostname and username fields are NULL in database.
        """
        # Arrange: Create test results directory
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        # Create minimal findings.json
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

        # Act: Store scan with default (collect_metadata=False)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
            collect_metadata=False,  # ← DEFAULT BEHAVIOR
        )

        # Assert: Verify scan was stored
        assert scan_id is not None
        assert db_path.exists()

        # Assert: Query database and verify hostname/username are NULL
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT hostname, username FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row is not None
        assert row[0] is None, "hostname should be NULL (privacy-first default)"
        assert row[1] is None, "username should be NULL (privacy-first default)"

        conn.close()

    def test_opt_in_metadata_collection(self, tmp_path):
        """
        Test that --collect-metadata flag enables hostname/username collection.

        When user explicitly opts in, metadata should be collected and stored.

        Expected: hostname and username fields are populated in database.
        """
        # Arrange: Create test results directory
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {
            "findings": [
                {
                    "schemaVersion": "1.2.0",
                    "id": "semgrep|rule-123|app.py|10|abc456",
                    "tool": {"name": "semgrep", "version": "1.45.0"},
                    "ruleId": "rule-123",
                    "severity": "MEDIUM",
                    "message": "SQL injection vulnerability",
                    "location": {"path": "app.py", "startLine": 10},
                    "raw": {"check_id": "rule-123", "path": "app.py"},
                }
            ]
        }
        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store scan with collect_metadata=True
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["semgrep"],
            db_path=db_path,
            collect_metadata=True,  # ← OPT-IN METADATA COLLECTION
        )

        # Assert: Verify scan was stored
        assert scan_id is not None

        # Assert: Query database and verify hostname/username are populated
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT hostname, username FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row is not None
        # Hostname and username should be present (not NULL)
        # We can't assert exact values (system-dependent), but they should exist
        assert row[0] is not None, "hostname should be collected when opt-in"
        assert row[1] is not None, "username should be collected when opt-in"

        # Verify they are non-empty strings
        assert (
            isinstance(row[0], str) and len(row[0]) > 0
        ), "hostname should be non-empty"
        assert (
            isinstance(row[1], str) and len(row[1]) > 0
        ), "username should be non-empty"

        conn.close()

    def test_ci_metadata_always_collected(self, tmp_path, monkeypatch):
        """
        Test that CI provider/build_id are always collected (even with collect_metadata=False).

        Rationale: CI metadata is non-PII and useful for traceability.
        Only hostname/username are privacy-sensitive.

        Expected: ci_provider and ci_build_id are populated even when collect_metadata=False.
        """
        # Arrange: Mock GitHub Actions CI environment
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_RUN_ID", "123456789")

        # Create test results
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {"findings": []}
        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Store scan with collect_metadata=False (privacy mode)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
            collect_metadata=False,  # Privacy mode
        )

        # Assert: CI metadata should STILL be collected
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT hostname, username, ci_provider, ci_build_id FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row is not None
        # PII should NOT be collected
        assert row[0] is None, "hostname should be NULL in privacy mode"
        assert row[1] is None, "username should be NULL in privacy mode"

        # CI metadata SHOULD be collected (non-PII)
        assert row[2] == "github", "ci_provider should be collected (non-PII)"
        assert row[3] == "123456789", "ci_build_id should be collected (non-PII)"

        conn.close()

    def test_backward_compatibility_default_true(self, tmp_path):
        """
        Test backward compatibility: old code calling store_scan() without collect_metadata.

        When collect_metadata parameter is omitted, it should default to False (privacy-first).

        Expected: hostname/username are NULL (privacy-first default).
        """
        # Arrange: Create test results
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_data = {"findings": []}
        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        db_path = tmp_path / "test_history.db"

        # Act: Call store_scan WITHOUT collect_metadata parameter (old code)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
            # collect_metadata parameter omitted (defaults to False)
        )

        # Assert: Should default to privacy mode (no metadata collection)
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute(
            "SELECT hostname, username FROM scans WHERE id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()

        assert row is not None
        assert (
            row[0] is None
        ), "hostname should be NULL (backward compatibility default)"
        assert (
            row[1] is None
        ), "username should be NULL (backward compatibility default)"

        conn.close()
