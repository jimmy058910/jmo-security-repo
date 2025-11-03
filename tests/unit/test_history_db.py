#!/usr/bin/env python3
"""
Unit tests for scripts/core/history_db.py (SQLite Historical Storage).

Tests cover:
- Database initialization
- Schema creation (tables, indices, triggers, views)
- Scan storage (store_scan)
- Scan retrieval (get_scan_by_id, list_scans)
- Finding retrieval (get_findings_for_scan)
- Database statistics (get_database_stats)
- Scan deletion and pruning (delete_scan, prune_old_scans)
- Git context extraction (get_git_context)
- Target type detection (detect_target_type)
- Error handling and edge cases

Target Coverage: ≥90%
"""

import json
import sqlite3
import subprocess
import time
from unittest.mock import MagicMock, patch

import pytest

from scripts.core.history_db import (
    SCHEMA_VERSION,
    collect_targets,
    delete_scan,
    detect_target_type,
    get_connection,
    get_database_stats,
    get_findings_for_scan,
    get_git_context,
    get_scan_by_id,
    init_database,
    list_scans,
    prune_old_scans,
    store_scan,
)


class TestDatabaseInitialization:
    """Test database initialization and schema creation."""

    def test_init_database_creates_tables(self, tmp_path):
        """Test that init_database creates all required tables."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        conn = get_connection(db_path)
        cursor = conn.cursor()

        # Check that all tables exist
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name"
        )
        tables = {row[0] for row in cursor.fetchall()}

        assert "scans" in tables
        assert "findings" in tables
        assert "scan_metadata" in tables
        assert "schema_version" in tables

        conn.close()

    def test_init_database_creates_indices(self, tmp_path):
        """Test that init_database creates all required indices."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        conn = get_connection(db_path)
        cursor = conn.cursor()

        # Check that indices exist
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='index' ORDER BY name"
        )
        indices = {row[0] for row in cursor.fetchall()}

        # Sample of expected indices
        assert "idx_scans_timestamp" in indices
        assert "idx_scans_branch" in indices
        assert "idx_findings_scan_id" in indices
        assert "idx_findings_fingerprint" in indices
        assert "idx_findings_severity" in indices

        conn.close()

    def test_init_database_creates_triggers(self, tmp_path):
        """Test that init_database creates all required triggers."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        conn = get_connection(db_path)
        cursor = conn.cursor()

        # Check that triggers exist
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='trigger' ORDER BY name"
        )
        triggers = {row[0] for row in cursor.fetchall()}

        assert "update_scan_counts_on_insert" in triggers
        assert "update_scan_counts_on_delete" in triggers

        conn.close()

    def test_init_database_creates_views(self, tmp_path):
        """Test that init_database creates all required views."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        conn = get_connection(db_path)
        cursor = conn.cursor()

        # Check that views exist
        cursor.execute("SELECT name FROM sqlite_master WHERE type='view' ORDER BY name")
        views = {row[0] for row in cursor.fetchall()}

        assert "latest_scan_by_branch" in views
        assert "finding_history" in views

        conn.close()

    def test_init_database_records_schema_version(self, tmp_path):
        """Test that init_database records the schema version."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT version FROM schema_version")
        version = cursor.fetchone()[0]

        assert version == SCHEMA_VERSION

        conn.close()

    def test_init_database_idempotent(self, tmp_path):
        """Test that init_database can be called multiple times safely."""
        db_path = tmp_path / "test.db"

        # Initialize twice
        init_database(db_path)
        init_database(db_path)

        # Should not raise errors
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM scans")
        assert cursor.fetchone()[0] == 0
        conn.close()


class TestGetConnection:
    """Test database connection management."""

    def test_get_connection_creates_directory(self, tmp_path):
        """Test that get_connection creates parent directory if needed."""
        db_path = tmp_path / "subdir" / "test.db"
        conn = get_connection(db_path)

        assert db_path.parent.exists()
        conn.close()

    def test_get_connection_sets_row_factory(self, tmp_path):
        """Test that get_connection sets row_factory."""
        db_path = tmp_path / "test.db"
        conn = get_connection(db_path)

        assert conn.row_factory == sqlite3.Row

        conn.close()

    def test_get_connection_enables_foreign_keys(self, tmp_path):
        """Test that get_connection enables foreign key constraints."""
        db_path = tmp_path / "test.db"
        conn = get_connection(db_path)

        cursor = conn.cursor()
        cursor.execute("PRAGMA foreign_keys")
        assert cursor.fetchone()[0] == 1

        conn.close()


class TestStoreScan:
    """Test scan storage functionality."""

    def test_store_scan_basic(self, tmp_path):
        """Test basic scan storage."""
        db_path = tmp_path / "test.db"

        # Create a minimal findings.json
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "test123",
                    "severity": "HIGH",
                    "tool": {"name": "trivy", "version": "0.68.0"},
                    "ruleId": "CVE-2024-1234",
                    "location": {"path": "src/main.py", "startLine": 42},
                    "message": "SQL injection vulnerability",
                }
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        # Store scan
        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
        )

        # Verify scan was stored
        assert scan_id is not None
        assert len(scan_id) == 36  # UUID length

        # Verify data in database
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()

        assert scan_row is not None
        assert scan_row["profile"] == "balanced"
        assert scan_row["total_findings"] == 1
        assert scan_row["high_count"] == 1

        # Verify finding was stored
        cursor.execute("SELECT * FROM findings WHERE scan_id = ?", (scan_id,))
        finding_rows = cursor.fetchall()

        assert len(finding_rows) == 1
        assert finding_rows[0]["fingerprint"] == "test123"
        assert finding_rows[0]["severity"] == "HIGH"
        assert finding_rows[0]["tool"] == "trivy"

        conn.close()

    def test_store_scan_with_git_context(self, tmp_path):
        """Test scan storage with Git context."""
        db_path = tmp_path / "test.db"

        # Create findings.json
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {"findings": []}
        findings_json.write_text(json.dumps(findings_data))

        # Store scan with explicit Git context
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["semgrep"],
            db_path=db_path,
            commit_hash="abc123def456",
            branch="main",
            tag="v1.0.0",
        )

        # Verify Git context was stored
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()

        assert scan_row["commit_hash"] == "abc123def456"
        assert scan_row["commit_short"] == "abc123d"
        assert scan_row["branch"] == "main"
        assert scan_row["tag"] == "v1.0.0"

        conn.close()

    def test_store_scan_with_multiple_findings(self, tmp_path):
        """Test scan storage with multiple findings."""
        db_path = tmp_path / "test.db"

        # Create findings with different severities
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "crit1",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 1},
                    "message": "Critical vuln",
                },
                {
                    "id": "high1",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "app.py", "startLine": 2},
                    "message": "High vuln",
                },
                {
                    "id": "med1",
                    "severity": "MEDIUM",
                    "tool": {"name": "checkov"},
                    "ruleId": "CKV_001",
                    "location": {"path": "infra.tf", "startLine": 3},
                    "message": "Medium vuln",
                },
                {
                    "id": "low1",
                    "severity": "LOW",
                    "tool": {"name": "hadolint"},
                    "ruleId": "DL3000",
                    "location": {"path": "Dockerfile", "startLine": 4},
                    "message": "Low vuln",
                },
                {
                    "id": "info1",
                    "severity": "INFO",
                    "tool": {"name": "syft"},
                    "ruleId": "INFO_001",
                    "location": {"path": "package.json", "startLine": 5},
                    "message": "Info finding",
                },
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        # Store scan
        scan_id = store_scan(
            results_dir=results_dir,
            profile="deep",
            tools=["trivy", "semgrep", "checkov", "hadolint", "syft"],
            db_path=db_path,
        )

        # Verify severity counts
        conn = get_connection(db_path)
        cursor = conn.cursor()

        cursor.execute("SELECT * FROM scans WHERE id = ?", (scan_id,))
        scan_row = cursor.fetchone()

        assert scan_row["total_findings"] == 5
        assert scan_row["critical_count"] == 1
        assert scan_row["high_count"] == 1
        assert scan_row["medium_count"] == 1
        assert scan_row["low_count"] == 1
        assert scan_row["info_count"] == 1

        conn.close()

    def test_store_scan_missing_findings_json(self, tmp_path):
        """Test that store_scan raises FileNotFoundError if findings.json missing."""
        db_path = tmp_path / "test.db"
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        with pytest.raises(FileNotFoundError, match="findings.json not found"):
            store_scan(
                results_dir=results_dir,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
            )

    def test_store_scan_invalid_profile(self, tmp_path):
        """Test that store_scan raises ValueError for invalid profile."""
        db_path = tmp_path / "test.db"

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        with pytest.raises(ValueError, match="Invalid profile"):
            store_scan(
                results_dir=results_dir,
                profile="invalid_profile",
                tools=["trivy"],
                db_path=db_path,
            )


class TestScanRetrieval:
    """Test scan retrieval functionality."""

    def test_get_scan_by_id_exact_match(self, tmp_path):
        """Test retrieving scan by exact UUID."""
        db_path = tmp_path / "test.db"

        # Create and store a scan
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # Retrieve scan
        conn = get_connection(db_path)
        scan = get_scan_by_id(conn, scan_id)
        conn.close()

        assert scan is not None
        assert scan["id"] == scan_id
        assert scan["profile"] == "fast"

    def test_get_scan_by_id_prefix_match(self, tmp_path):
        """Test retrieving scan by UUID prefix."""
        db_path = tmp_path / "test.db"

        # Create and store a scan
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # Retrieve scan by prefix (first 8 characters)
        conn = get_connection(db_path)
        scan = get_scan_by_id(conn, scan_id[:8])
        conn.close()

        assert scan is not None
        assert scan["id"] == scan_id

    def test_get_scan_by_id_not_found(self, tmp_path):
        """Test that get_scan_by_id returns None for non-existent scan."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        conn = get_connection(db_path)
        scan = get_scan_by_id(conn, "non_existent_id")
        conn.close()

        assert scan is None

    def test_list_scans_all(self, tmp_path):
        """Test listing all scans."""
        db_path = tmp_path / "test.db"

        # Create multiple scans
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_ids = []
        for i in range(3):
            scan_id = store_scan(
                results_dir=results_dir,
                profile="fast",
                tools=["trivy"],
                db_path=db_path,
                branch=f"branch-{i}",
            )
            scan_ids.append(scan_id)
            time.sleep(1.1)  # Ensure different timestamps (Unix seconds)

        # List all scans
        conn = get_connection(db_path)
        scans = list_scans(conn, limit=50)
        conn.close()

        assert len(scans) == 3
        # Most recent first (DESC order by timestamp)
        assert scans[0]["id"] == scan_ids[2]
        assert scans[1]["id"] == scan_ids[1]
        assert scans[2]["id"] == scan_ids[0]

    def test_list_scans_filter_by_branch(self, tmp_path):
        """Test listing scans filtered by branch."""
        db_path = tmp_path / "test.db"

        # Create scans with different branches
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
            branch="main",
        )
        store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
            branch="main",
        )
        store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
            branch="dev",
        )

        # List scans for branch=main
        conn = get_connection(db_path)
        scans = list_scans(conn, branch="main")
        conn.close()

        assert len(scans) == 2
        assert all(s["branch"] == "main" for s in scans)


class TestFindingRetrieval:
    """Test finding retrieval functionality."""

    def test_get_findings_for_scan(self, tmp_path):
        """Test retrieving findings for a specific scan."""
        db_path = tmp_path / "test.db"

        # Create scan with findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "find1",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 1},
                    "message": "Critical vulnerability",
                },
                {
                    "id": "find2",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "app.py", "startLine": 2},
                    "message": "High vulnerability",
                },
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy", "semgrep"],
            db_path=db_path,
        )

        # Retrieve findings
        conn = get_connection(db_path)
        findings = get_findings_for_scan(conn, scan_id)
        conn.close()

        assert len(findings) == 2
        # Check both findings exist (order not guaranteed without ORDER BY)
        fingerprints = {f["fingerprint"] for f in findings}
        assert fingerprints == {"find1", "find2"}
        assert findings[0]["severity"] in ["CRITICAL", "HIGH"]
        assert findings[1]["severity"] in ["CRITICAL", "HIGH"]


class TestDatabaseStats:
    """Test database statistics functionality."""

    def test_get_database_stats(self, tmp_path):
        """Test retrieving database statistics."""
        db_path = tmp_path / "test.db"

        # Create scans with findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "find1",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py"},
                    "message": "Test",
                }
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
            branch="main",
        )
        store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
            branch="dev",
        )

        # Get stats
        conn = get_connection(db_path)
        stats = get_database_stats(conn)
        conn.close()

        assert stats["total_scans"] == 2
        assert stats["total_findings"] == 2
        assert stats["db_size_mb"] >= 0
        assert len(stats["scans_by_branch"]) == 2
        assert len(stats["scans_by_profile"]) == 2
        assert len(stats["findings_by_severity"]) >= 1


class TestScanDeletion:
    """Test scan deletion functionality."""

    def test_delete_scan(self, tmp_path):
        """Test deleting a single scan."""
        db_path = tmp_path / "test.db"

        # Create scan
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # Delete scan
        conn = get_connection(db_path)
        deleted = delete_scan(conn, scan_id)
        conn.commit()
        conn.close()

        assert deleted is True

        # Verify scan was deleted
        conn = get_connection(db_path)
        scan = get_scan_by_id(conn, scan_id)
        conn.close()

        assert scan is None

    def test_prune_old_scans(self, tmp_path):
        """Test pruning old scans."""
        db_path = tmp_path / "test.db"

        # Create old scan (simulate old timestamp)
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # Manually update timestamp to 100 days ago
        conn = get_connection(db_path)
        old_timestamp = int(time.time()) - (100 * 86400)
        conn.execute(
            "UPDATE scans SET timestamp = ? WHERE id = ?", (old_timestamp, scan_id)
        )
        conn.commit()

        # Prune scans older than 90 days
        deleted = prune_old_scans(conn, 90 * 86400)
        conn.commit()
        conn.close()

        assert deleted == 1

        # Verify scan was deleted
        conn = get_connection(db_path)
        scan = get_scan_by_id(conn, scan_id)
        conn.close()

        assert scan is None


class TestHelperFunctions:
    """Test helper functions."""

    def test_detect_target_type_repo(self, tmp_path):
        """Test detecting repository target type."""
        results_dir = tmp_path / "results"
        repo_dir = results_dir / "individual-repos"
        repo_dir.mkdir(parents=True)

        target_type = detect_target_type(results_dir)
        assert target_type == "repo"

    def test_detect_target_type_image(self, tmp_path):
        """Test detecting container image target type."""
        results_dir = tmp_path / "results"
        image_dir = results_dir / "individual-images"
        image_dir.mkdir(parents=True)

        target_type = detect_target_type(results_dir)
        assert target_type == "image"

    def test_detect_target_type_unknown(self, tmp_path):
        """Test detecting unknown target type."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        target_type = detect_target_type(results_dir)
        assert target_type == "unknown"

    def test_collect_targets_repo(self, tmp_path):
        """Test collecting repository targets."""
        results_dir = tmp_path / "results"
        repo_dir = results_dir / "individual-repos"
        repo_dir.mkdir(parents=True)

        (repo_dir / "myrepo").mkdir()
        (repo_dir / "another-repo").mkdir()

        targets = collect_targets(results_dir)
        assert len(targets) == 2
        assert "myrepo" in targets
        assert "another-repo" in targets

    @patch("scripts.core.history_db.subprocess.run")
    def test_get_git_context_success(self, mock_run, tmp_path):
        """Test extracting Git context successfully."""
        # Mock successful Git commands
        mock_run.side_effect = [
            MagicMock(stdout="abc123def456\n", returncode=0),  # git rev-parse HEAD
            MagicMock(stdout="abc123d\n", returncode=0),  # git rev-parse --short HEAD
            MagicMock(stdout="main\n", returncode=0),  # git rev-parse --abbrev-ref HEAD
            MagicMock(stdout="v1.0.0\n", returncode=0),  # git describe --tags
            MagicMock(stdout="", returncode=0),  # git status --porcelain
        ]

        git_ctx = get_git_context(tmp_path)

        assert git_ctx["commit_hash"] == "abc123def456"
        assert git_ctx["commit_short"] == "abc123d"
        assert git_ctx["branch"] == "main"
        assert git_ctx["tag"] == "v1.0.0"
        assert git_ctx["is_dirty"] == 0

    @patch("scripts.core.history_db.subprocess.run")
    def test_get_git_context_not_git_repo(self, mock_run, tmp_path):
        """Test extracting Git context from non-Git directory."""
        # Mock failed Git command - raise exception on first call
        mock_run.side_effect = subprocess.CalledProcessError(128, "git")

        git_ctx = get_git_context(tmp_path)

        assert git_ctx["commit_hash"] is None
        assert git_ctx["branch"] is None
        assert git_ctx["tag"] is None
        assert git_ctx["is_dirty"] == 0


class TestEdgeCases:
    """Test edge cases and error paths for improved coverage."""

    def test_store_scan_with_ci_environment(self, tmp_path, monkeypatch):
        """Test scan storage with CI environment variables."""
        db_path = tmp_path / "test.db"

        # Set GitHub Actions environment
        monkeypatch.setenv("GITHUB_ACTIONS", "true")
        monkeypatch.setenv("GITHUB_RUN_ID", "12345")

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_id = store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
        )

        # Verify CI metadata was captured
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ci_provider, ci_build_id FROM scans WHERE id = ?", (scan_id,)
        )
        scan_row = cursor.fetchone()
        conn.close()

        assert scan_row["ci_provider"] == "github"
        assert scan_row["ci_build_id"] == "12345"

    def test_list_scans_with_since_filter(self, tmp_path):
        """Test listing scans filtered by timestamp."""
        db_path = tmp_path / "test.db"

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        # Store first scan
        store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # Wait 2 seconds and store second scan
        time.sleep(2)
        cutoff_time = int(time.time())
        time.sleep(1)

        scan_id_2 = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # List scans since cutoff (should only get scan_id_2)
        conn = get_connection(db_path)
        recent_scans = list_scans(conn, since=cutoff_time, limit=50)
        conn.close()

        assert len(recent_scans) == 1
        assert recent_scans[0]["id"] == scan_id_2

    def test_list_scans_with_profile_filter(self, tmp_path):
        """Test listing scans filtered by profile."""
        db_path = tmp_path / "test.db"

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        # Store scans with different profiles
        store_scan(results_dir, profile="fast", tools=["trivy"], db_path=db_path)
        deep_scan_id = store_scan(
            results_dir, profile="deep", tools=["trivy"], db_path=db_path
        )

        # Filter by deep profile
        conn = get_connection(db_path)
        deep_scans = list_scans(conn, profile="deep", limit=50)
        conn.close()

        assert len(deep_scans) == 1
        assert deep_scans[0]["id"] == deep_scan_id
        assert deep_scans[0]["profile"] == "deep"

    def test_collect_targets_multiple_types(self, tmp_path):
        """Test collecting targets from multiple target type directories."""
        results_dir = tmp_path / "results"

        # Create multiple target directories with subdirectories
        (results_dir / "individual-repos" / "myapp").mkdir(parents=True)
        (results_dir / "individual-repos" / "backend").mkdir(parents=True)
        (results_dir / "individual-images" / "nginx_latest").mkdir(parents=True)

        targets = collect_targets(results_dir)

        # Should collect from repos (primary target type)
        assert len(targets) >= 2
        assert any("myapp" in t for t in targets)
        assert any("backend" in t for t in targets)

    def test_get_scan_by_id_with_findings(self, tmp_path):
        """Test retrieving a scan with its findings."""
        db_path = tmp_path / "test.db"

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "finding1",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-1111",
                    "location": {"path": "app.py", "startLine": 10},
                    "message": "Vulnerability found",
                }
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        scan_id = store_scan(
            results_dir, profile="balanced", tools=["trivy"], db_path=db_path
        )

        # Retrieve scan and verify
        conn = get_connection(db_path)
        scan = get_scan_by_id(conn, scan_id)
        conn.close()

        assert scan is not None
        assert scan["id"] == scan_id
        assert scan["total_findings"] == 1
        assert scan["high_count"] == 1

    def test_store_scan_gitlab_ci(self, tmp_path, monkeypatch):
        """Test scan storage with GitLab CI environment."""
        db_path = tmp_path / "test.db"

        # Unset other CI environments to ensure GitLab is detected
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("JENKINS_URL", raising=False)

        # Set GitLab CI environment
        monkeypatch.setenv("GITLAB_CI", "true")
        monkeypatch.setenv("CI_PIPELINE_ID", "67890")

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_id = store_scan(
            results_dir, profile="fast", tools=["trivy"], db_path=db_path
        )

        # Verify GitLab CI metadata
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ci_provider, ci_build_id FROM scans WHERE id = ?", (scan_id,)
        )
        scan_row = cursor.fetchone()
        conn.close()

        assert scan_row["ci_provider"] == "gitlab"
        assert scan_row["ci_build_id"] == "67890"

    def test_store_scan_jenkins_ci(self, tmp_path, monkeypatch):
        """Test scan storage with Jenkins CI environment."""
        db_path = tmp_path / "test.db"

        # Unset other CI environments to ensure Jenkins is detected
        monkeypatch.delenv("GITHUB_ACTIONS", raising=False)
        monkeypatch.delenv("GITLAB_CI", raising=False)

        # Set Jenkins environment
        monkeypatch.setenv("JENKINS_URL", "https://jenkins.example.com")
        monkeypatch.setenv("BUILD_NUMBER", "456")

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps({"findings": []}))

        scan_id = store_scan(
            results_dir, profile="deep", tools=["trivy"], db_path=db_path
        )

        # Verify Jenkins CI metadata
        conn = get_connection(db_path)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT ci_provider, ci_build_id FROM scans WHERE id = ?", (scan_id,)
        )
        scan_row = cursor.fetchone()
        conn.close()

        assert scan_row["ci_provider"] == "jenkins"
        assert scan_row["ci_build_id"] == "456"

    def test_collect_targets_images(self, tmp_path):
        """Test collecting targets from individual-images directory."""
        results_dir = tmp_path / "results"
        (results_dir / "individual-images" / "nginx_latest").mkdir(parents=True)
        (results_dir / "individual-images" / "postgres_14").mkdir(parents=True)

        targets = collect_targets(results_dir)

        assert len(targets) >= 2
        assert any("nginx_latest" in t for t in targets)

    def test_collect_targets_iac(self, tmp_path):
        """Test collecting targets from individual-iac directory."""
        results_dir = tmp_path / "results"
        (results_dir / "individual-iac" / "terraform_tfstate").mkdir(parents=True)

        targets = collect_targets(results_dir)

        assert len(targets) >= 1
        assert any("terraform_tfstate" in t for t in targets)

    def test_collect_targets_web(self, tmp_path):
        """Test collecting targets from individual-web directory."""
        results_dir = tmp_path / "results"
        (results_dir / "individual-web" / "example_com").mkdir(parents=True)

        targets = collect_targets(results_dir)

        assert len(targets) >= 1
        assert any("example_com" in t for t in targets)

    def test_collect_targets_gitlab(self, tmp_path):
        """Test collecting targets from individual-gitlab directory."""
        results_dir = tmp_path / "results"
        (results_dir / "individual-gitlab" / "mygroup_myrepo").mkdir(parents=True)

        targets = collect_targets(results_dir)

        assert len(targets) >= 1
        assert any("mygroup_myrepo" in t for t in targets)

    def test_collect_targets_k8s(self, tmp_path):
        """Test collecting targets from individual-k8s directory."""
        results_dir = tmp_path / "results"
        (results_dir / "individual-k8s" / "prod_default").mkdir(parents=True)

        targets = collect_targets(results_dir)

        assert len(targets) >= 1
        assert any("prod_default" in t for t in targets)

    def test_get_findings_for_scan_with_severity_filter(self, tmp_path):
        """Test retrieving findings filtered by severity."""
        db_path = tmp_path / "test.db"

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings_json = summaries_dir / "findings.json"
        findings_data = {
            "findings": [
                {
                    "id": "crit1",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 1},
                    "message": "Critical issue",
                },
                {
                    "id": "high1",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "app.py", "startLine": 2},
                    "message": "High issue",
                },
            ]
        }
        findings_json.write_text(json.dumps(findings_data))

        scan_id = store_scan(
            results_dir, profile="balanced", tools=["trivy", "semgrep"], db_path=db_path
        )

        # Retrieve only CRITICAL findings
        conn = get_connection(db_path)
        critical_findings = get_findings_for_scan(conn, scan_id, severity="CRITICAL")
        conn.close()

        assert len(critical_findings) == 1
        assert critical_findings[0]["severity"] == "CRITICAL"
        assert critical_findings[0]["fingerprint"] == "crit1"

    def test_store_scan_with_nonexistent_results_dir(self, tmp_path):
        """Test that store_scan raises FileNotFoundError for nonexistent results directory."""
        db_path = tmp_path / "test.db"
        nonexistent_dir = tmp_path / "does_not_exist"

        with pytest.raises(FileNotFoundError, match="Results directory not found"):
            store_scan(
                nonexistent_dir, profile="balanced", tools=["trivy"], db_path=db_path
            )


if __name__ == "__main__":
    pytest.main(
        [__file__, "-v", "--cov=scripts.core.history_db", "--cov-report=term-missing"]
    )
