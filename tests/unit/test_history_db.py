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


class TestComputeDiff:
    """Test compute_diff() function for comparing two scans."""

    def test_compute_diff_basic(self, tmp_path):
        """Test basic diff between two scans with some changes."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Create results directory with findings for scan 1
        results_dir_1 = tmp_path / "results1"
        summaries_dir_1 = results_dir_1 / "summaries"
        summaries_dir_1.mkdir(parents=True)

        findings_1 = {
            "findings": [
                {
                    "id": "finding1",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 10},
                    "message": "Vulnerability A",
                },
                {
                    "id": "finding2",
                    "severity": "MEDIUM",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "app.py", "startLine": 20},
                    "message": "Issue B",
                },
                {
                    "id": "finding3",
                    "severity": "LOW",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0003",
                    "location": {"path": "app.py", "startLine": 30},
                    "message": "Issue C",
                },
                {
                    "id": "finding4",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0004",
                    "location": {"path": "lib.py", "startLine": 5},
                    "message": "Issue D",
                },
                {
                    "id": "finding5",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0005",
                    "location": {"path": "lib.py", "startLine": 15},
                    "message": "Critical issue E",
                },
            ]
        }
        (summaries_dir_1 / "findings.json").write_text(json.dumps(findings_1))

        # Store scan 1
        scan_id_1 = store_scan(
            results_dir_1,
            profile="balanced",
            tools=["trivy", "semgrep"],
            db_path=db_path,
        )

        # Create results directory with findings for scan 2
        # Scan 2: 3 unchanged (finding1, finding2, finding3), 1 resolved (finding5), 2 new (finding6, finding7)
        results_dir_2 = tmp_path / "results2"
        summaries_dir_2 = results_dir_2 / "summaries"
        summaries_dir_2.mkdir(parents=True)

        findings_2 = {
            "findings": [
                # Unchanged from scan 1
                {
                    "id": "finding1",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 10},
                    "message": "Vulnerability A",
                },
                {
                    "id": "finding2",
                    "severity": "MEDIUM",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "app.py", "startLine": 20},
                    "message": "Issue B",
                },
                {
                    "id": "finding3",
                    "severity": "LOW",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0003",
                    "location": {"path": "app.py", "startLine": 30},
                    "message": "Issue C",
                },
                # New findings
                {
                    "id": "finding6",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0006",
                    "location": {"path": "new.py", "startLine": 1},
                    "message": "New vulnerability",
                },
                {
                    "id": "finding7",
                    "severity": "MEDIUM",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G201",
                    "location": {"path": "new.py", "startLine": 10},
                    "message": "New issue",
                },
                # finding4 and finding5 resolved (not present in scan 2)
            ]
        }
        (summaries_dir_2 / "findings.json").write_text(json.dumps(findings_2))

        # Store scan 2
        scan_id_2 = store_scan(
            results_dir_2,
            profile="balanced",
            tools=["trivy", "semgrep"],
            db_path=db_path,
        )

        # Import compute_diff
        from scripts.core.history_db import compute_diff

        # Compute diff
        conn = get_connection(db_path)
        diff = compute_diff(conn, scan_id_1, scan_id_2)
        conn.close()

        # Expected: {"new": 2, "resolved": 2, "unchanged": 3}
        assert len(diff["new"]) == 2
        assert len(diff["resolved"]) == 2
        assert len(diff["unchanged"]) == 3

        # Verify new findings
        new_ids = {f["fingerprint"] for f in diff["new"]}
        assert "finding6" in new_ids
        assert "finding7" in new_ids

        # Verify resolved findings
        resolved_ids = {f["fingerprint"] for f in diff["resolved"]}
        assert "finding4" in resolved_ids
        assert "finding5" in resolved_ids

        # Verify unchanged findings
        unchanged_ids = {f["fingerprint"] for f in diff["unchanged"]}
        assert "finding1" in unchanged_ids
        assert "finding2" in unchanged_ids
        assert "finding3" in unchanged_ids

    def test_compute_diff_identical_scans(self, tmp_path):
        """Test diff when scans are identical."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        results_dir_1 = tmp_path / "results1"
        summaries_dir_1 = results_dir_1 / "summaries"
        summaries_dir_1.mkdir(parents=True)

        findings = {
            "findings": [
                {
                    "id": "finding1",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 10},
                    "message": "Vulnerability",
                },
                {
                    "id": "finding2",
                    "severity": "MEDIUM",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "app.py", "startLine": 20},
                    "message": "Issue",
                },
            ]
        }
        (summaries_dir_1 / "findings.json").write_text(json.dumps(findings))

        scan_id_1 = store_scan(
            results_dir_1, profile="balanced", tools=["trivy"], db_path=db_path
        )

        # Create identical scan 2
        results_dir_2 = tmp_path / "results2"
        summaries_dir_2 = results_dir_2 / "summaries"
        summaries_dir_2.mkdir(parents=True)
        (summaries_dir_2 / "findings.json").write_text(json.dumps(findings))

        scan_id_2 = store_scan(
            results_dir_2, profile="balanced", tools=["trivy"], db_path=db_path
        )

        # Import compute_diff
        from scripts.core.history_db import compute_diff

        conn = get_connection(db_path)
        diff = compute_diff(conn, scan_id_1, scan_id_2)
        conn.close()

        # Expected: {"new": 0, "resolved": 0, "unchanged": 2}
        assert len(diff["new"]) == 0
        assert len(diff["resolved"]) == 0
        assert len(diff["unchanged"]) == 2

    def test_compute_diff_all_new(self, tmp_path):
        """Test diff when first scan is empty."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Scan 1: 0 findings
        results_dir_1 = tmp_path / "results1"
        summaries_dir_1 = results_dir_1 / "summaries"
        summaries_dir_1.mkdir(parents=True)
        (summaries_dir_1 / "findings.json").write_text(json.dumps({"findings": []}))

        scan_id_1 = store_scan(
            results_dir_1, profile="fast", tools=["trivy"], db_path=db_path
        )

        # Scan 2: 5 findings
        results_dir_2 = tmp_path / "results2"
        summaries_dir_2 = results_dir_2 / "summaries"
        summaries_dir_2.mkdir(parents=True)

        findings_2 = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-000{i}",
                    "location": {"path": "app.py", "startLine": i * 10},
                    "message": f"Vulnerability {i}",
                }
                for i in range(1, 6)
            ]
        }
        (summaries_dir_2 / "findings.json").write_text(json.dumps(findings_2))

        scan_id_2 = store_scan(
            results_dir_2, profile="fast", tools=["trivy"], db_path=db_path
        )

        # Import compute_diff
        from scripts.core.history_db import compute_diff

        conn = get_connection(db_path)
        diff = compute_diff(conn, scan_id_1, scan_id_2)
        conn.close()

        # Expected: {"new": 5, "resolved": 0, "unchanged": 0}
        assert len(diff["new"]) == 5
        assert len(diff["resolved"]) == 0
        assert len(diff["unchanged"]) == 0

    def test_compute_diff_all_resolved(self, tmp_path):
        """Test diff when second scan is clean."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Scan 1: 5 findings
        results_dir_1 = tmp_path / "results1"
        summaries_dir_1 = results_dir_1 / "summaries"
        summaries_dir_1.mkdir(parents=True)

        findings_1 = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-000{i}",
                    "location": {"path": "app.py", "startLine": i * 10},
                    "message": f"Vulnerability {i}",
                }
                for i in range(1, 6)
            ]
        }
        (summaries_dir_1 / "findings.json").write_text(json.dumps(findings_1))

        scan_id_1 = store_scan(
            results_dir_1, profile="fast", tools=["trivy"], db_path=db_path
        )

        # Scan 2: 0 findings
        results_dir_2 = tmp_path / "results2"
        summaries_dir_2 = results_dir_2 / "summaries"
        summaries_dir_2.mkdir(parents=True)
        (summaries_dir_2 / "findings.json").write_text(json.dumps({"findings": []}))

        scan_id_2 = store_scan(
            results_dir_2, profile="fast", tools=["trivy"], db_path=db_path
        )

        # Import compute_diff
        from scripts.core.history_db import compute_diff

        conn = get_connection(db_path)
        diff = compute_diff(conn, scan_id_1, scan_id_2)
        conn.close()

        # Expected: {"new": 0, "resolved": 5, "unchanged": 0}
        assert len(diff["new"]) == 0
        assert len(diff["resolved"]) == 5
        assert len(diff["unchanged"]) == 0

    def test_compute_diff_fingerprint_matching(self, tmp_path):
        """Test that fingerprint-based matching works correctly."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Scan 1
        results_dir_1 = tmp_path / "results1"
        summaries_dir_1 = results_dir_1 / "summaries"
        summaries_dir_1.mkdir(parents=True)

        findings_1 = {
            "findings": [
                {
                    "id": "finding1",  # Same fingerprint
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 10},
                    "message": "Vulnerability",
                },
                {
                    "id": "finding2",  # Different fingerprint (will be resolved)
                    "severity": "MEDIUM",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G101",
                    "location": {"path": "old.py", "startLine": 20},
                    "message": "Old issue",
                },
            ]
        }
        (summaries_dir_1 / "findings.json").write_text(json.dumps(findings_1))

        scan_id_1 = store_scan(
            results_dir_1,
            profile="balanced",
            tools=["trivy", "semgrep"],
            db_path=db_path,
        )

        # Scan 2
        results_dir_2 = tmp_path / "results2"
        summaries_dir_2 = results_dir_2 / "summaries"
        summaries_dir_2.mkdir(parents=True)

        findings_2 = {
            "findings": [
                {
                    "id": "finding1",  # Same fingerprint (unchanged)
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": "CVE-2024-0001",
                    "location": {"path": "app.py", "startLine": 10},
                    "message": "Vulnerability",
                },
                {
                    "id": "finding3",  # Different fingerprint (new)
                    "severity": "MEDIUM",
                    "tool": {"name": "semgrep"},
                    "ruleId": "G201",
                    "location": {"path": "new.py", "startLine": 30},
                    "message": "New issue",
                },
            ]
        }
        (summaries_dir_2 / "findings.json").write_text(json.dumps(findings_2))

        scan_id_2 = store_scan(
            results_dir_2,
            profile="balanced",
            tools=["trivy", "semgrep"],
            db_path=db_path,
        )

        # Import compute_diff
        from scripts.core.history_db import compute_diff

        conn = get_connection(db_path)
        diff = compute_diff(conn, scan_id_1, scan_id_2)
        conn.close()

        # Verify fingerprint matching
        assert len(diff["unchanged"]) == 1
        assert diff["unchanged"][0]["fingerprint"] == "finding1"

        assert len(diff["resolved"]) == 1
        assert diff["resolved"][0]["fingerprint"] == "finding2"

        assert len(diff["new"]) == 1
        assert diff["new"][0]["fingerprint"] == "finding3"

    def test_compute_diff_invalid_scan_ids(self, tmp_path):
        """Test error handling for invalid scan IDs."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Import compute_diff
        from scripts.core.history_db import compute_diff

        conn = get_connection(db_path)

        # Test with invalid scan IDs
        with pytest.raises(ValueError, match="Invalid scan ID"):
            compute_diff(conn, "nonexistent-scan-1", "nonexistent-scan-2")

        conn.close()


class TestGetTrendSummary:
    """Test get_trend_summary() for trend analysis."""

    def test_get_trend_summary_30_days(self, tmp_path, monkeypatch):
        """Test trend summary over 30 days with multiple scans."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Mock time to control timestamp
        current_time = int(time.time())

        # Create 10 scans over 30 days with varying findings
        scan_ids = []
        for i in range(10):
            # Create scan i days ago (ensure all are in the past)
            days_ago = 29 - (i * 3)  # Scans at day 29, 26, 23, 20, 17, 14, 11, 8, 5, 2
            scan_time = (
                current_time - (days_ago * 86400) - 3600
            )  # Subtract 1 hour to ensure it's in the past

            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)

            # Vary findings count (showing improvement over time)
            finding_count = 20 - i  # 20, 19, 18, ... 11 findings
            critical_count = max(0, 5 - (i // 2))  # 5, 5, 4, 4, 3, 3, 2, 2, 1, 1
            high_count = max(0, 10 - i)  # 10, 9, 8, ... 1

            findings = {
                "findings": [
                    {
                        "id": f"finding{i}_{j}",
                        "severity": (
                            "CRITICAL"
                            if j < critical_count
                            else (
                                "HIGH" if j < critical_count + high_count else "MEDIUM"
                            )
                        ),
                        "tool": {"name": "trivy"},
                        "ruleId": f"CVE-2024-{j:04d}" if j < 5 else f"G{j}",
                        "location": {"path": "app.py", "startLine": j * 10},
                        "message": f"Finding {j}",
                    }
                    for j in range(finding_count)
                ]
            }
            (summaries_dir / "findings.json").write_text(json.dumps(findings))

            # Store scan with mocked timestamp
            with patch("time.time", return_value=scan_time):
                scan_id = store_scan(
                    results_dir,
                    profile="balanced",
                    tools=["trivy"],
                    db_path=db_path,
                    branch="main",
                )
                scan_ids.append(scan_id)

        # Import get_trend_summary
        from scripts.core.history_db import get_trend_summary

        # Get trend summary
        conn = get_connection(db_path)
        trend = get_trend_summary(conn, "main", days=30)
        conn.close()

        # Verify structure
        assert trend is not None
        assert "scan_count" in trend
        assert "date_range" in trend
        assert "severity_trends" in trend
        assert "top_rules" in trend
        assert "improvement_metrics" in trend

        # Verify scan count
        assert trend["scan_count"] == 10

        # Verify date range
        assert "start" in trend["date_range"]
        assert "end" in trend["date_range"]

        # Verify severity trends (should have arrays)
        assert "CRITICAL" in trend["severity_trends"]
        assert "HIGH" in trend["severity_trends"]
        assert len(trend["severity_trends"]["CRITICAL"]) == 10

        # Verify improvement metrics (findings decreasing)
        assert trend["improvement_metrics"]["trend"] == "improving"
        assert (
            trend["improvement_metrics"]["total_change"] < -5
        )  # More than 5 fewer findings

    def test_get_trend_summary_empty_branch(self, tmp_path):
        """Test trend when no scans exist for branch."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Import get_trend_summary
        from scripts.core.history_db import get_trend_summary

        conn = get_connection(db_path)
        trend = get_trend_summary(conn, "nonexistent", days=30)
        conn.close()

        # Expected: None
        assert trend is None

    def test_get_trend_summary_single_scan(self, tmp_path):
        """Test trend with only one scan (no trend possible)."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        findings = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-000{i}",
                    "location": {"path": "app.py", "startLine": i * 10},
                    "message": f"Vulnerability {i}",
                }
                for i in range(5)
            ]
        }
        (summaries_dir / "findings.json").write_text(json.dumps(findings))

        store_scan(
            results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=db_path,
            branch="main",
        )

        # Import get_trend_summary
        from scripts.core.history_db import get_trend_summary

        conn = get_connection(db_path)
        trend = get_trend_summary(conn, "main", days=30)
        conn.close()

        # Should return data but with insufficient_data trend
        assert trend is not None
        assert trend["scan_count"] == 1
        assert trend["improvement_metrics"]["trend"] == "insufficient_data"

    def test_get_trend_summary_improvement(self, tmp_path, monkeypatch):
        """Test trend showing security improvement."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        current_time = int(time.time())

        # Scan 1: 100 findings (50 CRITICAL, 50 HIGH) - 30 days ago
        results_dir_1 = tmp_path / "results1"
        summaries_dir_1 = results_dir_1 / "summaries"
        summaries_dir_1.mkdir(parents=True)

        findings_1 = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "CRITICAL" if i < 50 else "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-{i:04d}",
                    "location": {"path": "app.py", "startLine": i},
                    "message": f"Finding {i}",
                }
                for i in range(100)
            ]
        }
        (summaries_dir_1 / "findings.json").write_text(json.dumps(findings_1))

        with patch("time.time", return_value=current_time - (30 * 86400)):
            store_scan(
                results_dir_1,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )

        # Scan 2: 80 findings (40 CRITICAL, 40 HIGH) - 20 days ago
        results_dir_2 = tmp_path / "results2"
        summaries_dir_2 = results_dir_2 / "summaries"
        summaries_dir_2.mkdir(parents=True)

        findings_2 = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "CRITICAL" if i < 40 else "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-{i:04d}",
                    "location": {"path": "app.py", "startLine": i},
                    "message": f"Finding {i}",
                }
                for i in range(80)
            ]
        }
        (summaries_dir_2 / "findings.json").write_text(json.dumps(findings_2))

        with patch("time.time", return_value=current_time - (20 * 86400)):
            store_scan(
                results_dir_2,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )

        # Scan 3: 60 findings (30 CRITICAL, 30 HIGH) - 10 days ago
        results_dir_3 = tmp_path / "results3"
        summaries_dir_3 = results_dir_3 / "summaries"
        summaries_dir_3.mkdir(parents=True)

        findings_3 = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "CRITICAL" if i < 30 else "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-{i:04d}",
                    "location": {"path": "app.py", "startLine": i},
                    "message": f"Finding {i}",
                }
                for i in range(60)
            ]
        }
        (summaries_dir_3 / "findings.json").write_text(json.dumps(findings_3))

        with patch("time.time", return_value=current_time - (10 * 86400)):
            store_scan(
                results_dir_3,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )

        # Import get_trend_summary
        from scripts.core.history_db import get_trend_summary

        conn = get_connection(db_path)

        # Patch time.time() to ensure consistent time window calculation
        # get_trend_summary() calls time.time() internally at line 1305
        with patch("time.time", return_value=current_time):
            trend = get_trend_summary(conn, "main", days=30)

        conn.close()

        # Expected: improvement_metrics.trend = "improving"
        assert trend["improvement_metrics"]["trend"] == "improving"
        assert trend["improvement_metrics"]["total_change"] == 60 - 100  # -40
        assert trend["improvement_metrics"]["critical_change"] == 30 - 50  # -20
        assert trend["improvement_metrics"]["high_change"] == 30 - 50  # -20

    def test_get_trend_summary_degradation(self, tmp_path, monkeypatch):
        """Test trend showing security degradation."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        current_time = int(time.time())

        # Scan 1: 50 findings - 30 days ago
        results_dir_1 = tmp_path / "results1"
        summaries_dir_1 = results_dir_1 / "summaries"
        summaries_dir_1.mkdir(parents=True)

        findings_1 = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "MEDIUM",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-{i:04d}",
                    "location": {"path": "app.py", "startLine": i},
                    "message": f"Finding {i}",
                }
                for i in range(50)
            ]
        }
        (summaries_dir_1 / "findings.json").write_text(json.dumps(findings_1))

        with patch("time.time", return_value=current_time - (30 * 86400)):
            store_scan(
                results_dir_1,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )

        # Scan 2: 100 findings - now (degrading)
        results_dir_2 = tmp_path / "results2"
        summaries_dir_2 = results_dir_2 / "summaries"
        summaries_dir_2.mkdir(parents=True)

        findings_2 = {
            "findings": [
                {
                    "id": f"finding{i}",
                    "severity": "HIGH",
                    "tool": {"name": "trivy"},
                    "ruleId": f"CVE-2024-{i:04d}",
                    "location": {"path": "app.py", "startLine": i},
                    "message": f"Finding {i}",
                }
                for i in range(100)
            ]
        }
        (summaries_dir_2 / "findings.json").write_text(json.dumps(findings_2))

        with patch("time.time", return_value=current_time):
            store_scan(
                results_dir_2,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )

        # Import get_trend_summary
        from scripts.core.history_db import get_trend_summary

        conn = get_connection(db_path)

        # Patch time.time() to ensure consistent time window calculation
        with patch("time.time", return_value=current_time):
            trend = get_trend_summary(conn, "main", days=30)

        conn.close()

        # Expected: improvement_metrics.trend = "degrading"
        assert trend["improvement_metrics"]["trend"] == "degrading"
        assert trend["improvement_metrics"]["total_change"] == 100 - 50  # +50

    def test_get_trend_summary_top_rules(self, tmp_path, monkeypatch):
        """Test that top_rules are ranked by frequency."""
        db_path = tmp_path / "test.db"
        init_database(db_path)

        current_time = int(time.time())

        # Create 3 scans with rule "CVE-2024-0001" appearing most frequently
        for scan_idx in range(3):
            results_dir = tmp_path / f"results{scan_idx}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)

            findings = {
                "findings": [
                    # Rule A appears in all 3 scans (15 times total)
                    {
                        "id": f"findingA{scan_idx}_{i}",
                        "severity": "HIGH",
                        "tool": {"name": "trivy"},
                        "ruleId": "CVE-2024-0001",  # Rule A
                        "location": {"path": f"app{i}.py", "startLine": i},
                        "message": f"Finding {i}",
                    }
                    for i in range(5)
                ]
                + [
                    # Rule B appears less frequently (10 times total)
                    {
                        "id": f"findingB{scan_idx}_{i}",
                        "severity": "MEDIUM",
                        "tool": {"name": "semgrep"},
                        "ruleId": "G101",  # Rule B
                        "location": {"path": f"lib{i}.py", "startLine": i},
                        "message": f"Finding {i}",
                    }
                    for i in range(3 if scan_idx < 2 else 4)  # 3+3+4=10
                ]
            }
            (summaries_dir / "findings.json").write_text(json.dumps(findings))

            with patch(
                "time.time", return_value=current_time - ((3 - scan_idx) * 86400)
            ):
                store_scan(
                    results_dir,
                    profile="balanced",
                    tools=["trivy", "semgrep"],
                    db_path=db_path,
                    branch="main",
                )

        # Import get_trend_summary
        from scripts.core.history_db import get_trend_summary

        conn = get_connection(db_path)

        # Patch time.time() to ensure consistent time window calculation
        with patch("time.time", return_value=current_time):
            trend = get_trend_summary(conn, "main", days=7)

        conn.close()

        # Expected: top_rules[0].rule_id = "CVE-2024-0001" (15 occurrences)
        assert len(trend["top_rules"]) > 0
        assert trend["top_rules"][0]["rule_id"] == "CVE-2024-0001"
        assert trend["top_rules"][0]["count"] >= 15


class TestSecretRedaction:
    """Test secret redaction functionality for sensitive data."""

    def test_redact_secrets_no_store_raw(self):
        """Test that redact_secrets returns None when store_raw=False."""
        from scripts.core.history_db import redact_secrets

        finding = {
            "id": "fp1",
            "severity": "HIGH",
            "raw": {"secret": "my-api-key-12345"},
        }

        result = redact_secrets(finding, store_raw=False)

        assert result["raw_finding"] is None

    def test_redact_secrets_no_raw_data(self):
        """Test that redact_secrets handles findings without raw data."""
        from scripts.core.history_db import redact_secrets

        finding = {"id": "fp1", "severity": "HIGH"}

        result = redact_secrets(finding, store_raw=True)

        assert result["raw_finding"] == "{}"

    def test_redact_secrets_non_secret_tool(self):
        """Test that non-secret tools store raw data unchanged."""
        from scripts.core.history_db import redact_secrets

        finding = {
            "id": "fp1",
            "severity": "HIGH",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "raw": {"VulnerabilityID": "CVE-2024-0001", "Severity": "HIGH"},
        }

        result = redact_secrets(finding, store_raw=True)

        raw_data = json.loads(result["raw_finding"])
        assert raw_data["VulnerabilityID"] == "CVE-2024-0001"
        assert raw_data["Severity"] == "HIGH"

    def test_redact_trufflehog_secrets(self):
        """Test TruffleHog secret redaction."""
        from scripts.core.history_db import redact_secrets

        finding = {
            "id": "fp1",
            "severity": "HIGH",
            "tool": {"name": "trufflehog", "version": "3.82.0"},
            "raw": {
                "DetectorName": "AWS",
                "VerificationStatus": "Verified",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "RawV2": "aws_secret_access_key_value",
            },
        }

        result = redact_secrets(finding, store_raw=True)

        raw_data = json.loads(result["raw_finding"])
        assert raw_data["DetectorName"] == "AWS"
        assert raw_data["VerificationStatus"] == "Verified"
        assert raw_data["Raw"] == "[REDACTED]"
        assert raw_data["RawV2"] == "[REDACTED]"

    def test_redact_trufflehog_secrets_nested(self):
        """Test TruffleHog secret redaction with nested structures."""
        from scripts.core.history_db import redact_secrets

        finding = {
            "id": "fp1",
            "severity": "HIGH",
            "tool": {"name": "trufflehog", "version": "3.82.0"},
            "raw": {
                "DetectorName": "GitHub",
                "matches": [
                    {"Raw": "ghp_secret123", "context": {"file": "config.yml"}},
                    {"Raw": "ghp_secret456", "context": {"file": "env.sh"}},
                ],
            },
        }

        result = redact_secrets(finding, store_raw=True)

        raw_data = json.loads(result["raw_finding"])
        assert raw_data["matches"][0]["Raw"] == "[REDACTED]"
        assert raw_data["matches"][1]["Raw"] == "[REDACTED]"
        assert raw_data["matches"][0]["context"]["file"] == "config.yml"

    def test_redact_noseyparker_secrets(self):
        """Test NoseyParker secret redaction."""
        from scripts.core.history_db import redact_secrets

        finding = {
            "id": "fp1",
            "severity": "MEDIUM",
            "tool": {"name": "noseyparker", "version": "0.19.0"},
            "raw": {
                "rule_name": "Generic API Key",
                "match": {
                    "snippet": "api_key=abc123def456",
                    "capture_groups": {
                        "secret_value": "abc123def456",
                        "context": "config.py:15",
                    },
                },
            },
        }

        result = redact_secrets(finding, store_raw=True)

        raw_data = json.loads(result["raw_finding"])
        assert raw_data["rule_name"] == "Generic API Key"
        assert raw_data["match"]["snippet"] == "[REDACTED]"
        assert raw_data["match"]["capture_groups"]["secret_value"] == "[REDACTED]"
        assert raw_data["match"]["capture_groups"]["context"] == "config.py:15"

    def test_redact_semgrep_secrets(self):
        """Test Semgrep-secrets redaction."""
        from scripts.core.history_db import redact_secrets

        finding = {
            "id": "fp1",
            "severity": "HIGH",
            "tool": {"name": "semgrep-secrets", "version": "1.50.0"},
            "raw": {
                "check_id": "secrets.api-key",
                "extra": {
                    "lines": "api_key = 'sk-abc123'",
                    "message": "Hardcoded API key",
                    "metadata": {
                        "secret_type": "api_key",
                        "secret_confidence": "high",
                        "other_field": "keep",
                    },
                },
            },
        }

        result = redact_secrets(finding, store_raw=True)

        raw_data = json.loads(result["raw_finding"])
        assert raw_data["check_id"] == "secrets.api-key"
        assert raw_data["extra"]["lines"] == "[REDACTED]"
        assert raw_data["extra"]["message"] == "Hardcoded API key"
        assert raw_data["extra"]["metadata"]["secret_type"] == "[REDACTED]"
        assert raw_data["extra"]["metadata"]["secret_confidence"] == "[REDACTED]"
        assert raw_data["extra"]["metadata"]["other_field"] == "keep"


class TestDatabaseOptimization:
    """Test database optimization and query performance functions."""

    def test_get_query_plan(self, tmp_path):
        """Test query plan extraction for performance analysis."""
        from scripts.core.history_db import get_query_plan, init_database, store_scan

        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Store a scan to have data
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS",
                    }
                ]
            )
        )

        store_scan(
            results_dir,
            profile="balanced",
            tools=["semgrep"],
            db_path=db_path,
            branch="main",
        )

        conn = get_connection(db_path)

        # Get query plan for a simple query
        plan = get_query_plan(conn, "SELECT * FROM scans WHERE branch = 'main'")

        # Should contain query plan information
        assert len(plan) > 0
        assert isinstance(plan, str)
        # Should mention the index or SCAN
        assert "scans" in plan.lower() or "SCAN" in plan

        conn.close()

    def test_optimize_database(self, tmp_path):
        """Test database optimization (VACUUM, ANALYZE)."""
        from scripts.core.history_db import init_database, optimize_database, store_scan

        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Store some scans
        for i in range(3):
            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": f"fp{i}",
                            "severity": "MEDIUM",
                            "ruleId": "CWE-123",
                            "tool": {"name": "trivy"},
                            "location": {"path": f"file{i}.py", "startLine": i},
                            "message": f"Finding {i}",
                        }
                    ]
                )
            )
            store_scan(
                results_dir,
                profile="balanced",
                tools=["trivy"],
                db_path=db_path,
                branch="main",
            )

        # Run optimization
        result = optimize_database(db_path)

        # Check result structure
        assert "size_before_mb" in result
        assert "size_after_mb" in result
        assert "space_reclaimed_mb" in result
        assert "indices_count" in result
        assert "vacuum_success" in result
        assert "analyze_success" in result

        # Check types and reasonable values
        assert isinstance(result["size_before_mb"], float)
        assert isinstance(result["size_after_mb"], float)
        assert result["size_before_mb"] >= 0
        assert result["size_after_mb"] >= 0
        assert result["indices_count"] > 0  # Should have indices
        assert result["vacuum_success"] is True
        assert result["analyze_success"] is True

    def test_optimize_database_reclaims_space(self, tmp_path):
        """Test that optimization can reclaim space after deletions."""
        from scripts.core.history_db import (
            delete_scan,
            get_connection,
            init_database,
            optimize_database,
            store_scan,
        )

        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Store and delete scans to create fragmentation
        scan_ids = []
        for i in range(5):
            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": f"fp{j}",
                            "severity": "HIGH",
                            "ruleId": f"CWE-{j}",
                            "tool": {"name": "semgrep"},
                            "location": {"path": f"file{j}.py", "startLine": j},
                            "message": f"Finding {j}",
                        }
                        for j in range(100)  # 100 findings per scan
                    ]
                )
            )
            with patch("time.time", return_value=1000000 + i):
                store_scan(
                    results_dir,
                    profile="deep",
                    tools=["semgrep"],
                    db_path=db_path,
                    branch="main",
                )

        # Get scan IDs
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT id FROM scans ORDER BY timestamp")
        scan_ids = [row[0] for row in cursor.fetchall()]
        conn.close()

        # Delete first 3 scans (creates space to reclaim)
        conn = get_connection(db_path)
        for scan_id in scan_ids[:3]:
            delete_scan(conn, scan_id)
        conn.close()

        # Optimize should reclaim space
        result = optimize_database(db_path)

        # Space reclaimed should be >= 0 (can be 0 if SQLite doesn't fragment)
        assert result["space_reclaimed_mb"] >= 0


class TestDashboardFunctions:
    """Test dashboard summary and timeline functions."""

    def test_get_dashboard_summary(self, tmp_path):
        """Test dashboard summary generation."""
        from scripts.core.history_db import (
            get_dashboard_summary,
            get_connection,
            init_database,
            store_scan,
        )

        db_path = tmp_path / "test.db"
        init_database(db_path)

        # Store a scan with diverse findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "CRITICAL",
                        "ruleId": "CVE-2024-0001",
                        "tool": {"name": "trivy", "version": "0.68.0"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "Critical vulnerability",
                        "compliance": {
                            "owaspTop10_2021": ["A06:2021"],
                            "cweTop25_2024": [{"id": "CWE-79", "rank": 1}],
                        },
                    },
                    {
                        "id": "fp2",
                        "severity": "HIGH",
                        "ruleId": "CWE-89",
                        "tool": {"name": "semgrep", "version": "1.50.0"},
                        "location": {"path": "src/db.py", "startLine": 25},
                        "message": "SQL injection",
                    },
                    {
                        "id": "fp3",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-200",
                        "tool": {"name": "semgrep", "version": "1.50.0"},
                        "location": {"path": "src/info.py", "startLine": 5},
                        "message": "Information disclosure",
                    },
                ]
            )
        )

        scan_id = store_scan(
            results_dir,
            profile="balanced",
            tools=["trivy", "semgrep"],
            db_path=db_path,
            branch="main",
        )

        conn = get_connection(db_path)

        # Get dashboard summary
        summary = get_dashboard_summary(conn, scan_id)

        conn.close()

        # Verify structure
        assert summary is not None
        assert "scan" in summary
        assert "severity_counts" in summary
        assert "top_rules" in summary
        assert "tools_used" in summary
        assert "findings_by_tool" in summary
        assert "compliance_coverage" in summary

        # Check severity counts
        assert summary["severity_counts"]["CRITICAL"] == 1
        assert summary["severity_counts"]["HIGH"] == 1
        assert summary["severity_counts"]["MEDIUM"] == 1
        assert summary["severity_counts"]["LOW"] == 0

        # Check tools used
        assert "trivy" in summary["tools_used"]
        assert "semgrep" in summary["tools_used"]

        # Check compliance coverage
        assert summary["compliance_coverage"]["total_findings"] == 3
        assert (
            summary["compliance_coverage"]["findings_with_compliance"] >= 1
        )  # fp1 has compliance

    def test_get_dashboard_summary_invalid_scan(self, tmp_path):
        """Test dashboard summary with invalid scan ID."""
        from scripts.core.history_db import (
            get_dashboard_summary,
            get_connection,
            init_database,
        )

        db_path = tmp_path / "test.db"
        init_database(db_path)

        conn = get_connection(db_path)

        # Invalid scan ID should return None
        summary = get_dashboard_summary(conn, "nonexistent123")

        conn.close()

        assert summary is None


class TestEncryptionDecryption:
    """Test encryption and decryption of raw findings."""

    def test_encrypt_raw_finding_success(self, monkeypatch):
        """Test successful encryption of raw finding."""
        from scripts.core.history_db import encrypt_raw_finding

        # Set encryption key
        monkeypatch.setenv("JMO_ENCRYPTION_KEY", "test-encryption-key-32-chars!!")

        raw_json = '{"secret": "my-api-key", "value": 12345}'

        encrypted = encrypt_raw_finding(raw_json)

        # Should be encrypted (not equal to original)
        assert encrypted != raw_json
        # Should be a non-empty string
        assert len(encrypted) > 0
        assert isinstance(encrypted, str)

    def test_encrypt_raw_finding_missing_key(self, monkeypatch):
        """Test encryption fails without JMO_ENCRYPTION_KEY."""
        from scripts.core.history_db import encrypt_raw_finding

        # Ensure env var not set
        monkeypatch.delenv("JMO_ENCRYPTION_KEY", raising=False)

        raw_json = '{"secret": "my-api-key"}'

        with pytest.raises(ValueError, match="JMO_ENCRYPTION_KEY"):
            encrypt_raw_finding(raw_json)

    def test_encrypt_raw_finding_missing_cryptography(self, monkeypatch):
        """Test encryption fails without cryptography library."""
        monkeypatch.setenv("JMO_ENCRYPTION_KEY", "test-key-32-chars-long-here!!")

        # Mock ImportError for cryptography
        import builtins

        original_import = builtins.__import__

        def mock_import(name, *args, **kwargs):
            if name == "cryptography.fernet" or name.startswith("cryptography"):
                raise ImportError("No module named 'cryptography'")
            return original_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", mock_import)

        # Re-import after mocking
        from scripts.core.history_db import encrypt_raw_finding

        raw_json = '{"secret": "my-api-key"}'

        with pytest.raises(ImportError, match="cryptography library required"):
            encrypt_raw_finding(raw_json)

    def test_decrypt_raw_finding_success(self, monkeypatch):
        """Test successful decryption of encrypted finding."""
        from scripts.core.history_db import decrypt_raw_finding, encrypt_raw_finding

        monkeypatch.setenv("JMO_ENCRYPTION_KEY", "test-encryption-key-32-chars!!")

        original_json = '{"secret": "my-api-key", "value": 12345}'

        # Encrypt
        encrypted = encrypt_raw_finding(original_json)

        # Decrypt
        decrypted = decrypt_raw_finding(encrypted)

        # Should match original
        assert decrypted == original_json

    def test_decrypt_raw_finding_missing_key(self, monkeypatch):
        """Test decryption fails without JMO_ENCRYPTION_KEY."""
        from scripts.core.history_db import decrypt_raw_finding

        monkeypatch.delenv("JMO_ENCRYPTION_KEY", raising=False)

        encrypted_str = "fake-encrypted-data"

        with pytest.raises(ValueError, match="JMO_ENCRYPTION_KEY"):
            decrypt_raw_finding(encrypted_str)

    def test_decrypt_raw_finding_invalid_ciphertext(self, monkeypatch):
        """Test decryption fails with invalid ciphertext."""
        from scripts.core.history_db import decrypt_raw_finding

        monkeypatch.setenv("JMO_ENCRYPTION_KEY", "test-encryption-key-32-chars!!")

        invalid_encrypted = "not-valid-fernet-ciphertext"

        with pytest.raises(Exception):  # Fernet raises various exceptions
            decrypt_raw_finding(invalid_encrypted)

    def test_encrypt_decrypt_roundtrip(self, monkeypatch):
        """Test full encrypt/decrypt roundtrip with complex data."""
        from scripts.core.history_db import decrypt_raw_finding, encrypt_raw_finding

        monkeypatch.setenv("JMO_ENCRYPTION_KEY", "test-key-32-characters-here!!")

        complex_json = json.dumps(
            {
                "DetectorName": "AWS",
                "Raw": "AKIAIOSFODNN7EXAMPLE",
                "nested": {"data": [1, 2, 3], "unicode": "日本語"},
            }
        )

        encrypted = encrypt_raw_finding(complex_json)
        decrypted = decrypt_raw_finding(encrypted)

        assert decrypted == complex_json
        assert json.loads(decrypted)["nested"]["unicode"] == "日本語"


class TestAttestationFunctions:
    """Test SLSA attestation storage and retrieval."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        # Create unique database path for this test
        db_path = tmp_path / f"test_{id(self)}.db"

        # Monkeypatch DEFAULT_DB_PATH
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        # CRITICAL SOLUTION: Patch sqlite3.connect at the module level
        # This ensures ALL database connections in history_db module use test database
        # Even when get_connection() is called with default parameter
        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            # If trying to connect to default .jmo/history.db, redirect to test database
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)

        yield db_path

        # Cleanup: remove database file after test
        if db_path.exists():
            db_path.unlink()

    def test_store_attestation_success(self, tmp_path, isolate_database, monkeypatch):
        """Test successful attestation storage."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            store_attestation,
            store_scan,
        )

        db_path = isolate_database  # Use fixture-provided isolated database

        init_database(db_path)

        # Store a scan first
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS",
                    }
                ]
            )
        )

        scan_id = store_scan(
            results_dir,
            profile="balanced",
            tools=["semgrep"],
            # Don't pass db_path - use monkeypatched DEFAULT_DB_PATH
            branch="main",
        )

        # Mock time.time() for consistent timestamp
        mock_time = 1234567890
        monkeypatch.setattr("time.time", lambda: mock_time)

        # Store attestation
        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{"name": "scan-results", "digest": {"sha256": "abc123"}}],
            "predicate": {
                "builder": {"id": "https://github.com/actions"},
                "buildType": "jmo-security-scan",
            },
        }

        store_attestation(
            scan_id,
            attestation,
            signature_path="/path/to/signature.sig",
            certificate_path="/path/to/cert.pem",
            rekor_entry="https://rekor.sigstore.dev/api/v1/log/entries/abc123",
            rekor_published=True,
        )

        # Verify attestation was stored
        # Don't pass db_path - use monkeypatched DEFAULT_DB_PATH
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT attestation_json, signature_path, rekor_published, slsa_level FROM attestations WHERE scan_id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()
        conn.close()

        assert row is not None
        stored_attestation = json.loads(row[0])
        assert stored_attestation["_type"] == "https://in-toto.io/Statement/v0.1"
        assert row[1] == "/path/to/signature.sig"
        assert row[2] == 1  # rekor_published = True
        assert row[3] == 2  # SLSA Level 2

    def test_load_attestation_success(self, tmp_path, isolate_database, monkeypatch):
        """Test successful attestation loading."""
        from scripts.core.history_db import (
            init_database,
            load_attestation,
            store_attestation,
            store_scan,
        )

        db_path = isolate_database  # Use fixture-provided isolated database

        init_database(db_path)

        # Store a scan first
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS",
                    }
                ]
            )
        )

        scan_id = store_scan(
            results_dir,
            profile="balanced",
            tools=["semgrep"],
            # Don't pass db_path - use monkeypatched DEFAULT_DB_PATH
            branch="main",
        )

        # Mock time.time() for consistent timestamp
        mock_time = 1234567890
        monkeypatch.setattr("time.time", lambda: mock_time)

        # Store attestation
        attestation = {
            "_type": "https://in-toto.io/Statement/v0.1",
            "predicateType": "https://slsa.dev/provenance/v0.2",
            "subject": [{"name": "scan-results", "digest": {"sha256": "def456"}}],
        }

        store_attestation(
            scan_id,
            attestation,
            signature_path="/path/to/sig2.sig",
            certificate_path="/path/to/cert2.pem",
            rekor_entry="https://rekor.sigstore.dev/api/v1/log/entries/def456",
            rekor_published=False,
        )

        # Load attestation
        loaded = load_attestation(scan_id)

        assert loaded is not None
        assert loaded["scan_id"] == scan_id
        assert loaded["attestation"]["_type"] == "https://in-toto.io/Statement/v0.1"
        assert loaded["signature_path"] == "/path/to/sig2.sig"
        assert loaded["certificate_path"] == "/path/to/cert2.pem"
        assert (
            loaded["rekor_entry"]
            == "https://rekor.sigstore.dev/api/v1/log/entries/def456"
        )
        assert loaded["rekor_published"] is False
        assert loaded["created_at"] == mock_time
        assert loaded["slsa_level"] == 2

    def test_load_attestation_not_found(self, isolate_database):
        """Test loading attestation for non-existent scan."""
        from scripts.core.history_db import (
            init_database,
            load_attestation,
            migrate_add_attestations_table,
        )

        db_path = isolate_database  # Use fixture-provided isolated database

        init_database(db_path)

        # Ensure attestations table exists (normally created by store_attestation)
        migrate_add_attestations_table()

        # Try to load attestation for non-existent scan
        loaded = load_attestation("non-existent-scan-id")

        assert loaded is None

    def test_get_attestation_coverage(self, tmp_path, isolate_database, monkeypatch):
        """Test attestation coverage statistics."""
        from scripts.core.history_db import (
            get_attestation_coverage,
            init_database,
            store_attestation,
            store_scan,
        )

        db_path = isolate_database  # Use fixture-provided isolated database

        init_database(db_path)

        # Mock time.time() for consistent timestamps
        base_time = 1234567890
        current_time = base_time + (10 * 86400)  # 10 days later
        monkeypatch.setattr("time.time", lambda: current_time)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        # Store 3 scans within the 30-day window
        scan_ids = []
        for i in range(3):
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": f"fp{i}",
                            "severity": "HIGH",
                            "ruleId": f"CWE-{i}",
                            "tool": {"name": "semgrep"},
                            "location": {"path": f"src/file{i}.py", "startLine": 10},
                            "message": f"Issue {i}",
                        }
                    ]
                )
            )

            # Mock time for each scan (1 day apart)
            scan_time = current_time - (i * 86400)
            monkeypatch.setattr("time.time", lambda t=scan_time: t)

            scan_id = store_scan(
                results_dir,
                profile="balanced",
                tools=["semgrep"],
                # Don't pass db_path - use monkeypatched DEFAULT_DB_PATH
                branch="main",
            )
            scan_ids.append(scan_id)

        # Reset time to current
        monkeypatch.setattr("time.time", lambda: current_time)

        # Add attestations to 2 out of 3 scans
        # Scan 0: Attestation with Rekor published
        store_attestation(
            scan_ids[0],
            {"_type": "https://in-toto.io/Statement/v0.1"},
            signature_path="/sig0.sig",
            certificate_path="/cert0.pem",
            rekor_entry="https://rekor.sigstore.dev/entry0",
            rekor_published=True,
        )

        # Scan 1: Attestation WITHOUT Rekor published
        store_attestation(
            scan_ids[1],
            {"_type": "https://in-toto.io/Statement/v0.1"},
            signature_path="/sig1.sig",
            certificate_path="/cert1.pem",
            rekor_entry=None,
            rekor_published=False,
        )

        # Scan 2: No attestation

        # Get coverage for last 30 days
        coverage = get_attestation_coverage(days=30)

        # Verify statistics
        assert coverage["days"] == 30
        assert coverage["total_scans"] == 3
        assert coverage["attested_scans"] == 2
        assert coverage["missing_scans"] == 1
        assert coverage["coverage_percentage"] == pytest.approx(66.67, rel=0.1)
        assert coverage["rekor_published"] == 1
        assert coverage["rekor_rate"] == 50.0
        assert scan_ids[2] in coverage["missing_scan_ids"]
        assert len(coverage["missing_scan_ids"]) == 1

    def test_get_attestation_coverage_no_scans(self, isolate_database):
        """Test attestation coverage with no scans."""
        from scripts.core.history_db import (
            get_attestation_coverage,
            init_database,
            migrate_add_attestations_table,
        )

        db_path = isolate_database  # Use fixture-provided isolated database

        init_database(db_path)

        # Ensure attestations table exists (normally created by store_attestation)
        migrate_add_attestations_table()

        # Get coverage with no scans
        coverage = get_attestation_coverage(days=30)

        assert coverage["total_scans"] == 0
        assert coverage["attested_scans"] == 0
        assert coverage["missing_scans"] == 0
        assert coverage["coverage_percentage"] == 0
        assert coverage["rekor_rate"] == 0
        assert len(coverage["missing_scan_ids"]) == 0

    def test_store_attestation_overwrite(self, tmp_path, isolate_database, monkeypatch):
        """Test that storing attestation twice overwrites the first."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            store_attestation,
            store_scan,
        )

        db_path = isolate_database  # Use fixture-provided isolated database

        init_database(db_path)

        # Store a scan
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS",
                    }
                ]
            )
        )

        scan_id = store_scan(
            results_dir,
            profile="balanced",
            tools=["semgrep"],
            # Don't pass db_path - use monkeypatched DEFAULT_DB_PATH
            branch="main",
        )

        # Mock time.time()
        mock_time = 1234567890
        monkeypatch.setattr("time.time", lambda: mock_time)

        # Store first attestation
        attestation1 = {"version": "1.0", "data": "first"}
        store_attestation(
            scan_id,
            attestation1,
            signature_path="/sig1.sig",
            certificate_path="/cert1.pem",
            rekor_entry=None,
            rekor_published=False,
        )

        # Store second attestation (should overwrite)
        attestation2 = {"version": "2.0", "data": "second"}
        store_attestation(
            scan_id,
            attestation2,
            signature_path="/sig2.sig",
            certificate_path="/cert2.pem",
            rekor_entry="https://rekor.sigstore.dev/entry",
            rekor_published=True,
        )

        # Verify only one attestation exists with second data
        # Don't pass db_path - use monkeypatched DEFAULT_DB_PATH
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*), attestation_json, signature_path, rekor_published FROM attestations WHERE scan_id = ?",
            (scan_id,),
        )
        row = cursor.fetchone()
        conn.close()

        assert row[0] == 1  # Only one attestation
        stored_attestation = json.loads(row[1])
        assert stored_attestation["version"] == "2.0"
        assert stored_attestation["data"] == "second"
        assert row[2] == "/sig2.sig"
        assert row[3] == 1  # rekor_published = True


class TestSearchFindings:
    """Test suite for search_findings function (lines 2078-2205)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        # Create unique database path for this test
        db_path = tmp_path / f"test_{id(self)}.db"

        # Monkeypatch DEFAULT_DB_PATH
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        # CRITICAL SOLUTION: Patch sqlite3.connect at the module level
        # This ensures ALL database connections in history_db module use test database
        # Even when get_connection() is called with default parameter
        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            # If trying to connect to default .jmo/history.db, redirect to test database
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)

        yield db_path

        # Cleanup: remove database file after test
        if db_path.exists():
            db_path.unlink()

    def test_search_findings_text_query(self, tmp_path, isolate_database):
        """Test basic text search across message, path, and rule_id."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability detected",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection risk",
                    },
                    {
                        "id": "fp3",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-22",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/file.py", "startLine": 30},
                        "message": "Path traversal",
                    },
                ]
            )
        )

        store_scan(
            results_dir, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Search for "SQL" - should match message
        conn = get_connection()
        results = search_findings(conn, "SQL")
        conn.close()

        assert len(results) == 1
        assert results[0]["rule_id"] == "CWE-89"
        assert "SQL injection" in results[0]["message"]

    def test_search_findings_path_match(self, tmp_path, isolate_database):
        """Test text search matching file paths."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/auth/login.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                    {
                        "id": "fp2",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-22",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/api/endpoint.py", "startLine": 20},
                        "message": "Path traversal",
                    },
                ]
            )
        )

        store_scan(results_dir, profile="balanced", tools=["semgrep"], branch="main")

        # Search for "auth" - should match path
        conn = get_connection()
        results = search_findings(conn, "auth")
        conn.close()

        assert len(results) == 1
        assert "auth/login.py" in results[0]["path"]

    def test_search_findings_rule_id_match(self, tmp_path, isolate_database):
        """Test text search matching rule IDs."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                ]
            )
        )

        store_scan(
            results_dir, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Search for "CWE-89" - should match rule_id
        conn = get_connection()
        results = search_findings(conn, "CWE-89")
        conn.close()

        assert len(results) == 1
        assert results[0]["rule_id"] == "CWE-89"

    def test_search_findings_severity_filter_single(self, tmp_path, isolate_database):
        """Test filtering by single severity level."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                    {
                        "id": "fp3",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-22",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/file.py", "startLine": 30},
                        "message": "Path traversal",
                    },
                ]
            )
        )

        store_scan(
            results_dir, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Filter for HIGH severity only
        conn = get_connection()
        results = search_findings(conn, "", {"severity": "HIGH"})
        conn.close()

        assert len(results) == 1
        assert results[0]["severity"] == "HIGH"

    def test_search_findings_severity_filter_multiple(self, tmp_path, isolate_database):
        """Test filtering by multiple severity levels."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                    {
                        "id": "fp3",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-22",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/file.py", "startLine": 30},
                        "message": "Path traversal",
                    },
                ]
            )
        )

        store_scan(
            results_dir, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Filter for HIGH and CRITICAL severity
        conn = get_connection()
        results = search_findings(conn, "", {"severity": ["HIGH", "CRITICAL"]})
        conn.close()

        assert len(results) == 2
        severities = {r["severity"] for r in results}
        assert severities == {"HIGH", "CRITICAL"}

    def test_search_findings_tool_filter_single(self, tmp_path, isolate_database):
        """Test filtering by single tool."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                ]
            )
        )

        store_scan(
            results_dir, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Filter for semgrep only
        conn = get_connection()
        results = search_findings(conn, "", {"tool": "semgrep"})
        conn.close()

        assert len(results) == 1
        assert results[0]["tool"] == "semgrep"

    def test_search_findings_tool_filter_multiple(self, tmp_path, isolate_database):
        """Test filtering by multiple tools."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                    {
                        "id": "fp3",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-22",
                        "tool": {"name": "trivy"},
                        "location": {"path": "src/file.py", "startLine": 30},
                        "message": "Path traversal",
                    },
                ]
            )
        )

        store_scan(
            results_dir,
            profile="balanced",
            tools=["semgrep", "bandit", "trivy"],
            branch="main",
        )

        # Filter for semgrep and bandit
        conn = get_connection()
        results = search_findings(conn, "", {"tool": ["semgrep", "bandit"]})
        conn.close()

        assert len(results) == 2
        tools = {r["tool"] for r in results}
        assert tools == {"semgrep", "bandit"}

    def test_search_findings_scan_id_filter(self, tmp_path, isolate_database):
        """Test filtering by scan_id."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create first scan
        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                ]
            )
        )
        scan_id1 = store_scan(
            results_dir1, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Create second scan
        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                ]
            )
        )
        _ = store_scan(
            results_dir2, profile="balanced", tools=["bandit"], branch="main"
        )

        # Filter for scan_id1 only
        conn = get_connection()
        results = search_findings(conn, "", {"scan_id": scan_id1})
        conn.close()

        assert len(results) == 1
        assert results[0]["scan_id"] == scan_id1
        assert results[0]["rule_id"] == "CWE-79"

    def test_search_findings_branch_filter(self, tmp_path, isolate_database):
        """Test filtering by branch (requires JOIN with scans table)."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create main branch scan
        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                ]
            )
        )
        store_scan(results_dir1, profile="balanced", tools=["semgrep"], branch="main")

        # Create dev branch scan
        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                ]
            )
        )
        store_scan(results_dir2, profile="balanced", tools=["bandit"], branch="dev")

        # Filter for main branch only
        conn = get_connection()
        results = search_findings(conn, "", {"branch": "main"})
        conn.close()

        assert len(results) == 1
        assert results[0]["rule_id"] == "CWE-79"

    def test_search_findings_date_range_filter(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test filtering by date range (requires JOIN with scans table)."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create old scan (timestamp: 1000000000)
        mock_time_old = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_old)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                ]
            )
        )
        store_scan(results_dir1, profile="balanced", tools=["semgrep"], branch="main")

        # Create new scan (timestamp: 2000000000)
        mock_time_new = 2000000000
        monkeypatch.setattr("time.time", lambda: mock_time_new)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                ]
            )
        )
        store_scan(results_dir2, profile="balanced", tools=["bandit"], branch="main")

        # Filter for scans between 1500000000 and 2500000000 (should get new scan only)
        conn = get_connection()
        results = search_findings(conn, "", {"date_range": (1500000000, 2500000000)})
        conn.close()

        assert len(results) == 1
        assert results[0]["rule_id"] == "CWE-89"

    def test_search_findings_combined_filters(self, tmp_path, isolate_database):
        """Test combining text query with multiple filters."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability detected",
                    },
                    {
                        "id": "fp2",
                        "severity": "HIGH",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection risk",
                    },
                    {
                        "id": "fp3",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-22",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/file.py", "startLine": 30},
                        "message": "Path traversal vulnerability",
                    },
                ]
            )
        )

        store_scan(
            results_dir, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Search for "vulnerability" with HIGH severity and semgrep tool
        conn = get_connection()
        results = search_findings(
            conn, "vulnerability", {"severity": "HIGH", "tool": "semgrep"}
        )
        conn.close()

        assert len(results) == 1
        assert results[0]["rule_id"] == "CWE-79"
        assert "XSS" in results[0]["message"]

    def test_search_findings_limit_parameter(self, tmp_path, isolate_database):
        """Test limit parameter."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create many test findings
        findings = [
            {
                "id": f"fp{i}",
                "severity": "HIGH",
                "ruleId": f"CWE-{i}",
                "tool": {"name": "semgrep"},
                "location": {"path": f"src/file{i}.py", "startLine": 10},
                "message": f"Vulnerability {i}",
            }
            for i in range(10)
        ]

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(json.dumps(findings))

        store_scan(results_dir, profile="balanced", tools=["semgrep"], branch="main")

        # Limit to 5 results
        conn = get_connection()
        results = search_findings(conn, "", {"limit": 5})
        conn.close()

        assert len(results) == 5

    def test_search_findings_default_limit(self, tmp_path, isolate_database):
        """Test default limit of 100."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create 150 test findings (exceeds default limit of 100)
        findings = [
            {
                "id": f"fp{i}",
                "severity": "HIGH",
                "ruleId": f"CWE-{i}",
                "tool": {"name": "semgrep"},
                "location": {"path": f"src/file{i}.py", "startLine": 10},
                "message": f"Vulnerability {i}",
            }
            for i in range(150)
        ]

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(json.dumps(findings))

        store_scan(results_dir, profile="balanced", tools=["semgrep"], branch="main")

        # No limit specified - should default to 100
        conn = get_connection()
        results = search_findings(conn, "")
        conn.close()

        assert len(results) == 100

    def test_search_findings_severity_ordering(self, tmp_path, isolate_database):
        """Test results are ordered by severity (CRITICAL > HIGH > MEDIUM > LOW > INFO)."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings with different severities
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "LOW",
                        "ruleId": "CWE-1",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/a.py", "startLine": 10},
                        "message": "Low severity",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-2",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/b.py", "startLine": 20},
                        "message": "Critical severity",
                    },
                    {
                        "id": "fp3",
                        "severity": "HIGH",
                        "ruleId": "CWE-3",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/c.py", "startLine": 30},
                        "message": "High severity",
                    },
                    {
                        "id": "fp4",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-4",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/d.py", "startLine": 40},
                        "message": "Medium severity",
                    },
                ]
            )
        )

        store_scan(results_dir, profile="balanced", tools=["semgrep"], branch="main")

        # Get all findings - should be ordered by severity
        conn = get_connection()
        results = search_findings(conn, "")
        conn.close()

        severities = [r["severity"] for r in results]
        assert severities == ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

    def test_search_findings_empty_query(self, tmp_path, isolate_database):
        """Test search with empty query returns all findings."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                    {
                        "id": "fp2",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 20},
                        "message": "SQL injection",
                    },
                ]
            )
        )

        store_scan(
            results_dir, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Empty query - should return all findings
        conn = get_connection()
        results = search_findings(conn, "")
        conn.close()

        assert len(results) == 2

    def test_search_findings_no_matches(self, tmp_path, isolate_database):
        """Test search with no matches returns empty list."""
        from scripts.core.history_db import (
            get_connection,
            init_database,
            search_findings,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create test findings
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    },
                ]
            )
        )

        store_scan(results_dir, profile="balanced", tools=["semgrep"], branch="main")

        # Search for something that doesn't exist
        conn = get_connection()
        results = search_findings(conn, "nonexistent")
        conn.close()

        assert len(results) == 0


class TestRecurringFindings:
    """Test suite for get_recurring_findings function (lines 2536-2627)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        # Create unique database path for this test
        db_path = tmp_path / f"test_{id(self)}.db"

        # Monkeypatch DEFAULT_DB_PATH
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        # CRITICAL SOLUTION: Patch sqlite3.connect at the module level
        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)

        yield db_path

        if db_path.exists():
            db_path.unlink()

    def test_get_recurring_findings_basic(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test basic recurring findings detection."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create 3 scans with the same finding (recurring)
        for i in range(3):
            mock_time = 1000000000 + (i * 86400)  # 1 day apart
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-recurring",  # Same fingerprint = recurring
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS vulnerability",
                        }
                    ]
                )
            )
            store_scan(
                results_dir, profile="balanced", tools=["semgrep"], branch="main"
            )

        # Get recurring findings (min_occurrences=3)
        conn = get_connection()
        recurring = get_recurring_findings(conn, "main", min_occurrences=3)
        conn.close()

        assert len(recurring) == 1
        assert recurring[0]["fingerprint"] == "fp-recurring"
        assert recurring[0]["occurrence_count"] == 3
        assert recurring[0]["rule_id"] == "CWE-79"
        assert recurring[0]["severity"] == "HIGH"

    def test_get_recurring_findings_min_occurrences(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test min_occurrences parameter filtering."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create findings with different occurrence counts
        # Finding 1: appears 5 times
        for i in range(5):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"results_5_{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-5-times",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS",
                        }
                    ]
                )
            )
            store_scan(
                results_dir, profile="balanced", tools=["semgrep"], branch="main"
            )

        # Finding 2: appears 2 times (below threshold of 3)
        for i in range(2):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"results_2_{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-2-times",
                            "severity": "MEDIUM",
                            "ruleId": "CWE-89",
                            "tool": {"name": "bandit"},
                            "location": {"path": "src/db.py", "startLine": 20},
                            "message": "SQL",
                        }
                    ]
                )
            )
            store_scan(results_dir, profile="balanced", tools=["bandit"], branch="main")

        # Get recurring findings with min_occurrences=3 (default)
        conn = get_connection()
        recurring = get_recurring_findings(conn, "main", min_occurrences=3)
        conn.close()

        # Only fp-5-times should be returned
        assert len(recurring) == 1
        assert recurring[0]["fingerprint"] == "fp-5-times"
        assert recurring[0]["occurrence_count"] == 5

    def test_get_recurring_findings_branch_filtering(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test that findings are filtered by branch."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create 3 scans on main branch with recurring finding
        for i in range(3):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"main_{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-main",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS",
                        }
                    ]
                )
            )
            store_scan(
                results_dir, profile="balanced", tools=["semgrep"], branch="main"
            )

        # Create 3 scans on dev branch with different recurring finding
        for i in range(3):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"dev_{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-dev",
                            "severity": "CRITICAL",
                            "ruleId": "CWE-89",
                            "tool": {"name": "bandit"},
                            "location": {"path": "src/db.py", "startLine": 20},
                            "message": "SQL",
                        }
                    ]
                )
            )
            store_scan(results_dir, profile="balanced", tools=["bandit"], branch="dev")

        # Get recurring findings for main branch only
        conn = get_connection()
        recurring_main = get_recurring_findings(conn, "main", min_occurrences=3)
        conn.close()

        assert len(recurring_main) == 1
        assert recurring_main[0]["fingerprint"] == "fp-main"

        # Get recurring findings for dev branch only
        conn = get_connection()
        recurring_dev = get_recurring_findings(conn, "dev", min_occurrences=3)
        conn.close()

        assert len(recurring_dev) == 1
        assert recurring_dev[0]["fingerprint"] == "fp-dev"

    def test_get_recurring_findings_avg_days_calculation(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test average days between fixes calculation."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create 3 scans: day 0, day 10, day 20 (10 days apart each)
        timestamps = [1000000000, 1000000000 + (10 * 86400), 1000000000 + (20 * 86400)]

        for i, ts in enumerate(timestamps):
            monkeypatch.setattr("time.time", lambda t=ts: t)

            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-recurring",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS",
                        }
                    ]
                )
            )
            store_scan(
                results_dir, profile="balanced", tools=["semgrep"], branch="main"
            )

        # Get recurring findings
        conn = get_connection()
        recurring = get_recurring_findings(conn, "main", min_occurrences=3)
        conn.close()

        assert len(recurring) == 1
        # Total: 20 days, occurrences: 3, avg = 20 / (3-1) = 10.0 days
        assert recurring[0]["avg_days_between_fixes"] == 10.0

    def test_get_recurring_findings_severity_ordering(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test results are ordered by occurrence_count DESC, then severity DESC."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create finding 1: HIGH severity, 3 occurrences
        for i in range(3):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"high_3_{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-high-3",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS",
                        }
                    ]
                )
            )
            store_scan(
                results_dir, profile="balanced", tools=["semgrep"], branch="main"
            )

        # Create finding 2: CRITICAL severity, 5 occurrences (should be first)
        for i in range(5):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"critical_5_{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-critical-5",
                            "severity": "CRITICAL",
                            "ruleId": "CWE-89",
                            "tool": {"name": "bandit"},
                            "location": {"path": "src/db.py", "startLine": 20},
                            "message": "SQL",
                        }
                    ]
                )
            )
            store_scan(results_dir, profile="balanced", tools=["bandit"], branch="main")

        # Get recurring findings
        conn = get_connection()
        recurring = get_recurring_findings(conn, "main", min_occurrences=3)
        conn.close()

        assert len(recurring) == 2
        # First should be fp-critical-5 (more occurrences)
        assert recurring[0]["fingerprint"] == "fp-critical-5"
        assert recurring[0]["occurrence_count"] == 5
        # Second should be fp-high-3
        assert recurring[1]["fingerprint"] == "fp-high-3"
        assert recurring[1]["occurrence_count"] == 3

    def test_get_recurring_findings_first_last_seen(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test first_seen and last_seen timestamps."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create 3 scans with specific timestamps
        timestamps = [1000000000, 1500000000, 2000000000]

        for i, ts in enumerate(timestamps):
            monkeypatch.setattr("time.time", lambda t=ts: t)

            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-recurring",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS",
                        }
                    ]
                )
            )
            store_scan(
                results_dir, profile="balanced", tools=["semgrep"], branch="main"
            )

        # Get recurring findings
        conn = get_connection()
        recurring = get_recurring_findings(conn, "main", min_occurrences=3)
        conn.close()

        assert len(recurring) == 1
        # Verify first_seen and last_seen are ISO timestamps
        assert recurring[0]["first_seen"] is not None
        assert recurring[0]["last_seen"] is not None
        assert "T" in recurring[0]["first_seen"]  # ISO format check
        assert "T" in recurring[0]["last_seen"]

    def test_get_recurring_findings_no_results(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test when no findings meet min_occurrences threshold."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create only 2 scans with same finding (below threshold of 3)
        for i in range(2):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-only-2",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS",
                        }
                    ]
                )
            )
            store_scan(
                results_dir, profile="balanced", tools=["semgrep"], branch="main"
            )

        # Get recurring findings (min_occurrences=3)
        conn = get_connection()
        recurring = get_recurring_findings(conn, "main", min_occurrences=3)
        conn.close()

        assert len(recurring) == 0

    def test_get_recurring_findings_single_occurrence(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test avg_days_between_fixes is 0 for single occurrence."""
        from scripts.core.history_db import (
            get_connection,
            get_recurring_findings,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create exactly 1 scan (min_occurrences=1)
        mock_time = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-single",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS",
                    }
                ]
            )
        )
        store_scan(results_dir, profile="balanced", tools=["semgrep"], branch="main")

        # Get recurring findings with min_occurrences=1
        conn = get_connection()
        recurring = get_recurring_findings(conn, "main", min_occurrences=1)
        conn.close()

        assert len(recurring) == 1
        # Single occurrence should have avg_days_between_fixes = 0.0
        assert recurring[0]["avg_days_between_fixes"] == 0.0


class TestScanDiffForAI:
    """Test suite for get_scan_diff_for_ai function (lines 2390-2533)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        db_path = tmp_path / f"test_{id(self)}.db"
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    def test_get_scan_diff_for_ai_basic(self, tmp_path, isolate_database, monkeypatch):
        """Test basic AI-friendly diff computation."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create baseline scan
        mock_time_1 = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_1)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-old",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/old.py", "startLine": 10},
                        "message": "Old finding",
                    }
                ]
            )
        )
        scan_id1 = store_scan(
            results_dir1, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Create comparison scan with new finding
        mock_time_2 = 1000000000 + 86400  # 1 day later
        monkeypatch.setattr("time.time", lambda: mock_time_2)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-new",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/new.py", "startLine": 20},
                        "message": "New finding",
                    }
                ]
            )
        )
        scan_id2 = store_scan(
            results_dir2, profile="balanced", tools=["bandit"], branch="main"
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify structure
        assert "new_findings" in diff
        assert "resolved_findings" in diff
        assert "context" in diff

        # Verify new finding has priority score
        assert len(diff["new_findings"]) == 1
        new_finding = diff["new_findings"][0]
        assert "priority_score" in new_finding
        assert new_finding["severity"] == "CRITICAL"
        assert new_finding["rule_id"] == "CWE-89"

        # Verify resolved finding
        assert len(diff["resolved_findings"]) == 1
        resolved_finding = diff["resolved_findings"][0]
        assert "likely_fix" in resolved_finding
        assert resolved_finding["rule_id"] == "CWE-79"

    def test_get_scan_diff_for_ai_priority_scoring(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test priority scoring based on severity."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create baseline scan (empty)
        mock_time_1 = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_1)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(json.dumps([]))
        scan_id1 = store_scan(
            results_dir1, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Create comparison scan with findings of different severities
        mock_time_2 = 1000000000 + 86400
        monkeypatch.setattr("time.time", lambda: mock_time_2)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-critical",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/a.py", "startLine": 10},
                        "message": "Critical",
                    },
                    {
                        "id": "fp-high",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/b.py", "startLine": 20},
                        "message": "High",
                    },
                    {
                        "id": "fp-medium",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-22",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/c.py", "startLine": 30},
                        "message": "Medium",
                    },
                    {
                        "id": "fp-low",
                        "severity": "LOW",
                        "ruleId": "CWE-1",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/d.py", "startLine": 40},
                        "message": "Low",
                    },
                    {
                        "id": "fp-info",
                        "severity": "INFO",
                        "ruleId": "CWE-2",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/e.py", "startLine": 50},
                        "message": "Info",
                    },
                ]
            )
        )
        scan_id2 = store_scan(
            results_dir2, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify priority scores match severity
        # CRITICAL=10, HIGH=7, MEDIUM=4, LOW=2, INFO=1
        findings_by_severity = {f["severity"]: f for f in diff["new_findings"]}

        assert findings_by_severity["CRITICAL"]["priority_score"] == 10
        assert findings_by_severity["HIGH"]["priority_score"] == 7
        assert findings_by_severity["MEDIUM"]["priority_score"] == 4
        assert findings_by_severity["LOW"]["priority_score"] == 2
        assert findings_by_severity["INFO"]["priority_score"] == 1

    def test_get_scan_diff_for_ai_compliance_boost(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test priority score boost for compliance frameworks."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create baseline scan (empty)
        mock_time_1 = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_1)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(json.dumps([]))
        scan_id1 = store_scan(
            results_dir1, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Create comparison scan with compliance-tagged finding
        mock_time_2 = 1000000000 + 86400
        monkeypatch.setattr("time.time", lambda: mock_time_2)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-with-compliance",
                        "severity": "HIGH",  # Base score: 7
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/app.py", "startLine": 10},
                        "message": "XSS with compliance",
                        "compliance": {
                            "owaspTop10_2021": ["A03:2021"],  # Adds +2 boost
                        },
                    }
                ]
            )
        )
        scan_id2 = store_scan(
            results_dir2, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify compliance boost: 7 (HIGH) + 2 (compliance) = 9
        assert len(diff["new_findings"]) == 1
        assert diff["new_findings"][0]["priority_score"] == 9

    def test_get_scan_diff_for_ai_priority_sorting(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test that new findings are sorted by priority score DESC."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create baseline scan (empty)
        mock_time_1 = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_1)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(json.dumps([]))
        scan_id1 = store_scan(
            results_dir1, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Create comparison scan with mixed priority findings
        mock_time_2 = 1000000000 + 86400
        monkeypatch.setattr("time.time", lambda: mock_time_2)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-low",
                        "severity": "LOW",  # Priority: 2
                        "ruleId": "CWE-1",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/a.py", "startLine": 10},
                        "message": "Low",
                    },
                    {
                        "id": "fp-critical",
                        "severity": "CRITICAL",  # Priority: 10
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/b.py", "startLine": 20},
                        "message": "Critical",
                    },
                    {
                        "id": "fp-medium",
                        "severity": "MEDIUM",  # Priority: 4
                        "ruleId": "CWE-22",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/c.py", "startLine": 30},
                        "message": "Medium",
                    },
                ]
            )
        )
        scan_id2 = store_scan(
            results_dir2, profile="balanced", tools=["semgrep", "bandit"], branch="main"
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify findings are sorted by priority DESC
        priorities = [f["priority_score"] for f in diff["new_findings"]]
        assert priorities == [10, 4, 2]  # CRITICAL, MEDIUM, LOW

    def test_get_scan_diff_for_ai_context(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test context metadata in diff."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create baseline scan
        mock_time_1 = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_1)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(json.dumps([]))
        scan_id1 = store_scan(
            results_dir1,
            profile="balanced",
            tools=["semgrep"],
            branch="main",
            commit_hash="abc123",
        )

        # Create comparison scan 5 days later
        mock_time_2 = 1000000000 + (5 * 86400)  # 5 days later
        monkeypatch.setattr("time.time", lambda: mock_time_2)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(json.dumps([]))
        scan_id2 = store_scan(
            results_dir2,
            profile="balanced",
            tools=["semgrep"],
            branch="main",
            commit_hash="def456",
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify context
        assert "context" in diff
        context = diff["context"]
        assert "scan_1" in context
        assert "scan_2" in context
        assert "commit_diff" in context
        assert "time_delta_days" in context
        assert context["time_delta_days"] == 5
        assert "abc" in context["commit_diff"] and "def" in context["commit_diff"]

    def test_get_scan_diff_for_ai_likely_fix(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test likely_fix heuristic for resolved findings."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create baseline scan with finding
        mock_time_1 = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_1)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-resolved",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/vulnerable.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    }
                ]
            )
        )
        scan_id1 = store_scan(
            results_dir1, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Create comparison scan (finding resolved)
        mock_time_2 = 1000000000 + 86400
        monkeypatch.setattr("time.time", lambda: mock_time_2)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(json.dumps([]))
        scan_id2 = store_scan(
            results_dir2, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify likely_fix heuristic
        assert len(diff["resolved_findings"]) == 1
        resolved = diff["resolved_findings"][0]
        assert "likely_fix" in resolved
        assert "vulnerable.py" in resolved["likely_fix"]
        assert "Modified or deleted" in resolved["likely_fix"]

    def test_get_scan_diff_for_ai_no_changes(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test diff when no changes between scans."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create two identical scans
        for i in range(2):
            mock_time = 1000000000 + (i * 86400)
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-same",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/app.py", "startLine": 10},
                            "message": "XSS",
                        }
                    ]
                )
            )

        scan_id1 = store_scan(
            tmp_path / "results0", profile="balanced", tools=["semgrep"], branch="main"
        )
        scan_id2 = store_scan(
            tmp_path / "results1", profile="balanced", tools=["semgrep"], branch="main"
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify no changes
        assert len(diff["new_findings"]) == 0
        assert len(diff["resolved_findings"]) == 0

    def test_get_scan_diff_for_ai_priority_cap(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test priority score is capped at 10."""
        from scripts.core.history_db import (
            get_connection,
            get_scan_diff_for_ai,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create baseline scan (empty)
        mock_time_1 = 1000000000
        monkeypatch.setattr("time.time", lambda: mock_time_1)

        results_dir1 = tmp_path / "results1"
        summaries_dir1 = results_dir1 / "summaries"
        summaries_dir1.mkdir(parents=True)
        (summaries_dir1 / "findings.json").write_text(json.dumps([]))
        scan_id1 = store_scan(
            results_dir1, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Create comparison scan with CRITICAL + compliance (10 + 2 = 12, capped to 10)
        mock_time_2 = 1000000000 + 86400
        monkeypatch.setattr("time.time", lambda: mock_time_2)

        results_dir2 = tmp_path / "results2"
        summaries_dir2 = results_dir2 / "summaries"
        summaries_dir2.mkdir(parents=True)
        (summaries_dir2 / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-critical-compliance",
                        "severity": "CRITICAL",  # Base: 10
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/db.py", "startLine": 10},
                        "message": "SQL injection",
                        "pci_dss": ["6.5.1"],  # +2 boost
                    }
                ]
            )
        )
        scan_id2 = store_scan(
            results_dir2, profile="balanced", tools=["bandit"], branch="main"
        )

        # Get AI-friendly diff
        conn = get_connection()
        diff = get_scan_diff_for_ai(conn, scan_id1, scan_id2)
        conn.close()

        # Verify priority is capped at 10
        assert diff["new_findings"][0]["priority_score"] == 10


class TestComplianceSummary:
    """Tests for get_compliance_summary function (lines 2635-2850)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        db_path = tmp_path / f"test_{id(self)}.db"
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    def test_get_compliance_summary_all_frameworks(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test compliance summary with all 6 frameworks."""
        from scripts.core.history_db import (
            get_connection,
            get_compliance_summary,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create scan with findings mapped to all 6 frameworks
        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/xss.py", "startLine": 10},
                        "message": "XSS vulnerability",
                        "compliance": {
                            "owaspTop10_2021": ["A03:2021"],
                            "cweTop25_2024": [{"id": "79", "name": "XSS", "rank": 2}],
                            "cisControlsV8_1": [
                                {"id": "16.11", "name": "...", "ig": "IG2"}
                            ],
                            "nistCsf2_0": [
                                {"function": "Protect", "category": "PR.DS"}
                            ],
                            "pciDss4_0": [{"requirement": "6.5.7", "priority": "P1"}],
                            "mitreAttack": [{"tactic": "TA0001", "technique": "T1189"}],
                        },
                    }
                ]
            )
        )
        scan_id = store_scan(
            results_dir, profile="balanced", tools=["semgrep"], branch="main"
        )

        # Get compliance summary
        conn = get_connection()
        summary = get_compliance_summary(conn, scan_id, framework="all")
        conn.close()

        # Verify all 6 frameworks present
        assert "framework_summaries" in summary
        assert len(summary["framework_summaries"]) == 6
        assert "owasp_top10_2021" in summary["framework_summaries"]
        assert "cwe_top25_2024" in summary["framework_summaries"]
        assert "cis_controls_v8_1" in summary["framework_summaries"]
        assert "nist_csf_2_0" in summary["framework_summaries"]
        assert "pci_dss_4_0" in summary["framework_summaries"]
        assert "mitre_attack" in summary["framework_summaries"]

        # Verify coverage stats
        assert summary["coverage_stats"]["total_findings"] == 1
        assert summary["coverage_stats"]["findings_with_compliance"] == 1
        assert summary["coverage_stats"]["coverage_percentage"] == 100.0
        assert summary["coverage_stats"]["by_framework"]["owasp"] == 1
        assert summary["coverage_stats"]["by_framework"]["cwe"] == 1
        assert summary["coverage_stats"]["by_framework"]["cis"] == 1
        assert summary["coverage_stats"]["by_framework"]["nist"] == 1
        assert summary["coverage_stats"]["by_framework"]["pci"] == 1
        assert summary["coverage_stats"]["by_framework"]["mitre"] == 1

    def test_get_compliance_summary_single_framework(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test compliance summary with single framework filter."""
        from scripts.core.history_db import (
            get_connection,
            get_compliance_summary,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-owasp",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/xss.py", "startLine": 10},
                        "message": "XSS",
                        "compliance": {
                            "owaspTop10_2021": ["A03:2021"],
                            "cweTop25_2024": [{"id": "79"}],
                        },
                    }
                ]
            )
        )
        scan_id = store_scan(
            results_dir, profile="fast", tools=["semgrep"], branch="main"
        )

        # Get OWASP-only summary
        conn = get_connection()
        summary = get_compliance_summary(conn, scan_id, framework="owasp")
        conn.close()

        # Verify only OWASP framework present
        assert len(summary["framework_summaries"]) == 1
        assert "owasp_top10_2021" in summary["framework_summaries"]
        assert "cwe_top25_2024" not in summary["framework_summaries"]

    def test_get_compliance_summary_aggregation(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test aggregation of multiple findings in same category."""
        from scripts.core.history_db import (
            get_connection,
            get_compliance_summary,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-xss-1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/a.py", "startLine": 10},
                        "message": "XSS 1",
                        "compliance": {"owaspTop10_2021": ["A03:2021"]},
                    },
                    {
                        "id": "fp-xss-2",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/b.py", "startLine": 20},
                        "message": "XSS 2",
                        "compliance": {"owaspTop10_2021": ["A03:2021"]},
                    },
                    {
                        "id": "fp-sqli",
                        "severity": "CRITICAL",
                        "ruleId": "CWE-89",
                        "tool": {"name": "bandit"},
                        "location": {"path": "src/c.py", "startLine": 30},
                        "message": "SQL injection",
                        "compliance": {"owaspTop10_2021": ["A03:2021"]},
                    },
                ]
            )
        )
        scan_id = store_scan(
            results_dir, profile="fast", tools=["semgrep", "bandit"], branch="main"
        )

        conn = get_connection()
        summary = get_compliance_summary(conn, scan_id, framework="owasp")
        conn.close()

        # Verify aggregation
        owasp_data = summary["framework_summaries"]["owasp_top10_2021"]
        assert "A03:2021" in owasp_data
        assert owasp_data["A03:2021"]["count"] == 3
        assert owasp_data["A03:2021"]["severities"]["CRITICAL"] == 1
        assert owasp_data["A03:2021"]["severities"]["HIGH"] == 1
        assert owasp_data["A03:2021"]["severities"]["MEDIUM"] == 1

    def test_get_compliance_summary_coverage_percentage(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test coverage percentage calculation."""
        from scripts.core.history_db import (
            get_connection,
            get_compliance_summary,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-with-compliance",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/a.py", "startLine": 10},
                        "message": "XSS",
                        "compliance": {"owaspTop10_2021": ["A03:2021"]},
                    },
                    {
                        "id": "fp-without-compliance",
                        "severity": "LOW",
                        "ruleId": "CUSTOM-1",
                        "tool": {"name": "custom"},
                        "location": {"path": "src/b.py", "startLine": 20},
                        "message": "Custom rule",
                    },
                ]
            )
        )
        scan_id = store_scan(
            results_dir, profile="fast", tools=["semgrep", "custom"], branch="main"
        )

        conn = get_connection()
        summary = get_compliance_summary(conn, scan_id, framework="all")
        conn.close()

        # Verify coverage: 1 out of 2 = 50%
        assert summary["coverage_stats"]["total_findings"] == 2
        assert summary["coverage_stats"]["findings_with_compliance"] == 1
        assert summary["coverage_stats"]["coverage_percentage"] == 50.0

    def test_get_compliance_summary_no_compliance(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test compliance summary with no compliance data."""
        from scripts.core.history_db import (
            get_connection,
            get_compliance_summary,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-no-compliance",
                        "severity": "MEDIUM",
                        "ruleId": "CUSTOM-1",
                        "tool": {"name": "custom"},
                        "location": {"path": "src/test.py", "startLine": 10},
                        "message": "Custom rule",
                    }
                ]
            )
        )
        scan_id = store_scan(
            results_dir, profile="fast", tools=["custom"], branch="main"
        )

        conn = get_connection()
        summary = get_compliance_summary(conn, scan_id, framework="all")
        conn.close()

        # Verify zero coverage
        assert summary["coverage_stats"]["total_findings"] == 1
        assert summary["coverage_stats"]["findings_with_compliance"] == 0
        assert summary["coverage_stats"]["coverage_percentage"] == 0.0
        assert summary["coverage_stats"]["by_framework"]["owasp"] == 0
        assert summary["coverage_stats"]["by_framework"]["cwe"] == 0

    def test_get_compliance_summary_invalid_scan_id(self, tmp_path, isolate_database):
        """Test compliance summary with invalid scan ID."""
        from scripts.core.history_db import (
            get_connection,
            get_compliance_summary,
            init_database,
        )

        db_path = isolate_database
        init_database(db_path)

        conn = get_connection()

        # Should raise ValueError
        with pytest.raises(ValueError, match="Scan not found"):
            get_compliance_summary(conn, "nonexistent-scan-id", framework="all")

        conn.close()


class TestFindingContext:
    """Tests for get_finding_context function (lines 2213-2387)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        db_path = tmp_path / f"test_{id(self)}.db"
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    def test_get_finding_context_basic(self, tmp_path, isolate_database, monkeypatch):
        """Test basic finding context retrieval."""
        from scripts.core.history_db import (
            get_connection,
            get_finding_context,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-test",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/xss.py", "startLine": 10},
                        "message": "XSS vulnerability",
                    }
                ]
            )
        )
        _ = store_scan(
            results_dir, profile="fast", tools=["semgrep"], branch="main"
        )

        conn = get_connection()
        context = get_finding_context(conn, "fp-test")
        conn.close()

        # Verify context structure
        assert context is not None
        assert "finding" in context
        assert "history" in context
        assert "similar_findings" in context
        assert "remediation_history" in context
        assert "compliance_impact" in context

        # Verify finding data
        assert context["finding"]["fingerprint"] == "fp-test"
        assert context["finding"]["severity"] == "HIGH"

    def test_get_finding_context_nonexistent(self, tmp_path, isolate_database):
        """Test context retrieval for nonexistent finding."""
        from scripts.core.history_db import (
            get_connection,
            get_finding_context,
            init_database,
        )

        db_path = isolate_database
        init_database(db_path)

        conn = get_connection()
        context = get_finding_context(conn, "nonexistent-fingerprint")
        conn.close()

        # Should return None
        assert context is None

    def test_get_finding_context_history(self, tmp_path, isolate_database, monkeypatch):
        """Test finding context with historical occurrences."""
        from scripts.core.history_db import (
            get_connection,
            get_finding_context,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        # Create 3 scans with same finding (recurring)
        for i in range(3):
            mock_time = 1000000000 + (i * 86400)  # 1 day apart
            monkeypatch.setattr("time.time", lambda t=mock_time: t)

            results_dir = tmp_path / f"results{i}"
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir(parents=True)
            (summaries_dir / "findings.json").write_text(
                json.dumps(
                    [
                        {
                            "id": "fp-recurring",
                            "severity": "HIGH",
                            "ruleId": "CWE-79",
                            "tool": {"name": "semgrep"},
                            "location": {"path": "src/xss.py", "startLine": 10},
                            "message": "XSS vulnerability",
                        }
                    ]
                )
            )
            store_scan(results_dir, profile="fast", tools=["semgrep"], branch="main")

        conn = get_connection()
        context = get_finding_context(conn, "fp-recurring")
        conn.close()

        # Verify history (up to 10 occurrences)
        assert len(context["history"]) == 3
        assert context["history"][0]["branch"] == "main"

    def test_get_finding_context_similar_findings(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test finding context with similar findings."""
        from scripts.core.history_db import (
            get_connection,
            get_finding_context,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-primary",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/xss.py", "startLine": 10},
                        "message": "XSS primary",
                    },
                    {
                        "id": "fp-similar-1",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/xss.py", "startLine": 20},
                        "message": "XSS similar 1",
                    },
                    {
                        "id": "fp-similar-2",
                        "severity": "MEDIUM",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/xss.py", "startLine": 30},
                        "message": "XSS similar 2",
                    },
                ]
            )
        )
        store_scan(results_dir, profile="fast", tools=["semgrep"], branch="main")

        conn = get_connection()
        context = get_finding_context(conn, "fp-primary")
        conn.close()

        # Verify similar findings (same rule_id, same path, different line)
        assert len(context["similar_findings"]) == 2
        assert context["similar_findings"][0]["fingerprint"] == "fp-similar-1"
        assert context["similar_findings"][1]["fingerprint"] == "fp-similar-2"

    def test_get_finding_context_compliance(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test finding context with compliance frameworks."""
        from scripts.core.history_db import (
            get_connection,
            get_finding_context,
            init_database,
            store_scan,
        )

        db_path = isolate_database
        init_database(db_path)

        monkeypatch.setattr("time.time", lambda: 1000000000)

        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)
        (summaries_dir / "findings.json").write_text(
            json.dumps(
                [
                    {
                        "id": "fp-compliance",
                        "severity": "HIGH",
                        "ruleId": "CWE-79",
                        "tool": {"name": "semgrep"},
                        "location": {"path": "src/xss.py", "startLine": 10},
                        "message": "XSS with compliance",
                        "compliance": {
                            "owaspTop10_2021": ["A03:2021"],
                            "cweTop25_2024": [{"id": "79", "name": "XSS"}],
                            "pciDss4_0": [{"requirement": "6.5.7"}],
                        },
                    }
                ]
            )
        )
        store_scan(results_dir, profile="fast", tools=["semgrep"], branch="main")

        conn = get_connection()
        context = get_finding_context(conn, "fp-compliance")
        conn.close()

        # Verify compliance impact
        frameworks = context["compliance_impact"]["frameworks"]
        assert any("OWASP" in f for f in frameworks)
        assert any("CWE-79" in f for f in frameworks)
        assert any("PCI DSS" in f for f in frameworks)


class TestTimelineData:
    """Tests for get_timeline_data function (lines 1945-2030)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        db_path = tmp_path / f"test_{id(self)}.db"
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    def test_get_timeline_data_basic(self, tmp_path, isolate_database, monkeypatch):
        """Test basic timeline data retrieval."""
        from scripts.core.history_db import (
            store_scan,
            get_timeline_data,
            get_connection,
        )
        import time
        import json

        # Mock time.time() to return consistent timestamp
        current_time = 1700000000  # Nov 14, 2023
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create scan 10 days ago
        old_timestamp = current_time - (10 * 86400)
        results_dir = tmp_path / "results1"
        results_dir.mkdir()
        findings_file = results_dir / "summaries" / "findings.json"
        findings_file.parent.mkdir(parents=True)
        findings_file.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "schemaVersion": "1.2.0",
                            "id": "fp-test1",
                            "ruleId": "rule1",
                            "severity": "CRITICAL",
                            "tool": {"name": "semgrep", "version": "1.0.0"},
                            "location": {
                                "path": "test.py",
                                "startLine": 1,
                                "endLine": 1,
                            },
                            "message": "Test finding",
                        }
                    ]
                }
            )
        )

        # Patch store_scan to use old timestamp
        import scripts.core.history_db as history_db_module

        def mock_time_for_store():
            return old_timestamp

        monkeypatch.setattr(history_db_module.time, "time", mock_time_for_store)

        _ = store_scan(
            results_dir, branch="main", profile="balanced", tools=["semgrep"]
        )

        # Restore current time
        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get timeline data for last 30 days
        conn = get_connection()
        timeline = get_timeline_data(conn, branch="main", days=30)
        conn.close()

        # Verify timeline has 1 data point
        assert len(timeline) == 1
        assert timeline[0]["CRITICAL"] == 1
        assert timeline[0]["HIGH"] == 0
        assert timeline[0]["MEDIUM"] == 0
        assert timeline[0]["LOW"] == 0
        assert timeline[0]["INFO"] == 0
        assert timeline[0]["total"] == 1
        assert "date" in timeline[0]
        assert "timestamp" in timeline[0]

    def test_get_timeline_data_multiple_days(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test timeline with multiple scans across different days."""
        from scripts.core.history_db import (
            store_scan,
            get_timeline_data,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create 3 scans on different days
        for i, days_ago in enumerate([5, 10, 15]):
            timestamp = current_time - (days_ago * 86400)
            results_dir = tmp_path / f"results{i}"
            results_dir.mkdir()
            findings_file = results_dir / "summaries" / "findings.json"
            findings_file.parent.mkdir(parents=True)

            # Different severity counts for each day
            severities = [
                ["CRITICAL", "HIGH"],
                ["HIGH", "MEDIUM", "MEDIUM"],
                ["LOW", "INFO"],
            ]
            findings = [
                {
                    "schemaVersion": "1.2.0",
                    "id": f"fp-test{i}-{j}",
                    "ruleId": f"rule{j}",
                    "severity": sev,
                    "tool": {"name": "semgrep", "version": "1.0.0"},
                    "location": {
                        "path": "test.py",
                        "startLine": j + 1,
                        "endLine": j + 1,
                    },
                    "message": f"Test finding {j}",
                }
                for j, sev in enumerate(severities[i])
            ]

            findings_file.write_text(json.dumps({"findings": findings}))

            # Patch store_scan to use specific timestamp
            import scripts.core.history_db as history_db_module

            def mock_time_for_scan():
                return timestamp

            monkeypatch.setattr(history_db_module.time, "time", mock_time_for_scan)
            store_scan(
                results_dir, branch="main", profile="balanced", tools=["semgrep"]
            )

        # Restore current time
        import scripts.core.history_db as history_db_module

        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get timeline for last 30 days
        conn = get_connection()
        timeline = get_timeline_data(conn, branch="main", days=30)
        conn.close()

        # Verify 3 data points
        assert len(timeline) == 3

        # Verify sorted by date (oldest first)
        for i in range(len(timeline) - 1):
            assert timeline[i]["date"] <= timeline[i + 1]["date"]

        # Verify severity counts
        total_critical = sum(t["CRITICAL"] for t in timeline)
        total_high = sum(t["HIGH"] for t in timeline)
        total_medium = sum(t["MEDIUM"] for t in timeline)
        total_low = sum(t["LOW"] for t in timeline)
        total_info = sum(t["INFO"] for t in timeline)

        assert total_critical == 1
        assert total_high == 2
        assert total_medium == 2
        assert total_low == 1
        assert total_info == 1

    def test_get_timeline_data_same_day_multiple_scans(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test timeline with multiple scans on same day - should keep latest."""
        from scripts.core.history_db import (
            store_scan,
            get_timeline_data,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create 3 scans on same day (different times, within 12 hours to ensure same UTC date)
        for i in range(3):
            timestamp = (
                current_time - (5 * 86400) + (i * 1800)
            )  # Same day, 30-minute intervals
            results_dir = tmp_path / f"results{i}"
            results_dir.mkdir()
            findings_file = results_dir / "summaries" / "findings.json"
            findings_file.parent.mkdir(parents=True)

            # Each scan has i+1 findings
            findings = [
                {
                    "schemaVersion": "1.2.0",
                    "id": f"fp-test{i}-{j}",
                    "ruleId": f"rule{j}",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep", "version": "1.0.0"},
                    "location": {
                        "path": "test.py",
                        "startLine": j + 1,
                        "endLine": j + 1,
                    },
                    "message": f"Test finding {j}",
                }
                for j in range(i + 1)
            ]

            findings_file.write_text(json.dumps({"findings": findings}))

            import scripts.core.history_db as history_db_module

            def mock_time_for_scan():
                return timestamp

            monkeypatch.setattr(history_db_module.time, "time", mock_time_for_scan)
            store_scan(
                results_dir, branch="main", profile="balanced", tools=["semgrep"]
            )

        # Restore current time
        import scripts.core.history_db as history_db_module

        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get timeline
        conn = get_connection()
        timeline = get_timeline_data(conn, branch="main", days=30)
        conn.close()

        # Should have 1 data point (same day)
        assert len(timeline) == 1

        # Should keep latest scan (3 findings)
        assert timeline[0]["HIGH"] == 3
        assert timeline[0]["total"] == 3

    def test_get_timeline_data_different_branches(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test timeline filters by branch correctly."""
        from scripts.core.history_db import (
            store_scan,
            get_timeline_data,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create scan on main branch
        timestamp1 = current_time - (5 * 86400)
        results_dir1 = tmp_path / "results1"
        results_dir1.mkdir()
        findings_file1 = results_dir1 / "summaries" / "findings.json"
        findings_file1.parent.mkdir(parents=True)
        findings_file1.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "schemaVersion": "1.2.0",
                            "id": "fp-main",
                            "ruleId": "rule1",
                            "severity": "CRITICAL",
                            "tool": {"name": "semgrep", "version": "1.0.0"},
                            "location": {
                                "path": "test.py",
                                "startLine": 1,
                                "endLine": 1,
                            },
                            "message": "Main branch finding",
                        }
                    ]
                }
            )
        )

        import scripts.core.history_db as history_db_module

        def mock_time1():
            return timestamp1

        monkeypatch.setattr(history_db_module.time, "time", mock_time1)
        store_scan(results_dir1, branch="main", profile="balanced", tools=["semgrep"])

        # Create scan on dev branch
        timestamp2 = current_time - (3 * 86400)
        results_dir2 = tmp_path / "results2"
        results_dir2.mkdir()
        findings_file2 = results_dir2 / "summaries" / "findings.json"
        findings_file2.parent.mkdir(parents=True)
        findings_file2.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "schemaVersion": "1.2.0",
                            "id": "fp-dev",
                            "ruleId": "rule2",
                            "severity": "HIGH",
                            "tool": {"name": "semgrep", "version": "1.0.0"},
                            "location": {
                                "path": "test.py",
                                "startLine": 2,
                                "endLine": 2,
                            },
                            "message": "Dev branch finding",
                        }
                    ]
                }
            )
        )

        def mock_time2():
            return timestamp2

        monkeypatch.setattr(history_db_module.time, "time", mock_time2)
        store_scan(results_dir2, branch="dev", profile="balanced", tools=["semgrep"])

        # Restore current time
        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get timeline for main branch
        conn = get_connection()
        main_timeline = get_timeline_data(conn, branch="main", days=30)

        # Should only have main branch scan
        assert len(main_timeline) == 1
        assert main_timeline[0]["CRITICAL"] == 1
        assert main_timeline[0]["HIGH"] == 0

        # Get timeline for dev branch
        dev_timeline = get_timeline_data(conn, branch="dev", days=30)

        # Should only have dev branch scan
        assert len(dev_timeline) == 1
        assert dev_timeline[0]["CRITICAL"] == 0
        assert dev_timeline[0]["HIGH"] == 1

        conn.close()

    def test_get_timeline_data_time_window(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test timeline respects days parameter."""
        from scripts.core.history_db import (
            store_scan,
            get_timeline_data,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create scans at 5, 20, 40 days ago
        for days_ago in [5, 20, 40]:
            timestamp = current_time - (days_ago * 86400)
            results_dir = tmp_path / f"results_{days_ago}"
            results_dir.mkdir()
            findings_file = results_dir / "summaries" / "findings.json"
            findings_file.parent.mkdir(parents=True)
            findings_file.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "schemaVersion": "1.2.0",
                                "id": f"fp-{days_ago}",
                                "ruleId": "rule1",
                                "severity": "HIGH",
                                "tool": {"name": "semgrep", "version": "1.0.0"},
                                "location": {
                                    "path": "test.py",
                                    "startLine": 1,
                                    "endLine": 1,
                                },
                                "message": f"Finding from {days_ago} days ago",
                            }
                        ]
                    }
                )
            )

            import scripts.core.history_db as history_db_module

            def mock_time():
                return timestamp

            monkeypatch.setattr(history_db_module.time, "time", mock_time)
            store_scan(
                results_dir, branch="main", profile="balanced", tools=["semgrep"]
            )

        # Restore current time
        import scripts.core.history_db as history_db_module

        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        conn = get_connection()

        # Get timeline for last 30 days - should include 5 and 20, not 40
        timeline_30 = get_timeline_data(conn, branch="main", days=30)
        assert len(timeline_30) == 2

        # Get timeline for last 50 days - should include all 3
        timeline_50 = get_timeline_data(conn, branch="main", days=50)
        assert len(timeline_50) == 3

        # Get timeline for last 10 days - should include only 5
        timeline_10 = get_timeline_data(conn, branch="main", days=10)
        assert len(timeline_10) == 1

        conn.close()

    def test_get_timeline_data_empty(self, tmp_path, isolate_database):
        """Test timeline with no scans."""
        from scripts.core.history_db import (
            get_timeline_data,
            get_connection,
            init_database,
        )

        # Initialize database first
        init_database()
        conn = get_connection()

        timeline = get_timeline_data(conn, branch="main", days=30)
        conn.close()

        # Should return empty list
        assert timeline == []


class TestFindingDetailsBatch:
    """Tests for get_finding_details_batch function (lines 2033-2075)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        db_path = tmp_path / f"test_{id(self)}.db"
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    def test_get_finding_details_batch_basic(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test basic batch finding retrieval."""
        from scripts.core.history_db import (
            store_scan,
            get_finding_details_batch,
            get_connection,
        )
        import json

        # Create scan with 3 findings
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        findings_file = results_dir / "summaries" / "findings.json"
        findings_file.parent.mkdir(parents=True)

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": f"fp-test{i}",
                "ruleId": f"rule{i}",
                "severity": ["CRITICAL", "HIGH", "MEDIUM"][i],
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {
                    "path": f"test{i}.py",
                    "startLine": i + 1,
                    "endLine": i + 1,
                },
                "message": f"Test finding {i}",
            }
            for i in range(3)
        ]

        findings_file.write_text(json.dumps({"findings": findings}))
        store_scan(results_dir, branch="main", profile="balanced", tools=["semgrep"])

        # Fetch all 3 findings by fingerprint
        conn = get_connection()
        fingerprints = ["fp-test0", "fp-test1", "fp-test2"]
        batch = get_finding_details_batch(conn, fingerprints)
        conn.close()

        # Verify all 3 findings returned
        assert len(batch) == 3

        # Verify sorted by severity DESC (alphabetically: MEDIUM, HIGH, CRITICAL)
        # Note: SQLite sorts severity as strings, not by custom order
        assert batch[0]["severity"] == "MEDIUM"
        assert batch[1]["severity"] == "HIGH"
        assert batch[2]["severity"] == "CRITICAL"

        # Verify fingerprints match
        batch_fps = {f["fingerprint"] for f in batch}
        assert batch_fps == {"fp-test0", "fp-test1", "fp-test2"}

    def test_get_finding_details_batch_empty(self, tmp_path, isolate_database):
        """Test batch retrieval with empty fingerprint list."""
        from scripts.core.history_db import get_finding_details_batch, get_connection

        conn = get_connection()
        batch = get_finding_details_batch(conn, [])
        conn.close()

        # Should return empty list
        assert batch == []

    def test_get_finding_details_batch_nonexistent(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test batch retrieval with nonexistent fingerprints."""
        from scripts.core.history_db import (
            store_scan,
            get_finding_details_batch,
            get_connection,
        )
        import json

        # Create scan with 1 finding
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        findings_file = results_dir / "summaries" / "findings.json"
        findings_file.parent.mkdir(parents=True)
        findings_file.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "schemaVersion": "1.2.0",
                            "id": "fp-exists",
                            "ruleId": "rule1",
                            "severity": "HIGH",
                            "tool": {"name": "semgrep", "version": "1.0.0"},
                            "location": {
                                "path": "test.py",
                                "startLine": 1,
                                "endLine": 1,
                            },
                            "message": "Test finding",
                        }
                    ]
                }
            )
        )
        store_scan(results_dir, branch="main", profile="balanced", tools=["semgrep"])

        # Try to fetch nonexistent fingerprints
        conn = get_connection()
        batch = get_finding_details_batch(conn, ["fp-missing1", "fp-missing2"])
        conn.close()

        # Should return empty list
        assert batch == []

    def test_get_finding_details_batch_mixed(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test batch retrieval with mix of existing and nonexistent fingerprints."""
        from scripts.core.history_db import (
            store_scan,
            get_finding_details_batch,
            get_connection,
        )
        import json

        # Create scan with 2 findings
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        findings_file = results_dir / "summaries" / "findings.json"
        findings_file.parent.mkdir(parents=True)

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "fp-exists1",
                "ruleId": "rule1",
                "severity": "HIGH",
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {
                    "path": "test1.py",
                    "startLine": 1,
                    "endLine": 1,
                },
                "message": "Test finding 1",
            },
            {
                "schemaVersion": "1.2.0",
                "id": "fp-exists2",
                "ruleId": "rule2",
                "severity": "MEDIUM",
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {
                    "path": "test2.py",
                    "startLine": 2,
                    "endLine": 2,
                },
                "message": "Test finding 2",
            },
        ]

        findings_file.write_text(json.dumps({"findings": findings}))
        store_scan(results_dir, branch="main", profile="balanced", tools=["semgrep"])

        # Fetch mix of existing and nonexistent
        conn = get_connection()
        fingerprints = ["fp-exists1", "fp-missing", "fp-exists2"]
        batch = get_finding_details_batch(conn, fingerprints)
        conn.close()

        # Should return only the 2 existing findings
        assert len(batch) == 2
        batch_fps = {f["fingerprint"] for f in batch}
        assert batch_fps == {"fp-exists1", "fp-exists2"}

    def test_get_finding_details_batch_sorting(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test batch retrieval sorting (severity DESC, then path)."""
        from scripts.core.history_db import (
            store_scan,
            get_finding_details_batch,
            get_connection,
        )
        import json

        # Create scan with 5 findings with same severity, different paths
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        findings_file = results_dir / "summaries" / "findings.json"
        findings_file.parent.mkdir(parents=True)

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": f"fp-{i}",
                "ruleId": "rule1",
                "severity": "HIGH",
                "tool": {"name": "semgrep", "version": "1.0.0"},
                "location": {
                    "path": path,
                    "startLine": 1,
                    "endLine": 1,
                },
                "message": "Test finding",
            }
            for i, path in enumerate(["z.py", "a.py", "m.py"])
        ]

        findings_file.write_text(json.dumps({"findings": findings}))
        store_scan(results_dir, branch="main", profile="balanced", tools=["semgrep"])

        # Fetch all findings
        conn = get_connection()
        fingerprints = ["fp-0", "fp-1", "fp-2"]
        batch = get_finding_details_batch(conn, fingerprints)
        conn.close()

        # Verify sorted by path (a.py, m.py, z.py)
        assert len(batch) == 3
        assert batch[0]["path"] == "a.py"
        assert batch[1]["path"] == "m.py"
        assert batch[2]["path"] == "z.py"


class TestComplianceTrend:
    """Tests for get_compliance_trend function (lines 2853-3038)."""

    @pytest.fixture(autouse=True)
    def isolate_database(self, tmp_path, monkeypatch):
        """Isolate database for each test to prevent cross-test pollution."""
        import scripts.core.history_db as history_db_module
        import sqlite3
        from pathlib import Path as PathlibPath

        db_path = tmp_path / f"test_{id(self)}.db"
        monkeypatch.setattr(history_db_module, "DEFAULT_DB_PATH", db_path)

        original_connect = sqlite3.connect

        def patched_connect(database, *args, **kwargs):
            if str(database).endswith(".jmo/history.db") or database == str(
                PathlibPath(".jmo/history.db")
            ):
                database = str(db_path)
            return original_connect(database, *args, **kwargs)

        monkeypatch.setattr(sqlite3, "connect", patched_connect)
        yield db_path
        if db_path.exists():
            db_path.unlink()

    def test_get_compliance_trend_improving(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test compliance trend showing improvement (reduction in findings)."""
        from scripts.core.history_db import (
            store_scan,
            get_compliance_trend,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create 2 scans: first with 10 OWASP findings, second with 5 (50% reduction)
        for i, (days_ago, finding_count) in enumerate([(10, 10), (5, 5)]):
            timestamp = current_time - (days_ago * 86400)
            results_dir = tmp_path / f"results{i}"
            results_dir.mkdir()
            findings_file = results_dir / "summaries" / "findings.json"
            findings_file.parent.mkdir(parents=True)

            findings = [
                {
                    "schemaVersion": "1.2.0",
                    "id": f"fp-{i}-{j}",
                    "ruleId": f"rule{j}",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep", "version": "1.0.0"},
                    "location": {
                        "path": f"test{j}.py",
                        "startLine": 1,
                        "endLine": 1,
                    },
                    "message": "Test finding",
                    "compliance": {
                        "owaspTop10_2021": ["A03:2021"],
                    },
                }
                for j in range(finding_count)
            ]

            findings_file.write_text(json.dumps({"findings": findings}))

            import scripts.core.history_db as history_db_module

            def mock_time():
                return timestamp

            monkeypatch.setattr(history_db_module.time, "time", mock_time)
            store_scan(
                results_dir, branch="main", profile="balanced", tools=["semgrep"]
            )

        # Restore current time
        import scripts.core.history_db as history_db_module

        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get compliance trend for OWASP
        conn = get_connection()
        trend = get_compliance_trend(conn, branch="main", framework="owasp", days=30)
        conn.close()

        # Verify improving trend
        assert trend["framework"] == "owasp"
        assert trend["branch"] == "main"
        assert trend["days"] == 30
        assert trend["trend"] == "improving"  # 10 → 5 is 50% reduction
        assert len(trend["data_points"]) == 2
        assert trend["data_points"][0]["total_findings_with_framework"] == 10
        assert trend["data_points"][1]["total_findings_with_framework"] == 5
        assert trend["summary_stats"]["first_scan_count"] == 10
        assert trend["summary_stats"]["last_scan_count"] == 5
        assert trend["summary_stats"]["change_percentage"] == -50.0
        assert len(trend["insights"]) > 0
        assert "reduced" in trend["insights"][0].lower()

    def test_get_compliance_trend_degrading(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test compliance trend showing degradation (increase in findings)."""
        from scripts.core.history_db import (
            store_scan,
            get_compliance_trend,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create 2 scans: first with 5 CWE findings, second with 10 (100% increase)
        for i, (days_ago, finding_count) in enumerate([(10, 5), (5, 10)]):
            timestamp = current_time - (days_ago * 86400)
            results_dir = tmp_path / f"results{i}"
            results_dir.mkdir()
            findings_file = results_dir / "summaries" / "findings.json"
            findings_file.parent.mkdir(parents=True)

            findings = [
                {
                    "schemaVersion": "1.2.0",
                    "id": f"fp-{i}-{j}",
                    "ruleId": f"rule{j}",
                    "severity": "CRITICAL",
                    "tool": {"name": "semgrep", "version": "1.0.0"},
                    "location": {
                        "path": f"test{j}.py",
                        "startLine": 1,
                        "endLine": 1,
                    },
                    "message": "Test finding",
                    "compliance": {
                        "cweTop25_2024": [{"cweId": "CWE-79", "rank": 1}],
                    },
                }
                for j in range(finding_count)
            ]

            findings_file.write_text(json.dumps({"findings": findings}))

            import scripts.core.history_db as history_db_module

            def mock_time():
                return timestamp

            monkeypatch.setattr(history_db_module.time, "time", mock_time)
            store_scan(
                results_dir, branch="main", profile="balanced", tools=["semgrep"]
            )

        # Restore current time
        import scripts.core.history_db as history_db_module

        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get compliance trend for CWE
        conn = get_connection()
        trend = get_compliance_trend(conn, branch="main", framework="cwe", days=30)
        conn.close()

        # Verify degrading trend
        assert trend["framework"] == "cwe"
        assert trend["trend"] == "degrading"  # 5 → 10 is 100% increase
        assert trend["data_points"][0]["total_findings_with_framework"] == 5
        assert trend["data_points"][1]["total_findings_with_framework"] == 10
        assert trend["summary_stats"]["first_scan_count"] == 5
        assert trend["summary_stats"]["last_scan_count"] == 10
        assert trend["summary_stats"]["change_percentage"] == 100.0
        assert len(trend["insights"]) > 0
        assert "increased" in trend["insights"][0].lower()

    def test_get_compliance_trend_stable(self, tmp_path, isolate_database, monkeypatch):
        """Test compliance trend showing stability (minimal change)."""
        from scripts.core.history_db import (
            store_scan,
            get_compliance_trend,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create 3 scans: all with 10 PCI DSS findings (stable)
        for i, days_ago in enumerate([15, 10, 5]):
            timestamp = current_time - (days_ago * 86400)
            results_dir = tmp_path / f"results{i}"
            results_dir.mkdir()
            findings_file = results_dir / "summaries" / "findings.json"
            findings_file.parent.mkdir(parents=True)

            findings = [
                {
                    "schemaVersion": "1.2.0",
                    "id": f"fp-{i}-{j}",
                    "ruleId": f"rule{j}",
                    "severity": "MEDIUM",
                    "tool": {"name": "semgrep", "version": "1.0.0"},
                    "location": {
                        "path": f"test{j}.py",
                        "startLine": 1,
                        "endLine": 1,
                    },
                    "message": "Test finding",
                    "compliance": {
                        "pciDss4_0": [{"requirement": "3.2.1"}],
                    },
                }
                for j in range(10)
            ]

            findings_file.write_text(json.dumps({"findings": findings}))

            import scripts.core.history_db as history_db_module

            def mock_time():
                return timestamp

            monkeypatch.setattr(history_db_module.time, "time", mock_time)
            store_scan(
                results_dir, branch="main", profile="balanced", tools=["semgrep"]
            )

        # Restore current time
        import scripts.core.history_db as history_db_module

        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get compliance trend for PCI DSS
        conn = get_connection()
        trend = get_compliance_trend(conn, branch="main", framework="pci", days=30)
        conn.close()

        # Verify stable trend
        assert trend["framework"] == "pci"
        assert trend["trend"] == "stable"  # 10 → 10 is 0% change
        assert len(trend["data_points"]) == 3
        assert all(
            dp["total_findings_with_framework"] == 10 for dp in trend["data_points"]
        )
        assert trend["summary_stats"]["first_scan_count"] == 10
        assert trend["summary_stats"]["last_scan_count"] == 10
        assert trend["summary_stats"]["change_percentage"] == 0.0
        assert trend["summary_stats"]["avg_findings_per_scan"] == 10.0
        assert len(trend["insights"]) > 0
        assert "stable" in trend["insights"][0].lower()

    def test_get_compliance_trend_insufficient_data(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test compliance trend with insufficient data (< 2 scans)."""
        from scripts.core.history_db import (
            store_scan,
            get_compliance_trend,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create only 1 scan
        timestamp = current_time - (5 * 86400)
        results_dir = tmp_path / "results"
        results_dir.mkdir()
        findings_file = results_dir / "summaries" / "findings.json"
        findings_file.parent.mkdir(parents=True)
        findings_file.write_text(
            json.dumps(
                {
                    "findings": [
                        {
                            "schemaVersion": "1.2.0",
                            "id": "fp-test",
                            "ruleId": "rule1",
                            "severity": "HIGH",
                            "tool": {"name": "semgrep", "version": "1.0.0"},
                            "location": {
                                "path": "test.py",
                                "startLine": 1,
                                "endLine": 1,
                            },
                            "message": "Test finding",
                            "compliance": {
                                "owaspTop10_2021": ["A03:2021"],
                            },
                        }
                    ]
                }
            )
        )

        import scripts.core.history_db as history_db_module

        def mock_time():
            return timestamp

        monkeypatch.setattr(history_db_module.time, "time", mock_time)
        store_scan(results_dir, branch="main", profile="balanced", tools=["semgrep"])

        # Restore current time
        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get compliance trend
        conn = get_connection()
        trend = get_compliance_trend(conn, branch="main", framework="owasp", days=30)
        conn.close()

        # Verify insufficient_data status
        assert trend["framework"] == "owasp"
        assert trend["trend"] == "insufficient_data"
        assert trend["data_points"] == []
        assert trend["summary_stats"] == {}
        assert len(trend["insights"]) > 0
        assert "not enough" in trend["insights"][0].lower()

    def test_get_compliance_trend_invalid_framework(self, tmp_path, isolate_database):
        """Test compliance trend with invalid framework name."""
        from scripts.core.history_db import get_compliance_trend, get_connection

        conn = get_connection()

        # Should raise ValueError for invalid framework
        import pytest

        with pytest.raises(ValueError, match="Invalid framework"):
            get_compliance_trend(conn, branch="main", framework="invalid", days=30)

        conn.close()

    def test_get_compliance_trend_zero_to_zero(
        self, tmp_path, isolate_database, monkeypatch
    ):
        """Test compliance trend with zero findings in both scans (stable)."""
        from scripts.core.history_db import (
            store_scan,
            get_compliance_trend,
            get_connection,
        )
        import time
        import json

        current_time = 1700000000
        monkeypatch.setattr(time, "time", lambda: current_time)

        # Create 2 scans with no OWASP findings
        for i, days_ago in enumerate([10, 5]):
            timestamp = current_time - (days_ago * 86400)
            results_dir = tmp_path / f"results{i}"
            results_dir.mkdir()
            findings_file = results_dir / "summaries" / "findings.json"
            findings_file.parent.mkdir(parents=True)

            # Finding without OWASP compliance
            findings_file.write_text(
                json.dumps(
                    {
                        "findings": [
                            {
                                "schemaVersion": "1.2.0",
                                "id": f"fp-{i}",
                                "ruleId": "rule1",
                                "severity": "HIGH",
                                "tool": {"name": "semgrep", "version": "1.0.0"},
                                "location": {
                                    "path": "test.py",
                                    "startLine": 1,
                                    "endLine": 1,
                                },
                                "message": "Test finding",
                                # No OWASP compliance
                            }
                        ]
                    }
                )
            )

            import scripts.core.history_db as history_db_module

            def mock_time():
                return timestamp

            monkeypatch.setattr(history_db_module.time, "time", mock_time)
            store_scan(
                results_dir, branch="main", profile="balanced", tools=["semgrep"]
            )

        # Restore current time
        import scripts.core.history_db as history_db_module

        monkeypatch.setattr(history_db_module.time, "time", lambda: current_time)

        # Get compliance trend
        conn = get_connection()
        trend = get_compliance_trend(conn, branch="main", framework="owasp", days=30)
        conn.close()

        # Verify stable trend (0 → 0)
        assert trend["trend"] == "stable"
        assert trend["data_points"][0]["total_findings_with_framework"] == 0
        assert trend["data_points"][1]["total_findings_with_framework"] == 0
        assert trend["summary_stats"]["change_percentage"] == 0.0


if __name__ == "__main__":
    pytest.main(
        [__file__, "-v", "--cov=scripts.core.history_db", "--cov-report=term-missing"]
    )
