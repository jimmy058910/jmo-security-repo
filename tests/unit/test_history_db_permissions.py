#!/usr/bin/env python3
"""
Unit tests for history database file permissions (Phase 6 Step 6.2).

Tests that the database file is created with restrictive permissions (0o600)
to prevent unauthorized access to sensitive security findings.
"""

from __future__ import annotations

import os
import stat


from scripts.core.history_db import get_connection, store_scan


class TestDatabaseFilePermissions:
    """Test database file permission enforcement."""

    def test_database_file_permissions_restrictive(self, tmp_path):
        """
        Test that database file is created with 0o600 permissions.

        Security requirement: Database contains sensitive security findings
        and MUST NOT be readable by other users on the system.

        Expected permissions: 0o600 (owner read/write only)
        - Owner: read + write
        - Group: no access
        - Others: no access
        """
        # Arrange: Create test results directory
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        # Create minimal findings.json
        import json

        findings_data = {"findings": []}
        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        # Create individual-repos directory
        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        # Database path
        db_path = tmp_path / "test_history.db"

        # Act: Store scan (this creates the database)
        scan_id = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # Assert: Verify scan was stored
        assert scan_id is not None
        assert db_path.exists()

        # Assert: Check file permissions
        file_stat = os.stat(db_path)
        file_mode = stat.S_IMODE(file_stat.st_mode)

        # Expected: 0o600 (owner read/write only)
        expected_mode = 0o600

        assert (
            file_mode == expected_mode
        ), f"Database permissions {oct(file_mode)} != expected {oct(expected_mode)}"

        # Verify no group or other permissions
        assert not (file_mode & stat.S_IRGRP), "Group should not have read permission"
        assert not (file_mode & stat.S_IWGRP), "Group should not have write permission"
        assert not (
            file_mode & stat.S_IXGRP
        ), "Group should not have execute permission"
        assert not (file_mode & stat.S_IROTH), "Others should not have read permission"
        assert not (file_mode & stat.S_IWOTH), "Others should not have write permission"
        assert not (
            file_mode & stat.S_IXOTH
        ), "Others should not have execute permission"

        # Verify owner has read/write
        assert file_mode & stat.S_IRUSR, "Owner should have read permission"
        assert file_mode & stat.S_IWUSR, "Owner should have write permission"

    def test_existing_database_permissions_updated(self, tmp_path):
        """
        Test that permissions are enforced even if database already exists.

        Scenario: User manually creates database with incorrect permissions,
        or permissions are changed after creation. JMo should fix them.
        """
        # Arrange: Create database with wrong permissions
        db_path = tmp_path / "test_history.db"
        conn = get_connection(db_path)
        conn.close()

        # Set incorrect permissions (world-readable)
        os.chmod(db_path, 0o644)
        assert os.stat(db_path).st_mode & 0o777 == 0o644

        # Create test results directory
        results_dir = tmp_path / "results"
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir(parents=True)

        import json

        findings_data = {"findings": []}
        findings_json = summaries_dir / "findings.json"
        findings_json.write_text(json.dumps(findings_data), encoding="utf-8")

        (results_dir / "individual-repos" / "test-repo").mkdir(parents=True)

        # Act: Store scan (should fix permissions)
        _ = store_scan(
            results_dir=results_dir,
            profile="fast",
            tools=["trivy"],
            db_path=db_path,
        )

        # Assert: Permissions corrected to 0o600
        file_stat = os.stat(db_path)
        file_mode = stat.S_IMODE(file_stat.st_mode)

        assert file_mode == 0o600, f"Permissions not corrected: {oct(file_mode)}"
