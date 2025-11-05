#!/usr/bin/env python3
"""
Unit tests for database migration framework.

Tests cover:
- Migration discovery and ordering
- Migration execution with transaction management
- Version tracking in schema_version table
- Rollback on error
- Example migration v1.0.0 → v1.1.0

Run with: pytest tests/unit/test_history_migrations.py -v
"""

from __future__ import annotations

from pathlib import Path


from scripts.core.history_db import get_connection, init_database
from scripts.core.history_migrations import (
    Migration,
    discover_migrations,
    get_current_version,
    run_migrations,
)


def test_discover_migrations_finds_all(tmp_path: Path):
    """
    Migration Test 1: Discovery finds all migration files.

    Verifies that discover_migrations() correctly finds and loads
    all migration files in the migrations directory.
    """
    migrations = discover_migrations("1.0.0", "1.5.0")

    # Should find at least the example v1.1.0 migration
    assert len(migrations) >= 1, "Should discover at least 1 migration"

    # All returned objects should be Migration instances
    assert all(
        isinstance(m, Migration) for m in migrations
    ), "All discovered items should be Migration instances"

    # Check example migration is found
    versions = [m.version for m in migrations]
    assert "1.1.0" in versions, "Should find v1.1.0 migration"


def test_discover_migrations_correct_order(tmp_path: Path):
    """
    Migration Test 2: Migrations returned in ascending version order.

    Verifies that migrations are sorted by version number,
    ensuring they're applied in the correct sequence.
    """
    migrations = discover_migrations("1.0.0", "2.0.0")

    versions = [m.version for m in migrations]

    # Versions should be in ascending order
    assert versions == sorted(
        versions
    ), f"Migrations not in order: {versions} vs {sorted(versions)}"


def test_run_migrations_applies_all(tmp_path: Path):
    """
    Migration Test 3: All pending migrations applied successfully.

    Verifies that run_migrations() applies all pending migrations
    when no errors occur.
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Current version should be 1.0.0 (from init_database)
    current = get_current_version(db_path)
    assert current == "1.0.0", f"Expected 1.0.0, got {current}"

    # Run migrations up to 1.1.0
    result = run_migrations(db_path, "1.1.0")

    # Should apply v1.1.0 migration
    assert len(result["applied"]) >= 1, "Should apply at least 1 migration"
    assert "1.1.0" in result["applied"], "Should apply v1.1.0 migration"
    assert len(result["errors"]) == 0, f"Unexpected errors: {result['errors']}"
    assert (
        result["final_version"] == "1.1.0"
    ), f"Expected final version 1.1.0, got {result['final_version']}"


def test_run_migrations_updates_version(tmp_path: Path):
    """
    Migration Test 4: Schema version updated after migration.

    Verifies that schema_version table is updated correctly
    after applying migrations.
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Run migration
    run_migrations(db_path, "1.1.0")

    # Check version was updated
    conn = get_connection(db_path)
    version = conn.execute(
        "SELECT version FROM schema_version ORDER BY applied_at DESC, version DESC LIMIT 1"
    ).fetchone()[0]

    assert version == "1.1.0", f"Expected version 1.1.0, got {version}"

    # Check timestamp fields exist
    row = conn.execute(
        "SELECT version, applied_at, applied_at_iso FROM schema_version ORDER BY applied_at DESC, version DESC LIMIT 1"
    ).fetchone()

    assert row[0] == "1.1.0"
    assert isinstance(row[1], int), "applied_at should be integer timestamp"
    assert isinstance(row[2], str), "applied_at_iso should be ISO string"
    assert "T" in row[2], "applied_at_iso should be ISO format"


def test_migration_adds_columns(tmp_path: Path):
    """
    Migration Test 5: Example migration adds new columns correctly.

    Verifies that the v1.1.0 migration actually modifies the schema
    as expected (adds scan_notes and finding_status columns).
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Run migration
    run_migrations(db_path, "1.1.0")

    conn = get_connection(db_path)

    # Check scan_notes column exists in scans table
    scans_columns = [
        row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
    ]
    assert (
        "scan_notes" in scans_columns
    ), "scan_notes column should exist after migration"

    # Check finding_status column exists in findings table
    findings_columns = [
        row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()
    ]
    assert (
        "finding_status" in findings_columns
    ), "finding_status column should exist after migration"

    # Check index was created
    indices = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='index' AND name='idx_findings_status'"
    ).fetchall()
    assert len(indices) == 1, "idx_findings_status index should exist"


def test_migration_idempotent(tmp_path: Path):
    """
    Migration Test 6: Running migrations multiple times is safe.

    Verifies that running migrations again (when already at target version)
    doesn't fail or re-apply migrations.
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Run migration once
    result1 = run_migrations(db_path, "1.1.0")
    assert len(result1["applied"]) >= 1
    assert len(result1["errors"]) == 0

    # Run migration again (should be no-op)
    result2 = run_migrations(db_path, "1.1.0")
    assert len(result2["applied"]) == 0, "Should not re-apply migrations"
    assert len(result2["errors"]) == 0
    assert result2["final_version"] == "1.1.0"

    # Verify column still exists (wasn't duplicated)
    conn = get_connection(db_path)
    scans_columns = [
        row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
    ]
    # Count how many times scan_notes appears (should be exactly 1)
    scan_notes_count = scans_columns.count("scan_notes")
    assert (
        scan_notes_count == 1
    ), f"scan_notes should appear exactly once, found {scan_notes_count} times"
