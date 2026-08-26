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


# --- #721: legacy `profile` CHECK constraint -------------------------------


def _build_legacy_scans_table(db_path: Path) -> None:
    """Recreate `scans` with the pre-#721 CHECK that enumerated 3 profiles.

    Derived from the live DDL so that unrelated column changes stay in sync;
    only the constraint that #721 removed is added back.
    """
    from scripts.core.history_db import CREATE_SCANS_TABLE

    legacy_ddl = CREATE_SCANS_TABLE.replace(
        "CHECK (target_type IN",
        "CHECK (profile IN ('fast', 'balanced', 'deep')),\n    CHECK (target_type IN",
    )
    assert "CHECK (profile IN" in legacy_ddl, "legacy fixture failed to inject CHECK"

    conn = get_connection(db_path)

    # DROP TABLE takes the indexes with it, so capture and restore them --
    # otherwise the fixture is an unfaithful legacy database and any test
    # asserting the migration preserves indexes would pass vacuously.
    index_ddl = [
        row[0]
        for row in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='scans'"
        )
        if row[0]  # implicit indexes have sql = NULL
    ]

    conn.execute("DROP TABLE scans")
    conn.executescript(legacy_ddl)
    for ddl in index_ddl:
        conn.execute(ddl)
    conn.commit()


def _insert_scan(conn, scan_id: str, profile: str) -> None:
    conn.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets,
            target_type, total_findings, critical_count, high_count,
            medium_count, low_count, info_count, jmo_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, 0, 0, 0, 0, ?)
        """,
        (scan_id, 0, "1970-01-01T00:00:00", profile, "[]", "[]", "repo", "test"),
    )


def test_migration_lets_legacy_db_store_slim_scans(tmp_path: Path):
    """#721: an existing database can store `slim` scans after migrating.

    Changing CREATE_SCANS_TABLE only fixes databases created afterwards.
    SQLite cannot drop a CHECK constraint in place, so an existing database
    keeps rejecting slim scans until the table is rebuilt.
    """
    db_path = tmp_path / "legacy.db"
    init_database(db_path)
    _build_legacy_scans_table(db_path)

    conn = get_connection(db_path)
    _insert_scan(conn, "pre-existing", "balanced")
    conn.commit()

    result = run_migrations(db_path)
    assert result["errors"] == [], f"migration failed: {result['errors']}"

    conn = get_connection(db_path)
    _insert_scan(conn, "after-migration", "slim")
    conn.commit()

    stored = {
        row[0]
        for row in conn.execute("SELECT profile FROM scans ORDER BY id").fetchall()
    }
    assert stored == {"balanced", "slim"}


def _insert_finding(conn, scan_id: str, fingerprint: str) -> None:
    """Insert a minimal findings row for the scan (columns read from schema)."""
    notnull = [
        (row[1], row[2])
        for row in conn.execute("PRAGMA table_info(findings)")
        if row[3]
    ]
    values = {}
    for name, coltype in notnull:
        if name == "scan_id":
            values[name] = scan_id
        elif name == "fingerprint":
            values[name] = fingerprint
        elif name == "severity":
            values[name] = "HIGH"
        else:
            values[name] = 0 if coltype.upper() in ("INTEGER", "REAL") else "x"
    conn.execute(
        f"INSERT INTO findings ({','.join(values)}) "
        f"VALUES ({','.join('?' * len(values))})",
        list(values.values()),
    )


def test_migration_preserves_existing_rows(tmp_path: Path):
    """#721: the migration must not lose data in any table.

    `findings` and `scan_metadata` both declare ON DELETE CASCADE against
    `scans(id)`, and get_connection() sets PRAGMA foreign_keys=ON. A migration
    that drops and recreates `scans` therefore destroys every finding in the
    database -- silently, which is the same failure mode as the bug itself.
    """
    db_path = tmp_path / "legacy.db"
    init_database(db_path)
    _build_legacy_scans_table(db_path)

    conn = get_connection(db_path)
    for i, profile in enumerate(["fast", "balanced", "deep"]):
        _insert_scan(conn, f"scan-{i}", profile)
    conn.execute(
        "UPDATE scans SET total_findings = 42, duration_seconds = 1.5 WHERE id = 'scan-1'"
    )
    for i in range(3):
        _insert_finding(conn, "scan-0", f"fp-{i}")
    conn.execute(
        "INSERT INTO scan_metadata (scan_id, key, value) VALUES ('scan-0','k','v')"
    )
    conn.commit()

    before = conn.execute(
        "SELECT id, profile, total_findings, duration_seconds FROM scans ORDER BY id"
    ).fetchall()
    assert len(before) == 3

    result = run_migrations(db_path)
    assert result["errors"] == [], f"migration failed: {result['errors']}"

    conn = get_connection(db_path)
    after = conn.execute(
        "SELECT id, profile, total_findings, duration_seconds FROM scans ORDER BY id"
    ).fetchall()
    assert [tuple(r) for r in after] == [tuple(r) for r in before]

    # The cascade guard: these are what a drop-and-recreate would destroy.
    assert (
        conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
    ), "findings were destroyed -- ON DELETE CASCADE fired during the migration"
    assert (
        conn.execute("SELECT COUNT(*) FROM scan_metadata").fetchone()[0] == 1
    ), "scan_metadata was destroyed -- ON DELETE CASCADE fired during the migration"


def test_migration_keeps_dependent_schema_objects(tmp_path: Path):
    """#721: indexes, triggers and views on `scans` must survive.

    Eleven objects depend on `scans` (2 FK tables, 6 indexes, 2 triggers,
    2 views). A rebuild drops the indexes and triggers with the table, and
    `ALTER TABLE ... RENAME` fails outright because the triggers on `findings`
    reference `scans`.
    """
    db_path = tmp_path / "legacy.db"
    init_database(db_path)

    conn = get_connection(db_path)
    before = {
        (row[0], row[1])
        for row in conn.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN "
            "('index','trigger','view') AND sql LIKE '%scans%'"
        )
    }
    assert before, "fixture found no dependent objects to protect"

    _build_legacy_scans_table(db_path)
    result = run_migrations(db_path)
    assert result["errors"] == [], f"migration failed: {result['errors']}"

    conn = get_connection(db_path)
    after = {
        (row[0], row[1])
        for row in conn.execute(
            "SELECT type, name FROM sqlite_master WHERE type IN "
            "('index','trigger','view') AND sql LIKE '%scans%'"
        )
    }
    assert before - after == set(), f"migration destroyed: {sorted(before - after)}"


def test_migration_is_idempotent_on_fresh_db(tmp_path: Path):
    """#721: the migration is a no-op on a database that never had the CHECK.

    init_database() records version 1.0.0 even though it now creates the fixed
    schema, so run_migrations() will attempt this migration on fresh databases.
    """
    db_path = tmp_path / "fresh.db"
    init_database(db_path)

    conn = get_connection(db_path)
    _insert_scan(conn, "scan-slim", "slim")
    conn.commit()

    result = run_migrations(db_path)
    assert result["errors"] == [], f"migration failed: {result['errors']}"

    result_again = run_migrations(db_path)
    assert result_again["errors"] == []
    assert result_again["applied"] == [], "migrations should not re-apply"

    conn = get_connection(db_path)
    rows = conn.execute("SELECT profile FROM scans").fetchall()
    assert [r[0] for r in rows] == ["slim"]
