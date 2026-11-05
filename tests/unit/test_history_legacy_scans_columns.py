#!/usr/bin/env python3
"""A history database written before v2.0.0 keeps working without its old columns.

Two `scans` columns left in v2.0.0. `profile` went with the scan profiles, and
`target_type` went because one column could not hold a scan of two target
types: it recorded `repo` for every scan (#1321), and `scan_tool_runs` types
each target instead. `profile` was `TEXT NOT NULL`, so a database that kept it
would reject every insert; `target_type` names nothing v2.0.0 writes. Migrations
only run on an explicit `jmo history migrate`, so `init_database`, which
`store_scan` calls on every store, drops both in place.

"In place" is the property that matters. `findings` and `scan_metadata` carry
`ON DELETE CASCADE` foreign keys to `scans(id)` with `PRAGMA foreign_keys=ON`,
so the usual create-copy-drop-rename rebuild would delete every finding in the
database (the trap v1_2_0.py documents). These tests seed findings and prove
they survive.

SQLite refuses to drop a column a table-level CHECK names, and both columns had
one, so each drop first edits the CHECK out of the stored DDL. The shapes below
are the historical DDL, frozen, not derived from the live one: the edit has to
cope with what real databases hold, comment lines included. The profile CHECK
case was found by a real `jmo scan` against the maintainer's own database
(2,492 scans, 215,761 findings), after a CHECK-less fixture had passed. That
store dropped its `profile` column (2026-09-23), and v1.1.0's migration had
added `scan_notes` by ALTER TABLE, so today it is the "1.1.0-live" shape: the
1.1.0 DDL as SQLite rewrote it through those two steps, built here by the
same two steps rather than retyped (review of #1321).
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.core.history_db import (
    _rewrite_scans_ddl,
    get_connection,
    init_database,
    store_scan,
)
from scripts.core.history_migrations import get_current_version, run_migrations

PROFILE_CHECK = "CHECK (profile IN ('fast', 'balanced', 'deep'))"
TARGET_TYPE_CHECK = (
    "CHECK (target_type IN ('repo', 'image', 'iac', 'url', 'gitlab', 'k8s', 'unknown'))"
)

_COLUMNS = """
    -- Primary Key
    id TEXT PRIMARY KEY,

    -- Timestamp
    timestamp INTEGER NOT NULL,
    timestamp_iso TEXT NOT NULL,

    -- Git Context (nullable for non-repo targets)
    commit_hash TEXT,
    commit_short TEXT,
    branch TEXT,
    tag TEXT,
    is_dirty INTEGER DEFAULT 0,

    -- Scan Configuration
{profile}    tools TEXT NOT NULL,
    targets TEXT NOT NULL,
    target_type TEXT NOT NULL,

    -- Results Summary
    total_findings INTEGER NOT NULL DEFAULT 0,
    critical_count INTEGER NOT NULL DEFAULT 0,
    high_count INTEGER NOT NULL DEFAULT 0,
    medium_count INTEGER NOT NULL DEFAULT 0,
    low_count INTEGER NOT NULL DEFAULT 0,
    info_count INTEGER NOT NULL DEFAULT 0,

    -- Metadata
    jmo_version TEXT NOT NULL,
    hostname TEXT,
    username TEXT,
    ci_provider TEXT,
    ci_build_id TEXT,

    -- Performance
    duration_seconds REAL,
"""

# The `scans` DDL each released (or dev) schema created, verbatim from its tag:
# v1.0.0 for 1.1.0, v1.1.1 for 1.2.0, and dev at 2fc7fc30 for 2.0.0-dev.
LEGACY_SCANS_DDL = {
    "1.1.0": "CREATE TABLE IF NOT EXISTS scans ("
    + _COLUMNS.format(profile="    profile TEXT NOT NULL,\n")
    + f"""
    -- Constraints
    {PROFILE_CHECK},
    {TARGET_TYPE_CHECK}
);
""",
    "1.2.0": "CREATE TABLE IF NOT EXISTS scans ("
    + _COLUMNS.format(profile="    profile TEXT NOT NULL,\n")
    + f"""
    -- Constraints
    -- NOTE: `profile` is deliberately unconstrained here. A SQL CHECK can only
    -- enumerate a fixed list, and the real rule is "a profile that exists in
    -- tool_registry.PROFILE_TOOLS or in the user's jmo.yml `profiles:` dict" --
    -- neither of which SQL can see. The previous enumeration predated the
    -- `slim` profile and silently rejected every slim scan (#721). Validation
    -- lives in store_scan(), against the registry, so it cannot drift again.
    {TARGET_TYPE_CHECK}
);
""",
    "2.0.0-dev": "CREATE TABLE IF NOT EXISTS scans ("
    + _COLUMNS.format(profile="")
    + f"""
    -- Constraints
    -- There is no `profile` column: scan profiles left in v2.0.0, and
    -- init_database drops the column from databases written before that
    -- (see _drop_legacy_profile_column).
    {TARGET_TYPE_CHECK}
);
""",
}

# "1.1.0" still has the profile CHECK (v1.2.0's migration removes it); "1.2.0"
# has the profile column without it; "2.0.0-dev" is a v2 database written before
# `target_type` left; "1.1.0-live" is 1.1.0 after v1.1.0's ALTER TABLE and a
# profile-only drop, the maintainer's database as it is.
LEGACY_SHAPES = ["1.2.0", "1.1.0", "2.0.0-dev", "1.1.0-live"]


@pytest.fixture(params=LEGACY_SHAPES)
def legacy_shape(request: pytest.FixtureRequest) -> str:
    return request.param


def has_profile(shape: str) -> bool:
    return shape not in ("2.0.0-dev", "1.1.0-live")


def _live(conn: sqlite3.Connection) -> None:
    """1.1.0 -> "1.1.0-live", by the steps that made it: v1.1.0's migration
    (ALTER TABLE adds `scan_notes`, and SQLite rewrites the stored DDL), then
    the profile drop a v2.0.0 store made before `target_type` left."""
    from scripts.core.history_db import _drop_legacy_profile_column
    from scripts.migrations.v1_1_0 import Migration_1_0_0_to_1_1_0

    Migration_1_0_0_to_1_1_0().migrate_up(conn)
    assert _drop_legacy_profile_column(conn)
    conn.commit()


def _build_pre_v2_database(db_path: Path, shape: str) -> None:
    """A database as `shape` left it: its `scans` table and indexes, and 3 findings."""
    init_database(db_path)
    conn = get_connection(db_path)
    index_ddl = [
        row[0]
        for row in conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='index' AND tbl_name='scans'"
        )
        if row[0]
    ]
    # Rebuilt with foreign keys OFF so the fixture itself cannot cascade.
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("DROP TABLE scans")
    conn.executescript(LEGACY_SCANS_DDL[shape.removesuffix("-live")])
    for ddl in index_ddl:
        conn.execute(ddl)
    conn.execute(
        "CREATE INDEX IF NOT EXISTS idx_scans_target_type ON scans(target_type)"
    )
    if shape == "1.1.0-live":
        conn.execute("CREATE INDEX idx_scans_profile ON scans(profile)")
        conn.commit()
        _live(conn)
    profile_column, profile_value = "", ""
    if has_profile(shape):
        conn.execute("CREATE INDEX idx_scans_profile ON scans(profile)")
        profile_column, profile_value = "profile, ", "'balanced', "
    conn.execute(
        f"""
        INSERT INTO scans (
            id, timestamp, timestamp_iso, {profile_column}tools, targets,
            target_type, total_findings, critical_count, high_count,
            medium_count, low_count, info_count, jmo_version
        ) VALUES ('old-scan', 0, '1970-01-01T00:00:00', {profile_value}'["trivy"]',
                  '["old-repo"]', 'repo', 0, 0, 0, 0, 0, 0, '1.1.1')
        """
    )
    # The count triggers make total_findings 3 as the findings go in.
    notnull = [
        (row[1], row[2])
        for row in conn.execute("PRAGMA table_info(findings)")
        if row[3]
    ]
    for i in range(3):
        values: dict[str, object] = {}
        for name, coltype in notnull:
            if name == "scan_id":
                values[name] = "old-scan"
            elif name == "fingerprint":
                values[name] = f"fp-{i}"
            elif name == "severity":
                values[name] = "HIGH"
            else:
                values[name] = 0 if coltype.upper() in ("INTEGER", "REAL") else "x"
        conn.execute(
            f"INSERT INTO findings ({','.join(values)}) "
            f"VALUES ({','.join('?' * len(values))})",
            list(values.values()),
        )
    conn.commit()
    conn.execute("PRAGMA foreign_keys=ON")
    conn.close()


def _columns(conn) -> set[str]:
    return {row[1] for row in conn.execute("PRAGMA table_info(scans)")}


def _indexes(conn) -> set[str]:
    return {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
    }


def _scans_sql(conn) -> str:
    return conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'"
    ).fetchone()[0]


def _results_dir(tmp_path: Path) -> Path:
    results_dir = tmp_path / "results"
    summaries = results_dir / "summaries"
    summaries.mkdir(parents=True)
    finding = {
        "id": "new-finding",
        "severity": "HIGH",
        "tool": {"name": "trivy", "version": "0.74.0"},
        "ruleId": "CVE-2024-1234",
        "location": {"path": "src/main.py", "startLine": 1},
        "message": "x",
    }
    (summaries / "findings.json").write_bytes(
        json.dumps({"findings": [finding]}).encode("utf-8")
    )
    return results_dir


def _findings_columns(conn) -> set[str]:
    return {row[1] for row in conn.execute("PRAGMA table_info(findings)")}


def _add_v1_1_0_columns(db_path: Path) -> None:
    """What `jmo history migrate` did to any database recording 1.0.0, which
    is every one: `SCHEMA_VERSION` is still "1.0.0", so v1.1.0's migration
    runs first (#1337)."""
    from scripts.migrations.v1_1_0 import Migration_1_0_0_to_1_1_0

    conn = get_connection(db_path)
    Migration_1_0_0_to_1_1_0().migrate_up(conn)
    conn.commit()
    assert "scan_notes" in _columns(conn)
    assert "finding_status" in _findings_columns(conn)
    assert "idx_findings_status" in _indexes(conn)
    conn.close()


def _assert_both_columns_gone_in_place(conn) -> None:
    assert not {"profile", "target_type"} & _columns(conn)
    assert not {"idx_scans_profile", "idx_scans_target_type"} & _indexes(conn)
    # v1.1.0's two, which nothing reads and the current schema lacks (#1337).
    assert "scan_notes" not in _columns(conn)
    assert "finding_status" not in _findings_columns(conn)
    assert "idx_findings_status" not in _indexes(conn)
    assert "target_type" not in _scans_sql(conn)
    # The cascade guard: a drop-and-recreate would have deleted these.
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []
    # Every other value of the old row survives.
    assert tuple(
        conn.execute(
            "SELECT tools, targets, total_findings FROM scans WHERE id='old-scan'"
        ).fetchone()
    ) == ('["trivy"]', '["old-repo"]', 3)


def test_fixture_is_a_real_legacy_database(tmp_path: Path, legacy_shape: str) -> None:
    """Meta-guard: without the columns (or the CHECKs) the tests below pass vacuously."""
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)
    conn = get_connection(db_path)
    assert "target_type" in _columns(conn)
    assert "idx_scans_target_type" in _indexes(conn)
    scans_sql = _scans_sql(conn)
    assert TARGET_TYPE_CHECK in scans_sql
    assert ("profile" in _columns(conn)) == has_profile(legacy_shape)
    assert (PROFILE_CHECK in scans_sql) == (legacy_shape == "1.1.0")
    # The trap the CHECK edit must survive: it is the table's last constraint,
    # so the comma to remove is the one before it, and in two shapes comment
    # lines holding commas of their own sit between them.
    assert scans_sql.rstrip().removesuffix(")").rstrip().endswith(TARGET_TYPE_CHECK)
    gap = scans_sql.split(TARGET_TYPE_CHECK)[0].rsplit("duration_seconds REAL,", 1)[1]
    comments = [line for line in gap.splitlines() if line.strip().startswith("--")]
    assert any("," in line for line in comments) == (
        legacy_shape not in ("1.1.0", "1.1.0-live")
    ), gap
    # The live shape is SQLite's own rewrite, not a retyped string.
    assert ("scan_notes" in _columns(conn)) == (legacy_shape == "1.1.0-live")
    assert ("finding_status" in _findings_columns(conn)) == (
        legacy_shape == "1.1.0-live"
    )
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3


def test_init_database_drops_both_columns_in_place(
    tmp_path: Path, legacy_shape: str
) -> None:
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)

    init_database(db_path)

    _assert_both_columns_gone_in_place(get_connection(db_path))


def test_init_database_drops_v1_1_0s_columns_from_every_shape(
    tmp_path: Path, legacy_shape: str
) -> None:
    """`scans.scan_notes` and `findings.finding_status` went in by v1.1.0's
    ALTER TABLE, on any shape `jmo history migrate` ran on; nothing reads
    either (#1337). In place: `findings` cascades from `scans`."""
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)
    _add_v1_1_0_columns(db_path)

    init_database(db_path)

    _assert_both_columns_gone_in_place(get_connection(db_path))


def test_history_migrate_drops_v1_1_0s_columns_from_every_shape(
    tmp_path: Path, legacy_shape: str
) -> None:
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)
    _add_v1_1_0_columns(db_path)

    result = run_migrations(db_path)

    assert result["errors"] == [], result["errors"]
    _assert_both_columns_gone_in_place(get_connection(db_path))


def test_a_fresh_database_ends_migrate_without_v1_1_0s_columns(
    tmp_path: Path,
) -> None:
    """A fresh database records 1.0.0, so `jmo history migrate` runs v1.1.0's
    migration on it, which adds both columns; v2.0.0's must take them out
    again, or one version has two schemas."""
    db_path = tmp_path / "fresh.db"
    init_database(db_path)
    conn = get_connection(db_path)
    fresh = sorted(
        tuple(row) for row in conn.execute("SELECT type, name, sql FROM sqlite_master")
    )
    conn.close()

    result = run_migrations(db_path)

    assert result["errors"] == [], result["errors"]
    assert get_current_version(db_path) == "2.0.0"
    conn = get_connection(db_path)
    assert "scan_notes" not in _columns(conn)
    assert "finding_status" not in _findings_columns(conn)
    assert "idx_findings_status" not in _indexes(conn)
    # Down to the stored DDL: SQLite's DROP COLUMN undoes the ADD COLUMN text.
    assert (
        sorted(
            tuple(row)
            for row in conn.execute("SELECT type, name, sql FROM sqlite_master")
        )
        == fresh
    )


def test_a_legacy_database_accepts_the_next_store(
    tmp_path: Path, legacy_shape: str
) -> None:
    """The store that follows the upgrade must not fail."""
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)

    scan_id = store_scan(
        results_dir=_results_dir(tmp_path), tools=["trivy"], db_path=db_path
    )

    conn = get_connection(db_path)
    ids = {row[0] for row in conn.execute("SELECT id FROM scans")}
    assert ids == {"old-scan", scan_id}
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 4


def test_history_migrate_records_2_0_0(tmp_path: Path, legacy_shape: str) -> None:
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)

    result = run_migrations(db_path)

    assert result["errors"] == [], result["errors"]
    assert get_current_version(db_path) == "2.0.0"
    _assert_both_columns_gone_in_place(get_connection(db_path))


def test_init_database_is_idempotent(tmp_path: Path, legacy_shape: str) -> None:
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)
    init_database(db_path)
    conn = get_connection(db_path)
    first = conn.execute("SELECT type, name, sql FROM sqlite_master").fetchall()
    conn.close()

    init_database(db_path)

    conn = get_connection(db_path)
    assert conn.execute("SELECT type, name, sql FROM sqlite_master").fetchall() == first
    _assert_both_columns_gone_in_place(conn)


_V1_1_0_COLUMNS = {"scan_notes": "scans", "finding_status": "findings"}


@pytest.mark.parametrize(
    ("legacy_shape", "column"),
    [
        (shape, column)
        for shape in LEGACY_SHAPES
        for column in ("profile", "target_type", *_V1_1_0_COLUMNS)
        if column != "profile" or has_profile(shape)
    ],
)
def test_a_blocked_drop_leaves_the_database_exactly_as_it_was(
    tmp_path: Path, legacy_shape: str, column: str
) -> None:
    """All-or-nothing: a drop SQLite refuses must not half-apply.

    A view over the column (the kind a user adds for their own reporting)
    makes SQLite refuse its drop. The CHECK edit and the index drop run before
    it, and so does the other column's whole drop; without one transaction
    around all of them, those would already be committed when this one fails.
    """
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)
    _add_v1_1_0_columns(db_path)
    table = _V1_1_0_COLUMNS.get(column, "scans")
    key = "fingerprint" if table == "findings" else "id"
    conn = get_connection(db_path)
    conn.execute(f"CREATE VIEW user_view AS SELECT {key}, {column} FROM {table}")
    conn.commit()
    before = conn.execute(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
    ).fetchall()
    conn.close()

    with pytest.raises(sqlite3.OperationalError, match=column):
        init_database(db_path)

    conn = get_connection(db_path)
    after = conn.execute(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
    ).fetchall()
    assert after == before
    assert column in (_findings_columns if table == "findings" else _columns)(conn)
    assert "target_type" in _columns(conn)
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3


def test_an_edit_that_does_not_parse_is_refused_before_it_is_written(
    tmp_path: Path,
) -> None:
    """A statement written to sqlite_master that does not parse leaves a
    database no connection can open. The edit is parsed on its own first, so
    a bad one is refused and the database is untouched."""
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, "1.2.0")
    conn = get_connection(db_path)
    before = _scans_sql(conn)
    conn.execute("BEGIN")

    with pytest.raises(RuntimeError, match="does not parse"):
        _rewrite_scans_ddl(conn, before.replace(TARGET_TYPE_CHECK, ""))

    conn.rollback()
    conn.close()
    conn = get_connection(db_path)
    assert _scans_sql(conn) == before
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
