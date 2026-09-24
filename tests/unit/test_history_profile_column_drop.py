#!/usr/bin/env python3
"""A pre-v2.0.0 history database keeps working after scan profiles left.

Every database written before v2.0.0 has `scans.profile TEXT NOT NULL` and an
index on it. v2.0.0 stores no profile, so the next insert into such a database
would fail on the NOT NULL column -- and migrations only run on an explicit
`jmo history migrate`. `init_database`, which `store_scan` calls on every
store, therefore drops the column in place.

"In place" is the property that matters. `findings` and `scan_metadata` carry
`ON DELETE CASCADE` foreign keys to `scans(id)` with `PRAGMA foreign_keys=ON`,
so the usual create-copy-drop-rename rebuild would delete every finding in the
database (the trap v1_2_0.py documents). These tests seed findings and prove
they survive.

Two legacy shapes exist, and both are real. A database created before v1.2.0
and never put through `jmo history migrate` still carries the table-level
`CHECK (profile IN ('fast', 'balanced', 'deep'))`, and SQLite refuses to drop
a column a CHECK references ("error in table scans after drop column: no such
column: profile"). The maintainer's own `.jmo/history.db` (schema 1.1.0, 2,492
scans, 215,761 findings) is that shape; a real `jmo scan` against it is how the
case was found, after the CHECK-less fixture had passed.
"""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.core.history_db import (
    CREATE_SCANS_TABLE,
    get_connection,
    init_database,
    store_scan,
)
from scripts.core.history_migrations import get_current_version, run_migrations

PROFILE_CHECK = "CHECK (profile IN ('fast', 'balanced', 'deep'))"

# "1.2.0" is the shape v1.2.0+ left (the CHECK removed by Migration_1_1_0_to_1_2_0);
# "1.1.0" still has the CHECK.
LEGACY_SHAPES = ["1.2.0", "1.1.0"]


@pytest.fixture(params=LEGACY_SHAPES)
def legacy_shape(request: pytest.FixtureRequest) -> str:
    return request.param


def _legacy_scans_ddl(shape: str) -> str:
    """The live `scans` DDL with the pre-v2 `profile` column put back."""
    ddl = CREATE_SCANS_TABLE.replace(
        "    tools TEXT NOT NULL,",
        "    profile TEXT NOT NULL,\n    tools TEXT NOT NULL,",
    )
    assert "profile TEXT NOT NULL" in ddl, "legacy fixture failed to inject the column"
    if shape == "1.1.0":
        anchor = "    CHECK (target_type IN"
        assert ddl.count(anchor) == 1, "legacy fixture lost its CHECK anchor"
        ddl = ddl.replace(anchor, f"    {PROFILE_CHECK},\n{anchor}")
    return ddl


def _build_pre_v2_database(db_path: Path, shape: str) -> None:
    """A database as v1.x left it: profile column, its index, and 3 findings."""
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
    conn.executescript(_legacy_scans_ddl(shape))
    for ddl in index_ddl:
        conn.execute(ddl)
    conn.execute("CREATE INDEX idx_scans_profile ON scans(profile)")
    conn.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets,
            target_type, total_findings, critical_count, high_count,
            medium_count, low_count, info_count, jmo_version
        ) VALUES ('old-scan', 0, '1970-01-01T00:00:00', 'balanced', '[]', '[]',
                  'repo', 3, 0, 3, 0, 0, 0, '1.1.1')
        """
    )
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


def test_fixture_is_a_real_pre_v2_database(tmp_path: Path, legacy_shape: str) -> None:
    """Meta-guard: without the column (or the CHECK) the tests below pass vacuously."""
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)
    conn = get_connection(db_path)
    assert "profile" in _columns(conn)
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
    scans_sql = conn.execute(
        "SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'"
    ).fetchone()[0]
    assert (PROFILE_CHECK in scans_sql) == (legacy_shape == "1.1.0")


def test_init_database_drops_the_profile_column_in_place(
    tmp_path: Path, legacy_shape: str
) -> None:
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)

    init_database(db_path)

    conn = get_connection(db_path)
    assert "profile" not in _columns(conn)
    index_names = {
        row[0]
        for row in conn.execute("SELECT name FROM sqlite_master WHERE type='index'")
    }
    assert "idx_scans_profile" not in index_names
    # The cascade guard: a drop-and-recreate would have deleted these.
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
    assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    assert conn.execute("PRAGMA foreign_key_check").fetchall() == []


def test_a_pre_v2_database_accepts_the_next_store(
    tmp_path: Path, legacy_shape: str
) -> None:
    """Review Focus 1: the store that follows the upgrade must not fail."""
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
    assert "profile" not in _columns(get_connection(db_path))


def test_a_blocked_drop_leaves_the_database_exactly_as_it_was(
    tmp_path: Path, legacy_shape: str
) -> None:
    """All-or-nothing: a drop SQLite refuses must not half-apply.

    A view over `profile` (the kind a user adds for their own reporting) makes
    SQLite refuse the column drop. The index drop and, on the 1.1.0 shape, the
    CHECK removal run before it; without one transaction around all three, the
    first would already be committed when the last one fails.
    """
    db_path = tmp_path / "legacy.db"
    _build_pre_v2_database(db_path, legacy_shape)
    conn = get_connection(db_path)
    conn.execute("CREATE VIEW user_profiles AS SELECT id, profile FROM scans")
    conn.commit()
    before = conn.execute(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
    ).fetchall()
    conn.close()

    with pytest.raises(sqlite3.OperationalError, match="profile"):
        init_database(db_path)

    conn = get_connection(db_path)
    after = conn.execute(
        "SELECT type, name, sql FROM sqlite_master ORDER BY type, name"
    ).fetchall()
    assert after == before
    assert "profile" in _columns(conn)
    assert conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 3
