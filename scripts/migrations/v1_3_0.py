#!/usr/bin/env python3
"""
Migration v1.2.0 -> v1.3.0: relabel the fabricated `jmo_version` values.

`store_scan()` declared `jmo_version: str = "1.0.0"` as a literal default and
neither production caller -- `jmo history store` and the report phase's
auto-storage hook -- ever passed the argument. Every scan therefore recorded
the string '1.0.0' regardless of which release produced it. Measured on the
reference database: 1833 of 1833 rows, spanning 2025-11-13 to 2026-08-17 and
every release through v1.0.8 (#895).

The write path now resolves the running version through
`scripts.core.jmo_version.get_jmo_version()`, the same resolver the `jmo diff`
artifacts use. That fixes rows written from here on. It cannot fix the existing
ones: the release that produced a given historical scan is not recoverable from
anything stored alongside it.

Why 'unknown' and not NULL
--------------------------
The intent is that a value nobody measured should look missing rather than
plausible. Both NULL and 'unknown' express that; 'unknown' is chosen because:

- `scans.jmo_version` is `TEXT NOT NULL`. Reaching NULL means dropping that
  constraint, and on this schema a constraint change cannot be done by the
  usual create-copy-drop-rename -- `findings` and `scan_metadata` carry
  `ON DELETE CASCADE` foreign keys to `scans(id)` and `get_connection()` sets
  `PRAGMA foreign_keys=ON`, so `DROP TABLE scans` destroys every finding in the
  database. See v1_2_0.py, which documents the same trap.
- 'unknown' is already this codebase's word for it: `jmo_version.py` defines
  `UNKNOWN_VERSION = "unknown"` and returns it rather than a wrong number when
  the version cannot be resolved. Readers therefore already handle it, and a
  historical row and a present-day unresolvable row read the same.

Scope
-----
Only rows still carrying the fabricated literal are touched. A row written
after the write-path fix holds a real version and is left alone. The one
ambiguity is a genuine v1.0.0 scan, which is indistinguishable from a
fabricated one -- it is relabelled too. That is accepted: the column has never
been able to tell those apart, which is the defect being closed.
"""

from __future__ import annotations

import sqlite3

from scripts.core.history_migrations import Migration
from scripts.core.jmo_version import UNKNOWN_VERSION

# The value store_scan() used to write for every scan, whatever was running.
_FABRICATED_VERSION = "1.0.0"


class Migration_1_2_0_to_1_3_0(Migration):
    """Relabel fabricated '1.0.0' jmo_version values as 'unknown'."""

    @property
    def version(self) -> str:
        return "1.3.0"

    def migrate_up(self, conn: sqlite3.Connection) -> None:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()
        if row is None:
            return  # no scans table yet; init_database() creates the fixed schema

        before = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE jmo_version = ?",
            (_FABRICATED_VERSION,),
        ).fetchone()[0]
        if before == 0:
            return  # already migrated, or a database that never had the defect

        conn.execute(
            "UPDATE scans SET jmo_version = ? WHERE jmo_version = ?",
            (UNKNOWN_VERSION, _FABRICATED_VERSION),
        )

        remaining = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE jmo_version = ?",
            (_FABRICATED_VERSION,),
        ).fetchone()[0]
        if remaining:
            raise RuntimeError(
                f"{remaining} scans still carry the fabricated version after update"
            )

        # This migration writes no DDL and deletes nothing, so the integrity
        # surface is small -- but the foreign keys are the thing that turns a
        # mistake here into data loss, so they are checked anyway.
        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(
                f"foreign_key_check failed after migration: {violations}"
            )

    def migrate_down(self, conn: sqlite3.Connection) -> None:
        """Rollback is intentionally a no-op.

        Writing '1.0.0' back would restore a value that was never measured, and
        would also overwrite any row that legitimately holds it.
        """
