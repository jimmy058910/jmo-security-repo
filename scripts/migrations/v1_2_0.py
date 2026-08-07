#!/usr/bin/env python3
"""
Migration v1.1.0 -> v1.2.0: drop the legacy `profile` CHECK on `scans`.

The `scans.profile` CHECK enumerated ('fast', 'balanced', 'deep') and predated
the `slim` profile. Every slim scan was rejected at insert time while
`jmo report` logged a WARN and still exited 0, so the scan silently never
entered history (#721). User-defined profiles from `jmo.yml` were rejected for
the same reason.

A SQL CHECK can only enumerate a fixed list; the real rule is "a profile that
exists in tool_registry.PROFILE_TOOLS or in the user's jmo.yml". Validation
therefore moves into store_scan(), and this migration removes the constraint
from existing databases.

Why the schema is edited in place rather than rebuilt
-----------------------------------------------------
SQLite cannot drop a CHECK constraint, so the usual remedy is create-copy-drop-
rename. Measured against this schema, that is actively dangerous:

- `findings` and `scan_metadata` both carry `ON DELETE CASCADE` foreign keys to
  `scans(id)`, and `get_connection()` sets `PRAGMA foreign_keys=ON`. `DROP TABLE
  scans` therefore performs an implicit DELETE that cascades and destroys every
  finding in the database.
- Two triggers on `findings` reference `scans`, which makes
  `ALTER TABLE ... RENAME` fail outright with
  "error in trigger update_scan_counts_on_insert: no such table: main.scans".
- Six indexes and two views would also need faithful recreation.

Editing the stored DDL moves no data and drops nothing, so all eleven dependent
objects survive untouched. The result is verified with `integrity_check` and
`foreign_key_check` before the migration is allowed to commit.
"""

from __future__ import annotations

import re
import sqlite3

from scripts.core.history_migrations import Migration

# Matches the legacy constraint with or without a trailing comma, tolerating
# whitespace and quoting differences.
_PROFILE_CHECK = re.compile(
    r"\n?[ \t]*CHECK[ \t]*\(\s*profile\s+IN\s*\([^)]*\)\s*\)[ \t]*,?",
    re.IGNORECASE,
)


class Migration_1_1_0_to_1_2_0(Migration):
    """Remove the enumerated `profile` CHECK from the scans table."""

    @property
    def version(self) -> str:
        return "1.2.0"

    def migrate_up(self, conn: sqlite3.Connection) -> None:
        row = conn.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name='scans'"
        ).fetchone()
        if row is None:
            return  # no scans table yet; init_database() creates the fixed schema

        old_sql = row[0]
        if not _PROFILE_CHECK.search(old_sql):
            return  # already fixed, or created fresh -- idempotent no-op

        new_sql = _PROFILE_CHECK.sub("", old_sql, count=1)
        if "CHECK" in old_sql.upper() and new_sql == old_sql:
            raise RuntimeError("failed to remove the profile CHECK from scans DDL")

        schema_version = conn.execute("PRAGMA schema_version").fetchone()[0]

        conn.execute("PRAGMA writable_schema=ON")
        try:
            conn.execute(
                "UPDATE sqlite_master SET sql=? WHERE type='table' AND name='scans'",
                (new_sql,),
            )
            # Bump so every connection reloads the edited schema.
            conn.execute(f"PRAGMA schema_version={schema_version + 1}")
        finally:
            conn.execute("PRAGMA writable_schema=OFF")

        integrity = conn.execute("PRAGMA integrity_check").fetchone()[0]
        if integrity != "ok":
            raise RuntimeError(f"integrity_check failed after migration: {integrity}")

        violations = conn.execute("PRAGMA foreign_key_check").fetchall()
        if violations:
            raise RuntimeError(
                f"foreign_key_check failed after migration: {violations}"
            )

    def migrate_down(self, conn: sqlite3.Connection) -> None:
        """Rollback is intentionally a no-op.

        Restoring the constraint would re-introduce the defect, and any slim or
        user-defined-profile scan stored since would then violate it.
        """
