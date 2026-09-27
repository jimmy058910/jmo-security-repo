#!/usr/bin/env python3
"""
Migration v1.3.0 -> v2.0.0: drop scans.profile and scans.target_type.

v2.0.0 removed the fast/slim/balanced/deep profiles; one tool matrix runs
instead, and a scan records no profile. The column was `TEXT NOT NULL`, so a
database that kept it would reject every insert.

`target_type` went too (#1321). One column cannot type a scan of two target
types, and it recorded `repo` for every scan anyway: it was the first
`individual-*` folder that existed, and every scan creates `individual-repos`.
`scan_tool_runs` types each target instead. It left after v2.0.0's schema had
already been written by dev builds, so a database recording 2.0.0 can still
have it. `jmo history migrate` does not run this migration again there; the
drop in `init_database`, which does not read the recorded version, removes it
at that database's next store.

The drops themselves live in `history_db._drop_legacy_profile_column` and
`_drop_legacy_target_type_column`, which `init_database` also calls:
`store_scan` runs `init_database` on every store, while migrations run only on
an explicit `jmo history migrate`, so relying on this migration alone would
leave an un-migrated database unable to store anything. This migration exists
so `jmo history migrate` records 2.0.0.

Why ALTER TABLE ... DROP COLUMN and not a rebuild: `findings` and
`scan_metadata` carry ON DELETE CASCADE foreign keys to `scans(id)`, and
`get_connection()` sets `PRAGMA foreign_keys=ON`, so `DROP TABLE scans`
destroys every finding in the database. See v1_2_0.py, which documents the
same trap. DROP COLUMN rewrites the table in place and needs SQLite >= 3.35;
each column's table CHECK is edited out of the stored DDL first, since SQLite
refuses to drop a column a CHECK names.
"""

from __future__ import annotations

import sqlite3

from scripts.core.history_db import (
    _drop_legacy_profile_column,
    _drop_legacy_target_type_column,
)
from scripts.core.history_migrations import Migration


class Migration_1_3_0_to_2_0_0(Migration):
    """Drop the scans.profile and scans.target_type columns and their indexes."""

    @property
    def version(self) -> str:
        return "2.0.0"

    def migrate_up(self, conn: sqlite3.Connection) -> None:
        _drop_legacy_profile_column(conn)
        _drop_legacy_target_type_column(conn)

    def migrate_down(self, conn: sqlite3.Connection) -> None:
        """Rollback is intentionally a no-op.

        The dropped values cannot be recovered, and a NOT NULL column added
        back would have nothing truthful to hold for the scans stored since.
        """
