#!/usr/bin/env python3
"""
Example migration: v1.0.0 → v1.1.0

This migration adds example fields for demonstrating the migration framework.
In a real migration, this would add actual new functionality to the schema.

Changes:
- Add scan_notes TEXT column to scans table (for user annotations)
- Add finding_status TEXT column to findings table (for workflow tracking)
"""

from __future__ import annotations

import sqlite3

from scripts.core.history_migrations import Migration


class Migration_1_0_0_to_1_1_0(Migration):
    """Migration from schema v1.0.0 to v1.1.0."""

    @property
    def version(self) -> str:
        return "1.1.0"

    def migrate_up(self, conn: sqlite3.Connection) -> None:
        """
        Apply migration: Add scan_notes and finding_status columns.

        Note: SQLite ALTER TABLE only supports ADD COLUMN (not DROP/MODIFY).
        New columns must be nullable or have default values.
        """
        # Check if scan_notes column already exists
        scans_columns = [
            row[1] for row in conn.execute("PRAGMA table_info(scans)").fetchall()
        ]
        if "scan_notes" not in scans_columns:
            conn.execute(
                """
                ALTER TABLE scans
                ADD COLUMN scan_notes TEXT DEFAULT NULL
                """
            )

        # Check if finding_status column already exists
        findings_columns = [
            row[1] for row in conn.execute("PRAGMA table_info(findings)").fetchall()
        ]
        if "finding_status" not in findings_columns:
            conn.execute(
                """
                ALTER TABLE findings
                ADD COLUMN finding_status TEXT DEFAULT 'open'
                """
            )

        # Create index on finding_status for efficient filtering (IF NOT EXISTS is safe)
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_findings_status
            ON findings(finding_status)
            """
        )

    def migrate_down(self, conn: sqlite3.Connection) -> None:
        """
        Rollback migration (not supported in SQLite).

        SQLite doesn't support DROP COLUMN until version 3.35.0 (2021),
        and even then, it's limited. For production rollback, you would
        need to:
        1. Create new table without the columns
        2. Copy data
        3. Drop old table
        4. Rename new table

        For this example, we leave it as a no-op.
        """
        # Rollback not implemented (SQLite limitation)
        pass
