#!/usr/bin/env python3
"""
Database migration framework for JMo Security historical storage.

This module provides:
- Migration base class for version upgrades
- Migration discovery and ordering
- Migration execution with rollback support
- Version tracking in schema_version table

Usage:
    from scripts.core.history_migrations import run_migrations

    result = run_migrations(db_path, target_version="1.1.0")
    if result["errors"]:
        print(f"Migration failed: {result['errors']}")
    else:
        print(f"Migrated to version {result['final_version']}")
"""

from __future__ import annotations

import logging
import sqlite3
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.core.history_db import get_connection

# Configure logging
logger = logging.getLogger(__name__)


class Migration(ABC):
    """
    Abstract base class for database migrations.

    Each migration must implement:
    - version property: Target schema version (e.g., "1.1.0")
    - migrate_up(): Apply the migration
    - migrate_down(): Rollback the migration (optional)

    Example:
        class Migration_1_0_0_to_1_1_0(Migration):
            @property
            def version(self) -> str:
                return "1.1.0"

            def migrate_up(self, conn: sqlite3.Connection) -> None:
                conn.execute("ALTER TABLE scans ADD COLUMN new_field TEXT")

            def migrate_down(self, conn: sqlite3.Connection) -> None:
                # Rollback not always possible with SQLite
                pass
    """

    @property
    @abstractmethod
    def version(self) -> str:
        """
        Target version for this migration (e.g., "1.1.0").

        Returns:
            Version string in semver format
        """
        pass

    @abstractmethod
    def migrate_up(self, conn: sqlite3.Connection) -> None:
        """
        Apply the migration.

        This method should execute all DDL/DML statements needed
        to upgrade the database schema to the target version.

        Args:
            conn: Database connection (transaction will be managed by caller)

        Raises:
            Exception: On migration failure (will trigger rollback)
        """
        pass

    @abstractmethod
    def migrate_down(self, conn: sqlite3.Connection) -> None:
        """
        Rollback the migration (optional).

        Note: SQLite has limited ALTER TABLE support. Many migrations
        cannot be rolled back. This method is optional and may be
        implemented as a no-op.

        Args:
            conn: Database connection
        """
        pass


def discover_migrations(
    current_version: str,
    target_version: str,
    migrations_dir: Optional[Path] = None
) -> List[Migration]:
    """
    Find all migrations between current and target version.

    Scans the migrations directory for migration files matching the pattern:
    v{version}.py (e.g., v1_1_0.py for version 1.1.0)

    Args:
        current_version: Current schema version (e.g., "1.0.0")
        target_version: Target schema version (e.g., "1.5.0")
        migrations_dir: Path to migrations directory (default: scripts/migrations)

    Returns:
        List of Migration instances in ascending version order

    Example:
        >>> migrations = discover_migrations("1.0.0", "1.5.0")
        >>> print([m.version for m in migrations])
        ['1.1.0', '1.2.0', '1.3.0', '1.4.0', '1.5.0']
    """
    if migrations_dir is None:
        migrations_dir = Path(__file__).parent.parent / "migrations"

    if not migrations_dir.exists():
        logger.warning(f"Migrations directory not found: {migrations_dir}")
        return []

    migrations: List[Migration] = []

    # Find all migration files
    migration_files = sorted(migrations_dir.glob("v*.py"))

    for file in migration_files:
        # Skip __pycache__ and __init__.py
        if file.stem.startswith("__"):
            continue

        try:
            # Import migration module
            import importlib.util
            spec = importlib.util.spec_from_file_location(file.stem, file)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)

                # Find Migration class in module
                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (isinstance(attr, type) and
                        issubclass(attr, Migration) and
                        attr is not Migration):
                        migration = attr()

                        # Filter by version range (use tuple comparison for proper semver)
                        current_v = _parse_version(current_version)
                        migration_v = _parse_version(migration.version)
                        target_v = _parse_version(target_version)

                        if current_v < migration_v <= target_v:
                            migrations.append(migration)
                            logger.debug(f"Discovered migration: {migration.version} from {file}")
                        break

        except Exception as e:
            logger.error(f"Failed to load migration from {file}: {e}")
            continue

    # Sort by version
    migrations.sort(key=lambda m: _parse_version(m.version))

    return migrations


def run_migrations(
    db_path: Path,
    target_version: Optional[str] = None
) -> Dict[str, Any]:
    """
    Apply all pending migrations up to target version.

    This function:
    1. Gets current schema version from database
    2. Discovers migrations between current and target version
    3. Applies migrations in order within transactions
    4. Updates schema_version table after each migration
    5. Rolls back on error and returns error details

    Args:
        db_path: Path to database file
        target_version: Target version (default: apply all available migrations)

    Returns:
        Dict with migration results:
        - applied: List of successfully applied migration versions
        - errors: List of error dicts (empty if all successful)
        - final_version: Schema version after migrations
        - rollback_performed: True if any migration was rolled back

    Example:
        >>> result = run_migrations(Path(".jmo/history.db"), "1.5.0")
        >>> if result["errors"]:
        ...     print(f"Migration failed at {result['errors'][0]['version']}")
        >>> else:
        ...     print(f"Migrated to {result['final_version']}")
    """
    conn = get_connection(db_path)

    # Get current version (order by applied_at DESC, then version DESC for tiebreaking)
    try:
        row = conn.execute(
            "SELECT version FROM schema_version ORDER BY applied_at DESC, version DESC LIMIT 1"
        ).fetchone()
        current_version = row[0] if row else "0.0.0"
    except sqlite3.OperationalError:
        # schema_version table doesn't exist (pre-migration database)
        current_version = "0.0.0"

    logger.info(f"Current schema version: {current_version}")

    # Discover migrations
    if target_version is None:
        target_version = "999.999.999"  # Apply all available

    migrations = discover_migrations(current_version, target_version)

    if not migrations:
        logger.info("No migrations to apply")
        return {
            "applied": [],
            "errors": [],
            "final_version": current_version,
            "rollback_performed": False
        }

    logger.info(f"Found {len(migrations)} migrations to apply: {[m.version for m in migrations]}")

    applied: List[str] = []
    errors: List[Dict[str, Any]] = []
    rollback_performed = False

    for migration in migrations:
        try:
            logger.info(f"Applying migration: {migration.version}")

            # Apply migration in transaction
            with conn:
                migration.migrate_up(conn)

                # Record migration in schema_version table
                conn.execute(
                    """
                    INSERT INTO schema_version (version, applied_at, applied_at_iso)
                    VALUES (?, ?, ?)
                    """,
                    (
                        migration.version,
                        int(time.time()),
                        datetime.now(timezone.utc).isoformat()
                    )
                )

            applied.append(migration.version)
            logger.info(f"✅ Migration {migration.version} applied successfully")

        except Exception as e:
            logger.error(f"❌ Migration {migration.version} failed: {e}")

            # Attempt rollback
            try:
                logger.info(f"Attempting rollback of {migration.version}")
                with conn:
                    migration.migrate_down(conn)
                rollback_performed = True
                logger.info(f"✅ Rollback of {migration.version} successful")
            except Exception as rollback_error:
                logger.error(f"❌ Rollback of {migration.version} failed: {rollback_error}")
                errors.append({
                    "version": migration.version,
                    "error": str(e),
                    "rollback_error": str(rollback_error)
                })

            errors.append({
                "version": migration.version,
                "error": str(e)
            })

            # Stop applying further migrations
            break

    final_version = applied[-1] if applied else current_version

    return {
        "applied": applied,
        "errors": errors,
        "final_version": final_version,
        "rollback_performed": rollback_performed
    }


def get_current_version(db_path: Path) -> str:
    """
    Get current schema version from database.

    Args:
        db_path: Path to database file

    Returns:
        Current schema version string (e.g., "1.0.0")
    """
    conn = get_connection(db_path)

    try:
        row = conn.execute(
            "SELECT version FROM schema_version ORDER BY applied_at DESC, version DESC LIMIT 1"
        ).fetchone()
        return row[0] if row else "0.0.0"
    except sqlite3.OperationalError:
        return "0.0.0"


def _parse_version(version: str) -> tuple[int, int, int]:
    """
    Parse version string into tuple for sorting.

    Args:
        version: Version string (e.g., "1.2.3")

    Returns:
        Tuple of (major, minor, patch)
    """
    parts = version.split(".")
    return (
        int(parts[0]) if len(parts) > 0 else 0,
        int(parts[1]) if len(parts) > 1 else 0,
        int(parts[2]) if len(parts) > 2 else 0
    )
