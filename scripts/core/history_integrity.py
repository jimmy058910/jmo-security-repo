#!/usr/bin/env python3
"""
Database integrity verification and recovery for JMo Security historical storage.

This module provides:
- verify_database_integrity(): Comprehensive integrity checks using PRAGMA commands
- recover_database(): Dump/reimport corrupted databases with backup preservation

Usage:
    from scripts.core.history_integrity import verify_database_integrity, recover_database

    # Verify database integrity
    result = verify_database_integrity(db_path)
    if not result["is_valid"]:
        print(f"Integrity issues: {result['errors']}")

    # Recover corrupted database
    result = recover_database(db_path)
    if result["success"]:
        print(f"Database recovered, backup at {result['backup_path']}")
"""

from __future__ import annotations

import logging
import shutil
import sqlite3
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List

from scripts.core.history_db import get_connection, init_database

# Configure logging
logger = logging.getLogger(__name__)


def verify_database_integrity(db_path: Path) -> Dict[str, Any]:
    """
    Verify database integrity using PRAGMA checks.

    Runs comprehensive integrity checks:
    1. PRAGMA integrity_check - Detects corruption in database structure
    2. PRAGMA foreign_key_check - Finds orphaned foreign key references
    3. PRAGMA quick_check - Fast corruption detection

    Args:
        db_path: Path to database file

    Returns:
        Dict with verification results:
        - is_valid: bool (True if all checks pass)
        - errors: List of error messages
        - integrity_check: Result of PRAGMA integrity_check
        - foreign_key_check: Result of PRAGMA foreign_key_check
        - quick_check: Result of PRAGMA quick_check
        - stats: Database statistics (tables, rows, indices)

    Example:
        >>> result = verify_database_integrity(Path(".jmo/history.db"))
        >>> if not result["is_valid"]:
        ...     print(f"Errors: {result['errors']}")
    """
    conn = get_connection(db_path)
    errors: List[str] = []

    logger.info(f"Verifying database integrity: {db_path}")

    # 1. PRAGMA integrity_check (comprehensive corruption detection)
    try:
        integrity_result = conn.execute("PRAGMA integrity_check").fetchall()
        # Result is [('ok',)] if clean, otherwise list of error messages
        if len(integrity_result) == 1 and integrity_result[0][0] == "ok":
            integrity_check = "ok"
        else:
            integrity_check = [row[0] for row in integrity_result]
            errors.extend(integrity_check)
            logger.error(f"Integrity check failed: {integrity_check}")
    except Exception as e:
        integrity_check = f"error: {e}"
        errors.append(str(e))
        logger.error(f"Integrity check error: {e}")

    # 2. PRAGMA foreign_key_check (orphaned references)
    try:
        # Enable foreign keys for check
        conn.execute("PRAGMA foreign_keys = ON")
        fk_result = conn.execute("PRAGMA foreign_key_check").fetchall()

        if len(fk_result) == 0:
            foreign_key_check = "ok"
        else:
            # Each row: (table, rowid, referenced_table, fk_index)
            foreign_key_check = [
                f"Table {row[0]} row {row[1]} references missing {row[2]}"
                for row in fk_result
            ]
            errors.extend(foreign_key_check)
            logger.warning(f"Foreign key violations: {foreign_key_check}")
    except Exception as e:
        foreign_key_check = f"error: {e}"
        logger.warning(f"Foreign key check error: {e}")

    # 3. PRAGMA quick_check (fast corruption check)
    try:
        quick_result = conn.execute("PRAGMA quick_check").fetchall()
        if len(quick_result) == 1 and quick_result[0][0] == "ok":
            quick_check = "ok"
        else:
            quick_check = [row[0] for row in quick_result]
            errors.extend(quick_check)
            logger.error(f"Quick check failed: {quick_check}")
    except Exception as e:
        quick_check = f"error: {e}"
        errors.append(str(e))
        logger.error(f"Quick check error: {e}")

    # 4. Collect database statistics
    try:
        stats = {
            "scans_count": conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0],
            "findings_count": conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0],
            "schema_version_count": conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0],
        }

        # Count indices
        indices = conn.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type='index'"
        ).fetchone()[0]
        stats["indices_count"] = indices

        # Database size
        stats["size_mb"] = db_path.stat().st_size / (1024 * 1024)
    except Exception as e:
        stats = {"error": str(e)}
        logger.warning(f"Stats collection error: {e}")

    is_valid = len(errors) == 0

    result = {
        "is_valid": is_valid,
        "errors": errors,
        "integrity_check": integrity_check,
        "foreign_key_check": foreign_key_check,
        "quick_check": quick_check,
        "stats": stats,
    }

    if is_valid:
        logger.info("✅ Database integrity verification PASSED")
    else:
        logger.error(f"❌ Database integrity verification FAILED: {len(errors)} errors")

    return result


def recover_database(db_path: Path) -> Dict[str, Any]:
    """
    Recover corrupted database by dump/reimport.

    This function:
    1. Creates a backup of the corrupted database (.backup file)
    2. Dumps all data to SQL statements
    3. Creates a fresh database with init_database()
    4. Reimports all data from dump
    5. Verifies recovery integrity

    Args:
        db_path: Path to database file to recover

    Returns:
        Dict with recovery results:
        - success: bool (True if recovery succeeded)
        - backup_path: Path to backup file
        - errors: List of error messages (empty if success)
        - rows_recovered: Dict of table → row count
        - recovery_time_sec: Time taken for recovery

    Example:
        >>> result = recover_database(Path(".jmo/history.db"))
        >>> if result["success"]:
        ...     print(f"Recovered, backup at {result['backup_path']}")
    """
    start_time = time.time()
    errors: List[str] = []

    logger.info(f"Starting database recovery: {db_path}")

    # 1. Create backup
    backup_path = db_path.with_suffix(".backup")
    try:
        shutil.copy2(db_path, backup_path)
        logger.info(f"Created backup: {backup_path}")
    except Exception as e:
        errors.append(f"Backup failed: {e}")
        logger.error(f"Backup creation failed: {e}")
        return {
            "success": False,
            "backup_path": None,
            "errors": errors,
            "rows_recovered": {},
            "recovery_time_sec": time.time() - start_time,
        }

    # 2. Dump data from corrupted database
    try:
        conn_old = get_connection(db_path)

        # Extract all data
        scans = conn_old.execute("SELECT * FROM scans").fetchall()
        findings = conn_old.execute("SELECT * FROM findings").fetchall()
        schema_versions = conn_old.execute("SELECT * FROM schema_version").fetchall()

        logger.info(f"Dumped {len(scans)} scans, {len(findings)} findings, {len(schema_versions)} schema versions")
    except Exception as e:
        errors.append(f"Data dump failed: {e}")
        logger.error(f"Data dump failed: {e}")
        return {
            "success": False,
            "backup_path": str(backup_path),
            "errors": errors,
            "rows_recovered": {},
            "recovery_time_sec": time.time() - start_time,
        }

    # 3. Create fresh database (delete old one first)
    try:
        db_path.unlink()  # Delete corrupted database
        init_database(db_path)  # Create fresh schema
        logger.info(f"Created fresh database: {db_path}")
    except Exception as e:
        errors.append(f"Fresh database creation failed: {e}")
        logger.error(f"Fresh database creation failed: {e}")
        return {
            "success": False,
            "backup_path": str(backup_path),
            "errors": errors,
            "rows_recovered": {},
            "recovery_time_sec": time.time() - start_time,
        }

    # 4. Reimport data
    try:
        conn_new = get_connection(db_path)

        # Disable foreign keys during import for flexibility
        conn_new.execute("PRAGMA foreign_keys = OFF")

        # Import scans
        if scans:
            # Get column names from PRAGMA table_info
            scans_columns = [row[1] for row in conn_old.execute("PRAGMA table_info(scans)").fetchall()]
            placeholders = ", ".join(["?"] * len(scans_columns))
            conn_new.executemany(
                f"INSERT INTO scans ({', '.join(scans_columns)}) VALUES ({placeholders})",
                scans
            )
            logger.info(f"Imported {len(scans)} scans")

        # Import findings
        if findings:
            findings_columns = [row[1] for row in conn_old.execute("PRAGMA table_info(findings)").fetchall()]
            placeholders = ", ".join(["?"] * len(findings_columns))
            conn_new.executemany(
                f"INSERT INTO findings ({', '.join(findings_columns)}) VALUES ({placeholders})",
                findings
            )
            logger.info(f"Imported {len(findings)} findings")

        # Import schema_versions (skip if we just created 1.0.0)
        # Only import versions > 1.0.0 to avoid duplicates
        schema_versions_to_import = [sv for sv in schema_versions if sv[0] != "1.0.0"]
        if schema_versions_to_import:
            conn_new.executemany(
                "INSERT INTO schema_version (version, applied_at, applied_at_iso) VALUES (?, ?, ?)",
                schema_versions_to_import
            )
            logger.info(f"Imported {len(schema_versions_to_import)} schema versions")

        # Re-enable foreign keys
        conn_new.execute("PRAGMA foreign_keys = ON")

        conn_new.commit()

    except Exception as e:
        errors.append(f"Data import failed: {e}")
        logger.error(f"Data import failed: {e}")
        return {
            "success": False,
            "backup_path": str(backup_path),
            "errors": errors,
            "rows_recovered": {},
            "recovery_time_sec": time.time() - start_time,
        }

    # 5. Verify recovery
    try:
        verification = verify_database_integrity(db_path)
        if not verification["is_valid"]:
            errors.append(f"Post-recovery verification failed: {verification['errors']}")
            logger.warning(f"Post-recovery verification issues: {verification['errors']}")
    except Exception as e:
        logger.warning(f"Post-recovery verification error: {e}")

    rows_recovered = {
        "scans": len(scans),
        "findings": len(findings),
        "schema_versions": len(schema_versions_to_import) if schema_versions_to_import else 0,
    }

    recovery_time = time.time() - start_time

    if len(errors) == 0:
        logger.info(f"✅ Database recovery SUCCEEDED in {recovery_time:.2f}s")
    else:
        logger.warning(f"⚠️  Database recovery completed with warnings in {recovery_time:.2f}s")

    return {
        "success": len(errors) == 0,
        "backup_path": str(backup_path),
        "errors": errors,
        "rows_recovered": rows_recovered,
        "recovery_time_sec": recovery_time,
    }
