#!/usr/bin/env python3
"""
Integration tests for Phase 4 CLI commands (optimize, migrate, verify, repair).

Tests the end-to-end functionality of:
- jmo history optimize (performance optimization)
- jmo history migrate (schema migrations)
- jmo history verify (integrity checks)
- jmo history repair (database recovery)

Run with: pytest tests/integration/test_cli_history_phase4.py -v
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path


from scripts.core.history_db import init_database, get_connection


def run_jmo(*args: str, input_text: str = None):
    """
    Run jmo CLI with given arguments.

    Args:
        *args: CLI arguments (e.g., "history", "optimize", "--json")
        input_text: Optional stdin input for interactive prompts

    Returns:
        Tuple of (returncode, stdout, stderr)
    """
    cmd = [sys.executable, "scripts/cli/jmo.py"] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        input=input_text,
        timeout=30,
    )
    return result.returncode, result.stdout, result.stderr


def test_cli_history_optimize(tmp_path: Path):
    """
    CLI Test 1: jmo history optimize runs successfully.

    Verifies that:
    - Command executes without errors
    - Returns optimization results
    - JSON output mode works
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Add some test data
    conn = get_connection(db_path)
    conn.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets, target_type,
            total_findings, critical_count, high_count, medium_count, low_count, info_count,
            jmo_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "test-scan-001",
            1234567890,
            "2024-01-01T00:00:00Z",
            "balanced",
            '["trivy"]',
            '["/test"]',
            "repo",
            1,
            0,
            1,
            0,
            0,
            0,
            "1.0.0",
        ),
    )
    conn.commit()

    # Test regular output
    returncode, stdout, stderr = run_jmo("history", "optimize", "--db", str(db_path))

    assert returncode == 0, f"Command failed: {stderr}"
    assert "Optimization complete" in stdout or "✅" in stdout
    assert "Size before" in stdout
    assert "Size after" in stdout

    # Test JSON output
    returncode, stdout, stderr = run_jmo(
        "history", "optimize", "--db", str(db_path), "--json"
    )

    assert returncode == 0, f"Command failed: {stderr}"
    # Skip any lines before JSON (like "Optimizing database: ...")
    json_start = stdout.find("{")
    assert json_start >= 0, f"No JSON found in output: {stdout}"
    result = json.loads(stdout[json_start:])
    assert "size_before_mb" in result
    assert "size_after_mb" in result
    assert "space_reclaimed_mb" in result
    assert "indices_count" in result


def test_cli_history_migrate(tmp_path: Path):
    """
    CLI Test 2: jmo history migrate applies migrations.

    Verifies that:
    - Command detects and applies pending migrations
    - Shows current and target versions
    - JSON output mode works
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Test regular output (should apply v1.1.0 migration)
    returncode, stdout, stderr = run_jmo("history", "migrate", "--db", str(db_path))

    assert returncode == 0, f"Command failed: {stderr}"
    assert "Current schema version" in stdout
    # Either applied migration or already up-to-date
    assert ("Applied" in stdout or "up-to-date" in stdout) or "No pending" in stdout

    # Test JSON output
    returncode, stdout, stderr = run_jmo(
        "history", "migrate", "--db", str(db_path), "--json"
    )

    assert returncode == 0, f"Command failed: {stderr}"
    # Skip any lines before JSON
    json_start = stdout.find("{")
    assert json_start >= 0, f"No JSON found in output: {stdout}"
    result = json.loads(stdout[json_start:])
    assert "applied" in result
    assert "errors" in result
    assert "final_version" in result
    assert isinstance(result["applied"], list)


def test_cli_history_verify(tmp_path: Path):
    """
    CLI Test 3: jmo history verify checks integrity.

    Verifies that:
    - Command runs PRAGMA checks
    - Returns success for clean database
    - Shows database statistics
    - JSON output mode works
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Test regular output
    returncode, stdout, stderr = run_jmo("history", "verify", "--db", str(db_path))

    assert returncode == 0, f"Command failed (expected success for clean DB): {stderr}"
    assert "integrity verification" in stdout.lower()
    assert "PASSED" in stdout or "✅" in stdout
    assert "Database Statistics" in stdout

    # Test JSON output
    returncode, stdout, stderr = run_jmo(
        "history", "verify", "--db", str(db_path), "--json"
    )

    assert returncode == 0, f"Command failed: {stderr}"
    # Skip any lines before JSON
    json_start = stdout.find("{")
    assert json_start >= 0, f"No JSON found in output: {stdout}"
    result = json.loads(stdout[json_start:])
    assert "is_valid" in result
    assert result["is_valid"] is True, "Clean database should pass verification"
    assert "errors" in result
    assert len(result["errors"]) == 0
    assert "stats" in result


def test_cli_history_repair(tmp_path: Path):
    """
    CLI Test 4: jmo history repair recovers database.

    Verifies that:
    - Command prompts for confirmation (interactive mode)
    - --force flag skips confirmation
    - Creates backup and recovers data
    - JSON output mode works
    """
    db_path = tmp_path / "test.db"
    init_database(db_path)

    # Add test data
    conn = get_connection(db_path)
    scan_id = "test-repair-scan"
    conn.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets, target_type,
            total_findings, critical_count, high_count, medium_count, low_count, info_count,
            jmo_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            scan_id,
            1234567890,
            "2024-01-01T00:00:00Z",
            "balanced",
            '["trivy"]',
            '["/test"]',
            "repo",
            1,
            1,
            0,
            0,
            0,
            0,
            "1.0.0",
        ),
    )
    conn.commit()

    # Test interactive mode (cancel)
    returncode, stdout, stderr = run_jmo(
        "history", "repair", "--db", str(db_path), input_text="n\n"
    )

    assert returncode == 0, "Should succeed on cancel"
    assert "cancelled" in stdout.lower() or "Continue?" in stdout

    # Test --force flag (should complete repair)
    returncode, stdout, stderr = run_jmo(
        "history", "repair", "--db", str(db_path), "--force"
    )

    assert returncode == 0, f"Repair should succeed: {stderr}"
    assert "repair" in stdout.lower()
    assert "SUCCESSFUL" in stdout or "✅" in stdout
    assert "Backup created" in stdout

    # Verify backup exists (check using suffix from result)
    # The backup path is reported in stdout, let's extract it
    if "Backup created" in stdout:
        # Backup was created, check for .backup suffix
        backup_candidates = list(tmp_path.glob("*.backup"))
        assert (
            len(backup_candidates) >= 1
        ), f"Backup file should exist in {tmp_path}, found: {list(tmp_path.glob('*'))}"

    # Verify data preserved
    conn2 = get_connection(db_path)
    scan = conn2.execute("SELECT id FROM scans WHERE id = ?", (scan_id,)).fetchone()
    assert scan is not None, "Data should be preserved after repair"
    assert scan[0] == scan_id

    # Test JSON output (need fresh DB without .backup file conflict)
    db_path2 = tmp_path / "test2.db"
    init_database(db_path2)
    conn3 = get_connection(db_path2)
    conn3.execute(
        """
        INSERT INTO scans (
            id, timestamp, timestamp_iso, profile, tools, targets, target_type,
            total_findings, critical_count, high_count, medium_count, low_count, info_count,
            jmo_version
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "test-scan-json",
            1234567890,
            "2024-01-01T00:00:00Z",
            "balanced",
            '["trivy"]',
            '["/test"]',
            "repo",
            1,
            1,
            0,
            0,
            0,
            0,
            "1.0.0",
        ),
    )
    conn3.commit()

    returncode, stdout, stderr = run_jmo(
        "history", "repair", "--db", str(db_path2), "--force", "--json"
    )

    assert returncode == 0, f"Command failed: {stderr}"
    # Skip any lines before JSON
    json_start = stdout.find("{")
    assert json_start >= 0, f"No JSON found in output: {stdout}"
    result = json.loads(stdout[json_start:])
    assert "success" in result
    assert result["success"] is True
    assert "backup_path" in result
    assert "rows_recovered" in result
    assert "recovery_time_sec" in result
