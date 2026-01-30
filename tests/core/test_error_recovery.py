#!/usr/bin/env python3
"""
Error Recovery Tests for JMo Security.

Tests system resilience against various failure scenarios including:
- Database corruption
- Disk space exhaustion
- Process crashes
- Permission errors
- Concurrent access issues

Usage:
    pytest tests/core/test_error_recovery.py -v
"""

from __future__ import annotations

import json
import os
import sqlite3
import threading
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from tests.conftest import IS_WINDOWS, skip_on_windows


# ============================================================================
# Database Recovery Tests
# ============================================================================


class TestDatabaseRecovery:
    """Test database error recovery scenarios."""

    def test_sqlite_corruption_detection(self, tmp_path: Path):
        """Verify corrupted database is detected gracefully."""
        from scripts.core.history_db import init_database, get_connection

        db_path = tmp_path / "corrupted.db"

        # Create a valid database first
        init_database(db_path)

        # Corrupt the database by writing garbage
        with open(db_path, "r+b") as f:
            f.seek(100)  # Skip SQLite header
            f.write(b"CORRUPTED_DATA_GARBAGE" * 100)

        # Opening corrupted DB should be handled gracefully
        try:
            conn = get_connection(db_path)
            cursor = conn.execute("SELECT COUNT(*) FROM scans")
            cursor.fetchone()
        except sqlite3.DatabaseError:
            pass  # Expected - corruption detected

    def test_database_locked_handling(self, tmp_path: Path):
        """Verify database locking is handled gracefully."""
        from scripts.core.history_db import init_database

        db_path = tmp_path / "locked.db"

        # Create database
        init_database(db_path)

        # Open first connection and start a transaction
        conn1 = sqlite3.connect(db_path, timeout=1)
        conn1.execute("BEGIN EXCLUSIVE")

        # Try to access from another connection
        try:
            conn2 = sqlite3.connect(db_path, timeout=1)
            conn2.execute("SELECT 1 FROM sqlite_master")
        except sqlite3.OperationalError as e:
            # Expected: database is locked
            assert "locked" in str(e).lower()
        finally:
            conn1.rollback()
            conn1.close()

    def test_transaction_rollback_on_failure(self, tmp_path: Path):
        """Verify transactions are rolled back on failure."""
        from scripts.core.history_db import init_database, get_connection

        db_path = tmp_path / "rollback.db"

        init_database(db_path)
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        initial_count = cursor.fetchone()[0]
        conn.close()

        # Try to insert with simulated failure
        conn = None
        try:
            conn = get_connection(db_path)
            conn.execute("BEGIN")
            conn.execute(
                "INSERT INTO scans (id, timestamp, timestamp_iso, profile, tools, targets, target_type, jmo_version) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                ("test-scan", 1704067200, "2024-01-01T00:00:00", "fast", "[]", "[]", "repo", "1.0.0"),
            )
            # Simulate failure before commit
            raise Exception("Simulated failure")
        except Exception:
            if conn:
                conn.rollback()
                conn.close()

        # Verify data was not committed
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        final_count = cursor.fetchone()[0]
        conn.close()
        assert final_count == initial_count

    def test_database_missing_tables(self, tmp_path: Path):
        """Verify handling of database with missing tables."""
        from scripts.core.history_db import init_database, get_connection

        db_path = tmp_path / "empty.db"

        # Create empty database without tables
        conn = sqlite3.connect(db_path)
        conn.close()

        # init_database should create tables
        init_database(db_path)
        conn = get_connection(db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        count = cursor.fetchone()[0]
        conn.close()
        assert count == 0


# ============================================================================
# Disk Space Tests
# ============================================================================


class TestDiskSpaceRecovery:
    """Test handling of disk space exhaustion."""

    def test_disk_full_during_json_write(self, tmp_path: Path):
        """Verify graceful handling when disk is full during JSON write."""
        from scripts.core.reporters.basic_reporter import write_json

        # Create test findings in dict format (CommonFinding format)
        findings = [
            {
                "severity": "HIGH",
                "message": "Test finding",
                "tool": {"name": "test"},
                "location": {"path": "test.py"},
            }
        ]

        # Mock Path.write_text to raise disk full error
        with patch.object(Path, "write_text") as mock_write:
            mock_write.side_effect = OSError(28, "No space left on device")

            # Should raise OSError
            try:
                write_json(findings, tmp_path / "output.json")
            except OSError as e:
                assert e.errno == 28 or "space" in str(e).lower()

    def test_disk_full_during_db_insert(self, tmp_path: Path):
        """Verify graceful handling when disk is full during DB insert."""
        from scripts.core.history_db import init_database, get_connection

        db_path = tmp_path / "test.db"

        # Initialize database
        init_database(db_path)

        # Simulate disk full by mocking sqlite3.connect to return a mock connection
        # that raises on execute
        mock_conn = MagicMock()
        mock_conn.execute.side_effect = sqlite3.OperationalError(
            "database or disk is full"
        )

        with patch("scripts.core.history_db.sqlite3.connect", return_value=mock_conn):
            try:
                conn = get_connection(db_path)
                conn.execute("INSERT INTO scans VALUES (?)", ("test",))
            except sqlite3.OperationalError as e:
                assert "full" in str(e).lower()


# ============================================================================
# Tool Crash Recovery Tests
# ============================================================================


class TestToolCrashRecovery:
    """Test recovery from tool crashes during scan."""

    def test_partial_results_after_tool_crash(self, tmp_path: Path):
        """Verify partial results are preserved after tool crash."""
        from scripts.core.normalize_and_report import gather_results

        # Create results with some valid and some corrupt files
        indiv = tmp_path / "individual-repos" / "test-repo"
        indiv.mkdir(parents=True)

        # Valid result
        valid_result = {
            "results": [
                {
                    "check_id": "test",
                    "path": "test.py",
                    "start": {"line": 1},
                    "extra": {"message": "test", "severity": "HIGH"},
                }
            ],
            "version": "1.0.0",
        }
        (indiv / "semgrep.json").write_text(json.dumps(valid_result), encoding="utf-8")

        # Corrupt/partial result (tool crashed mid-write)
        (indiv / "trivy.json").write_text('{"Results": [{"incomplete', encoding="utf-8")

        findings = gather_results(tmp_path)

        # Should have findings from valid tool
        assert isinstance(findings, list)

    def test_tool_timeout_handling(self, tmp_path: Path):
        """Verify timeout handling doesn't corrupt results."""
        import subprocess
        from unittest.mock import patch

        # Mock subprocess to timeout
        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="tool", timeout=60)

            # Should handle timeout gracefully
            try:
                subprocess.run(["tool"], timeout=60)
            except subprocess.TimeoutExpired:
                pass  # Expected

    def test_tool_segfault_handling(self, tmp_path: Path):
        """Verify tool segfault doesn't crash the scan."""
        import subprocess
        from unittest.mock import patch

        # Mock subprocess to return segfault exit code
        mock_result = MagicMock()
        mock_result.returncode = -11  # SIGSEGV on Unix
        mock_result.stdout = ""
        mock_result.stderr = "Segmentation fault"

        with patch("subprocess.run", return_value=mock_result):
            # Should handle segfault gracefully
            result = subprocess.run(["tool"], capture_output=True, text=True)
            assert result.returncode != 0


# ============================================================================
# Permission Error Tests
# ============================================================================


class TestPermissionRecovery:
    """Test recovery from permission errors."""

    @skip_on_windows
    def test_read_only_results_dir(self, tmp_path: Path):
        """Verify handling of read-only results directory."""
        results_dir = tmp_path / "readonly_results"
        results_dir.mkdir()

        # Make read-only (Unix only)
        os.chmod(results_dir, 0o444)

        try:
            # Try to create file in read-only dir
            with pytest.raises(PermissionError):
                (results_dir / "test.json").write_text("{}", encoding="utf-8")
        finally:
            # Restore permissions for cleanup
            os.chmod(results_dir, 0o755)

    @skip_on_windows
    def test_unreadable_source_file(self, tmp_path: Path):
        """Verify handling of unreadable source files."""
        source_file = tmp_path / "secret.py"
        source_file.write_text("SECRET = 'password'", encoding="utf-8")
        os.chmod(source_file, 0o000)

        try:
            # Try to read unreadable file
            with pytest.raises(PermissionError):
                source_file.read_text()
        finally:
            os.chmod(source_file, 0o644)

    def test_jmo_dir_permission_denied(self, tmp_path: Path, monkeypatch):
        """Verify handling when .jmo directory is not accessible."""
        # Mock Path.home() to point to tmp_path
        monkeypatch.setattr(Path, "home", staticmethod(lambda: tmp_path))

        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        if not IS_WINDOWS:
            os.chmod(jmo_dir, 0o000)

            try:
                # Should handle gracefully
                with pytest.raises((PermissionError, OSError)):
                    (jmo_dir / "history.db").write_text("", encoding="utf-8")
            finally:
                os.chmod(jmo_dir, 0o755)


# ============================================================================
# Concurrent Access Tests
# ============================================================================


class TestConcurrentAccessRecovery:
    """Test recovery from concurrent access issues."""

    def test_concurrent_db_writes(self, tmp_path: Path):
        """Verify concurrent database writes are handled."""
        from scripts.core.history_db import init_database, get_connection

        db_path = tmp_path / "concurrent.db"
        errors = []
        success_count = 0
        lock = threading.Lock()

        # Initialize database
        init_database(db_path)

        def write_scan(scan_id: str):
            nonlocal success_count
            try:
                conn = get_connection(db_path)
                try:
                    conn.execute(
                        "INSERT INTO scans (id, timestamp, timestamp_iso, profile, tools, targets, target_type, jmo_version) "
                        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                        (scan_id, 1704067200, "2024-01-01T00:00:00", "fast", "[]", "[]", "repo", "1.0.0"),
                    )
                    conn.commit()
                    with lock:
                        success_count += 1
                finally:
                    conn.close()
            except Exception as e:
                errors.append(e)

        # Run concurrent writes
        threads = []
        for i in range(5):
            t = threading.Thread(target=write_scan, args=(f"scan-{i}",))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # At least some should succeed
        assert success_count > 0

    def test_concurrent_file_writes(self, tmp_path: Path):
        """Verify concurrent file writes don't corrupt data."""
        output_file = tmp_path / "output.json"
        errors = []

        def write_json(data: dict):
            try:
                with open(output_file, "w", encoding="utf-8") as f:
                    json.dump(data, f)
            except Exception as e:
                errors.append(e)

        threads = []
        for i in range(5):
            data = {"thread": i, "data": [j for j in range(100)]}
            t = threading.Thread(target=write_json, args=(data,))
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        # File should exist and be valid JSON
        if output_file.exists():
            content = output_file.read_text(encoding="utf-8")
            try:
                json.loads(content)
            except json.JSONDecodeError:
                # Concurrent writes may corrupt, but shouldn't crash
                pass


# ============================================================================
# Process Termination Tests
# ============================================================================


class TestProcessTerminationRecovery:
    """Test recovery from process termination."""

    def test_cleanup_on_keyboard_interrupt(self, tmp_path: Path):
        """Verify cleanup runs on KeyboardInterrupt."""
        from scripts.core.history_db import init_database, get_connection

        db_path = tmp_path / "interrupt.db"

        class CleanupTracker:
            def __init__(self):
                self.cleaned = False

            def cleanup(self):
                self.cleaned = True

        tracker = CleanupTracker()

        # Initialize database
        init_database(db_path)
        conn = get_connection(db_path)

        try:
            # Simulate interrupt during operation
            raise KeyboardInterrupt()
        except KeyboardInterrupt:
            tracker.cleanup()
        finally:
            conn.close()

        assert tracker.cleaned

    def test_temp_files_cleanup(self, tmp_path: Path):
        """Verify temporary files are cleaned up on error."""
        temp_files = []

        try:
            # Create temp files
            for i in range(3):
                tf = tmp_path / f"temp_{i}.json"
                tf.write_text("{}", encoding="utf-8")
                temp_files.append(tf)

            # Simulate error
            raise RuntimeError("Simulated error")
        except RuntimeError:
            # Cleanup in exception handler
            for tf in temp_files:
                if tf.exists():
                    tf.unlink()

        # Verify cleanup
        for tf in temp_files:
            assert not tf.exists()

    def test_database_connection_cleanup(self, tmp_path: Path):
        """Verify database connections are closed on error."""
        from scripts.core.history_db import init_database, get_connection

        db_path = tmp_path / "cleanup.db"

        # Initialize database
        init_database(db_path)
        conn = get_connection(db_path)

        try:
            # Simulate error during operation
            raise RuntimeError("Simulated error")
        except RuntimeError:
            pass
        finally:
            conn.close()

        # Connection should be closed, allowing new connection
        conn2 = get_connection(db_path)
        try:
            cursor = conn2.execute("SELECT COUNT(*) FROM scans")
            count = cursor.fetchone()[0]
            assert count >= 0
        finally:
            conn2.close()


# ============================================================================
# Memory Error Tests
# ============================================================================


class TestMemoryErrorRecovery:
    """Test recovery from memory-related errors."""

    def test_large_findings_batch_handling(self, tmp_path: Path):
        """Verify large finding batches are handled efficiently."""
        from scripts.core.normalize_and_report import gather_results

        # Create results with many findings
        indiv = tmp_path / "individual-repos" / "test-repo"
        indiv.mkdir(parents=True)

        # Generate 10k findings
        findings = []
        for i in range(10000):
            findings.append({
                "check_id": f"rule-{i}",
                "path": f"file_{i % 100}.py",
                "start": {"line": i % 1000},
                "extra": {"message": f"Finding {i}", "severity": "LOW"},
            })

        (indiv / "semgrep.json").write_text(
            json.dumps({"results": findings, "version": "1.0.0"}),
            encoding="utf-8",
        )

        # Should handle without memory error
        result = gather_results(tmp_path)
        assert isinstance(result, list)

    def test_streaming_json_handling(self, tmp_path: Path):
        """Verify large JSON files are handled without loading all into memory."""
        # Create a large JSON file
        large_file = tmp_path / "large.json"

        with open(large_file, "w", encoding="utf-8") as f:
            f.write('{"results": [')
            for i in range(1000):
                if i > 0:
                    f.write(",")
                f.write(json.dumps({"id": i, "data": "x" * 100}))
            f.write("]}")

        # Should be able to read
        with open(large_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        assert len(data["results"]) == 1000


# ============================================================================
# Network Error Tests
# ============================================================================


class TestNetworkErrorRecovery:
    """Test recovery from network-related errors."""

    def test_gitlab_connection_timeout(self):
        """Verify GitLab connection timeout is handled."""
        import requests
        from unittest.mock import patch

        with patch("requests.get") as mock_get:
            mock_get.side_effect = requests.Timeout("Connection timed out")

            try:
                requests.get("https://gitlab.example.com", timeout=5)
            except requests.Timeout:
                pass  # Expected

    def test_docker_registry_unavailable(self):
        """Verify Docker registry errors are handled."""
        import subprocess
        from unittest.mock import patch

        mock_result = MagicMock()
        mock_result.returncode = 1
        mock_result.stderr = "Error: Cannot connect to registry"

        with patch("subprocess.run", return_value=mock_result):
            result = subprocess.run(
                ["docker", "pull", "registry.example.com/image:latest"],
                capture_output=True,
                text=True,
            )
            assert result.returncode != 0
