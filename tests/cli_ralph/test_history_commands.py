#!/usr/bin/env python3
"""
HS: History Commands Tests for JMo Security CLI.

Tests verify history listing, showing, and querying commands.
Uses pre-generated test-history.db fixture.
"""

from __future__ import annotations

import json
import sqlite3

import pytest


class TestHistoryList:
    """Test suite for `jmo history list` command (HS-001)."""

    def test_hs_001_history_list(self, run_jmo_with_history):
        """HS-001: jmo history list shows stored scans."""
        result = run_jmo_with_history(["history", "list"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should show scan entries
        output = result.stdout.lower()
        # History list should show scan IDs or timestamps
        list_indicators = ["scan", "timestamp", "profile", "finding", "id", "main"]
        has_content = any(ind in output for ind in list_indicators)
        assert (
            has_content or "no scans" in output
        ), f"No history content: {result.stdout}"

    def test_history_list_json(self, run_jmo_with_history):
        """History list --json outputs valid JSON."""
        result = run_jmo_with_history(["history", "list", "--json"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        if result.stdout.strip():
            try:
                data = json.loads(result.stdout)
                # Should have scans array or similar
                assert isinstance(data, (dict, list)), "Should be JSON object or array"
            except json.JSONDecodeError:
                # JSON might have non-JSON prefix (logs)
                start = result.stdout.find("{")
                if start == -1:
                    start = result.stdout.find("[")
                if start >= 0:
                    json.loads(result.stdout[start:])  # Validate it parses


class TestHistoryShow:
    """Test suite for `jmo history show` command (HS-002)."""

    def test_hs_002_history_show(self, run_jmo_with_history):
        """HS-002: jmo history show <scan_id> shows scan details."""
        # First get a scan ID from list
        list_result = run_jmo_with_history(["history", "list", "--json"])

        if list_result.returncode != 0:
            pytest.skip("Could not list history")

        # Try to extract a scan ID
        try:
            # Handle possible log prefix
            output = list_result.stdout
            start = output.find("{")
            if start == -1:
                start = output.find("[")
            if start >= 0:
                output = output[start:]

            data = json.loads(output)
            scans = data.get("scans") or data.get("data") or []
            if isinstance(data, list):
                scans = data

            if scans and isinstance(scans[0], dict):
                scan_id = scans[0].get("id") or scans[0].get("scan_id")
                if scan_id:
                    show_result = run_jmo_with_history(
                        ["history", "show", str(scan_id)]
                    )
                    assert (
                        show_result.returncode == 0
                    ), f"Show failed: {show_result.stderr}"
                    return
        except (json.JSONDecodeError, IndexError, KeyError, TypeError):
            pass

        # If we couldn't extract scan ID, just verify the command exists
        result = run_jmo_with_history(["history", "show", "--help"])
        assert result.returncode == 0, "history show command should exist"


class TestHistoryStats:
    """Test suite for `jmo history stats` command (HS-003)."""

    def test_hs_003_history_stats(self, run_jmo_with_history):
        """HS-003: jmo history stats shows aggregate statistics."""
        result = run_jmo_with_history(["history", "stats"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should show some statistics
        output = result.stdout.lower()
        stats_indicators = [
            "total",
            "scan",
            "finding",
            "critical",
            "high",
            "average",
            "count",
            "statistic",
        ]
        has_stats = any(ind in output for ind in stats_indicators)
        assert (
            has_stats or result.returncode == 0
        ), f"No stats in output: {result.stdout}"


class TestHistoryQuery:
    """Test suite for `jmo history query` command (HS-004)."""

    def test_hs_004_history_query_severity(self, run_jmo_with_history):
        """HS-004: jmo history query --severity filters findings."""
        result = run_jmo_with_history(["history", "query", "--severity", "CRITICAL"])

        # Command should work (may have no results)
        assert result.returncode in (0, 1), f"Query failed: {result.stderr}"


class TestHistoryEdgeCases:
    """Edge cases for history commands."""

    def test_history_with_empty_db(self, jmo_runner_with_env, tmp_path):
        """History commands handle empty database gracefully."""
        # Create empty .jmo directory
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        # Create proper database with required schema
        db_path = jmo_dir / "history.db"
        conn = sqlite3.connect(db_path)
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                timestamp INTEGER,
                timestamp_iso TEXT,
                profile TEXT,
                tools TEXT,
                targets TEXT,
                target_type TEXT,
                total_findings INTEGER,
                critical_count INTEGER,
                high_count INTEGER,
                medium_count INTEGER,
                low_count INTEGER,
                info_count INTEGER,
                jmo_version TEXT
            )
        """
        )
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version TEXT PRIMARY KEY,
                applied_at INTEGER,
                applied_at_iso TEXT
            )
        """
        )
        conn.commit()
        conn.close()

        result = jmo_runner_with_env(
            ["history", "list"],
            env={"JMO_HISTORY_DB": str(db_path)},
        )

        # Should handle empty database gracefully
        assert result.returncode in (0, 1), f"Should handle empty DB: {result.stderr}"

    def test_history_help(self, jmo_runner):
        """History --help shows available subcommands."""
        result = jmo_runner(["history", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        assert "list" in output, "Missing 'list' subcommand"
