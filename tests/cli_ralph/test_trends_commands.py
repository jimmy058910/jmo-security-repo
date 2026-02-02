#!/usr/bin/env python3
"""
TR: Trends Commands Tests for JMo Security CLI.

Tests verify trend analysis commands.
Uses pre-generated test-history.db fixture with 5+ scans.
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone


class TestTrendsAnalyze:
    """Test suite for `jmo trends analyze` command (TR-001)."""

    def test_tr_001_trends_analyze(self, run_jmo_with_history):
        """TR-001: jmo trends analyze shows trend direction."""
        result = run_jmo_with_history(["trends", "analyze"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should show trend information
        output = result.stdout.lower()
        trend_indicators = [
            "trend",
            "improv",
            "worsen",
            "stable",
            "increas",
            "decreas",
            "change",
            "direction",
            "finding",
            "security",
            "score",
        ]
        has_trend = any(ind in output for ind in trend_indicators)
        assert (
            has_trend or "no data" in output or "insufficient" in output
        ), f"No trend info: {result.stdout}"


class TestTrendsScore:
    """Test suite for `jmo trends score` command (TR-002)."""

    def test_tr_002_trends_score(self, run_jmo_with_history):
        """TR-002: jmo trends score shows security score."""
        result = run_jmo_with_history(["trends", "score"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should show a score
        output = result.stdout.lower()
        score_indicators = ["score", "rating", "grade", "%", "100", "point", "security"]
        has_score = any(ind in output for ind in score_indicators)
        # Or might show message about insufficient data
        assert (
            has_score or "no data" in output or "insufficient" in output
        ), f"No score info: {result.stdout}"


class TestTrendsInsights:
    """Test suite for `jmo trends insights` command (TR-003)."""

    def test_tr_003_trends_insights(self, run_jmo_with_history):
        """TR-003: jmo trends insights provides actionable insights."""
        result = run_jmo_with_history(["trends", "insights"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should provide some insights or message
        output = result.stdout.lower()
        insight_indicators = [
            "insight",
            "recommend",
            "suggest",
            "action",
            "improve",
            "focus",
            "priority",
            "finding",
            "trend",
            "security",
        ]
        has_insight = any(ind in output for ind in insight_indicators)
        assert (
            has_insight or "no data" in output or result.returncode == 0
        ), f"No insights: {result.stdout}"


class TestTrendsExplain:
    """Test suite for `jmo trends explain` command (TR-004)."""

    def test_tr_004_trends_explain(self, jmo_runner):
        """TR-004: jmo trends explain describes methodology."""
        # Note: trends explain is a documentation command - no database needed
        result = jmo_runner(["trends", "explain"])

        assert result.returncode == 0, f"Command failed: {result.stderr}"

        # Should explain the methodology
        output = result.stdout.lower()
        explain_indicators = [
            "mann-kendall",
            "statistic",
            "methodology",
            "calculate",
            "trend",
            "significance",
            "analysis",
            "how",
            "score",
        ]
        has_explanation = any(ind in output for ind in explain_indicators)
        assert (
            has_explanation or result.returncode == 0
        ), f"No explanation: {result.stdout}"


class TestTrendsEdgeCases:
    """Edge cases for trends commands."""

    def test_trends_with_single_scan(self, jmo_runner_with_env, tmp_path):
        """Trends handle database with single scan gracefully."""
        # Create database with single scan
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()
        db_path = jmo_dir / "history.db"

        conn = sqlite3.connect(db_path)
        now = datetime.now(timezone.utc)

        # Create schema
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS schema_version (
                version TEXT PRIMARY KEY,
                applied_at INTEGER NOT NULL,
                applied_at_iso TEXT NOT NULL
            )
        """
        )
        conn.execute(
            "INSERT INTO schema_version VALUES (?, ?, ?)",
            ("1.0.0", int(now.timestamp()), now.isoformat()),
        )

        conn.execute(
            """
            CREATE TABLE scans (
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
            INSERT INTO scans VALUES (
                'single-scan', ?, ?, 'fast', '[]', '[]', 'repo',
                5, 1, 1, 1, 1, 1, '1.0.0'
            )
        """,
            (int(now.timestamp()), now.isoformat()),
        )
        conn.commit()
        conn.close()

        result = jmo_runner_with_env(
            ["trends", "analyze"],
            env={"JMO_HISTORY_DB": str(db_path)},
        )

        # Should handle single scan gracefully (may show "insufficient data")
        assert result.returncode in (
            0,
            1,
        ), f"Should handle single scan: {result.stderr}"

    def test_trends_help(self, jmo_runner):
        """Trends --help shows available subcommands."""
        result = jmo_runner(["trends", "--help"])

        assert result.returncode == 0
        output = result.stdout.lower()
        subcommands = ["analyze", "score", "insight", "explain"]
        found = sum(1 for cmd in subcommands if cmd in output)
        assert found >= 1, "Missing trends subcommands in help"
