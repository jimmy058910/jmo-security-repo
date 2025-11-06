#!/usr/bin/env python3
"""
Tests for wizard trend analysis integration (Phase 7).

Tests the interactive and non-interactive trend analysis features
added to the wizard in v1.0.0.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from unittest import mock

import pytest


@pytest.fixture
def mock_db(tmp_path):
    """Create a mock SQLite history database with test data."""
    db_path = tmp_path / "history.db"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()

    # Create scans table
    cursor.execute("""
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            timestamp_iso TEXT,
            profile TEXT,
            branch TEXT,
            total_findings INTEGER
        )
    """)

    # Create findings table
    cursor.execute("""
        CREATE TABLE findings (
            id INTEGER PRIMARY KEY,
            scan_id TEXT,
            fingerprint TEXT,
            severity TEXT,
            tool TEXT,
            rule_id TEXT,
            path TEXT,
            start_line INTEGER,
            end_line INTEGER,
            message TEXT,
            raw_finding TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )
    """)

    # Insert test scans
    test_scans = [
        ("scan1", "2025-11-01T10:00:00", "balanced", "main", 10),
        ("scan2", "2025-11-02T10:00:00", "balanced", "main", 8),
        ("scan3", "2025-11-03T10:00:00", "balanced", "main", 5),
    ]

    cursor.executemany(
        "INSERT INTO scans VALUES (?, ?, ?, ?, ?)", test_scans
    )

    # Insert test findings
    test_findings = [
        ("scan1", "fp1", "HIGH", "semgrep", "rule1", "src/main.py", 10, 15, "Test finding 1", "{}"),
        ("scan1", "fp2", "MEDIUM", "trivy", "rule2", "src/app.py", 20, 25, "Test finding 2", "{}"),
        ("scan2", "fp2", "MEDIUM", "trivy", "rule2", "src/app.py", 20, 25, "Test finding 2", "{}"),
        ("scan2", "fp3", "LOW", "bandit", "rule3", "src/util.py", 30, 35, "Test finding 3", "{}"),
        ("scan3", "fp3", "LOW", "bandit", "rule3", "src/util.py", 30, 35, "Test finding 3", "{}"),
    ]

    cursor.executemany(
        "INSERT INTO findings (scan_id, fingerprint, severity, tool, rule_id, path, start_line, end_line, message, raw_finding) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        test_findings,
    )

    conn.commit()
    conn.close()

    return db_path


# ============================================================================
# Test: offer_trend_analysis_after_scan()
# ============================================================================


def test_offer_trend_analysis_no_db(tmp_path, monkeypatch):
    """Test offer when no history database exists."""
    from scripts.cli.wizard import offer_trend_analysis_after_scan

    # Set HOME to tmp_path so .jmo/history.db doesn't exist
    monkeypatch.setenv("HOME", str(tmp_path))

    # Should not raise, just return silently
    offer_trend_analysis_after_scan("results")


def test_offer_trend_analysis_insufficient_scans(tmp_path, monkeypatch):
    """Test offer when < 2 scans in history."""
    from scripts.cli.wizard import offer_trend_analysis_after_scan

    # Create DB with only 1 scan
    db_path = tmp_path / ".jmo" / "history.db"
    db_path.parent.mkdir(parents=True)

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE scans (id TEXT PRIMARY KEY)")
    cursor.execute("INSERT INTO scans VALUES ('scan1')")
    conn.commit()
    conn.close()

    monkeypatch.setenv("HOME", str(tmp_path))

    # Should not prompt (returns silently)
    offer_trend_analysis_after_scan("results")


def test_offer_trend_analysis_with_scans(tmp_path, mock_db, monkeypatch):
    """Test offer when ≥2 scans exist (user declines)."""
    from scripts.cli.wizard import offer_trend_analysis_after_scan

    # Move mock DB to expected location
    db_dir = tmp_path / ".jmo"
    db_dir.mkdir(parents=True)
    target_db = db_dir / "history.db"
    import shutil
    shutil.copy(mock_db, target_db)

    monkeypatch.setenv("HOME", str(tmp_path))

    # Mock user declining prompt AND explore_trends_interactive
    with mock.patch("builtins.input", return_value="n"):
        with mock.patch("scripts.cli.wizard.explore_trends_interactive") as mock_explore:
            offer_trend_analysis_after_scan("results")
            # Verify it didn't call explore (user declined)
            assert not mock_explore.called


def test_offer_trend_analysis_exception_handling(tmp_path, monkeypatch):
    """Test offer handles exceptions gracefully."""
    from scripts.cli.wizard import offer_trend_analysis_after_scan

    # Create invalid DB (missing table)
    db_path = tmp_path / ".jmo" / "history.db"
    db_path.parent.mkdir(parents=True)
    conn = sqlite3.connect(db_path)
    conn.close()

    monkeypatch.setenv("HOME", str(tmp_path))

    # Should not raise, just log debug message
    offer_trend_analysis_after_scan("results")


# ============================================================================
# Test: explore_trends_interactive()
# ============================================================================


def test_explore_trends_menu_exit_immediately(tmp_path, mock_db):
    """Test exploring trends menu and immediately exiting."""
    from scripts.cli.wizard import explore_trends_interactive

    # Mock user selecting "9" (Back)
    with mock.patch("builtins.input", return_value="9"):
        explore_trends_interactive(mock_db, "results")


def test_explore_trends_menu_option_1(tmp_path, mock_db, capsys):
    """Test menu option 1: Overall security trend."""
    from scripts.cli.wizard import explore_trends_interactive

    # Mock user selecting "1" then "9" (exit)
    inputs_with_enter = ["1", "", "9"]  # Add empty string for Enter press

    with mock.patch("builtins.input", side_effect=inputs_with_enter):
        # Mock the _run_trend_command_interactive function
        with mock.patch("scripts.cli.wizard._run_trend_command_interactive") as mock_run:
            explore_trends_interactive(mock_db, "results")
            # Verify it was called with correct params
            assert mock_run.called


def test_explore_trends_menu_option_8(tmp_path, mock_db, capsys):
    """Test menu option 8: Explain metrics."""
    from scripts.cli.wizard import explore_trends_interactive

    # Mock user selecting "8" then "9" (exit)
    inputs = ["8", "", "9"]  # Enter to continue after explanation

    with mock.patch("builtins.input", side_effect=inputs):
        explore_trends_interactive(mock_db, "results")

    captured = capsys.readouterr()
    assert "Trend Analysis Metrics Explained" in captured.out
    assert "OVERALL SECURITY TREND" in captured.out
    assert "Mann-Kendall" in captured.out


# ============================================================================
# Test: _run_trend_command_interactive()
# ============================================================================


def test_run_trend_command_analyze(tmp_path, mock_db):
    """Test running trend analyze command."""
    import sys
    from scripts.cli.wizard import _run_trend_command_interactive

    # Mock the trend_commands module as if it was imported
    fake_trend_commands = mock.MagicMock()
    fake_trend_commands.cmd_trends_analyze = mock.MagicMock(return_value=0)

    with mock.patch.dict("sys.modules", {"scripts.cli.trend_commands": fake_trend_commands}):
        with mock.patch("builtins.input", return_value=""):  # Enter to continue
            with mock.patch("builtins.print"):  # Suppress output
                _run_trend_command_interactive(mock_db, "analyze", last_n=30)

    # Verify command was called
    assert fake_trend_commands.cmd_trends_analyze.called


def test_run_trend_command_unknown(tmp_path, mock_db):
    """Test running unknown trend command."""
    from scripts.cli.wizard import _run_trend_command_interactive

    with mock.patch("builtins.input", return_value=""):  # Enter to continue
        # Mock print to suppress output
        with mock.patch("builtins.print"):
            _run_trend_command_interactive(mock_db, "unknown", last_n=30)


def test_run_trend_command_import_error(tmp_path, mock_db):
    """Test handling import errors gracefully."""
    from scripts.cli.wizard import _run_trend_command_interactive

    with mock.patch("builtins.input", return_value=""):  # Enter to continue
        # Mock the import to raise ImportError
        with mock.patch.dict("sys.modules", {"scripts.cli.trend_commands": None}):
            with mock.patch("builtins.print"):  # Suppress output
                _run_trend_command_interactive(mock_db, "analyze", last_n=30)


# ============================================================================
# Test: _compare_scans_interactive()
# ============================================================================


def test_compare_scans_insufficient_scans(tmp_path):
    """Test comparison with < 2 scans."""
    from scripts.cli.wizard import _compare_scans_interactive

    # Create DB with 1 scan
    db_path = tmp_path / "history.db"
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE scans (id TEXT PRIMARY KEY)")
    cursor.execute("INSERT INTO scans VALUES ('scan1')")
    conn.commit()
    conn.close()

    with mock.patch("builtins.input", return_value=""):  # Enter to continue
        with mock.patch("builtins.print"):  # Suppress output
            _compare_scans_interactive(db_path)


def test_compare_scans_success(tmp_path, mock_db):
    """Test successful scan comparison."""
    from scripts.cli.wizard import _compare_scans_interactive

    # Mock user selecting scans 1 and 2, then Enter to continue
    inputs = ["1", "2", ""]

    with mock.patch("builtins.input", side_effect=inputs):
        with mock.patch("scripts.cli.trend_commands.cmd_trends_compare", return_value=0):
            with mock.patch("builtins.print"):  # Suppress output
                _compare_scans_interactive(mock_db)


def test_compare_scans_invalid_selection(tmp_path, mock_db):
    """Test handling invalid scan selection."""
    from scripts.cli.wizard import _compare_scans_interactive

    # Mock invalid input, then valid inputs
    inputs = ["999", "1", "abc", "2", ""]

    with mock.patch("builtins.input", side_effect=inputs):
        with mock.patch("scripts.cli.trend_commands.cmd_trends_compare", return_value=0):
            with mock.patch("builtins.print"):  # Suppress output
                _compare_scans_interactive(mock_db)


def test_compare_scans_same_scan(tmp_path, mock_db):
    """Test handling selection of same scan twice."""
    from scripts.cli.wizard import _compare_scans_interactive

    # Mock selecting same scan twice, then correct selection
    inputs = ["1", "1", "2", ""]

    with mock.patch("builtins.input", side_effect=inputs):
        with mock.patch("scripts.cli.trend_commands.cmd_trends_compare", return_value=0):
            with mock.patch("builtins.print"):  # Suppress output
                _compare_scans_interactive(mock_db)


# ============================================================================
# Test: _export_trends_interactive()
# ============================================================================


def test_export_trends_html(tmp_path, mock_db, monkeypatch):
    """Test exporting trend report as HTML."""
    from scripts.cli.wizard import _export_trends_interactive

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Mock user selecting HTML, 30 days, no browser open
    inputs = ["html", "2", "n", ""]  # Enter at end for continue

    with mock.patch("builtins.input", side_effect=inputs):
        with mock.patch("scripts.core.trend_analyzer.TrendAnalyzer.analyze_trends") as mock_analyze:
            with mock.patch("scripts.cli.trend_formatters.format_html_report") as mock_format:
                with mock.patch("builtins.print"):  # Suppress output
                    mock_analyze.return_value = {}
                    mock_format.return_value = "<html>Test Report</html>"

                    _export_trends_interactive(mock_db, str(results_dir))

    # Verify HTML file was created
    output_file = results_dir / "summaries" / "trend_report.html"
    assert output_file.exists()
    assert "Test Report" in output_file.read_text()


def test_export_trends_json(tmp_path, mock_db):
    """Test exporting trend report as JSON."""
    from scripts.cli.wizard import _export_trends_interactive

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Mock user selecting JSON, all time
    inputs = ["json", "4", ""]

    with mock.patch("builtins.input", side_effect=inputs):
        with mock.patch("scripts.core.trend_analyzer.TrendAnalyzer.analyze_trends") as mock_analyze:
            with mock.patch("scripts.cli.trend_formatters.format_json_report") as mock_format:
                with mock.patch("builtins.print"):  # Suppress output
                    mock_analyze.return_value = {}
                    mock_format.return_value = '{"test": "report"}'

                    _export_trends_interactive(mock_db, str(results_dir))

    # Verify JSON file was created
    output_file = results_dir / "summaries" / "trend_report.json"
    assert output_file.exists()
    assert "test" in output_file.read_text()


def test_export_trends_html_with_browser(tmp_path, mock_db):
    """Test exporting HTML and opening in browser."""
    from scripts.cli.wizard import _export_trends_interactive

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Mock user selecting HTML, 7 days, yes to browser
    inputs = ["html", "1", "y", ""]  # Enter at end for continue

    with mock.patch("builtins.input", side_effect=inputs):
        with mock.patch("scripts.core.trend_analyzer.TrendAnalyzer.analyze_trends") as mock_analyze:
            with mock.patch("scripts.cli.trend_formatters.format_html_report") as mock_format:
                with mock.patch("webbrowser.open") as mock_browser:
                    with mock.patch("builtins.print"):  # Suppress output
                        mock_analyze.return_value = {}
                        mock_format.return_value = "<html>Test</html>"

                        _export_trends_interactive(mock_db, str(results_dir))

                        # Verify browser was opened
                        assert mock_browser.called


# ============================================================================
# Test: _explain_metrics_interactive()
# ============================================================================


def test_explain_metrics(capsys):
    """Test metrics explanation display."""
    from scripts.cli.wizard import _explain_metrics_interactive

    with mock.patch("builtins.input", return_value=""):  # Enter to continue
        _explain_metrics_interactive()

    captured = capsys.readouterr()
    assert "OVERALL SECURITY TREND" in captured.out
    assert "REGRESSIONS" in captured.out
    assert "REMEDIATION VELOCITY" in captured.out
    assert "TOP REMEDIATORS" in captured.out
    assert "SECURITY SCORE" in captured.out
    assert "Mann-Kendall" in captured.out


# ============================================================================
# Test: Non-interactive wizard trend flags
# ============================================================================


def test_wizard_analyze_trends_flag(tmp_path, mock_db, monkeypatch):
    """Test --analyze-trends flag in non-interactive mode."""
    from scripts.cli.wizard import run_wizard

    # Move mock DB to expected location
    db_dir = tmp_path / ".jmo"
    db_dir.mkdir(parents=True)
    target_db = db_dir / "history.db"
    import shutil
    shutil.copy(mock_db, target_db)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    # Create dummy repo directory
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    # Create results dir
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Mock execute_scan and trend command
    # Need to mock get_connection to return scan count ≥ 2
    mock_conn = mock.MagicMock()
    mock_cursor = mock.MagicMock()
    mock_cursor.fetchone.return_value = (3,)  # 3 scans in history
    mock_conn.execute.return_value = mock_cursor

    with mock.patch("scripts.cli.wizard.execute_scan", return_value=0):
        with mock.patch("scripts.core.history_db.get_connection", return_value=mock_conn):
            with mock.patch("scripts.cli.wizard._run_trend_command_interactive") as mock_run:
                with mock.patch("builtins.print"):  # Suppress output
                    result = run_wizard(
                        yes=True,
                        analyze_trends=True,
                    )

    assert result == 0
    assert mock_run.called


def test_wizard_export_trends_html_flag(tmp_path, mock_db, monkeypatch):
    """Test --export-trends-html flag."""
    from scripts.cli.wizard import run_wizard

    # Move mock DB to expected location
    db_dir = tmp_path / ".jmo"
    db_dir.mkdir(parents=True)
    target_db = db_dir / "history.db"
    import shutil
    shutil.copy(mock_db, target_db)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    # Create dummy repo
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    # Create results dir
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Mock get_connection to return scan count ≥ 2
    mock_conn = mock.MagicMock()
    mock_cursor = mock.MagicMock()
    mock_cursor.fetchone.return_value = (3,)  # 3 scans
    mock_conn.execute.return_value = mock_cursor

    with mock.patch("scripts.cli.wizard.execute_scan", return_value=0):
        with mock.patch("scripts.core.history_db.get_connection", return_value=mock_conn):
            with mock.patch("scripts.core.trend_analyzer.TrendAnalyzer.analyze_trends") as mock_analyze:
                with mock.patch("scripts.cli.trend_formatters.format_html_report") as mock_format:
                    with mock.patch("builtins.print"):  # Suppress output
                        mock_analyze.return_value = {}
                        mock_format.return_value = "<html>Test</html>"

                        result = run_wizard(
                            yes=True,
                            export_trends_html=True,
                        )

    assert result == 0
    output_file = results_dir / "summaries" / "trend_report.html"
    assert output_file.exists()


def test_wizard_export_trends_json_flag(tmp_path, mock_db, monkeypatch):
    """Test --export-trends-json flag."""
    from scripts.cli.wizard import run_wizard

    # Move mock DB to expected location
    db_dir = tmp_path / ".jmo"
    db_dir.mkdir(parents=True)
    target_db = db_dir / "history.db"
    import shutil
    shutil.copy(mock_db, target_db)

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    # Create dummy repo
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    # Create results dir
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Mock get_connection to return scan count ≥ 2
    mock_conn = mock.MagicMock()
    mock_cursor = mock.MagicMock()
    mock_cursor.fetchone.return_value = (3,)  # 3 scans
    mock_conn.execute.return_value = mock_cursor

    with mock.patch("scripts.cli.wizard.execute_scan", return_value=0):
        with mock.patch("scripts.core.history_db.get_connection", return_value=mock_conn):
            with mock.patch("scripts.core.trend_analyzer.TrendAnalyzer.analyze_trends") as mock_analyze:
                with mock.patch("scripts.cli.trend_formatters.format_json_report") as mock_format:
                    with mock.patch("builtins.print"):  # Suppress output
                        mock_analyze.return_value = {}
                        mock_format.return_value = '{"test": "report"}'

                        result = run_wizard(
                            yes=True,
                            export_trends_json=True,
                        )

    assert result == 0
    output_file = results_dir / "summaries" / "trend_report.json"
    assert output_file.exists()


def test_wizard_no_db_with_trend_flags(tmp_path, monkeypatch, capsys):
    """Test trend flags when no history database exists."""
    from scripts.cli.wizard import run_wizard

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    # Create dummy repo
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    with mock.patch("scripts.cli.wizard.execute_scan", return_value=0):
        result = run_wizard(
            yes=True,
            analyze_trends=True,
        )

    assert result == 0
    captured = capsys.readouterr()
    assert "No history database found" in captured.out


def test_wizard_insufficient_scans_with_trend_flags(tmp_path, monkeypatch):
    """Test trend flags when < 2 scans in history."""
    from scripts.cli.wizard import run_wizard

    # Create DB with 1 scan
    db_dir = tmp_path / ".jmo"
    db_dir.mkdir(parents=True)
    db_path = db_dir / "history.db"

    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    cursor.execute("CREATE TABLE scans (id TEXT PRIMARY KEY)")
    cursor.execute("INSERT INTO scans VALUES ('scan1')")
    conn.commit()
    conn.close()

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)

    # Create dummy repo
    repo_dir = tmp_path / "test_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    with mock.patch("scripts.cli.wizard.execute_scan", return_value=0):
        with mock.patch("builtins.print"):  # Suppress output
            result = run_wizard(
                yes=True,
                analyze_trends=True,
            )

    assert result == 0
