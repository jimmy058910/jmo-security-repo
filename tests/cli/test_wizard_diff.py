#!/usr/bin/env python3
"""
Tests for the diff wizard functionality in scripts/cli/wizard.py.

Tests cover:
- Directory comparison mode
- History database mode
- Interactive input handling
- Error handling (missing directories, invalid inputs)
- KeyboardInterrupt handling
- Output format selection (json, md, html, sarif)

Architecture Note:
- Uses fixtures for mock directories with findings
- Mocks Path.home() for cross-platform database location
- Mocks builtins.input for interactive prompts
- Mocks cmd_diff for command execution
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch

import pytest


class TestRunDiffWizardDirectoryMode:
    """Test cases for run_diff_wizard in directory comparison mode."""

    @pytest.fixture
    def mock_results_dirs(self, tmp_path):
        """Create mock results directories with aggregated findings."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        # Create mock aggregated_findings.json files
        baseline_findings = {
            "findings": [
                {
                    "id": "finding-1",
                    "ruleId": "CWE-79",
                    "severity": "HIGH",
                    "message": "XSS vulnerability",
                }
            ]
        }
        current_findings = {
            "findings": [
                {
                    "id": "finding-1",
                    "ruleId": "CWE-79",
                    "severity": "HIGH",
                    "message": "XSS vulnerability",
                },
                {
                    "id": "finding-2",
                    "ruleId": "CWE-89",
                    "severity": "CRITICAL",
                    "message": "SQL injection",
                },
            ]
        }

        (baseline / "aggregated_findings.json").write_text(
            json.dumps(baseline_findings)
        )
        (current / "aggregated_findings.json").write_text(json.dumps(current_findings))

        return baseline, current

    def test_diff_wizard_directory_mode_basic(self, mock_results_dirs, tmp_path):
        """Test diff wizard with valid directories in directory mode."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = mock_results_dirs

        # Mock inputs: directory mode, baseline path, current path,
        # severity filter (all), category filter (all), format (md), output file (default), confirm
        inputs = [
            "2",  # Directory comparison mode
            str(baseline),  # Baseline directory
            str(current),  # Current directory
            "1",  # All severities
            "1",  # All categories
            "2",  # Markdown format
            "",  # Default output file
            "y",  # Confirm execution
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff", return_value=0
            ) as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 0
        assert mock_cmd_diff.called

    def test_diff_wizard_directory_mode_missing_baseline(self, tmp_path):
        """Test diff wizard with missing baseline directory."""
        from scripts.cli.wizard import run_diff_wizard

        current = tmp_path / "current"
        current.mkdir()

        # Mock inputs: directory mode, non-existent baseline
        inputs = [
            "2",  # Directory comparison mode
            str(tmp_path / "nonexistent"),  # Non-existent baseline
        ]

        with patch("builtins.input", side_effect=inputs):
            result = run_diff_wizard()

        assert result == 1  # Error exit code

    def test_diff_wizard_directory_mode_missing_current(
        self, mock_results_dirs, tmp_path
    ):
        """Test diff wizard with missing current directory."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, _ = mock_results_dirs

        # Mock inputs: directory mode, valid baseline, non-existent current
        inputs = [
            "2",  # Directory comparison mode
            str(baseline),  # Valid baseline
            str(tmp_path / "nonexistent"),  # Non-existent current
        ]

        with patch("builtins.input", side_effect=inputs):
            result = run_diff_wizard()

        assert result == 1  # Error exit code

    def test_diff_wizard_directory_mode_json_format(self, mock_results_dirs):
        """Test diff wizard with JSON output format."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = mock_results_dirs

        inputs = [
            "2",  # Directory comparison mode
            str(baseline),
            str(current),
            "1",  # All severities
            "1",  # All categories
            "1",  # JSON format
            "",  # Default output file
            "y",  # Confirm
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff", return_value=0
            ) as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 0
        # Verify JSON format was selected
        args = mock_cmd_diff.call_args[0][0]
        assert args.format == "json"

    def test_diff_wizard_directory_mode_severity_filter(self, mock_results_dirs):
        """Test diff wizard with severity filter (CRITICAL only)."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = mock_results_dirs

        inputs = [
            "2",  # Directory mode
            str(baseline),
            str(current),
            "2",  # CRITICAL only
            "1",  # All categories
            "2",  # Markdown
            "",
            "y",
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff", return_value=0
            ) as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 0
        args = mock_cmd_diff.call_args[0][0]
        assert args.severity == "CRITICAL"

    def test_diff_wizard_directory_mode_category_filter_new_only(
        self, mock_results_dirs
    ):
        """Test diff wizard filtering for new findings only."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = mock_results_dirs

        inputs = [
            "2",  # Directory mode
            str(baseline),
            str(current),
            "1",  # All severities
            "2",  # New findings only
            "2",  # Markdown
            "",
            "y",
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff", return_value=0
            ) as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 0
        args = mock_cmd_diff.call_args[0][0]
        assert args.only == "new"

    def test_diff_wizard_user_cancels(self, mock_results_dirs):
        """Test diff wizard when user cancels at confirmation."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = mock_results_dirs

        inputs = [
            "2",  # Directory mode
            str(baseline),
            str(current),
            "1",  # All severities
            "1",  # All categories
            "2",  # Markdown
            "",
            "n",  # Cancel at confirmation
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch("scripts.cli.diff_commands.cmd_diff") as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 0  # Cancelled, not error
        assert not mock_cmd_diff.called


class TestRunDiffWizardHistoryMode:
    """Test cases for run_diff_wizard in history database mode."""

    @pytest.fixture
    def mock_history_db(self, tmp_path):
        """Create mock history database with test scans."""
        import sqlite3

        db_path = tmp_path / ".jmo" / "history.db"
        db_path.parent.mkdir(parents=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create scans table matching the real schema
        cursor.execute("""
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                timestamp_iso TEXT NOT NULL,
                profile TEXT NOT NULL,
                branch TEXT,
                total_findings INTEGER,
                tools TEXT NOT NULL,
                targets TEXT NOT NULL,
                target_type TEXT NOT NULL
            )
        """)

        # Insert test scans with all required fields
        test_scans = [
            (
                "scan-001-abc",
                1730455200,  # 2025-11-01 10:00:00 UTC
                "2025-11-01T10:00:00",
                "balanced",
                "main",
                10,
                "semgrep,trivy",
                "/repo",
                "repo",
            ),
            (
                "scan-002-def",
                1730541600,  # 2025-11-02 10:00:00 UTC
                "2025-11-02T10:00:00",
                "balanced",
                "main",
                8,
                "semgrep,trivy",
                "/repo",
                "repo",
            ),
            (
                "scan-003-ghi",
                1730628000,  # 2025-11-03 10:00:00 UTC
                "2025-11-03T10:00:00",
                "balanced",
                "feature-x",
                12,
                "semgrep,trivy",
                "/repo",
                "repo",
            ),
        ]
        cursor.executemany(
            """INSERT INTO scans
            (id, timestamp, timestamp_iso, profile, branch, total_findings, tools, targets, target_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            test_scans,
        )

        conn.commit()
        conn.close()

        return tmp_path

    def test_diff_wizard_history_mode_basic(self, mock_history_db):
        """Test diff wizard with history database mode."""
        from scripts.cli.wizard import run_diff_wizard

        # Mock inputs: history mode, select scan 1 as baseline, scan 2 as current
        inputs = [
            "1",  # History mode
            "1",  # Select scan 1 as baseline
            "2",  # Select scan 2 as current
            "1",  # All severities
            "1",  # All categories
            "2",  # Markdown format
            "",  # Default output file
            "y",  # Confirm
        ]

        with patch("pathlib.Path.home", return_value=mock_history_db):
            with patch("builtins.input", side_effect=inputs):
                with patch(
                    "scripts.cli.diff_commands.cmd_diff", return_value=0
                ) as mock_cmd_diff:
                    result = run_diff_wizard()

        assert result == 0
        assert mock_cmd_diff.called
        args = mock_cmd_diff.call_args[0][0]
        assert args.scan_ids is not None
        assert len(args.scan_ids) == 2

    def test_diff_wizard_history_mode_no_database(self, tmp_path):
        """Test diff wizard when history database doesn't exist."""
        from scripts.cli.wizard import run_diff_wizard

        inputs = [
            "1",  # History mode (will fail because no DB)
        ]

        with patch("pathlib.Path.home", return_value=tmp_path):
            with patch("builtins.input", side_effect=inputs):
                result = run_diff_wizard()

        assert result == 1  # Error exit code

    def test_diff_wizard_history_mode_insufficient_scans(self, tmp_path):
        """Test diff wizard when < 2 scans in history."""
        from scripts.cli.wizard import run_diff_wizard

        import sqlite3

        # Create DB with only 1 scan
        db_path = tmp_path / ".jmo" / "history.db"
        db_path.parent.mkdir(parents=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                timestamp_iso TEXT,
                profile TEXT,
                branch TEXT,
                total_findings INTEGER
            )
        """)
        cursor.execute(
            "INSERT INTO scans VALUES (?, ?, ?, ?, ?)",
            ("scan-001", "2025-11-01T10:00:00", "balanced", "main", 10),
        )
        conn.commit()
        conn.close()

        inputs = ["1"]  # History mode

        with patch("pathlib.Path.home", return_value=tmp_path):
            with patch("builtins.input", side_effect=inputs):
                result = run_diff_wizard()

        assert result == 1  # Error - need at least 2 scans

    def test_diff_wizard_history_mode_same_scan_selected(self, mock_history_db):
        """Test diff wizard when user selects same scan twice."""
        from scripts.cli.wizard import run_diff_wizard

        # Mock inputs: select same scan twice, then different scan
        inputs = [
            "1",  # History mode
            "1",  # Select scan 1 as baseline
            "1",  # Try to select scan 1 again as current (should reject)
            "2",  # Select scan 2 as current
            "1",  # All severities
            "1",  # All categories
            "2",  # Markdown
            "",
            "y",
        ]

        with patch("pathlib.Path.home", return_value=mock_history_db):
            with patch("builtins.input", side_effect=inputs):
                with patch(
                    "scripts.cli.diff_commands.cmd_diff", return_value=0
                ) as mock_cmd_diff:
                    result = run_diff_wizard()

        assert result == 0
        assert mock_cmd_diff.called


class TestRunDiffWizardErrorHandling:
    """Test cases for run_diff_wizard error handling."""

    def test_diff_wizard_keyboard_interrupt_early(self):
        """Test diff wizard handles KeyboardInterrupt at mode selection."""
        from scripts.cli.wizard import run_diff_wizard

        with patch("builtins.input", side_effect=KeyboardInterrupt):
            result = run_diff_wizard()

        assert result == 130  # Standard interrupt exit code

    def test_diff_wizard_keyboard_interrupt_during_selection(self, tmp_path):
        """Test diff wizard handles KeyboardInterrupt during scan selection."""
        from scripts.cli.wizard import run_diff_wizard

        import sqlite3

        # Create DB with scans matching the real schema
        db_path = tmp_path / ".jmo" / "history.db"
        db_path.parent.mkdir(parents=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                timestamp_iso TEXT NOT NULL,
                profile TEXT NOT NULL,
                branch TEXT,
                total_findings INTEGER,
                tools TEXT NOT NULL,
                targets TEXT NOT NULL,
                target_type TEXT NOT NULL
            )
        """)
        cursor.executemany(
            """INSERT INTO scans
            (id, timestamp, timestamp_iso, profile, branch, total_findings, tools, targets, target_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    "scan-001",
                    1730455200,
                    "2025-11-01T10:00:00",
                    "balanced",
                    "main",
                    10,
                    "semgrep",
                    "/repo",
                    "repo",
                ),
                (
                    "scan-002",
                    1730541600,
                    "2025-11-02T10:00:00",
                    "balanced",
                    "main",
                    8,
                    "semgrep",
                    "/repo",
                    "repo",
                ),
            ],
        )
        conn.commit()
        conn.close()

        inputs = [
            "1",  # History mode
            KeyboardInterrupt,  # Interrupt during baseline selection
        ]

        def mock_input(prompt=""):
            value = inputs.pop(0)
            # Use BaseException to catch KeyboardInterrupt (not a subclass of Exception)
            if isinstance(value, type) and issubclass(value, BaseException):
                raise value()
            return value

        with patch("pathlib.Path.home", return_value=tmp_path):
            with patch("builtins.input", side_effect=mock_input):
                result = run_diff_wizard()

        assert result == 130

    def test_diff_wizard_cmd_diff_failure(self, tmp_path):
        """Test diff wizard handles cmd_diff failure gracefully."""
        from scripts.cli.wizard import run_diff_wizard

        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        inputs = [
            "2",  # Directory mode
            str(baseline),
            str(current),
            "1",
            "1",
            "2",
            "",
            "y",
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff", return_value=1
            ) as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 1
        assert mock_cmd_diff.called


class TestRunDiffWizardOutputFormats:
    """Test cases for run_diff_wizard output format options."""

    @pytest.fixture
    def valid_dirs(self, tmp_path):
        """Create valid test directories."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()
        return baseline, current

    @pytest.mark.parametrize(
        "format_choice,expected_format",
        [
            ("1", "json"),
            ("2", "md"),
            ("3", "html"),
            ("4", "sarif"),
        ],
    )
    def test_diff_wizard_output_formats(
        self, valid_dirs, format_choice, expected_format
    ):
        """Test diff wizard with different output formats."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = valid_dirs

        inputs = [
            "2",  # Directory mode
            str(baseline),
            str(current),
            "1",  # All severities
            "1",  # All categories
            format_choice,  # Selected format
            "",  # Default output file
            "y",
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff", return_value=0
            ) as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 0
        args = mock_cmd_diff.call_args[0][0]
        assert args.format == expected_format

    def test_diff_wizard_custom_output_file(self, valid_dirs):
        """Test diff wizard with custom output file name."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = valid_dirs

        inputs = [
            "2",
            str(baseline),
            str(current),
            "1",
            "1",
            "2",  # Markdown
            "my-custom-report.md",  # Custom output file
            "y",
        ]

        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff", return_value=0
            ) as mock_cmd_diff:
                result = run_diff_wizard()

        assert result == 0
        args = mock_cmd_diff.call_args[0][0]
        assert args.output == "my-custom-report.md"


class TestRunDiffWizardHTMLBrowserOpen:
    """Test cases for HTML output with browser opening."""

    @pytest.fixture
    def valid_dirs_with_html(self, tmp_path):
        """Create valid test directories and mock HTML output."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()
        return baseline, current, tmp_path

    def test_diff_wizard_html_opens_browser(self, valid_dirs_with_html):
        """Test diff wizard offers to open HTML report in browser."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current, tmp_path = valid_dirs_with_html

        # Create the output file that cmd_diff would create
        output_file = Path("diff-report.html")

        inputs = [
            "2",
            str(baseline),
            str(current),
            "1",
            "1",
            "3",  # HTML format
            "",
            "y",  # Confirm diff
            "n",  # Don't open browser
        ]

        def mock_cmd_diff(args):
            # Simulate creating the output file
            Path(args.output).write_text("<html>Report</html>")
            return 0

        with patch("builtins.input", side_effect=inputs):
            with patch("scripts.cli.diff_commands.cmd_diff", side_effect=mock_cmd_diff):
                with patch("webbrowser.open") as mock_browser:
                    result = run_diff_wizard()

        assert result == 0
        # Browser should not be opened (user said no)
        assert not mock_browser.called

        # Cleanup
        if output_file.exists():
            output_file.unlink()

    def test_diff_wizard_html_browser_open_yes(self, valid_dirs_with_html):
        """Test diff wizard opens browser when user confirms."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current, tmp_path = valid_dirs_with_html

        output_file = Path("diff-report.html")

        inputs = [
            "2",
            str(baseline),
            str(current),
            "1",
            "1",
            "3",  # HTML format
            "",
            "y",  # Confirm diff
            "y",  # Open browser
        ]

        def mock_cmd_diff(args):
            Path(args.output).write_text("<html>Report</html>")
            return 0

        with patch("builtins.input", side_effect=inputs):
            with patch("scripts.cli.diff_commands.cmd_diff", side_effect=mock_cmd_diff):
                with patch("webbrowser.open") as mock_browser:
                    result = run_diff_wizard()

        assert result == 0
        assert mock_browser.called

        # Cleanup
        if output_file.exists():
            output_file.unlink()


class TestRunDiffWizardExceptionHandling:
    """Test cases for generic exception handling in run_diff_wizard."""

    def test_diff_wizard_generic_exception_in_flow(self, tmp_path):
        """Test diff wizard handles generic exceptions in main flow.

        Covers lines 348-351 in diff_flow.py: the except Exception handler
        that catches non-KeyboardInterrupt exceptions, logs them, and returns 1.
        """
        from scripts.cli.wizard import run_diff_wizard

        # Create directories so we get past initial validation
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()

        inputs = [
            "2",  # Directory mode
            str(baseline),
            str(current),
            "1",  # All severities
            "1",  # All categories
            "2",  # Markdown
            "",  # Default output
            "y",  # Confirm
        ]

        # Make cmd_diff raise a generic exception (not KeyboardInterrupt)
        with patch("builtins.input", side_effect=inputs):
            with patch(
                "scripts.cli.diff_commands.cmd_diff",
                side_effect=RuntimeError("Database connection failed"),
            ):
                result = run_diff_wizard()

        # Generic exception should return error code 1 (not 130 for interrupt)
        assert result == 1

    def test_diff_wizard_exception_during_history_load(self, tmp_path):
        """Test exception during history database loading.

        Covers the try/except around list_recent_scans() at lines 148-202.
        """
        from scripts.cli.wizard import run_diff_wizard

        # Create a valid-looking but corrupted database
        db_path = tmp_path / ".jmo" / "history.db"
        db_path.parent.mkdir(parents=True)
        db_path.write_text("not a valid sqlite database")

        inputs = [
            "1",  # History mode - will fail when loading corrupted DB
        ]

        with patch("pathlib.Path.home", return_value=tmp_path):
            with patch("builtins.input", side_effect=inputs):
                result = run_diff_wizard()

        # Should return error 1 due to database load failure
        assert result == 1

    def test_diff_wizard_value_error_during_scan_selection(self, tmp_path):
        """Test ValueError during scan selection triggers KeyboardInterrupt re-raise.

        The ValueError catch at line 180/197 re-raises KeyboardInterrupt,
        returning exit code 130.
        """
        from scripts.cli.wizard import run_diff_wizard

        import sqlite3

        # Create valid DB with proper schema
        db_path = tmp_path / ".jmo" / "history.db"
        db_path.parent.mkdir(parents=True)

        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute("""
            CREATE TABLE scans (
                id TEXT PRIMARY KEY,
                timestamp INTEGER NOT NULL,
                timestamp_iso TEXT NOT NULL,
                profile TEXT NOT NULL,
                branch TEXT,
                total_findings INTEGER,
                tools TEXT NOT NULL,
                targets TEXT NOT NULL,
                target_type TEXT NOT NULL
            )
        """)
        cursor.executemany(
            """INSERT INTO scans
            (id, timestamp, timestamp_iso, profile, branch, total_findings, tools, targets, target_type)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            [
                (
                    "scan-001",
                    1730455200,
                    "2025-11-01T10:00:00",
                    "balanced",
                    "main",
                    10,
                    "semgrep",
                    "/repo",
                    "repo",
                ),
                (
                    "scan-002",
                    1730541600,
                    "2025-11-02T10:00:00",
                    "balanced",
                    "main",
                    8,
                    "semgrep",
                    "/repo",
                    "repo",
                ),
            ],
        )
        conn.commit()
        conn.close()

        # Enter non-numeric value for baseline selection - raises ValueError
        # which is caught and re-raises KeyboardInterrupt
        inputs = [
            "1",  # History mode
            "abc",  # Invalid non-numeric input triggers ValueError -> KeyboardInterrupt
        ]

        with patch("pathlib.Path.home", return_value=tmp_path):
            with patch("builtins.input", side_effect=inputs):
                result = run_diff_wizard()

        # ValueError in scan selection re-raises KeyboardInterrupt -> 130
        assert result == 130


class TestRunDiffWizardNonInteractive:
    """Test cases for run_diff_wizard --yes non-interactive mode."""

    @pytest.fixture
    def valid_dirs(self, tmp_path):
        """Create valid baseline and current directories."""
        baseline = tmp_path / "baseline"
        current = tmp_path / "current"
        baseline.mkdir()
        current.mkdir()
        return baseline, current

    def test_yes_with_baseline_and_current(self, valid_dirs):
        """Test --yes mode with both --baseline and --current provided."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = valid_dirs

        with patch(
            "scripts.cli.diff_commands.cmd_diff", return_value=0
        ) as mock_cmd_diff:
            result = run_diff_wizard(
                yes=True, baseline=str(baseline), current=str(current)
            )

        assert result == 0
        assert mock_cmd_diff.called
        args = mock_cmd_diff.call_args[0][0]
        assert args.directories == [str(baseline), str(current)]
        assert args.format == "json"  # Default for non-interactive

    def test_yes_missing_baseline(self):
        """Test --yes mode errors when --baseline is missing."""
        from scripts.cli.wizard import run_diff_wizard

        result = run_diff_wizard(yes=True, baseline=None, current="/some/dir")

        assert result == 1

    def test_yes_missing_current(self, tmp_path):
        """Test --yes mode errors when --current is missing."""
        from scripts.cli.wizard import run_diff_wizard

        baseline = tmp_path / "baseline"
        baseline.mkdir()

        result = run_diff_wizard(yes=True, baseline=str(baseline), current=None)

        assert result == 1

    def test_yes_missing_both(self):
        """Test --yes mode errors when both --baseline and --current are missing."""
        from scripts.cli.wizard import run_diff_wizard

        result = run_diff_wizard(yes=True)

        assert result == 1

    def test_yes_nonexistent_baseline(self, tmp_path):
        """Test --yes mode errors when baseline directory doesn't exist."""
        from scripts.cli.wizard import run_diff_wizard

        current = tmp_path / "current"
        current.mkdir()

        result = run_diff_wizard(
            yes=True,
            baseline=str(tmp_path / "nonexistent"),
            current=str(current),
        )

        assert result == 1

    def test_yes_nonexistent_current(self, tmp_path):
        """Test --yes mode errors when current directory doesn't exist."""
        from scripts.cli.wizard import run_diff_wizard

        baseline = tmp_path / "baseline"
        baseline.mkdir()

        result = run_diff_wizard(
            yes=True,
            baseline=str(baseline),
            current=str(tmp_path / "nonexistent"),
        )

        assert result == 1

    def test_yes_does_not_prompt(self, valid_dirs):
        """Test --yes mode never calls input()."""
        from scripts.cli.wizard import run_diff_wizard

        baseline, current = valid_dirs

        with patch("builtins.input") as mock_input:
            with patch("scripts.cli.diff_commands.cmd_diff", return_value=0):
                run_diff_wizard(yes=True, baseline=str(baseline), current=str(current))

        mock_input.assert_not_called()
