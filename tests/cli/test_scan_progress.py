#!/usr/bin/env python3
"""Tests for scripts/cli/scan_progress.py module.

This test suite validates the ScanProgressReporter class:
1. Initialization and defaults
2. Tool start/complete tracking
3. Progress summary generation
4. Time formatting
5. Callback factory function

Target Coverage: >= 85%
"""

import time
from unittest.mock import patch


# ========== Category 1: ScanProgressReporter Initialization ==========


def test_scan_progress_reporter_init_defaults():
    """Test ScanProgressReporter initializes with correct defaults."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=10)

    assert reporter.total_tools == 10
    assert reporter.current_index == 0
    assert reporter.current_tool is None
    assert reporter.tool_start_time is None
    assert reporter.completed == []
    assert reporter.verbose is False


def test_scan_progress_reporter_init_verbose():
    """Test ScanProgressReporter initializes with verbose flag."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=5, verbose=True)

    assert reporter.verbose is True


def test_scan_progress_reporter_init_start_time():
    """Test ScanProgressReporter records start time."""
    from scripts.cli.scan_progress import ScanProgressReporter

    before = time.time()
    reporter = ScanProgressReporter(total_tools=10)
    after = time.time()

    assert before <= reporter.start_time <= after


# ========== Category 2: Tool Start Tracking ==========


def test_on_tool_start_increments_index():
    """Test on_tool_start increments current_index."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3)

    with patch("builtins.print"):
        reporter.on_tool_start("trivy")
        assert reporter.current_index == 1

        reporter.on_tool_start("semgrep")
        assert reporter.current_index == 2


def test_on_tool_start_sets_current_tool():
    """Test on_tool_start sets current_tool name."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3)

    with patch("builtins.print"):
        reporter.on_tool_start("nuclei")
        assert reporter.current_tool == "nuclei"


def test_on_tool_start_records_tool_start_time():
    """Test on_tool_start records tool_start_time."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3)

    with patch("builtins.print"):
        before = time.time()
        reporter.on_tool_start("trivy")
        after = time.time()

        assert reporter.tool_start_time is not None
        assert before <= reporter.tool_start_time <= after


def test_on_tool_start_prints_progress():
    """Test on_tool_start prints progress line."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=5)

    with patch("builtins.print") as mock_print:
        reporter.on_tool_start("bandit")

        mock_print.assert_called_once()
        call_args = mock_print.call_args
        printed_line = call_args[0][0]
        assert "[1/5]" in printed_line
        assert "bandit" in printed_line


# ========== Category 3: Tool Complete Tracking ==========


def test_on_tool_complete_appends_to_completed():
    """Test on_tool_complete adds entry to completed list."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3)

    with patch("builtins.print"):
        reporter.on_tool_start("trivy")
        reporter.on_tool_complete("trivy", "success", findings_count=5)

        assert len(reporter.completed) == 1
        tool, status, duration = reporter.completed[0]
        assert tool == "trivy"
        assert status == "success"
        assert duration >= 0


def test_on_tool_complete_calculates_duration():
    """Test on_tool_complete calculates duration from start time."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3)

    with patch("builtins.print"):
        reporter.on_tool_start("trivy")
        # Simulate some work
        time.sleep(0.01)
        reporter.on_tool_complete("trivy", "success")

        _, _, duration = reporter.completed[0]
        assert duration >= 0.01


def test_on_tool_complete_handles_no_start_time():
    """Test on_tool_complete handles case where start time wasn't recorded."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3)

    with patch("builtins.print"):
        # Complete without start
        reporter.on_tool_complete("trivy", "skipped")

        _, _, duration = reporter.completed[0]
        assert duration == 0.0


def test_on_tool_complete_verbose_output():
    """Test on_tool_complete prints detailed output in verbose mode."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3, verbose=True)
    reporter.current_index = 1

    with patch("builtins.print") as mock_print:
        reporter.on_tool_start("semgrep")
        mock_print.reset_mock()

        reporter.on_tool_complete("semgrep", "success", findings_count=10)

        mock_print.assert_called_once()
        printed_line = mock_print.call_args[0][0]
        assert "semgrep" in printed_line
        assert "OK" in printed_line
        assert "10 findings" in printed_line


def test_on_tool_complete_non_verbose_output():
    """Test on_tool_complete prints brief output in non-verbose mode."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3, verbose=False)
    reporter.current_index = 1

    with patch("builtins.print") as mock_print:
        reporter.on_tool_start("semgrep")
        mock_print.reset_mock()

        reporter.on_tool_complete("semgrep", "success")

        mock_print.assert_called_once()
        printed_line = mock_print.call_args[0][0]
        assert "semgrep" in printed_line
        assert "done" in printed_line


def test_on_tool_complete_failed_status():
    """Test on_tool_complete handles failed status."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3, verbose=True)
    reporter.current_index = 1

    with patch("builtins.print") as mock_print:
        reporter.on_tool_start("trivy")
        mock_print.reset_mock()

        reporter.on_tool_complete("trivy", "failed")

        printed_line = mock_print.call_args[0][0]
        assert "ERR" in printed_line


def test_on_tool_complete_skipped_status():
    """Test on_tool_complete handles skipped status."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3, verbose=True)
    reporter.current_index = 1

    with patch("builtins.print") as mock_print:
        reporter.on_tool_start("zap")
        mock_print.reset_mock()

        reporter.on_tool_complete("zap", "skipped")

        printed_line = mock_print.call_args[0][0]
        assert "SKIP" in printed_line


# ========== Category 4: Summary Generation ==========


def test_print_summary_counts():
    """Test print_summary shows correct counts."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=5)
    reporter.completed = [
        ("trivy", "success", 1.0),
        ("semgrep", "success", 2.0),
        ("bandit", "failed", 0.5),
        ("checkov", "skipped", 0.0),
        ("hadolint", "success", 0.3),
    ]

    with patch("builtins.print") as mock_print:
        reporter.print_summary()

        # Collect all printed lines
        printed_lines = " ".join(str(call[0][0]) for call in mock_print.call_args_list)

        assert "3 success" in printed_lines
        assert "1 failed" in printed_lines
        assert "1 skipped" in printed_lines


def test_print_summary_shows_failed_tools_in_verbose():
    """Test print_summary lists failed tools when verbose."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3, verbose=True)
    reporter.completed = [
        ("trivy", "success", 1.0),
        ("semgrep", "failed", 2.0),
        ("bandit", "failed", 0.5),
    ]

    with patch("builtins.print") as mock_print:
        reporter.print_summary()

        printed_lines = " ".join(str(call[0][0]) for call in mock_print.call_args_list)
        assert "semgrep" in printed_lines
        assert "bandit" in printed_lines


def test_print_summary_hides_failed_tools_not_verbose():
    """Test print_summary doesn't list failed tools when not verbose."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=3, verbose=False)
    reporter.completed = [
        ("trivy", "success", 1.0),
        ("semgrep", "failed", 2.0),
    ]

    with patch("builtins.print") as mock_print:
        reporter.print_summary()

        # Should not list individual failed tools
        printed_lines = " ".join(str(call[0][0]) for call in mock_print.call_args_list)
        # The failed tools section only appears in verbose mode
        assert "Failed tools:" not in printed_lines


# ========== Category 5: Time Formatting ==========


def test_format_time_seconds():
    """Test _format_time formats seconds correctly."""
    from scripts.cli.scan_progress import ScanProgressReporter

    assert ScanProgressReporter._format_time(0) == "0s"
    assert ScanProgressReporter._format_time(30) == "30s"
    assert ScanProgressReporter._format_time(59) == "59s"


def test_format_time_minutes():
    """Test _format_time formats minutes correctly."""
    from scripts.cli.scan_progress import ScanProgressReporter

    assert ScanProgressReporter._format_time(60) == "1m 0s"
    assert ScanProgressReporter._format_time(90) == "1m 30s"
    assert ScanProgressReporter._format_time(150) == "2m 30s"


def test_format_time_hours():
    """Test _format_time formats hours correctly."""
    from scripts.cli.scan_progress import ScanProgressReporter

    assert ScanProgressReporter._format_time(3600) == "1h 0m"
    assert ScanProgressReporter._format_time(3900) == "1h 5m"
    assert ScanProgressReporter._format_time(7200) == "2h 0m"


def test_format_time_float_values():
    """Test _format_time handles float values."""
    from scripts.cli.scan_progress import ScanProgressReporter

    assert ScanProgressReporter._format_time(45.7) == "45s"
    assert ScanProgressReporter._format_time(125.9) == "2m 5s"


# ========== Category 6: Callback Factory ==========


def test_create_progress_callback_returns_callable():
    """Test create_progress_callback returns a callable."""
    from scripts.cli.scan_progress import ScanProgressReporter, create_progress_callback

    reporter = ScanProgressReporter(total_tools=5)
    callback = create_progress_callback(reporter)

    assert callable(callback)


def test_create_progress_callback_start_status():
    """Test callback handles 'start' status."""
    from scripts.cli.scan_progress import ScanProgressReporter, create_progress_callback

    reporter = ScanProgressReporter(total_tools=5)
    callback = create_progress_callback(reporter)

    with patch("builtins.print"):
        callback("trivy", "start")

        assert reporter.current_index == 1
        assert reporter.current_tool == "trivy"


def test_create_progress_callback_complete_status():
    """Test callback handles complete statuses."""
    from scripts.cli.scan_progress import ScanProgressReporter, create_progress_callback

    reporter = ScanProgressReporter(total_tools=5)
    callback = create_progress_callback(reporter)

    with patch("builtins.print"):
        callback("trivy", "start")
        callback("trivy", "success", 10)

        assert len(reporter.completed) == 1
        tool, status, _ = reporter.completed[0]
        assert tool == "trivy"
        assert status == "success"


def test_create_progress_callback_with_findings_count():
    """Test callback passes findings_count correctly."""
    from scripts.cli.scan_progress import ScanProgressReporter, create_progress_callback

    reporter = ScanProgressReporter(total_tools=3, verbose=True)
    callback = create_progress_callback(reporter)

    with patch("builtins.print") as mock_print:
        callback("semgrep", "start")
        mock_print.reset_mock()

        callback("semgrep", "success", 25)

        printed_line = mock_print.call_args[0][0]
        assert "25 findings" in printed_line


def test_create_progress_callback_default_findings_count():
    """Test callback uses default findings_count of 0."""
    from scripts.cli.scan_progress import ScanProgressReporter, create_progress_callback

    reporter = ScanProgressReporter(total_tools=3, verbose=True)
    callback = create_progress_callback(reporter)

    with patch("builtins.print") as mock_print:
        callback("bandit", "start")
        mock_print.reset_mock()

        callback("bandit", "success")  # No findings_count specified

        printed_line = mock_print.call_args[0][0]
        assert "0 findings" in printed_line


# ========== Category 7: Integration Tests ==========


def test_full_scan_workflow():
    """Test a complete scan workflow simulation."""
    from scripts.cli.scan_progress import ScanProgressReporter

    tools = ["trivy", "semgrep", "bandit"]
    reporter = ScanProgressReporter(total_tools=len(tools))

    with patch("builtins.print"):
        for tool in tools:
            reporter.on_tool_start(tool)
            reporter.on_tool_complete(tool, "success", findings_count=5)

        reporter.print_summary()

    assert reporter.current_index == 3
    assert len(reporter.completed) == 3
    assert all(status == "success" for _, status, _ in reporter.completed)


def test_mixed_status_workflow():
    """Test workflow with mixed success/failure statuses."""
    from scripts.cli.scan_progress import ScanProgressReporter

    reporter = ScanProgressReporter(total_tools=4, verbose=True)

    with patch("builtins.print"):
        reporter.on_tool_start("trivy")
        reporter.on_tool_complete("trivy", "success", 10)

        reporter.on_tool_start("semgrep")
        reporter.on_tool_complete("semgrep", "failed", 0)

        reporter.on_tool_start("zap")
        reporter.on_tool_complete("zap", "skipped", 0)

        reporter.on_tool_start("bandit")
        reporter.on_tool_complete("bandit", "success", 3)

        reporter.print_summary()

    success_count = sum(1 for _, s, _ in reporter.completed if s == "success")
    failed_count = sum(1 for _, s, _ in reporter.completed if s == "failed")
    skipped_count = sum(1 for _, s, _ in reporter.completed if s == "skipped")

    assert success_count == 2
    assert failed_count == 1
    assert skipped_count == 1
