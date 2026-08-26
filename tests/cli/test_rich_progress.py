"""Tests for scripts/cli/rich_progress.py.

Covers:
- RichScanProgressTracker initialization
- Context manager (__enter__/__exit__)
- update() for target completion
- update_tool() for tool status callbacks
- Multi-phase tool handling (_get_base_tool_name)
- _format_elapsed() time formatting
- _make_display() panel rendering
- log() method
- create_progress_tracker() factory function
- Thread safety (lock usage)
"""

from __future__ import annotations

import threading
from unittest.mock import MagicMock

import pytest

from scripts.cli.rich_progress import (
    RichScanProgressTracker,
    create_progress_tracker,
)

# ========== Helpers ==========


def make_tracker(
    total_targets: int = 3,
    total_tools: int = 10,
    verbose: bool = False,
) -> RichScanProgressTracker:
    """Create a tracker for testing (without entering context manager)."""
    return RichScanProgressTracker(
        total_targets=total_targets,
        total_tools=total_tools,
        args=None,
        verbose=verbose,
    )


# ========== Category 1: Initialization ==========


class TestInit:
    """Tests for RichScanProgressTracker initialization."""

    def test_default_values(self):
        """Test default initialization state."""
        tracker = make_tracker(total_targets=5, total_tools=20)
        assert tracker.total_targets == 5
        assert tracker.total_tools == 20
        assert tracker.targets_completed == 0
        assert tracker.tools_completed == 0
        assert tracker.current_target == ""
        assert tracker.current_target_type == ""
        assert len(tracker.tools_in_progress) == 0
        assert len(tracker.tool_status) == 0

    def test_verbose_flag(self):
        """Test verbose flag is stored."""
        tracker = make_tracker(verbose=True)
        assert tracker.verbose is True

    def test_args_stored(self):
        """Test args are stored."""
        mock_args = MagicMock()
        tracker = RichScanProgressTracker(1, 1, args=mock_args)
        assert tracker.args is mock_args


# ========== Category 2: Context Manager ==========


class TestContextManager:
    """Tests for __enter__ and __exit__."""

    def test_enter_sets_start_time(self):
        """Test that __enter__ sets _start_time."""
        tracker = make_tracker()
        with tracker:
            assert tracker._start_time is not None
            assert isinstance(tracker._start_time, float)

    def test_exit_cleans_up_live(self):
        """Test that __exit__ sets _live to None."""
        tracker = make_tracker()
        with tracker:
            assert tracker._live is not None
        assert tracker._live is None

    def test_context_manager_protocol(self):
        """Test that tracker works as context manager."""
        tracker = make_tracker()
        result = tracker.__enter__()
        assert result is tracker
        tracker.__exit__(None, None, None)


# ========== Category 3: Tool Name Handling ==========


class TestGetBaseToolName:
    """Tests for _get_base_tool_name() multi-phase tool handling."""

    def test_plain_tool_name(self):
        """Test tool name without phase suffix."""
        tracker = make_tracker()
        assert tracker._get_base_tool_name("trivy") == "trivy"

    def test_init_suffix(self):
        """Test -init suffix stripping."""
        tracker = make_tracker()
        assert tracker._get_base_tool_name("noseyparker-init") == "noseyparker"

    def test_scan_suffix(self):
        """Test -scan suffix stripping."""
        tracker = make_tracker()
        assert tracker._get_base_tool_name("noseyparker-scan") == "noseyparker"

    def test_report_suffix(self):
        """Test -report suffix stripping."""
        tracker = make_tracker()
        assert tracker._get_base_tool_name("noseyparker-report") == "noseyparker"

    def test_non_phase_hyphen(self):
        """Test that non-phase hyphens are preserved."""
        tracker = make_tracker()
        assert tracker._get_base_tool_name("dependency-check") == "dependency-check"


# ========== Category 4: Time Formatting ==========


class TestFormatElapsed:
    """Tests for _format_elapsed()."""

    def test_seconds_only(self):
        """Test formatting under 60 seconds."""
        tracker = make_tracker()
        assert tracker._format_elapsed(30.5) == "30s"

    def test_minutes_and_seconds(self):
        """Test formatting over 60 seconds."""
        tracker = make_tracker()
        assert tracker._format_elapsed(90.0) == "1m30s"

    def test_zero(self):
        """Test formatting zero seconds."""
        tracker = make_tracker()
        assert tracker._format_elapsed(0.0) == "0s"

    def test_exact_minute(self):
        """Test formatting exactly 60 seconds."""
        tracker = make_tracker()
        assert tracker._format_elapsed(60.0) == "1m0s"


# ========== Category 5: update_tool() Callback ==========


class TestUpdateTool:
    """Tests for update_tool() tool status callback."""

    def test_tool_start(self):
        """Test tool start status adds to in_progress."""
        tracker = make_tracker()
        tracker.update_tool("trivy", "start")
        assert "trivy" in tracker.tools_in_progress
        assert "trivy" in tracker._tool_start_times

    def test_tool_success(self):
        """Test tool success status completes tool."""
        tracker = make_tracker()
        tracker.update_tool("trivy", "start")
        tracker.update_tool("trivy", "success")
        assert "trivy" not in tracker.tools_in_progress
        assert tracker.tools_completed == 1
        assert tracker.tool_status.get("trivy") == "success"

    def test_tool_error(self):
        """Test tool error status marks as failed."""
        tracker = make_tracker()
        tracker.update_tool("semgrep", "start")
        tracker.update_tool("semgrep", "error")
        assert tracker.tools_completed == 1
        assert tracker.tool_status.get("semgrep") == "error"

    def test_tool_timeout_mapped_to_error(self):
        """Test timeout status is mapped to error."""
        tracker = make_tracker()
        tracker.update_tool("slow-tool", "start")
        tracker.update_tool("slow-tool", "timeout", max_attempts=3)
        assert tracker.tool_status.get("slow-tool") == "error"

    def test_retrying_does_not_count_as_completed(self):
        """Test retrying status doesn't increment completed count."""
        tracker = make_tracker()
        tracker.update_tool("flaky", "start")
        tracker.update_tool(
            "flaky", "retrying", attempt=1, max_attempts=3, message="timeout"
        )
        assert tracker.tools_completed == 0
        assert "flaky" in tracker.tools_in_progress

    def test_multi_phase_tool_counted_once(self):
        """Test multi-phase tool is counted as single completion."""
        tracker = make_tracker()
        # noseyparker has 3 phases: init, scan, report
        tracker.update_tool("noseyparker-init", "start")
        tracker.update_tool("noseyparker-init", "success")
        assert tracker.tools_completed == 1

        tracker.update_tool("noseyparker-scan", "start")
        tracker.update_tool("noseyparker-scan", "success")
        # Still 1, not 2 - same base tool
        assert tracker.tools_completed == 1

    def test_kwargs_accepted(self):
        """Test forward-compatibility **kwargs don't cause errors."""
        tracker = make_tracker()
        # Should not raise even with unknown kwargs
        tracker.update_tool("trivy", "start", future_param="value", extra=42)

    def test_live_display_refresh(self):
        """Test live display is refreshed on tool update."""
        tracker = make_tracker()
        tracker._live = MagicMock()
        tracker.update_tool("trivy", "start")
        tracker._live.update.assert_called()


# ========== Category 6: update() Target Completion ==========


class TestUpdate:
    """Tests for update() target completion."""

    def test_target_completion(self):
        """Test target completion increments counter."""
        tracker = make_tracker(total_targets=3)
        tracker.update("repo", "/path/to/repo")
        assert tracker.targets_completed == 1
        assert tracker.current_target == "/path/to/repo"
        assert tracker.current_target_type == "repo"

    def test_resets_tool_tracking(self):
        """Test that target completion resets tool-level tracking."""
        tracker = make_tracker()
        # Add some tool state
        tracker.tools_completed = 5
        tracker.tools_in_progress.add("trivy")
        tracker.tool_status["trivy"] = "success"

        tracker.update("repo", "repo1")

        assert tracker.tools_completed == 0
        assert len(tracker.tools_in_progress) == 0
        assert len(tracker.tool_status) == 0


# ========== Category 7: log() Method ==========


class TestLog:
    """Tests for log() method."""

    def test_log_info(self):
        """Test INFO log level."""
        tracker = make_tracker()
        # Just verify it doesn't raise
        tracker.log("INFO", "Test info message")

    def test_log_warn(self):
        """Test WARN log level."""
        tracker = make_tracker()
        tracker.log("WARN", "Test warning message")

    def test_log_error(self):
        """Test ERROR log level."""
        tracker = make_tracker()
        tracker.log("ERROR", "Test error message")

    def test_log_unknown_level(self):
        """Test unknown log level defaults to white style."""
        tracker = make_tracker()
        tracker.log("DEBUG", "Test debug message")


# ========== Category 8: _make_display() ==========


class TestMakeDisplay:
    """Tests for _make_display() panel rendering."""

    def test_initial_display(self):
        """Test display with no progress."""
        tracker = make_tracker()
        panel = tracker._make_display()
        assert panel is not None

    def test_display_with_running_tools(self):
        """Test display with tools in progress."""
        tracker = make_tracker()
        tracker.tools_in_progress = {"trivy", "semgrep"}
        panel = tracker._make_display()
        assert panel is not None

    def test_display_truncates_long_tool_list(self):
        """Test display truncates when >5 tools running."""
        tracker = make_tracker()
        tracker.tools_in_progress = {f"tool-{i}" for i in range(8)}
        panel = tracker._make_display()
        assert panel is not None

    def test_display_with_status_counts(self):
        """Test display shows success/error counts."""
        tracker = make_tracker()
        tracker.tool_status = {
            "trivy": "success",
            "semgrep": "error",
            "bandit": "success",
        }
        panel = tracker._make_display()
        assert panel is not None


# ========== Category 9: Factory Function ==========


class TestCreateProgressTracker:
    """Tests for create_progress_tracker() factory."""

    def test_returns_tracker_instance(self):
        """Test factory returns RichScanProgressTracker."""
        tracker = create_progress_tracker(3, 10)
        assert isinstance(tracker, RichScanProgressTracker)
        assert tracker.total_targets == 3
        assert tracker.total_tools == 10

    def test_passes_args(self):
        """Test factory passes args through."""
        mock_args = MagicMock()
        tracker = create_progress_tracker(1, 5, args=mock_args)
        assert tracker.args is mock_args


# ========== Category 10: start() Compatibility ==========


class TestStart:
    """Tests for start() compatibility method."""

    def test_start_sets_time(self):
        """Test start() sets _start_time."""
        tracker = make_tracker()
        assert tracker._start_time is None
        tracker.start()
        assert tracker._start_time is not None


# ========== Category 11: Deadlock Prevention ==========


class TestUpdateToolDoesNotDeadlock:
    """`self._lock` must be reentrant, or a future edit self-deadlocks.

    Unlike its sibling `ProgressTracker` in scripts/cli/jmo.py, `update_tool()`
    here does not call `self.log()` from any status branch today -- the
    "retrying", "timeout" and "no_output" branches call
    `self.console.print()` directly instead, specifically so a plain
    `threading.Lock` does not self-deadlock. That split is easy to lose: the
    more obvious call from inside `update_tool()` is `self.log()`, and
    `self.log()` also acquires `self._lock`. With a plain `Lock`, one such
    edit deadlocks the worker thread permanently -- and since that thread
    backs a scan future, `scan_all()` blocks on `future.result()` and the
    entire scan hangs forever.

    `test_lock_is_reentrant` asserts the mechanism directly and is the test
    that actually fails against today's source before the RLock fix.
    `test_update_tool_returns_for_status` is a tripwire against the specific
    future edit described above -- it cannot fail on the *current* source
    (nothing here calls self.log() from inside the lock yet), but it will
    catch the swap immediately if someone makes it, in a positive-cases
    parametrization that mirrors the sibling in
    tests/cli/test_progress_tracker.py rather than depending on nobody ever
    writing the "obvious" line.
    """

    # Each status only formats and prints, so anything beyond a second is a
    # deadlock rather than slowness. Generous for a loaded CI runner.
    WATCHDOG_S = 20.0

    @pytest.mark.parametrize(
        "status",
        ["start", "success", "retrying", "timeout", "error", "no_output"],
    )
    def test_update_tool_returns_for_status(self, status: str) -> None:
        tracker = make_tracker(total_targets=1, total_tools=1)
        returned = threading.Event()

        def call_update_tool() -> None:
            try:
                tracker.update_tool(
                    "semgrep",
                    status,
                    0,
                    message="watchdog probe",
                    attempt=1,
                    max_attempts=1,
                )
            finally:
                returned.set()

        # Daemon thread + Event.wait, never a bare join(): a deadlocked
        # thread must not be able to hang the suite (see
        # .claude/rules/testing.cross-platform.rules.md). pytest-timeout's
        # thread method cannot reliably interrupt a blocked lock
        # acquisition, so the bound has to come from here, not the marker.
        worker = threading.Thread(target=call_update_tool, daemon=True)
        worker.start()

        assert returned.wait(self.WATCHDOG_S), (
            f"RichScanProgressTracker.update_tool() never returned for "
            f"status={status!r} within {self.WATCHDOG_S}s. This is the "
            "self-deadlock described in this class's docstring: a branch "
            "logging from inside self._lock while _lock is a non-reentrant "
            "threading.Lock. In a real scan this hangs the whole run, "
            "because the tool's future never completes."
        )

    def test_lock_is_reentrant(self) -> None:
        """Guard the mechanism directly, not just today's call pattern.

        The parametrized test above cannot fail on today's source at all --
        nothing in update_tool() currently calls self.log() from inside the
        lock. This asserts the property that makes it *safe* if something
        ever does, independent of what update_tool() happens to call today.
        """
        tracker = make_tracker(total_targets=1, total_tools=1)

        with tracker._lock:
            acquired_again = tracker._lock.acquire(timeout=5)
            if acquired_again:
                tracker._lock.release()

        assert acquired_again, (
            "RichScanProgressTracker._lock is not reentrant. A future edit "
            "that calls self.log() from inside update_tool()'s "
            "`with self._lock:` block requires RLock to avoid a self-deadlock."
        )
