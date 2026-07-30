#!/usr/bin/env python3
"""Tests for ProgressTracker in scripts/cli/jmo.py."""

# Import ProgressTracker from jmo.py
import sys
import threading
from argparse import Namespace
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from scripts.cli.jmo import ProgressTracker


class TestProgressTracker:
    """Tests for ProgressTracker class."""

    def test_initialization(self):
        """Test ProgressTracker initialization."""
        args = Namespace()
        tracker = ProgressTracker(total=10, args=args)

        assert tracker.total == 10
        assert tracker.completed == 0
        assert tracker.args == args
        assert tracker._start_time is None

    def test_start(self):
        """Test start() method sets start time."""
        args = Namespace()
        tracker = ProgressTracker(total=5, args=args)

        tracker.start()
        assert tracker._start_time is not None
        assert isinstance(tracker._start_time, float)

    def test_update_increments_completed(self):
        """Test update() increments completed count."""
        args = Namespace()
        tracker = ProgressTracker(total=3, args=args)
        tracker.start()

        # Mock _log to prevent actual logging
        with patch("scripts.cli.jmo._log"):
            tracker.update("repo", "test-repo", 10.5)
            assert tracker.completed == 1

            tracker.update("image", "nginx:latest", 5.2)
            assert tracker.completed == 2

    def test_update_calls_log(self):
        """Test update() calls _log with progress message."""
        args = Namespace()
        tracker = ProgressTracker(total=5, args=args)
        tracker.start()

        with patch("scripts.cli.jmo._log") as mock_log:
            tracker.update("repo", "my-repo", 15.0)

            # Verify _log was called
            mock_log.assert_called_once()
            call_args = mock_log.call_args[0]
            assert call_args[0] == args
            assert call_args[1] == "INFO"

            # Check message contains key elements
            message = call_args[2]
            assert "[1/5]" in message
            assert "repo" in message
            assert "my-repo" in message
            assert "20%" in message  # 1/5 = 20%

    def test_progress_percentage_calculation(self):
        """Test progress percentage is calculated correctly."""
        with patch("scripts.cli.jmo._log") as mock_log:
            # Test 10%, 20%, 50%, 90%, 100% by calling update() sequentially
            args = Namespace()
            tracker = ProgressTracker(total=10, args=args)
            tracker.start()

            # Update 1/10 = 10%
            tracker.update("repo", "repo1", 1.0)
            assert "10%" in mock_log.call_args[0][2]

            # Update 2/10 = 20%
            tracker.update("repo", "repo2", 1.0)
            assert "20%" in mock_log.call_args[0][2]

            # Update 3-5/10 = 30-50%
            tracker.update("repo", "repo3", 1.0)
            tracker.update("repo", "repo4", 1.0)
            tracker.update("repo", "repo5", 1.0)
            assert "50%" in mock_log.call_args[0][2]

            # Update 6-9/10 = 60-90%
            tracker.update("repo", "repo6", 1.0)
            tracker.update("repo", "repo7", 1.0)
            tracker.update("repo", "repo8", 1.0)
            tracker.update("repo", "repo9", 1.0)
            assert "90%" in mock_log.call_args[0][2]

            # Update 10/10 = 100%
            tracker.update("repo", "repo10", 1.0)
            assert "100%" in mock_log.call_args[0][2]

    def test_format_duration_seconds(self):
        """Test _format_duration() formats seconds correctly."""
        args = Namespace()
        tracker = ProgressTracker(total=1, args=args)

        assert tracker._format_duration(0) == "0s"
        assert tracker._format_duration(30) == "30s"
        assert tracker._format_duration(59) == "59s"

    def test_format_duration_minutes(self):
        """Test _format_duration() formats minutes correctly."""
        args = Namespace()
        tracker = ProgressTracker(total=1, args=args)

        assert tracker._format_duration(60) == "1m 0s"
        assert tracker._format_duration(90) == "1m 30s"
        assert tracker._format_duration(150) == "2m 30s"
        assert tracker._format_duration(3599) == "59m 59s"

    def test_format_duration_hours(self):
        """Test _format_duration() formats hours correctly."""
        args = Namespace()
        tracker = ProgressTracker(total=1, args=args)

        assert tracker._format_duration(3600) == "1h 0m"
        assert tracker._format_duration(3660) == "1h 1m"
        assert tracker._format_duration(7200) == "2h 0m"
        assert tracker._format_duration(5430) == "1h 30m"

    def test_eta_calculation(self):
        """Test ETA calculation based on average time."""
        args = Namespace()
        tracker = ProgressTracker(total=10, args=args)
        tracker.start()

        # Simulate completing first target in 10 seconds
        with patch("scripts.cli.jmo._log") as mock_log, patch("time.time") as mock_time:
            mock_time.return_value = tracker._start_time + 10
            tracker.update("repo", "repo1", 10.0)

            message = mock_log.call_args[0][2]
            # ETA: 9 remaining * 10s each = 90s = 1m 30s
            assert "ETA:" in message
            assert "1m 30s" in message

    def test_success_symbol(self):
        """Test success symbol (✓) for positive elapsed time."""
        args = Namespace()
        tracker = ProgressTracker(total=1, args=args)
        tracker.start()

        with patch("scripts.cli.jmo._log") as mock_log:
            tracker.update("repo", "success-repo", 5.0)
            message = mock_log.call_args[0][2]
            assert "✓" in message

    def test_failure_symbol(self):
        """Test failure symbol (✗) for negative elapsed time."""
        args = Namespace()
        tracker = ProgressTracker(total=1, args=args)
        tracker.start()

        with patch("scripts.cli.jmo._log") as mock_log:
            tracker.update("repo", "failed-repo", -1.0)
            message = mock_log.call_args[0][2]
            assert "✗" in message

    def test_thread_safety(self):
        """Test ProgressTracker is thread-safe."""
        import threading

        args = Namespace()
        tracker = ProgressTracker(total=100, args=args)
        tracker.start()

        with patch("scripts.cli.jmo._log"):
            threads = []
            for i in range(100):
                t = threading.Thread(
                    target=tracker.update, args=("repo", f"repo{i}", 0.1)
                )
                threads.append(t)
                t.start()

            for t in threads:
                t.join(timeout=10)

            # All updates should be counted
            assert tracker.completed == 100

    def test_multiple_target_types(self):
        """Test progress tracking with multiple target types."""
        args = Namespace()
        tracker = ProgressTracker(total=6, args=args)
        tracker.start()

        target_types = [
            ("repo", "my-repo"),
            ("image", "nginx:latest"),
            ("iac", "terraform.tfstate"),
            ("url", "https://example.com"),
            ("gitlab", "mygroup/myrepo"),
            ("k8s", "prod-cluster"),
        ]

        with patch("scripts.cli.jmo._log") as mock_log:
            for idx, (target_type, target_name) in enumerate(target_types, 1):
                tracker.update(target_type, target_name, 1.0)

                message = mock_log.call_args[0][2]
                assert f"[{idx}/6]" in message
                assert target_type in message
                assert target_name in message

    def test_calculating_eta_on_first_update(self):
        """Test ETA shows 'calculating...' before first update completes."""
        args = Namespace()
        tracker = ProgressTracker(total=5, args=args)
        # Don't call start() - _start_time is None

        with patch("scripts.cli.jmo._log") as mock_log:
            tracker.update("repo", "repo1", 1.0)
            message = mock_log.call_args[0][2]
            assert "calculating..." in message


class TestUpdateToolDoesNotDeadlock:
    """`update_tool` must not deadlock on statuses that log from inside the lock.

    `update_tool` takes `self._lock`, and three of its status branches --
    "retrying", "timeout" and "no_output" -- then call `self.log()`, which
    acquires the same lock. With a plain `threading.Lock` that is an
    unconditional self-deadlock, and it is not a cosmetic one: the worker
    thread never returns, so its future never completes, so `scan_all()` blocks
    on `future.result()` and the entire scan hangs forever. Measured before the
    fix (`threading.Lock` -> `threading.RLock`), with a 5s watchdog:

        start      returned
        success    returned
        retrying   NO -- deadlock
        timeout    NO -- deadlock
        error      returned
        no_output  NO -- deadlock

    Every status is exercised here rather than only the three known-bad ones,
    so a future branch that logs from inside the lock is caught by this test
    instead of by a hung scan.
    """

    # Each status only formats and prints, so anything beyond a second is a
    # deadlock rather than slowness. Generous for a loaded CI runner.
    WATCHDOG_S = 20.0

    @pytest.mark.parametrize(
        "status",
        ["start", "success", "retrying", "timeout", "error", "no_output"],
    )
    def test_update_tool_returns_for_status(self, status: str) -> None:
        args = Namespace(human_logs=True, verbose=False, quiet=False)
        tracker = ProgressTracker(total=1, args=args, total_tools=1)
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

        # Daemon thread + Event.wait, never a bare join(): a deadlocked thread
        # must not be able to hang the suite (see
        # .claude/rules/testing.cross-platform.rules.md).
        worker = threading.Thread(target=call_update_tool, daemon=True)
        worker.start()

        assert returned.wait(self.WATCHDOG_S), (
            f"ProgressTracker.update_tool() never returned for status={status!r} "
            f"within {self.WATCHDOG_S}s. This is the self-deadlock described in "
            "this class's docstring: a branch logging from inside self._lock "
            "while _lock is a non-reentrant threading.Lock. In a real scan this "
            "hangs the whole run, because the tool's future never completes."
        )

    def test_lock_is_reentrant(self) -> None:
        """Guard the mechanism directly, not just the symptom.

        The parametrized test above would also pass if someone "fixed" the hang
        by deleting the log calls. This asserts the property that makes
        logging-from-inside-the-lock safe in the first place.
        """
        args = Namespace(human_logs=True, verbose=False, quiet=False)
        tracker = ProgressTracker(total=1, args=args, total_tools=1)

        with tracker._lock:
            acquired_again = tracker._lock.acquire(timeout=5)
            if acquired_again:
                tracker._lock.release()

        assert acquired_again, (
            "ProgressTracker._lock is not reentrant. update_tool() holds it and "
            "calls log(), which acquires it again -- that requires RLock."
        )


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
