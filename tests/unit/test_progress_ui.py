"""Tests for scripts.cli.ui.progress module.

Covers SilentProgressReporter, ParallelInstallProgress, and RichProgressReporter.
"""

from __future__ import annotations

import threading


from scripts.cli.installers.models import InstallResult
from scripts.cli.ui.progress import (
    ParallelInstallProgress,
    RichProgressReporter,
    SilentProgressReporter,
)


class TestSilentProgressReporter:
    """Tests for the no-op SilentProgressReporter."""

    def test_initial_state(self) -> None:
        reporter = SilentProgressReporter()
        assert reporter.is_cancelled() is False

    def test_on_start_no_error(self) -> None:
        reporter = SilentProgressReporter()
        reporter.on_start("trivy")  # Should not raise

    def test_on_complete_no_error(self) -> None:
        reporter = SilentProgressReporter()
        result = InstallResult(tool_name="trivy", success=True)
        reporter.on_complete("trivy", result)  # Should not raise

    def test_on_error_no_error(self) -> None:
        reporter = SilentProgressReporter()
        reporter.on_error("trivy", "something failed")  # Should not raise

    def test_cancel(self) -> None:
        reporter = SilentProgressReporter()
        assert reporter.is_cancelled() is False
        reporter.cancel()
        assert reporter.is_cancelled() is True


class TestParallelInstallProgress:
    """Tests for thread-safe ParallelInstallProgress."""

    def test_initialization(self) -> None:
        progress = ParallelInstallProgress(total=5)
        assert progress.total == 5
        assert progress.completed == 0
        assert progress.failed == 0
        assert progress.skipped == 0
        assert progress.current_tools == []
        assert progress.results == []

    def test_on_start_adds_tool(self) -> None:
        progress = ParallelInstallProgress(total=3)
        progress.on_start("trivy")
        assert "trivy" in progress.current_tools

    def test_on_complete_success(self) -> None:
        progress = ParallelInstallProgress(total=3)
        progress.on_start("trivy")
        result = InstallResult(tool_name="trivy", success=True, method="binary")
        progress.on_complete("trivy", result)
        assert progress.completed == 1
        assert progress.failed == 0
        assert "trivy" not in progress.current_tools
        assert len(progress.results) == 1

    def test_on_complete_failure(self) -> None:
        progress = ParallelInstallProgress(total=3)
        progress.on_start("trivy")
        result = InstallResult(tool_name="trivy", success=False, message="not found")
        progress.on_complete("trivy", result)
        assert progress.completed == 0
        assert progress.failed == 1

    def test_on_complete_skipped(self) -> None:
        progress = ParallelInstallProgress(total=3)
        progress.on_start("trivy")
        result = InstallResult(tool_name="trivy", success=True, method="skipped")
        progress.on_complete("trivy", result)
        assert progress.skipped == 1
        assert progress.completed == 0  # Skipped != completed

    def test_get_status_line(self) -> None:
        progress = ParallelInstallProgress(total=5)
        progress.on_start("trivy")
        progress.on_start("grype")
        line = progress.get_status_line()
        assert "[0/5]" in line
        assert "trivy" in line
        assert "grype" in line

    def test_get_status_line_truncates_long_list(self) -> None:
        progress = ParallelInstallProgress(total=10)
        for tool in ["tool1", "tool2", "tool3", "tool4", "tool5"]:
            progress.on_start(tool)
        line = progress.get_status_line()
        assert "+2" in line  # 5 tools, shows 3 + "+2"

    def test_cancel(self) -> None:
        progress = ParallelInstallProgress(total=3)
        assert progress.is_cancelled() is False
        progress.cancel()
        assert progress.is_cancelled() is True

    def test_to_install_progress(self) -> None:
        progress = ParallelInstallProgress(total=5)
        # Complete 2, skip 1, fail 1
        for name, success, method in [
            ("t1", True, "binary"),
            ("t2", True, "pip"),
            ("t3", True, "skipped"),
            ("t4", False, ""),
        ]:
            progress.on_start(name)
            progress.on_complete(
                name, InstallResult(tool_name=name, success=success, method=method)
            )

        legacy = progress.to_install_progress()
        assert legacy.total == 5
        assert legacy.completed == 3  # successful + skipped
        assert legacy.successful == 2
        assert legacy.failed == 1
        assert legacy.skipped == 1
        assert len(legacy.results) == 4

    def test_thread_safety(self) -> None:
        """Verify concurrent on_start/on_complete doesn't corrupt state."""
        progress = ParallelInstallProgress(total=20)
        errors: list[str] = []

        def worker(tool_id: int) -> None:
            try:
                name = f"tool-{tool_id}"
                progress.on_start(name)
                result = InstallResult(tool_name=name, success=True, method="binary")
                progress.on_complete(name, result)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0, f"Thread errors: {errors}"
        assert progress.completed == 20
        assert len(progress.results) == 20

    def test_on_complete_tool_not_in_current(self) -> None:
        """Completing a tool not in current_tools should not error."""
        progress = ParallelInstallProgress(total=1)
        result = InstallResult(tool_name="mystery", success=True, method="binary")
        progress.on_complete("mystery", result)  # Should not raise
        assert progress.completed == 1


class TestRichProgressReporter:
    """Tests for RichProgressReporter wrapper."""

    def test_on_start_delegates(self) -> None:
        inner = ParallelInstallProgress(total=3)
        reporter = RichProgressReporter(inner)
        reporter.on_start("trivy")
        assert "trivy" in inner.current_tools

    def test_on_complete_delegates(self) -> None:
        inner = ParallelInstallProgress(total=3)
        reporter = RichProgressReporter(inner)
        reporter.on_start("trivy")
        result = InstallResult(tool_name="trivy", success=True, method="binary")
        reporter.on_complete("trivy", result)
        assert inner.completed == 1

    def test_on_error_creates_failed_result(self) -> None:
        inner = ParallelInstallProgress(total=3)
        reporter = RichProgressReporter(inner)
        reporter.on_start("trivy")
        reporter.on_error("trivy", "download failed")
        assert inner.failed == 1
        assert inner.results[-1].success is False
        assert "download failed" in inner.results[-1].message

    def test_is_cancelled_delegates(self) -> None:
        inner = ParallelInstallProgress(total=1)
        reporter = RichProgressReporter(inner)
        assert reporter.is_cancelled() is False
        inner.cancel()
        assert reporter.is_cancelled() is True
