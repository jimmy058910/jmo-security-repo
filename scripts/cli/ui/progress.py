"""Progress tracking and reporting for installations."""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from scripts.cli.installers.models import InstallResult

from scripts.cli.installers.models import InstallProgress


class ProgressReporter(Protocol):
    """Protocol for installation progress reporting."""

    def on_start(self, tool_name: str) -> None:
        """Called when tool installation starts."""
        ...

    def on_complete(self, tool_name: str, result: InstallResult) -> None:
        """Called when tool installation completes."""
        ...

    def on_error(self, tool_name: str, error: str) -> None:
        """Called when tool installation fails."""
        ...

    def is_cancelled(self) -> bool:
        """Check if installation was cancelled."""
        ...


class SilentProgressReporter:
    """No-op progress reporter for testing or CI environments."""

    def __init__(self) -> None:
        self._cancelled = False

    def on_start(self, tool_name: str) -> None:
        pass

    def on_complete(self, tool_name: str, result: InstallResult) -> None:
        pass

    def on_error(self, tool_name: str, error: str) -> None:
        pass

    def is_cancelled(self) -> bool:
        return self._cancelled

    def cancel(self) -> None:
        self._cancelled = True


@dataclass
class ParallelInstallProgress:
    """Thread-safe progress tracking for parallel installations.

    Uses threading.Lock to protect shared state from race conditions
    when multiple threads update progress concurrently.

    Attributes:
        total: Total number of tools to install
        completed: Number of successfully installed tools
        failed: Number of failed installations
        skipped: Number of skipped (already installed) tools
        current_tools: List of tools currently being installed
        results: List of InstallResult objects
    """

    total: int
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    current_tools: list[str] = field(default_factory=list)
    results: list["InstallResult"] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cancelled: threading.Event = field(default_factory=threading.Event, repr=False)

    def on_start(self, tool_name: str) -> None:
        """Called when a tool installation begins (thread-safe)."""
        with self._lock:
            self.current_tools.append(tool_name)

    def on_complete(self, tool_name: str, result: InstallResult) -> None:
        """Called when a tool installation completes (thread-safe)."""
        with self._lock:
            if tool_name in self.current_tools:
                self.current_tools.remove(tool_name)
            self.results.append(result)
            if result.success:
                if result.method == "skipped":
                    self.skipped += 1
                else:
                    self.completed += 1
            else:
                self.failed += 1

    def get_status_line(self) -> str:
        """Get current progress status for display (thread-safe)."""
        with self._lock:
            done = self.completed + self.failed + self.skipped
            running = ", ".join(self.current_tools[:3])
            if len(self.current_tools) > 3:
                running += f" +{len(self.current_tools) - 3}"
            return f"[{done}/{self.total}] Installing: {running}"

    def is_cancelled(self) -> bool:
        """Check if installation has been cancelled."""
        return self._cancelled.is_set()

    def cancel(self) -> None:
        """Signal cancellation to all worker threads."""
        self._cancelled.set()

    def to_install_progress(self) -> InstallProgress:
        """Convert to legacy InstallProgress for compatibility."""
        with self._lock:
            progress = InstallProgress(
                total=self.total,
                completed=self.completed + self.skipped,
                successful=self.completed,
                failed=self.failed,
                skipped=self.skipped,
                results=list(self.results),
            )
            return progress


class RichProgressReporter:
    """Rich-based progress reporter for terminal UI.

    Note: Rich console integration extracted from _install_with_rich_progress().
    This is a thin wrapper - the main display logic stays in orchestrator for now.
    """

    def __init__(self, progress: ParallelInstallProgress) -> None:
        self._progress = progress

    def on_start(self, tool_name: str) -> None:
        self._progress.on_start(tool_name)

    def on_complete(self, tool_name: str, result: InstallResult) -> None:
        self._progress.on_complete(tool_name, result)

    def on_error(self, tool_name: str, error: str) -> None:
        from scripts.cli.installers.models import InstallResult

        self._progress.on_complete(
            tool_name,
            InstallResult(tool_name=tool_name, success=False, message=error),
        )

    def is_cancelled(self) -> bool:
        return self._progress.is_cancelled()
