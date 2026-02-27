"""Simple scan progress reporter for wizard and CLI.

Provides real-time progress feedback during security scans.
Part of Fix 2.1 for Issues #6, #9 (v1.0.x).

This is the SIMPLE implementation. Full implementation with spinners,
ETA tracking, and parallel tool visualization planned for v1.1.0.
"""

from __future__ import annotations

import time
from typing import Callable, Optional


class ScanProgressReporter:
    """Basic progress reporter showing tool-by-tool status.

    Usage:
        reporter = ScanProgressReporter(total_tools=15, verbose=True)

        for tool in tools:
            reporter.on_tool_start(tool)
            # ... run tool ...
            reporter.on_tool_complete(tool, "success", findings_count=5)

        reporter.print_summary()
    """

    def __init__(self, total_tools: int, verbose: bool = False):
        """Initialize progress reporter.

        Args:
            total_tools: Total number of tools that will run
            verbose: Show detailed per-tool output with findings counts
        """
        self.total_tools = total_tools
        self.current_index = 0
        self.current_tool: Optional[str] = None
        self.start_time = time.time()
        self.tool_start_time: Optional[float] = None
        self.completed: list[tuple[str, str, float]] = []  # (tool, status, duration)
        self.verbose = verbose

    def on_tool_start(self, tool_name: str) -> None:
        """Called when a tool starts running.

        Args:
            tool_name: Name of the tool starting
        """
        self.current_index += 1
        self.current_tool = tool_name
        self.tool_start_time = time.time()

        # Print progress line (overwrites previous line)
        elapsed = time.time() - self.start_time
        progress_line = (
            f"\r[{self.current_index}/{self.total_tools}] "
            f"Running {tool_name}... ({self._format_time(elapsed)} elapsed)"
        )
        # Pad to clear any leftover characters from previous line
        print(f"{progress_line:<70}", end="", flush=True)

    def on_tool_complete(
        self,
        tool_name: str,
        status: str,  # "success", "failed", "skipped"
        findings_count: int = 0,
    ) -> None:
        """Called when a tool completes.

        Args:
            tool_name: Name of the tool that completed
            status: Completion status ("success", "failed", "skipped")
            findings_count: Number of findings from this tool
        """
        duration = 0.0
        if self.tool_start_time:
            duration = time.time() - self.tool_start_time

        self.completed.append((tool_name, status, duration))

        if self.verbose:
            # Verbose mode: show detailed output on new line
            status_icon = {"success": "OK", "failed": "ERR", "skipped": "SKIP"}.get(
                status, "?"
            )
            print(
                f"\r[{self.current_index}/{self.total_tools}] "
                f"{tool_name}: {status_icon} ({self._format_time(duration)}) "
                f"- {findings_count} findings"
            )
        else:
            # Non-verbose: update same line with completion marker
            status_short = {"success": "done", "failed": "FAIL", "skipped": "skip"}.get(
                status, "?"
            )
            print(
                f"\r[{self.current_index}/{self.total_tools}] "
                f"{tool_name}: {status_short:<6}"
            )

    def print_summary(self) -> None:
        """Print final summary after all tools complete."""
        total_time = time.time() - self.start_time

        success = sum(1 for _, s, _ in self.completed if s == "success")
        failed = sum(1 for _, s, _ in self.completed if s == "failed")
        skipped = sum(1 for _, s, _ in self.completed if s == "skipped")

        # Print summary box
        print(f"\n{'=' * 50}")
        print(f"Scan Complete: {self._format_time(total_time)}")
        print(f"  Tools run: {success} success, {failed} failed, {skipped} skipped")

        if failed > 0 and self.verbose:
            print("\nFailed tools:")
            for tool, status, _ in self.completed:
                if status == "failed":
                    print(f"  - {tool}")

        print(f"{'=' * 50}\n")

    @staticmethod
    def _format_time(seconds: float) -> str:
        """Format seconds as human-readable string.

        Args:
            seconds: Time in seconds

        Returns:
            Human-readable time string (e.g., "45s", "2m 30s", "1h 5m")
        """
        if seconds < 60:
            return f"{int(seconds)}s"
        elif seconds < 3600:
            mins = int(seconds // 60)
            secs = int(seconds % 60)
            return f"{mins}m {secs}s"
        else:
            hours = int(seconds // 3600)
            mins = int((seconds % 3600) // 60)
            return f"{hours}h {mins}m"


def create_progress_callback(
    reporter: ScanProgressReporter,
) -> Callable[[str, str, int], None]:
    """Create a progress callback function for use with tool runners.

    Args:
        reporter: ScanProgressReporter instance

    Returns:
        Callback function with signature (tool_name, status, findings_count)
    """

    def callback(tool_name: str, status: str, findings_count: int = 0) -> None:
        """Progress callback for tool runner integration."""
        if status == "start":
            reporter.on_tool_start(tool_name)
        else:
            reporter.on_tool_complete(tool_name, status, findings_count)

    return callback
