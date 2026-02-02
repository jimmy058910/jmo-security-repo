"""Rich-based progress display for scan operations.

Provides thread-safe, coordinated output using Rich Live display.
Replaces the simple carriage-return based ProgressTracker for wizard scans.

Key benefits:
- Thread-safe updates via lock (multiple tools run concurrently)
- Coordinated stderr output (prevents overlapping lines)
- Clean progress bars with ETA calculations
- Captures stray stderr from third-party libraries

Usage:
    with RichScanProgressTracker(total_targets, total_tools, args) as progress:
        # Pass progress.update_tool as callback to scan orchestrator
        orchestrator.scan_all(..., tool_progress_callback=progress.update_tool)
"""

from __future__ import annotations

import io
import sys
import threading
import time
from typing import TYPE_CHECKING, Any

from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table

if TYPE_CHECKING:
    from argparse import Namespace


class RichScanProgressTracker:
    """Thread-safe progress display using Rich Live.

    Coordinates all scan output through a single Rich Console instance
    to prevent overlapping lines and garbled output from concurrent tools.

    Attributes:
        total_targets: Total number of scan targets (repos, images, etc.)
        total_tools: Total number of tools to run per target
        console: Rich Console instance (writes to stderr)
    """

    # Suffixes for multi-phase tools (e.g., noseyparker-init, noseyparker-scan)
    # These phases should be counted as a single logical tool
    _PHASE_SUFFIXES = ("-init", "-scan", "-report")

    def __init__(
        self,
        total_targets: int,
        total_tools: int,
        args: Namespace | None = None,
        verbose: bool = False,
    ):
        """Initialize progress tracker.

        Args:
            total_targets: Total number of targets to scan
            total_tools: Total number of tools to run
            args: CLI arguments (for logging configuration)
            verbose: Show detailed tool-by-tool output
        """
        self.total_targets = total_targets
        self.total_tools = total_tools
        self.args = args
        self.verbose = verbose

        self._lock = threading.Lock()
        self._start_time: float | None = None

        # Target-level tracking
        self.targets_completed = 0
        self.current_target: str = ""
        self.current_target_type: str = ""

        # Tool-level tracking (per target, reset on each target)
        self.tools_completed = 0
        self.tools_in_progress: set[str] = set()
        self.tool_status: dict[str, str] = {}  # tool_name -> "success" | "error"
        # Track completed base tools (handles multi-phase tools like noseyparker)
        self._completed_base_tools: set[str] = set()
        # Elapsed time tracking for running tools
        self._tool_start_times: dict[str, float] = {}

        # Rich components - use stderr to match existing behavior
        self.console = Console(stderr=True, force_terminal=True)

        # Target progress bar
        self.target_progress = Progress(
            SpinnerColumn(),
            TextColumn("[bold blue]{task.description}"),
            BarColumn(bar_width=30),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=self.console,
        )
        self.target_task = self.target_progress.add_task(
            f"Targets [0/{total_targets}]", total=total_targets
        )

        # Tool progress bar
        self.tool_progress = Progress(
            SpinnerColumn(),
            TextColumn("[cyan]{task.description}"),
            BarColumn(bar_width=20),
            TaskProgressColumn(),
            console=self.console,
        )
        self.tool_task = self.tool_progress.add_task(
            f"Tools (this target) [0/{total_tools}]", total=total_tools
        )

        # Live display (manages refresh)
        self._live: Live | None = None

        # Stderr capture buffer (Phase 5.1 enhancement)
        self._stderr_buffer = io.StringIO()
        self._original_stderr = sys.stderr

    def _get_base_tool_name(self, tool_name: str) -> str:
        """Extract base tool name from a potentially phased tool name.

        Multi-phase tools like noseyparker run as:
        - noseyparker-init
        - noseyparker-scan
        - noseyparker-report

        All should be counted as one logical tool "noseyparker".

        Args:
            tool_name: The tool name (may include phase suffix)

        Returns:
            Base tool name without phase suffix
        """
        for suffix in self._PHASE_SUFFIXES:
            if tool_name.endswith(suffix):
                return tool_name[: -len(suffix)]
        return tool_name

    def _format_elapsed(self, elapsed: float) -> str:
        """Format elapsed time as human-readable string."""
        if elapsed < 60:
            return f"{int(elapsed)}s"
        else:
            mins = int(elapsed // 60)
            secs = int(elapsed % 60)
            return f"{mins}m{secs}s"

    def _make_display(self) -> Panel:
        """Create the combined progress display panel."""
        # Tools in progress section with elapsed time
        if self.tools_in_progress:
            tools_list = sorted(self.tools_in_progress)[:5]
            # Show elapsed time for each running tool
            tools_with_time = []
            for tool in tools_list:
                if tool in self._tool_start_times:
                    elapsed = time.time() - self._tool_start_times[tool]
                    elapsed_str = self._format_elapsed(elapsed)
                    tools_with_time.append(f"{tool} ({elapsed_str})")
                else:
                    tools_with_time.append(tool)
            tools_text = ", ".join(tools_with_time)
            if len(self.tools_in_progress) > 5:
                tools_text += f" (+{len(self.tools_in_progress) - 5} more)"
        else:
            tools_text = "waiting..."

        # Status summary
        success_count = sum(1 for s in self.tool_status.values() if s == "success")
        error_count = sum(1 for s in self.tool_status.values() if s == "error")

        # Status table with clear labels (Phase 5.2 enhancement)
        status_table = Table.grid(padding=(0, 2))
        status_table.add_column(style="bold")
        status_table.add_column()

        # Clear "per-target" vs "total" labeling
        target_label = (
            f"{self.current_target_type}: {self.current_target}"
            if self.current_target
            else "initializing..."
        )
        status_table.add_row(
            "Target:",
            f"{target_label} ({self.targets_completed}/{self.total_targets})",
        )
        status_table.add_row("Running:", tools_text)
        status_table.add_row(
            "Status:",
            f"[green]{success_count} passed[/] | [red]{error_count} failed[/]",
        )

        # Combine into panel
        group = Group(
            self.target_progress,
            "",  # spacer
            self.tool_progress,
            "",  # spacer
            status_table,
        )

        return Panel(
            group,
            title="[bold]JMo Security Scan[/]",
            border_style="blue",
        )

    def __enter__(self) -> "RichScanProgressTracker":
        """Start the live display."""
        self._start_time = time.time()
        self._live = Live(
            self._make_display(),
            console=self.console,
            refresh_per_second=4,
            transient=False,
        )
        self._live.__enter__()
        return self

    def __exit__(self, *args: Any) -> None:
        """Stop the live display."""
        if self._live:
            self._live.__exit__(*args)
            self._live = None

        # Flush any captured stderr (Phase 5.1 enhancement)
        captured = self._stderr_buffer.getvalue()
        if captured.strip():
            # Only show if there's meaningful output
            self.console.print(f"[dim]Captured output: {captured[:200]}...[/dim]")

    def start(self) -> None:
        """Start progress tracking timer (compatibility method)."""
        self._start_time = time.time()

    def update(
        self, target_type: str, target_name: str, elapsed: float = 1.0  # noqa: ARG002
    ) -> None:
        """Update progress after completing a target scan.

        This method is called when an entire target (repo, image, etc.) finishes.

        Args:
            target_type: Type of target (repo, image, url, etc.)
            target_name: Name/identifier of target
            elapsed: Elapsed time in seconds for this target
        """
        with self._lock:
            self.targets_completed += 1
            self.current_target_type = target_type
            self.current_target = target_name

            # Update target progress bar
            self.target_progress.update(
                self.target_task,
                completed=self.targets_completed,
                description=f"Targets [{self.targets_completed}/{self.total_targets}]",
            )

            # Reset tool progress for next target
            self.tools_completed = 0
            self.tools_in_progress.clear()
            self.tool_status.clear()
            self._completed_base_tools.clear()
            self._tool_start_times.clear()
            self.tool_progress.update(
                self.tool_task,
                completed=0,
                description=f"Tools (this target) [0/{self.total_tools}]",
            )

            # Refresh display
            if self._live:
                self._live.update(self._make_display())

    def update_tool(
        self,
        tool_name: str,
        status: str,
        findings_count: int = 0,  # noqa: ARG002
        *,
        message: str = "",
        attempt: int = 1,
        max_attempts: int = 1,
        **kwargs,  # noqa: ARG002 - Forward compatibility
    ) -> None:
        """Update progress when a tool starts or completes.

        This is the main callback passed to the scan orchestrator.
        Handles multi-phase tools (noseyparker-init, etc.) correctly.

        Args:
            tool_name: Name of the tool (may include phase suffix)
            status: "start"/"success"/"error"/"retrying"/"timeout"
            findings_count: Number of findings (for verbose mode)
            message: Optional message (e.g., timeout reason)
            attempt: Current attempt number (for retries)
            max_attempts: Maximum attempts configured
            **kwargs: Forward compatibility for future parameters
        """
        # Get the base tool name (strip phase suffixes like -init, -scan, -report)
        base_tool_name = self._get_base_tool_name(tool_name)

        with self._lock:
            # Handle intermediate statuses (retrying/timeout)
            if status == "retrying":
                # Log retry through Rich console (below live display)
                self.console.print(
                    f"[yellow]WARN[/] {base_tool_name}: "
                    f"Retry {attempt}/{max_attempts} - {message}"
                )
                return  # Don't update completion count

            if status == "timeout":
                self.console.print(
                    f"[red]ERROR[/] {base_tool_name}: "
                    f"Timed out after {max_attempts} attempts"
                )
                # Fall through to mark as failed

            if status == "start":
                self.tools_in_progress.add(tool_name)
                self._tool_start_times[tool_name] = time.time()
            else:
                # Tool/phase completed (success, error, or timeout)
                self.tools_in_progress.discard(tool_name)
                # Clean up start time
                self._tool_start_times.pop(tool_name, None)

                # Only count as completed if base tool hasn't been counted yet
                # This handles multi-phase tools correctly
                if base_tool_name not in self._completed_base_tools:
                    self._completed_base_tools.add(base_tool_name)
                    self.tools_completed += 1
                    # Map timeout to error for status tracking
                    self.tool_status[base_tool_name] = (
                        "error" if status == "timeout" else status
                    )

                    # Update tool progress bar
                    self.tool_progress.update(
                        self.tool_task,
                        completed=self.tools_completed,
                        description=f"Tools (this target) [{self.tools_completed}/{self.total_tools}]",
                    )

            # Refresh display
            if self._live:
                self._live.update(self._make_display())

    def log(self, level: str, message: str) -> None:
        """Log a message through the Rich console.

        Use this instead of direct print() to maintain coordinated output.

        Args:
            level: Log level (INFO, WARN, ERROR)
            message: Log message
        """
        style_map = {
            "INFO": "blue",
            "WARN": "yellow",
            "ERROR": "red",
        }
        style = style_map.get(level, "white")

        with self._lock:
            if self._live:
                # Print below the live display
                self.console.print(f"[{style}]{level}[/] {message}")
            else:
                # Fallback when not in live context
                self.console.print(f"[{style}]{level}[/] {message}")


def create_progress_tracker(
    total_targets: int,
    total_tools: int,
    args: Namespace | None = None,
    use_rich: bool = True,  # noqa: ARG001 - Reserved for future fallback mode
) -> RichScanProgressTracker:
    """Factory function to create a progress tracker.

    Args:
        total_targets: Total number of targets to scan
        total_tools: Total number of tools to run
        args: CLI arguments
        use_rich: Whether to use Rich display (default True)

    Returns:
        RichScanProgressTracker instance
    """
    return RichScanProgressTracker(
        total_targets=total_targets,
        total_tools=total_tools,
        args=args,
    )
