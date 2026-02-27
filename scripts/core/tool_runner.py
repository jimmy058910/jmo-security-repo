"""
Tool execution management for JMo Security.

This module provides the ToolRunner class for parallel/serial execution of security tools
with timeout, retry, and status tracking capabilities.

Created as part of PHASE 1 refactoring to extract tool execution logic from cmd_scan().
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import subprocess
import time

from scripts.core.config import RetryConfig
from scripts.core.exceptions import ToolExecutionException

# Configure logging
logger = logging.getLogger(__name__)


class ProgressCallback(Protocol):
    """Protocol for progress callback functions.

    Callbacks receive tool status updates during scan execution.
    """

    def __call__(
        self,
        tool_name: str,
        status: str,
        findings_count: int = 0,
        *,
        message: str = "",
        attempt: int = 1,
        max_attempts: int = 1,
        **kwargs: Any,
    ) -> None:
        """Called when tool status changes.

        Args:
            tool_name: Name of the tool
            status: Status string ("start", "success", "error", "retrying", "timeout")
            findings_count: Number of findings (optional)
            message: Additional context (e.g., timeout reason)
            attempt: Current attempt number
            max_attempts: Total attempts configured
            **kwargs: Forward compatibility for future parameters
        """
        ...


@dataclass
class ToolDefinition:
    """
    Definition of a security tool to execute.

    Attributes:
        name: Tool name (e.g., "trufflehog", "semgrep", "trivy")
        command: Command to execute as list of arguments (no shell expansion)
        output_file: Path where tool writes JSON output (None for tools that don't write files)
        timeout: Maximum execution time in seconds (default: 600)
        retries: Number of retry attempts on failure (default: 0)
        ok_return_codes: Tuple of acceptable return codes (default: (0, 1))
        capture_stdout: Whether to capture stdout (default: False, writes to file)
    """

    name: str
    command: list[str]
    output_file: Path | None
    timeout: int = 600
    retries: int | RetryConfig = 0
    ok_return_codes: tuple[int, ...] = (0, 1)
    capture_stdout: bool = False

    @property
    def retry_config(self) -> RetryConfig:
        """Get retries as a RetryConfig, converting flat int if needed."""
        if isinstance(self.retries, RetryConfig):
            return self.retries
        return RetryConfig.from_flat_retries(self.retries)

    def __post_init__(self):
        """Validate tool definition after initialization."""
        if not self.name:
            raise ValueError("Tool name cannot be empty")
        if not self.command:
            raise ValueError("Tool command cannot be empty")
        if self.timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {self.timeout}")
        if isinstance(self.retries, int) and self.retries < 0:
            raise ValueError(f"Retries must be non-negative, got {self.retries}")


@dataclass
class ToolResult:
    """
    Result of a tool execution.

    Attributes:
        tool: Tool name
        status: Execution status ("success", "timeout", "error", "retry_exhausted")
        returncode: Process return code (or -1 if timeout/error)
        stdout: Standard output (empty if not captured)
        stderr: Standard error output
        attempts: Number of execution attempts made
        duration: Execution time in seconds
        output_file: Path to output file (if any)
        capture_stdout: Whether stdout was captured (if False, tool writes its own file)
        error_message: Error message (if status != "success")
    """

    tool: str
    status: str
    returncode: int = -1
    stdout: str = ""
    stderr: str = ""
    attempts: int = 1
    duration: float = 0.0
    output_file: Path | None = None
    capture_stdout: bool = False
    error_message: str = ""

    def is_success(self) -> bool:
        """Check if tool execution was successful."""
        return self.status == "success"

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON serialization."""
        return {
            "tool": self.tool,
            "status": self.status,
            "returncode": self.returncode,
            "attempts": self.attempts,
            "duration": self.duration,
            "output_file": str(self.output_file) if self.output_file else None,
            "error_message": self.error_message,
        }


class ToolRunner:
    """
    Execute security tools with timeout, retry, and parallel execution support.

    This class extracts the tool execution logic from cmd_scan() to improve
    testability, reusability, and maintainability.

    Example:
        >>> tools = [
        ...     ToolDefinition(
        ...         name="trufflehog",
        ...         command=["trufflehog", "filesystem", "/path/to/repo"],
        ...         output_file=Path("/tmp/trufflehog.json"),
        ...         timeout=300
        ...     ),
        ...     ToolDefinition(
        ...         name="semgrep",
        ...         command=["semgrep", "scan", "/path/to/repo"],
        ...         output_file=Path("/tmp/semgrep.json"),
        ...         timeout=600
        ...     )
        ... ]
        >>> runner = ToolRunner(tools, max_workers=2)
        >>> results = runner.run_all_parallel()
        >>> for result in results:
        ...     print(f"{result.tool}: {result.status}")
    """

    def __init__(
        self,
        tools: list[ToolDefinition],
        max_workers: int = 4,
        progress_callback: ProgressCallback | None = None,
    ):
        """
        Initialize ToolRunner.

        Args:
            tools: List of tool definitions to execute
            max_workers: Maximum number of parallel workers (default: 4)
            progress_callback: Optional callback for tool status updates.
                              Called with (tool_name, status, findings_count, **kwargs).
                              Status values: "start", "success", "error", "retrying", "timeout"
        """
        self.tools = tools
        self.max_workers = max_workers
        self.progress_callback = progress_callback

    @staticmethod
    def _classify_failure(exc: Exception | None, returncode: int | None) -> str:
        """Classify a failure into a type for retry budget lookup."""
        if isinstance(exc, subprocess.TimeoutExpired):
            return "timeout"
        if isinstance(exc, FileNotFoundError):
            return "missing_tool"
        if isinstance(exc, (OSError, PermissionError)):
            return "system_error"
        if exc is not None:
            return "unknown"
        # Non-exception failure (bad return code)
        return "crash"

    def run_tool(self, tool: ToolDefinition) -> ToolResult:
        """
        Run a single tool with timeout and typed retry support.

        Different failure types get different retry budgets:
        - timeout: max_attempts + timeout_retries (transient, worth retrying)
        - crash: max_attempts (bad exit code, may be transient)
        - missing_tool: 1 (never retry, tool won't appear)
        - system_error: max_attempts (OS/permission errors)

        Uses exponential backoff between retries, capped at backoff_max.

        Args:
            tool: Tool definition to execute

        Returns:
            ToolResult with execution status and metadata
        """
        start_time = time.time()
        rc = tool.retry_config
        attempt = 0
        last_error = ""

        # Track attempts per failure type
        attempts_by_type: dict[str, int] = {}

        while True:
            attempt += 1

            try:
                result = subprocess.run(
                    tool.command,
                    stdout=(
                        subprocess.PIPE if tool.capture_stdout else subprocess.DEVNULL
                    ),
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=tool.timeout,
                    check=False,  # Don't raise on non-zero exit
                )

                # Check if return code is acceptable
                if result.returncode in tool.ok_return_codes:
                    duration = time.time() - start_time
                    return ToolResult(
                        tool=tool.name,
                        status="success",
                        returncode=result.returncode,
                        stdout=result.stdout if tool.capture_stdout else "",
                        stderr=result.stderr,
                        attempts=attempt,
                        duration=duration,
                        output_file=tool.output_file,
                        capture_stdout=tool.capture_stdout,
                    )

                # Unacceptable return code -> classify as crash
                last_error = (
                    f"Return code {result.returncode} not in {tool.ok_return_codes}"
                )
                attempts_by_type["crash"] = attempts_by_type.get("crash", 0) + 1
                budget = rc.attempts_for_failure("crash")
                if attempts_by_type["crash"] < budget:
                    delay = rc.backoff_delay(attempts_by_type["crash"])
                    if delay > 0:
                        time.sleep(delay)
                    continue
                break  # Budget exhausted

            except subprocess.TimeoutExpired:
                last_error = f"Timeout after {tool.timeout}s"
                attempts_by_type["timeout"] = attempts_by_type.get("timeout", 0) + 1
                budget = rc.attempts_for_failure("timeout")

                if self.progress_callback:
                    self.progress_callback(
                        tool.name,
                        (
                            "retrying"
                            if attempts_by_type["timeout"] < budget
                            else "timeout"
                        ),
                        0,
                        message=f"Timeout after {tool.timeout}s",
                        attempt=attempt,
                        max_attempts=budget,
                    )
                else:
                    logger.warning(
                        f"{tool.name} timed out after {tool.timeout}s "
                        f"(attempt {attempts_by_type['timeout']}/{budget})"
                    )

                if attempts_by_type["timeout"] < budget:
                    delay = rc.backoff_delay(attempts_by_type["timeout"])
                    if delay > 0:
                        time.sleep(delay)
                    continue
                break  # Budget exhausted

            except FileNotFoundError:
                # Tool not found - never retry
                duration = time.time() - start_time
                return ToolResult(
                    tool=tool.name,
                    status="error",
                    returncode=-1,
                    attempts=attempt,
                    duration=duration,
                    error_message=f"Tool not found: {tool.command[0]}",
                )

            except (OSError, PermissionError) as e:
                last_error = str(e)
                attempts_by_type["system_error"] = (
                    attempts_by_type.get("system_error", 0) + 1
                )
                budget = rc.attempts_for_failure("system_error")
                logger.debug(f"{tool.name} execution failed: {e}")
                if attempts_by_type["system_error"] < budget:
                    delay = rc.backoff_delay(attempts_by_type["system_error"])
                    if delay > 0:
                        time.sleep(delay)
                    continue
                break

            except Exception as e:
                last_error = str(e)
                attempts_by_type["unknown"] = attempts_by_type.get("unknown", 0) + 1
                budget = rc.attempts_for_failure("unknown")
                logger.error(
                    f"Unexpected error running {tool.name}: {e}", exc_info=True
                )
                if attempts_by_type["unknown"] < budget:
                    delay = rc.backoff_delay(attempts_by_type["unknown"])
                    if delay > 0:
                        time.sleep(delay)
                    continue
                break

        # All retries exhausted for the last failure type
        duration = time.time() - start_time
        return ToolResult(
            tool=tool.name,
            status="retry_exhausted" if attempt > 1 else "error",
            returncode=-1,
            attempts=attempt,
            duration=duration,
            error_message=last_error,
        )

    def run_all_parallel(self) -> list[ToolResult]:
        """
        Run all tools in parallel using ThreadPoolExecutor.

        Tools are executed concurrently up to max_workers limit.
        Each tool has independent timeout and retry logic.

        Returns:
            List of ToolResult objects (one per tool)
        """
        results: list[ToolResult] = []

        # Signal start of all tools if progress callback exists
        if self.progress_callback:
            for tool in self.tools:
                try:
                    self.progress_callback(tool.name, "start", 0)
                except Exception:
                    pass  # Don't let callback errors affect scanning

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tool executions
            future_to_tool = {
                executor.submit(self.run_tool, tool): tool for tool in self.tools
            }

            # Collect results as they complete
            for future in as_completed(future_to_tool):
                try:
                    result = future.result()
                    results.append(result)

                    # Call progress callback on completion
                    if self.progress_callback:
                        try:
                            self.progress_callback(result.tool, result.status, 0)
                        except Exception:
                            pass  # Don't let callback errors affect scanning

                except ToolExecutionException as e:
                    # Tool execution raised our custom exception
                    tool = future_to_tool[future]
                    logger.error(f"Tool execution exception for {tool.name}: {e}")
                    error_result = ToolResult(
                        tool=tool.name,
                        status="error",
                        returncode=e.return_code,
                        attempts=1,
                        duration=0.0,
                        error_message=str(e),
                    )
                    results.append(error_result)

                    if self.progress_callback:
                        try:
                            self.progress_callback(tool.name, "error", 0)
                        except Exception:
                            pass

                except Exception as e:
                    # Unexpected exception from future (should rarely happen)
                    tool = future_to_tool[future]
                    logger.error(
                        f"Unexpected exception from future for {tool.name}: {e}",
                        exc_info=True,
                    )
                    error_result = ToolResult(
                        tool=tool.name,
                        status="error",
                        returncode=-1,
                        error_message=f"Unexpected error: {e}",
                    )
                    results.append(error_result)

                    if self.progress_callback:
                        try:
                            self.progress_callback(tool.name, "error", 0)
                        except Exception:
                            pass

        return results

    def run_all_serial(self) -> list[ToolResult]:
        """
        Run all tools serially (one at a time).

        Useful for debugging or when parallel execution causes issues.

        Returns:
            List of ToolResult objects (one per tool)
        """
        return [self.run_tool(tool) for tool in self.tools]

    def get_summary(self, results: list[ToolResult]) -> dict[str, Any]:
        """
        Generate summary statistics from tool results.

        Args:
            results: List of tool results

        Returns:
            Dictionary with summary statistics
        """
        total = len(results)
        successes = sum(1 for r in results if r.is_success())
        failures = total - successes
        total_duration = sum(r.duration for r in results)

        return {
            "total_tools": total,
            "successful": successes,
            "failed": failures,
            "success_rate": (successes / total * 100) if total > 0 else 0,
            "total_duration": total_duration,
            "average_duration": (total_duration / total) if total > 0 else 0,
            "results_by_status": {
                status: sum(1 for r in results if r.status == status)
                for status in set(r.status for r in results)
            },
        }


def run_tools(
    tools: list[ToolDefinition],
    max_workers: int = 4,
    parallel: bool = True,
) -> list[ToolResult]:
    """
    Convenience function to run tools with default ToolRunner.

    Args:
        tools: List of tool definitions
        max_workers: Maximum parallel workers (ignored if parallel=False)
        parallel: Whether to run tools in parallel (default: True)

    Returns:
        List of ToolResult objects
    """
    runner = ToolRunner(tools, max_workers=max_workers)
    return runner.run_all_parallel() if parallel else runner.run_all_serial()
