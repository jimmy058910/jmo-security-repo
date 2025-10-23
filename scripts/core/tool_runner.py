"""
Tool execution management for JMo Security.

This module provides the ToolRunner class for parallel/serial execution of security tools
with timeout, retry, and status tracking capabilities.

Created as part of PHASE 1 refactoring to extract tool execution logic from cmd_scan().
"""

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple, List, Dict, Any
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import subprocess
import time

from scripts.core.exceptions import ToolExecutionException

# Configure logging
logger = logging.getLogger(__name__)


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
    command: List[str]
    output_file: Optional[Path]
    timeout: int = 600
    retries: int = 0
    ok_return_codes: Tuple[int, ...] = (0, 1)
    capture_stdout: bool = False

    def __post_init__(self):
        """Validate tool definition after initialization."""
        if not self.name:
            raise ValueError("Tool name cannot be empty")
        if not self.command:
            raise ValueError("Tool command cannot be empty")
        if self.timeout <= 0:
            raise ValueError(f"Timeout must be positive, got {self.timeout}")
        if self.retries < 0:
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
    output_file: Optional[Path] = None
    capture_stdout: bool = False
    error_message: str = ""

    def is_success(self) -> bool:
        """Check if tool execution was successful."""
        return self.status == "success"

    def to_dict(self) -> Dict[str, Any]:
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

    def __init__(self, tools: List[ToolDefinition], max_workers: int = 4):
        """
        Initialize ToolRunner.

        Args:
            tools: List of tool definitions to execute
            max_workers: Maximum number of parallel workers (default: 4)
        """
        self.tools = tools
        self.max_workers = max_workers

    def run_tool(self, tool: ToolDefinition) -> ToolResult:
        """
        Run a single tool with timeout and retry support.

        This method wraps the tool execution with:
        - Timeout enforcement
        - Retry logic for transient failures
        - Return code validation
        - Error handling

        Args:
            tool: Tool definition to execute

        Returns:
            ToolResult with execution status and metadata
        """
        start_time = time.time()
        attempts = tool.retries + 1
        last_error = ""

        for attempt in range(1, attempts + 1):
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
                else:
                    # Unacceptable return code
                    last_error = (
                        f"Return code {result.returncode} not in {tool.ok_return_codes}"
                    )

                    # Don't retry for findings exit codes (1 usually means findings found)
                    if result.returncode == 1 and 1 in tool.ok_return_codes:
                        # This shouldn't happen (already checked above), but be defensive
                        break

                    # Retry for other error codes if retries available
                    if attempt < attempts:
                        time.sleep(1)  # Brief delay before retry
                        continue

            except subprocess.TimeoutExpired:
                last_error = f"Timeout after {tool.timeout}s"
                if attempt < attempts:
                    time.sleep(2)  # Longer delay after timeout
                    continue

            except FileNotFoundError:
                # Tool not found - no point retrying
                duration = time.time() - start_time
                return ToolResult(
                    tool=tool.name,
                    status="error",
                    returncode=-1,
                    attempts=attempt,
                    duration=duration,
                    error_message=f"Tool not found: {tool.command[0]}",
                )

            except subprocess.TimeoutExpired:
                # Tool timed out - log and retry if attempts remain
                last_error = f"Timeout after {tool.timeout}s"
                logger.debug(f"{tool.name} timed out (attempt {attempt}/{attempts})")
                if attempt < attempts:
                    time.sleep(1)
                    continue
            except (OSError, PermissionError) as e:
                # System errors (file not found, permissions, etc.)
                last_error = str(e)
                logger.debug(f"{tool.name} execution failed: {e}")
                if attempt < attempts:
                    time.sleep(1)
                    continue
            except Exception as e:
                # Unexpected errors - log with traceback
                last_error = str(e)
                logger.error(
                    f"Unexpected error running {tool.name}: {e}", exc_info=True
                )
                if attempt < attempts:
                    time.sleep(1)
                    continue

        # All retries exhausted
        duration = time.time() - start_time
        return ToolResult(
            tool=tool.name,
            status="retry_exhausted" if attempts > 1 else "error",
            returncode=-1,
            attempts=attempts,
            duration=duration,
            error_message=last_error,
        )

    def run_all_parallel(self) -> List[ToolResult]:
        """
        Run all tools in parallel using ThreadPoolExecutor.

        Tools are executed concurrently up to max_workers limit.
        Each tool has independent timeout and retry logic.

        Returns:
            List of ToolResult objects (one per tool)
        """
        results: List[ToolResult] = []

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
                except ToolExecutionException as e:
                    # Tool execution raised our custom exception
                    tool = future_to_tool[future]
                    logger.error(f"Tool execution exception for {tool.name}: {e}")
                    results.append(
                        ToolResult(
                            tool=tool.name,
                            status="error",
                            returncode=e.return_code,
                            attempts=1,
                            duration=0.0,
                            error_message=str(e),
                        )
                    )
                except Exception as e:
                    # Unexpected exception from future (should rarely happen)
                    tool = future_to_tool[future]
                    logger.error(
                        f"Unexpected exception from future for {tool.name}: {e}",
                        exc_info=True,
                    )
                    results.append(
                        ToolResult(
                            tool=tool.name,
                            status="error",
                            returncode=-1,
                            error_message=f"Unexpected error: {e}",
                        )
                    )

        return results

    def run_all_serial(self) -> List[ToolResult]:
        """
        Run all tools serially (one at a time).

        Useful for debugging or when parallel execution causes issues.

        Returns:
            List of ToolResult objects (one per tool)
        """
        return [self.run_tool(tool) for tool in self.tools]

    def get_summary(self, results: List[ToolResult]) -> Dict[str, Any]:
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
    tools: List[ToolDefinition],
    max_workers: int = 4,
    parallel: bool = True,
) -> List[ToolResult]:
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
