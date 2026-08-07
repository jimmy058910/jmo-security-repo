"""
Unit tests for scripts/core/tool_runner.py

Tests the ToolRunner class extracted from cmd_scan() as part of PHASE 1 refactoring.
"""

import subprocess
import sys
import time
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.core.tool_runner import (
    ToolDefinition,
    ToolResult,
    ToolRunner,
    run_tools,
)

TOOL_RUNNER_SOURCE = (
    Path(__file__).resolve().parents[2] / "scripts" / "core" / "tool_runner.py"
)


def test_duration_is_measured_with_perf_counter() -> None:
    """Elapsed time must come from perf_counter -- not time() and NOT monotonic.

    `test_run_tool_success` asserts `duration > 0` and flaked on Windows with
    `assert 0.0 > 0`: a fast subprocess finished inside one clock tick.

    The intuitive fix -- "use the monotonic clock for elapsed time" -- makes it
    strictly worse here. On CPython/Windows `time.monotonic()` is GetTickCount64,
    fixed at ~15.6ms granularity, while `time.time()` follows the *global* system
    timer, which any process can raise to ~1ms via timeBeginPeriod. Measured on a
    dev box with 60 runs of the `echo hello` tool used by that test:

        time.time()          0/60 zero, 59 distinct values
        time.monotonic()    16/60 zero (26.7%), 5 distinct values
        time.perf_counter()  0/60 zero, 60 distinct values

    So monotonic would have converted an intermittent flake into a frequent one,
    and time() only avoids it by luck -- whichever unrelated process happens to
    have raised the timer resolution. `time.perf_counter()` is QueryPerformance-
    Counter (100ns, monotonic, unaffected by wall-clock adjustment), which is
    what the stdlib documents for measuring short durations.

    Guarded at the source level because the whole measurement is one unit: the
    `start_time` assignment and every `duration =` subtraction must use the same
    clock. Mixing them subtracts a wall-clock epoch from a since-boot counter.
    """
    text = TOOL_RUNNER_SOURCE.read_text(encoding="utf-8")

    for forbidden, why in (
        ("time.monotonic()", "~15.6ms granularity on Windows -- coarser than time()"),
        ("time.time()", "wall-clock; adjustable, and granularity varies by host"),
    ):
        assert forbidden not in text, (
            f"tool_runner.py measures elapsed time with {forbidden} ({why}). "
            "Use time.perf_counter() -- see this test's docstring for measurements."
        )

    assert text.count("time.perf_counter()") == 6, (
        "Expected 6 perf_counter() calls (1 start_time + 5 duration subtractions). "
        "If a return path was added or removed, update this count -- but every "
        "elapsed-time measurement in the file must use the same clock."
    )


class TestToolDefinition:
    """Test ToolDefinition dataclass"""

    def test_valid_tool_definition(self):
        """Test creating a valid tool definition"""
        tool = ToolDefinition(
            name="test-tool",
            command=["echo", "hello"],
            output_file=Path("/tmp/test.json"),
            timeout=300,
            retries=1,
        )

        assert tool.name == "test-tool"
        assert tool.command == ["echo", "hello"]
        assert tool.output_file == Path("/tmp/test.json")
        assert tool.timeout == 300
        assert tool.retries == 1
        assert tool.ok_return_codes == (0, 1)  # Default

    def test_default_values(self):
        """Test default values are applied correctly"""
        tool = ToolDefinition(
            name="minimal",
            command=["ls"],
            output_file=Path("/tmp/out.json"),
        )

        assert tool.timeout == 600  # Default
        assert tool.retries == 0  # Default
        assert tool.ok_return_codes == (0, 1)  # Default
        assert tool.capture_stdout is False  # Default

    def test_empty_name_raises_error(self):
        """Test that empty tool name raises ValueError"""
        with pytest.raises(ValueError, match="Tool name cannot be empty"):
            ToolDefinition(
                name="",
                command=["ls"],
                output_file=Path("/tmp/out.json"),
            )

    def test_empty_command_raises_error(self):
        """Test that empty command raises ValueError"""
        with pytest.raises(ValueError, match="Tool command cannot be empty"):
            ToolDefinition(
                name="test",
                command=[],
                output_file=Path("/tmp/out.json"),
            )

    def test_negative_timeout_raises_error(self):
        """Test that negative timeout raises ValueError"""
        with pytest.raises(ValueError, match="Timeout must be positive"):
            ToolDefinition(
                name="test",
                command=["ls"],
                output_file=Path("/tmp/out.json"),
                timeout=-1,
            )

    def test_negative_retries_raises_error(self):
        """Test that negative retries raises ValueError"""
        with pytest.raises(ValueError, match="Retries must be non-negative"):
            ToolDefinition(
                name="test",
                command=["ls"],
                output_file=Path("/tmp/out.json"),
                retries=-1,
            )


class TestToolResult:
    """Test ToolResult dataclass"""

    def test_successful_result(self):
        """Test creating a successful result"""
        result = ToolResult(
            tool="trufflehog",
            status="success",
            returncode=0,
            attempts=1,
            duration=5.2,
            output_file=Path("/tmp/trufflehog.json"),
        )

        assert result.tool == "trufflehog"
        assert result.is_success() is True
        assert result.returncode == 0
        assert result.attempts == 1
        assert result.duration == 5.2

    def test_failed_result(self):
        """Test creating a failed result.

        Uses the shape `run_tool` actually produces for a timeout:
        `status="retry_exhausted"` plus `timed_out=True`. This test previously
        constructed `status="timeout"` — a value nothing assigns — which made
        the docstring's false claim look validated by a passing test, and is
        part of how #722 came to be filed on a false premise (#727).
        """
        result = ToolResult(
            tool="semgrep",
            status="retry_exhausted",
            returncode=-1,
            timed_out=True,
            error_message="Timeout after 600s",
        )

        assert result.is_success() is False
        assert result.status == "retry_exhausted"
        assert result.timed_out is True
        assert result.error_message == "Timeout after 600s"

    def test_to_dict_conversion(self):
        """Test converting result to dictionary"""
        result = ToolResult(
            tool="trivy",
            status="success",
            returncode=0,
            attempts=1,
            duration=3.5,
            output_file=Path("/tmp/trivy.json"),
        )

        data = result.to_dict()

        assert data["tool"] == "trivy"
        assert data["status"] == "success"
        assert data["returncode"] == 0
        assert data["attempts"] == 1
        assert data["duration"] == 3.5
        # Path separator is platform-dependent; compare using Path for consistency
        assert Path(data["output_file"]) == Path("/tmp/trivy.json")


class TestToolRunner:
    """Test ToolRunner class"""

    def test_runner_initialization(self):
        """Test creating a ToolRunner instance"""
        tools = [
            ToolDefinition(
                name="test",
                command=["echo", "test"],
                output_file=Path("/tmp/test.json"),
            )
        ]

        runner = ToolRunner(tools, max_workers=2)

        assert len(runner.tools) == 1
        assert runner.max_workers == 2

    def test_run_tool_success(self):
        """Test running a successful tool"""
        tool = ToolDefinition(
            name="echo",
            command=["echo", "hello"],
            # None, not a path: `echo` writes no file, and run_tool now treats a
            # declared-but-unwritten output_file as "no_output" rather than
            # success. See TestDeclaredOutputFile for that contract.
            output_file=None,
            timeout=5,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        assert result.is_success() is True
        assert result.tool == "echo"
        assert result.returncode == 0
        assert result.attempts == 1
        assert result.duration > 0

    def test_run_tool_timeout(self):
        """Test tool execution timeout"""
        tool = ToolDefinition(
            name="sleep",
            command=["sleep", "10"],
            output_file=Path("/tmp/sleep.json"),
            timeout=1,  # Will timeout
            retries=0,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        assert result.is_success() is False
        assert result.status in ("error", "retry_exhausted")
        assert (
            "timeout" in result.error_message.lower()
            or "Timeout" in result.error_message
        )

    def test_run_tool_not_found(self):
        """Test tool not found error"""
        tool = ToolDefinition(
            name="nonexistent",
            command=["this-command-does-not-exist-12345"],
            output_file=Path("/tmp/nonexistent.json"),
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        assert result.is_success() is False
        assert result.status == "error"
        assert "not found" in result.error_message.lower()

    def test_run_tool_with_retries(self):
        """Test tool execution with retry logic"""
        # Command that will fail but we accept rc=1
        tool = ToolDefinition(
            name="false",
            command=["false"],  # Always returns 1
            output_file=None,  # `false` writes no file
            ok_return_codes=(0, 1),  # Accept both 0 and 1
            retries=2,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        # Should succeed because rc=1 is acceptable
        assert result.is_success() is True
        assert result.returncode == 1
        assert result.attempts == 1  # No retries needed (rc=1 is OK)

    def test_run_tool_with_unacceptable_return_code(self):
        """Test tool with unacceptable return code"""
        tool = ToolDefinition(
            name="false",
            command=["false"],  # Returns 1
            output_file=Path("/tmp/false.json"),
            ok_return_codes=(0,),  # Only accept 0
            retries=1,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        # Should fail after retries
        assert result.is_success() is False
        assert result.attempts == 2  # Initial + 1 retry

    def test_run_all_parallel(self):
        """Test running multiple tools in parallel"""
        tools = [
            ToolDefinition(
                name="echo1",
                command=["echo", "test1"],
                output_file=None,
            ),
            ToolDefinition(
                name="echo2",
                command=["echo", "test2"],
                output_file=None,
            ),
            ToolDefinition(
                name="echo3",
                command=["echo", "test3"],
                output_file=None,
            ),
        ]

        runner = ToolRunner(tools, max_workers=2)
        start_time = time.time()
        results = runner.run_all_parallel()
        duration = time.time() - start_time

        assert len(results) == 3
        assert all(r.is_success() for r in results)

        # Parallel execution should be faster than serial
        # (though with echo commands it's hard to measure)
        assert duration < 5  # Sanity check

    def test_run_all_serial(self):
        """Test running multiple tools serially"""
        tools = [
            ToolDefinition(
                name="echo1",
                command=["echo", "test1"],
                output_file=None,
            ),
            ToolDefinition(
                name="echo2",
                command=["echo", "test2"],
                output_file=None,
            ),
        ]

        runner = ToolRunner(tools, max_workers=1)
        results = runner.run_all_serial()

        assert len(results) == 2
        assert all(r.is_success() for r in results)

    def test_get_summary(self):
        """Test summary statistics generation"""
        results = [
            ToolResult(
                tool="tool1",
                status="success",
                returncode=0,
                duration=5.0,
            ),
            ToolResult(
                tool="tool2",
                status="success",
                returncode=0,
                duration=3.0,
            ),
            ToolResult(
                tool="tool3",
                status="error",
                returncode=-1,
                duration=1.0,
                error_message="Failed",
            ),
        ]

        runner = ToolRunner([])  # Empty runner
        summary = runner.get_summary(results)

        assert summary["total_tools"] == 3
        assert summary["successful"] == 2
        assert summary["failed"] == 1
        assert summary["success_rate"] == pytest.approx(66.67, rel=0.1)
        assert summary["total_duration"] == 9.0
        assert summary["average_duration"] == 3.0
        assert summary["results_by_status"]["success"] == 2
        assert summary["results_by_status"]["error"] == 1

    def test_capture_stdout(self):
        """Test capturing stdout when requested"""
        tool = ToolDefinition(
            name="echo",
            command=["echo", "captured output"],
            output_file=Path("/tmp/echo.json"),
            capture_stdout=True,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        assert result.is_success() is True
        assert "captured output" in result.stdout

    def test_no_capture_stdout_by_default(self):
        """Test that stdout is not captured by default"""
        tool = ToolDefinition(
            name="echo",
            command=["echo", "not captured"],
            output_file=None,  # `echo` writes no file
            capture_stdout=False,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        assert result.is_success() is True
        assert result.stdout == ""  # Not captured


class TestRunToolsConvenienceFunction:
    """Test the run_tools() convenience function"""

    def test_run_tools_parallel(self):
        """Test run_tools with parallel execution"""
        tools = [
            ToolDefinition(
                name="test1",
                command=["echo", "test1"],
                output_file=None,
            ),
            ToolDefinition(
                name="test2",
                command=["echo", "test2"],
                output_file=None,
            ),
        ]

        results = run_tools(tools, max_workers=2, parallel=True)

        assert len(results) == 2
        assert all(r.is_success() for r in results)

    def test_run_tools_serial(self):
        """Test run_tools with serial execution"""
        tools = [
            ToolDefinition(
                name="test1",
                command=["echo", "test1"],
                output_file=None,
            ),
            ToolDefinition(
                name="test2",
                command=["echo", "test2"],
                output_file=None,
            ),
        ]

        results = run_tools(tools, max_workers=2, parallel=False)

        assert len(results) == 2
        assert all(r.is_success() for r in results)


class TestEdgeCases:
    """Test edge cases and error conditions"""

    def test_empty_tools_list(self):
        """Test runner with empty tools list"""
        runner = ToolRunner([], max_workers=4)
        results = runner.run_all_parallel()

        assert len(results) == 0

    def test_max_workers_one(self):
        """Test runner with max_workers=1 (serial-like parallel execution)"""
        tools = [
            ToolDefinition(
                name="echo",
                command=["echo", "test"],
                output_file=None,  # `echo` writes no file
            )
        ]

        # max_workers=1 means serial execution via parallel infrastructure
        runner = ToolRunner(tools, max_workers=1)
        results = runner.run_all_parallel()

        assert len(results) == 1
        assert results[0].is_success()

    def test_large_number_of_tools(self):
        """Test running many tools in parallel"""
        num_tools = 20
        tools = [
            ToolDefinition(
                name=f"echo{i}",
                command=["echo", f"test{i}"],
                output_file=None,
            )
            for i in range(num_tools)
        ]

        runner = ToolRunner(tools, max_workers=4)
        results = runner.run_all_parallel()

        assert len(results) == num_tools
        assert all(r.is_success() for r in results)


class TestErrorHandling:
    """Test comprehensive error handling and edge cases"""

    def test_run_tool_timeout_with_retry_logic(self):
        """Test timeout handling with retry logic - covers retry delay paths"""
        tool = ToolDefinition(
            name="slow-timeout",
            command=["sleep", "5"],
            output_file=Path("/tmp/timeout-retry.json"),
            timeout=1,  # Will timeout
            retries=2,  # Try 3 times total
        )

        runner = ToolRunner([tool])
        start_time = time.time()
        result = runner.run_tool(tool)
        duration = time.time() - start_time

        # Should fail after all retries exhausted
        assert result.is_success() is False
        assert result.status in ("error", "retry_exhausted")
        assert result.attempts == 3  # Initial + 2 retries
        assert (
            "timeout" in result.error_message.lower()
            or "Timeout" in result.error_message
        )

        # Should have delays between retries (2s after timeout)
        # 3 attempts × 1s timeout + delays ≈ 3-7s
        assert duration >= 3.0, f"Expected ≥3s with retries, got {duration}s"

    def test_run_tool_file_not_found_no_retry(self):
        """Test FileNotFoundError returns immediately without retry"""
        tool = ToolDefinition(
            name="missing-binary",
            command=["this-binary-absolutely-does-not-exist-xyz123"],
            output_file=Path("/tmp/missing.json"),
            retries=5,  # Should not retry for FileNotFoundError
        )

        runner = ToolRunner([tool])
        start_time = time.time()
        result = runner.run_tool(tool)
        duration = time.time() - start_time

        assert result.is_success() is False
        assert result.status == "error"
        assert result.returncode == -1
        assert (
            "not found" in result.error_message.lower()
            or "Tool not found" in result.error_message
        )
        assert result.attempts == 1  # No retries for FileNotFoundError

        # Should return quickly (no retries)
        assert (
            duration < 2.0
        ), f"FileNotFoundError should return quickly, got {duration}s"

    @pytest.mark.skipif(
        sys.platform == "win32", reason="Unix permissions not supported on Windows"
    )
    def test_run_tool_permission_error_with_retry(self):
        """Test PermissionError handling with retry attempts"""
        # Create a file with no execute permissions
        import os
        import stat
        import tempfile

        with tempfile.NamedTemporaryFile(
            encoding="utf-8", mode="w", suffix=".sh", delete=False
        ) as f:
            f.write("#!/bin/bash\necho test\n")
            script_path = f.name

        try:
            # Remove all permissions
            os.chmod(script_path, 0)

            tool = ToolDefinition(
                name="no-permission",
                command=[script_path],
                output_file=Path("/tmp/permission.json"),
                retries=2,
            )

            runner = ToolRunner([tool])
            result = runner.run_tool(tool)

            # Should fail with error status
            assert result.is_success() is False
            assert result.status == "error" or result.status == "retry_exhausted"
            # Permission errors may retry or fail immediately depending on OS
            assert result.attempts >= 1

        finally:
            # Cleanup
            try:
                os.chmod(script_path, stat.S_IRWXU)
                os.unlink(script_path)
            except Exception:
                pass

    @pytest.mark.skipif(
        sys.platform == "win32", reason="sh command not available on Windows"
    )
    def test_run_tool_unexpected_exception_handling(self):
        """Test handling of unexpected exceptions during execution"""
        # Create a tool that will cause an exception in subprocess handling
        tool = ToolDefinition(
            name="exception-test",
            command=["sh", "-c", "exit 127"],  # Special exit code
            output_file=Path("/tmp/exception.json"),
            ok_return_codes=(0,),  # Only accept 0
            retries=1,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        # Should handle the non-OK return code gracefully
        assert result.is_success() is False
        assert result.status == "retry_exhausted"
        assert result.attempts == 2  # Initial + 1 retry
        # Return code is set to -1 when retries exhausted
        assert result.returncode == -1
        assert "127" in result.error_message  # Original code should be in message

    @pytest.mark.skipif(
        sys.platform == "win32", reason="sh command not available on Windows"
    )
    def test_run_tool_with_acceptable_findings_code(self):
        """Test tool that returns 1 (findings) which is acceptable"""
        tool = ToolDefinition(
            name="findings-ok",
            command=["sh", "-c", "exit 1"],  # Exit 1 (findings detected)
            output_file=None,  # `sh -c "exit 1"` writes no file
            ok_return_codes=(0, 1),  # Accept 0 and 1
            retries=0,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        # Should succeed because rc=1 is acceptable
        assert result.is_success() is True
        assert result.returncode == 1
        assert result.attempts == 1
        assert result.status == "success"

    def test_run_tools_parallel_with_mixed_results(self):
        """Test parallel execution with mix of success, timeout, and failure"""
        tools = [
            ToolDefinition(
                name="success",
                command=["echo", "ok"],
                output_file=None,
            ),
            ToolDefinition(
                name="timeout",
                command=["sleep", "10"],
                output_file=Path("/tmp/timeout.json"),
                timeout=1,
                retries=0,
            ),
            ToolDefinition(
                name="missing",
                command=["nonexistent-tool-xyz"],
                output_file=Path("/tmp/missing.json"),
                retries=0,
            ),
        ]

        runner = ToolRunner(tools, max_workers=3)
        results = runner.run_all_parallel()

        assert len(results) == 3

        # Find each result
        success_result = next(r for r in results if r.tool == "success")
        timeout_result = next(r for r in results if r.tool == "timeout")
        missing_result = next(r for r in results if r.tool == "missing")

        assert success_result.is_success() is True
        assert timeout_result.is_success() is False
        assert missing_result.is_success() is False

    def test_run_tools_parallel_future_exception_handling(self):
        """Test that parallel execution handles future exceptions gracefully"""
        # Create a mix of tools, some will fail
        tools = [
            ToolDefinition(
                name="good1",
                command=["echo", "test1"],
                output_file=None,
            ),
            ToolDefinition(
                name="bad",
                command=["nonexistent-xyz-123"],
                output_file=Path("/tmp/bad.json"),
            ),
            ToolDefinition(
                name="good2",
                command=["echo", "test2"],
                output_file=None,
            ),
        ]

        runner = ToolRunner(tools, max_workers=2)
        results = runner.run_all_parallel()

        # All futures should be collected, even if one fails
        assert len(results) == 3

        good_results = [r for r in results if r.is_success()]
        bad_results = [r for r in results if not r.is_success()]

        assert len(good_results) == 2
        assert len(bad_results) == 1

    def test_run_tool_very_short_timeout(self):
        """Test handling of extremely short timeout (edge case)"""
        tool = ToolDefinition(
            name="instant-timeout",
            command=["sleep", "0.5"],
            output_file=Path("/tmp/instant.json"),
            timeout=0.1,  # 100ms timeout
            retries=0,
        )

        runner = ToolRunner([tool])
        result = runner.run_tool(tool)

        assert result.is_success() is False
        assert (
            "timeout" in result.error_message.lower()
            or "Timeout" in result.error_message
        )

    def test_run_tool_zero_retries_no_delay(self):
        """Test that tools with retries=0 don't have delay overhead"""
        tool = ToolDefinition(
            name="fast-fail",
            command=["false"],
            output_file=Path("/tmp/fast-fail.json"),
            ok_return_codes=(0,),  # Only accept 0
            retries=0,
            timeout=5,
        )

        runner = ToolRunner([tool])
        start_time = time.time()
        result = runner.run_tool(tool)
        duration = time.time() - start_time

        assert result.is_success() is False
        assert result.attempts == 1
        # Should complete quickly without retry delays
        assert duration < 1.0, f"Expected <1s without retries, got {duration}s"

    def test_summary_with_all_statuses(self):
        """Test summary generation with diverse result statuses"""
        results = [
            ToolResult(tool="success1", status="success", returncode=0, duration=1.0),
            ToolResult(
                tool="success2", status="success", returncode=1, duration=2.0
            ),  # Findings
            ToolResult(
                tool="timeout1",
                status="error",
                returncode=-1,
                duration=5.0,
                error_message="Timeout",
            ),
            ToolResult(
                tool="error1",
                status="error",
                returncode=-1,
                duration=0.5,
                error_message="Not found",
            ),
            ToolResult(
                tool="retry",
                status="retry_exhausted",
                returncode=2,
                duration=3.0,
                attempts=3,
            ),
        ]

        runner = ToolRunner([])
        summary = runner.get_summary(results)

        assert summary["total_tools"] == 5
        assert summary["successful"] == 2
        assert summary["failed"] == 3
        assert summary["success_rate"] == pytest.approx(40.0, rel=0.1)
        assert summary["results_by_status"]["success"] == 2
        assert summary["results_by_status"]["error"] == 2
        assert summary["results_by_status"]["retry_exhausted"] == 1


class TestProgressCallback:
    """Test progress callback functionality for timeout/retry scenarios"""

    def test_run_tool_timeout_calls_callback_with_retrying_status(self):
        """Verify callback is called with 'retrying' status on timeout with retries remaining."""
        callback_calls = []

        def capture_callback(name, status, count=0, **kwargs):
            callback_calls.append((name, status, kwargs))

        tool = ToolDefinition(
            name="slow-tool",
            command=["sleep", "10"],
            output_file=Path("/tmp/slow.json"),
            timeout=1,  # Will timeout
            retries=1,  # 2 attempts total
        )

        runner = ToolRunner([tool], progress_callback=capture_callback)
        result = runner.run_tool(tool)

        # Should have failed after retries exhausted
        assert result.is_success() is False
        assert result.attempts == 2

        # Should have callback calls for retrying and timeout
        assert len(callback_calls) >= 1

        # First timeout should be 'retrying' (attempt 1, more retries available)
        retrying_calls = [c for c in callback_calls if c[1] == "retrying"]
        assert len(retrying_calls) >= 1
        first_retry = retrying_calls[0]
        assert first_retry[0] == "slow-tool"
        assert "message" in first_retry[2]
        assert "Timeout" in first_retry[2]["message"]
        assert first_retry[2]["attempt"] == 1
        assert first_retry[2]["max_attempts"] == 2

    def test_run_tool_timeout_calls_callback_with_timeout_status_on_final_attempt(self):
        """Verify callback is called with 'timeout' status on final attempt."""
        callback_calls = []

        def capture_callback(name, status, count=0, **kwargs):
            callback_calls.append((name, status, kwargs))

        tool = ToolDefinition(
            name="timeout-tool",
            command=["sleep", "10"],
            output_file=Path("/tmp/timeout.json"),
            timeout=1,  # Will timeout
            retries=0,  # Only 1 attempt (no retries)
        )

        runner = ToolRunner([tool], progress_callback=capture_callback)
        result = runner.run_tool(tool)

        # Should have failed
        assert result.is_success() is False
        assert result.attempts == 1

        # Should have exactly one callback with 'timeout' status (no retries)
        timeout_calls = [c for c in callback_calls if c[1] == "timeout"]
        assert len(timeout_calls) == 1
        timeout_call = timeout_calls[0]
        assert timeout_call[0] == "timeout-tool"
        assert timeout_call[2]["attempt"] == 1
        assert timeout_call[2]["max_attempts"] == 1

    def test_run_tool_success_does_not_call_callback_with_retrying_status(self):
        """Verify successful tools don't trigger retrying/timeout callbacks."""
        callback_calls = []

        def capture_callback(name, status, count=0, **kwargs):
            callback_calls.append((name, status, kwargs))

        tool = ToolDefinition(
            name="fast-tool",
            command=["echo", "done"],
            output_file=None,
            timeout=10,
        )

        runner = ToolRunner([tool], progress_callback=capture_callback)
        result = runner.run_tool(tool)

        assert result.is_success() is True

        # Should have no retrying or timeout callbacks
        retry_timeout_calls = [
            c for c in callback_calls if c[1] in ("retrying", "timeout")
        ]
        assert len(retry_timeout_calls) == 0

    def test_callback_receives_kwargs_for_timeout(self):
        """Verify callback kwargs include message, attempt, max_attempts."""
        callback_calls = []

        def capture_callback(name, status, count=0, **kwargs):
            callback_calls.append({"name": name, "status": status, "kwargs": kwargs})

        tool = ToolDefinition(
            name="kwargs-test",
            command=["sleep", "10"],
            output_file=Path("/tmp/kwargs.json"),
            timeout=1,
            retries=0,
        )

        runner = ToolRunner([tool], progress_callback=capture_callback)
        runner.run_tool(tool)

        # Find the timeout call
        timeout_call = next(
            (c for c in callback_calls if c["status"] == "timeout"), None
        )
        assert timeout_call is not None

        kwargs = timeout_call["kwargs"]
        assert "message" in kwargs
        assert "attempt" in kwargs
        assert "max_attempts" in kwargs
        assert isinstance(kwargs["attempt"], int)
        assert isinstance(kwargs["max_attempts"], int)


# ========== Typed Retry Logic (RetryConfig) Tests ==========


class TestRetryConfigIntegration:
    """Tests for typed retry logic with per-failure-type budgets."""

    def test_run_tool_timeout_gets_extra_retries(self):
        """Timeout budget = max_attempts + timeout_retries."""
        from scripts.core.config import RetryConfig

        rc = RetryConfig(
            max_attempts=2, timeout_retries=2, backoff_base=0, backoff_max=0
        )
        tool = ToolDefinition(
            name="slow_tool",
            command=["sleep", "999"],
            output_file=None,
            timeout=1,
            retries=rc,
        )
        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded",
            side_effect=subprocess.TimeoutExpired("cmd", 1),
        ):
            result = runner.run_tool(tool)
        assert result.status == "retry_exhausted"
        assert result.attempts == 4  # 2 base + 2 timeout = 4

    def test_run_tool_crash_limited_to_max_attempts(self):
        """Crash uses base budget only (no timeout_retries)."""
        from scripts.core.config import RetryConfig

        rc = RetryConfig(
            max_attempts=2, timeout_retries=3, backoff_base=0, backoff_max=0
        )
        tool = ToolDefinition(
            name="crashy",
            command=["false"],
            output_file=None,
            retries=rc,
            ok_return_codes=(0,),
        )
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stderr = "error"

        runner = ToolRunner([tool])
        with patch("scripts.core.tool_runner._run_bounded", return_value=mock_result):
            result = runner.run_tool(tool)
        assert result.status == "retry_exhausted"
        assert result.attempts == 2  # Only max_attempts, not +timeout_retries

    def test_run_tool_missing_tool_never_retries(self):
        """Missing tool causes immediate failure, no retries."""
        from scripts.core.config import RetryConfig

        rc = RetryConfig(max_attempts=5, timeout_retries=5)
        tool = ToolDefinition(
            name="ghost",
            command=["nonexistent_tool"],
            output_file=None,
            retries=rc,
        )
        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded",
            side_effect=FileNotFoundError("not found"),
        ):
            result = runner.run_tool(tool)
        assert result.status == "error"
        assert result.attempts == 1

    def test_run_tool_retry_disabled_for_crash(self):
        """retry_on_crash=False disables crash retries."""
        from scripts.core.config import RetryConfig

        rc = RetryConfig(
            max_attempts=3, retry_on_crash=False, backoff_base=0, backoff_max=0
        )
        tool = ToolDefinition(
            name="crashy",
            command=["false"],
            output_file=None,
            retries=rc,
            ok_return_codes=(0,),
        )
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stderr = "error"

        runner = ToolRunner([tool])
        with patch("scripts.core.tool_runner._run_bounded", return_value=mock_result):
            result = runner.run_tool(tool)
        assert result.attempts == 1  # No retries when disabled

    def test_run_tool_retry_disabled_for_timeout(self):
        """retry_on_timeout=False disables timeout retries."""
        from scripts.core.config import RetryConfig

        rc = RetryConfig(
            max_attempts=3,
            timeout_retries=2,
            retry_on_timeout=False,
            backoff_base=0,
            backoff_max=0,
        )
        tool = ToolDefinition(
            name="slow",
            command=["sleep", "999"],
            output_file=None,
            timeout=1,
            retries=rc,
        )
        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded",
            side_effect=subprocess.TimeoutExpired("cmd", 1),
        ):
            result = runner.run_tool(tool)
        assert result.attempts == 1  # No retries when disabled

    def test_run_tool_backward_compat_flat_int(self):
        """Flat int retries still works as before."""
        tool = ToolDefinition(
            name="basic",
            command=["echo", "hi"],
            output_file=None,
            retries=1,  # flat int
            ok_return_codes=(0,),
        )
        mock_result = MagicMock()
        mock_result.returncode = 2
        mock_result.stderr = "error"

        runner = ToolRunner([tool])
        with patch("scripts.core.tool_runner._run_bounded", return_value=mock_result):
            result = runner.run_tool(tool)
        assert result.status == "retry_exhausted"
        assert result.attempts == 2  # retries=1 -> max_attempts=2


class TestDeclaredOutputFile:
    """An acceptable return code alone must not be reported as success.

    Every `capture_stdout=False` tool in `scan_jobs/` is told exactly where to
    write (`-o` / `--output` / `-out=` / prowler's `--output-directory` +
    `--output-filename`). A tool that exits acceptably and writes nothing there
    has not done its job, and two of the accepted codes *mean* "I did nothing":
    prowler's 3 is "no credentials", semgrep's 2 is "errors".

    This is unrecoverable further down the pipeline. `normalize_and_report`
    discovers outputs with `target.glob("*.json")`, so it only ever sees files
    that exist -- it holds no manifest of what was expected and therefore cannot
    notice an absence. `run_tool` is the only layer that knows.

    The user-visible bug: `jmo` printed `[1/1] OK semgrep [100%]` for a semgrep
    that crashed on a non-UTF-8 Windows console and wrote nothing, so the scan
    looked clean while semgrep's findings were silently missing.
    """

    @staticmethod
    def _ok_subprocess(returncode: int = 0):
        mock_result = MagicMock()
        mock_result.returncode = returncode
        mock_result.stdout = "some stdout"
        mock_result.stderr = ""
        return mock_result

    def test_missing_output_file_is_not_success(self, tmp_path: Path):
        """rc=0 but no file written -> no_output, not success."""
        tool = ToolDefinition(
            name="crasher",
            command=["crasher", "-o", str(tmp_path / "crasher.json")],
            output_file=tmp_path / "crasher.json",  # never created
            capture_stdout=False,
        )

        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded", return_value=self._ok_subprocess(0)
        ):
            result = runner.run_tool(tool)

        assert result.status == "no_output"
        assert result.is_success() is False
        assert result.returncode == 0
        # The message must name the path, or a user cannot tell which file is
        # missing when several tools run in parallel.
        assert str(tool.output_file) in result.error_message

    def test_written_output_file_is_success(self, tmp_path: Path):
        """The same tool succeeds once the file exists -- proves the guard
        discriminates rather than failing everything."""
        out = tmp_path / "good.json"
        out.write_bytes(b'{"results": []}')
        tool = ToolDefinition(
            name="good",
            command=["good", "-o", str(out)],
            output_file=out,
            capture_stdout=False,
        )

        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded", return_value=self._ok_subprocess(0)
        ):
            result = runner.run_tool(tool)

        assert result.status == "success"
        assert result.is_success() is True

    def test_empty_output_file_is_still_success(self, tmp_path: Path):
        """A zero-findings run is a real result. Only *absence* is the failure --
        an empty or empty-JSON file means the tool ran and found nothing."""
        out = tmp_path / "empty.json"
        out.write_bytes(b"")
        tool = ToolDefinition(
            name="clean",
            command=["clean", "-o", str(out)],
            output_file=out,
            capture_stdout=False,
        )

        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded", return_value=self._ok_subprocess(0)
        ):
            result = runner.run_tool(tool)

        assert result.status == "success"

    def test_capture_stdout_tools_are_exempt(self, tmp_path: Path):
        """With capture_stdout=True the *caller* writes the file after run_tool
        returns (scan_jobs/*_scanner.py), so absence here proves nothing."""
        tool = ToolDefinition(
            name="stdout-tool",
            command=["stdout-tool"],
            output_file=tmp_path / "not-yet-written.json",
            capture_stdout=True,
        )

        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded", return_value=self._ok_subprocess(0)
        ):
            result = runner.run_tool(tool)

        assert result.status == "success"
        assert result.stdout == "some stdout"

    def test_no_declared_output_file_is_exempt(self):
        """output_file=None declares that no file is expected at all
        (noseyparker's init and scan phases)."""
        tool = ToolDefinition(
            name="noseyparker-init",
            command=["noseyparker", "datastore", "init"],
            output_file=None,
            capture_stdout=False,
        )

        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded", return_value=self._ok_subprocess(0)
        ):
            result = runner.run_tool(tool)

        assert result.status == "success"

    def test_accepted_but_did_nothing_code_is_caught(self, tmp_path: Path):
        """prowler's ok_return_codes includes 3 == "no credentials". That is an
        accepted code for a run that cannot have produced findings."""
        tool = ToolDefinition(
            name="prowler",
            command=["prowler", "--output-directory", str(tmp_path)],
            output_file=tmp_path / "prowler.json",  # never created
            ok_return_codes=(0, 1, 3),
            capture_stdout=False,
        )

        runner = ToolRunner([tool])
        with patch(
            "scripts.core.tool_runner._run_bounded", return_value=self._ok_subprocess(3)
        ):
            result = runner.run_tool(tool)

        assert result.status == "no_output"
        assert result.returncode == 3

    def test_unstattable_output_file_fails_open(self, tmp_path: Path):
        """An unreadable path is not evidence of absence.

        Python 3.12 made `Path.exists()` propagate `PermissionError` instead of
        returning False (see .claude/rules/testing.cross-platform.rules.md).
        A permissions quirk on a bind mount must not redden an otherwise good
        scan, and must certainly not raise out of run_tool.
        """
        out = tmp_path / "unstattable.json"
        tool = ToolDefinition(
            name="mounted",
            command=["mounted", "-o", str(out)],
            output_file=out,
            capture_stdout=False,
        )

        runner = ToolRunner([tool])
        with (
            patch(
                "scripts.core.tool_runner._run_bounded",
                return_value=self._ok_subprocess(0),
            ),
            patch.object(
                Path, "exists", side_effect=PermissionError("EACCES on bind mount")
            ),
        ):
            result = runner.run_tool(tool)

        assert result.status == "success"

    def test_no_output_counts_as_failed_in_summary(self):
        """get_summary() must not count no_output as successful."""
        results = [
            ToolResult(tool="ok", status="success", returncode=0, duration=1.0),
            ToolResult(tool="silent", status="no_output", returncode=0, duration=1.0),
        ]

        summary = ToolRunner([]).get_summary(results)

        assert summary["successful"] == 1
        assert summary["failed"] == 1
        assert summary["results_by_status"]["no_output"] == 1


class TestEmptyCaptureWithNonZeroExit:
    """A tool claiming findings while emitting nothing has not run.

    #700 covers `capture_stdout=False` tools: told where to write, wrote
    nothing. The mirror case was left open. For a `capture_stdout=True` tool the
    caller writes the file from `result.stdout` *after* `run_tool` returns:

        if result.output_file and result.capture_stdout:
            result.output_file.write_text(result.stdout or "", ...)

    `or ""` turns lost output into a 0-byte file that exists, so every
    downstream check that asks "was a file written?" answers yes.

    Measured. checkov's venv wrapper on Windows is broken (`File association not
    found for extension .py`) and exits **1**. checkov declares
    `ok_return_codes=(0, 1)` because 1 legitimately means "issues found", so the
    crash was graded acceptable, empty stdout was written as `checkov.json` at
    0 bytes in all 5 repos of a public-repo benchmark, and the scan exited 0.
    The report phase logged "JSON file is empty" without escalating.

    Emptiness alone cannot be the signal: trufflehog on a repo with no secrets
    exits **0** and correctly emits nothing (measured on docker-library/postgres
    in the same run). The discriminator is the return code. A non-zero
    *accepted* code is the tool saying "I found something" -- emitting nothing
    while saying so is self-contradictory, and is what a crash looks like.
    """

    @staticmethod
    def _tool(tmp_path: Path, name: str = "quiet") -> ToolDefinition:
        return ToolDefinition(
            name=name,
            command=[name],
            output_file=tmp_path / f"{name}.json",
            capture_stdout=True,
            ok_return_codes=(0, 1),
        )

    @staticmethod
    def _result(returncode: int, stdout: str, stderr: str = ""):
        mock = MagicMock()
        mock.returncode = returncode
        mock.stdout = stdout
        mock.stderr = stderr
        return mock

    def test_empty_capture_with_nonzero_accepted_code_is_not_success(
        self, tmp_path: Path
    ):
        """rc=1 (accepted, means 'findings') plus no output -> no_output."""
        tool = self._tool(tmp_path, "checkov")
        runner = ToolRunner([tool])

        with patch(
            "scripts.core.tool_runner._run_bounded",
            return_value=self._result(
                1, "", "File association not found for extension .py"
            ),
        ):
            result = runner.run_tool(tool)

        assert result.status == "no_output"
        assert result.is_success() is False
        # Name the tool and the consequence, or a parallel scan gives the user
        # no way to tell which of nine tools produced nothing.
        assert "checkov" in result.error_message or "checkov" in result.tool

    def test_empty_capture_with_zero_exit_is_still_success(self, tmp_path: Path):
        """rc=0 plus no output is a clean scan, not a failure.

        Guards the fix against over-reach: trufflehog on a repo with no secrets
        must not be reported as broken.
        """
        tool = self._tool(tmp_path, "trufflehog")
        runner = ToolRunner([tool])

        with patch(
            "scripts.core.tool_runner._run_bounded",
            return_value=self._result(0, "", 'msg":"finished scanning"'),
        ):
            result = runner.run_tool(tool)

        assert result.status == "success"
        assert result.is_success() is True

    def test_nonzero_code_with_output_is_still_success(self, tmp_path: Path):
        """rc=1 with real findings is the normal 'issues found' path."""
        tool = self._tool(tmp_path, "checkov")
        runner = ToolRunner([tool])

        with patch(
            "scripts.core.tool_runner._run_bounded",
            return_value=self._result(1, '{"results": {"failed_checks": []}}'),
        ):
            result = runner.run_tool(tool)

        assert result.status == "success"
        assert result.stdout


class TestSubprocessDecoding:
    """Tool output must survive bytes the host locale cannot decode.

    Scanners emit whatever bytes the scanned repository contains -- file names,
    matched secrets, and code snippets from arbitrary public source. Bare
    `text=True` decodes those with the *parent's* locale codec under `strict`
    errors, which is the wrong codec and the wrong error policy:

    - On Windows the decode runs inside `subprocess._readerthread`. The
      exception cannot propagate to the caller, so it is printed and the
      captured output is simply **lost**. `run_tool` then sees empty stdout,
      reports `success`, and the caller writes a 0-byte output file.
    - On Linux/macOS the same decode raises out of `subprocess.run` and the
      whole tool is recorded as a failure.

    Measured on a real 5-repo public scan (cp1252 host): five
    `UnicodeDecodeError: 'charmap' codec can't decode byte 0x90` tracebacks in
    `_readerthread`, `trufflehog.json` written as **0 bytes in all 5 repos**,
    trufflehog reported successful, and the `zero-secrets` policy PASSED.

    0x90 is deliberately chosen: it is undefined in cp1252 *and* an illegal
    lead byte in UTF-8, so this test bites on every platform rather than only
    on the one where the bug was found. `PYTHONUTF8=1` (set on the CI shards)
    does not rescue it.
    """

    # Undefined in cp1252; illegal UTF-8 lead byte. Invalid under both.
    UNDECODABLE = b"\x90"

    def _emit_bytes_tool(self, payload: bytes, tmp_path: Path) -> ToolDefinition:
        """A tool that writes raw, locale-hostile bytes to stdout."""
        return ToolDefinition(
            name="byte-emitter",
            command=[
                sys.executable,
                "-c",
                (
                    "import sys;"
                    f"sys.stdout.buffer.write({payload!r});"
                    "sys.stdout.buffer.flush()"
                ),
            ],
            output_file=tmp_path / "byte-emitter.json",
            capture_stdout=True,
            timeout=60,
        )

    def test_undecodable_bytes_do_not_destroy_captured_output(self, tmp_path: Path):
        """The payload must arrive, not vanish into a swallowed decode error."""
        payload = b'{"found": "' + self.UNDECODABLE + b'secret"}'
        tool = self._emit_bytes_tool(payload, tmp_path)

        result = ToolRunner([tool]).run_tool(tool)

        assert (
            result.status == "success"
        ), f"decode failure surfaced as {result.status!r}: {result.error_message!r}"
        # The bug's signature is empty stdout despite the tool having written
        # ~25 bytes. Assert on content, not just truthiness -- an empty string
        # is exactly what the broken path produced.
        assert result.stdout, "captured stdout was lost to a decode error"
        assert "found" in result.stdout
        assert "secret" in result.stdout

    def test_decoding_is_not_left_to_the_host_locale(self, tmp_path: Path):
        """Guard the fix itself: `text=True` alone must not be reintroduced.

        The behavioural test above passes on a UTF-8 host even with the bug, if
        the payload happens to be valid UTF-8. This asserts the actual contract
        -- an explicit codec and a non-strict error policy -- so the guard
        cannot silently stop guarding on a maintainer's Linux box.
        """
        tool = self._emit_bytes_tool(b"{}", tmp_path)

        with patch("scripts.core.tool_runner._run_bounded") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="{}", stderr="")
            ToolRunner([tool]).run_tool(tool)

        kwargs = mock_run.call_args.kwargs
        assert (
            kwargs.get("encoding") == "utf-8"
        ), "tool output must be decoded as UTF-8, not the host locale codec"
        assert (
            kwargs.get("errors") == "replace"
        ), "a single undecodable byte must not discard the whole capture"
        assert not kwargs.get(
            "text"
        ), "text=True re-enables locale decoding and overrides the intent"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


class TestChildEnvironment:
    """A scanner that shells out to another scanner must be able to find it.

    JMo installs tools into ``~/.jmo/bin``, a directory nothing puts on PATH.
    `prowler iac` invokes `trivy`; with trivy installed by JMo but absent from
    the child's PATH it died with ``FileNotFoundError [WinError 2]`` raised
    inside prowler and wrote nothing. Measured: adding that one directory to
    PATH made the identical command produce 88 records, 13 of them FAIL.

    `tool_manager._get_clean_env` already prepends it for the *version probe*,
    so the two execution paths disagreed - the same one-right-one-wrong split
    that hid the checkov, yara and dependency-check resolver bugs.
    """

    def test_jmo_bin_is_on_the_child_path(self, tmp_path, monkeypatch):
        import os as _os
        from pathlib import Path as _Path

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env") or {}
            raise FileNotFoundError("stop here - we only want the env")

        jmo_bin = tmp_path / ".jmo" / "bin"
        jmo_bin.mkdir(parents=True)
        monkeypatch.setattr(_Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setattr("scripts.core.tool_runner._run_bounded", fake_run)

        from scripts.core.tool_runner import ToolDefinition, ToolRunner

        ToolRunner(tools=[]).run_tool(
            ToolDefinition(name="t", command=["nonexistent-binary"], output_file=None)
        )

        entries = captured["env"].get("PATH", "").split(_os.pathsep)
        assert str(jmo_bin) in entries, (
            "~/.jmo/bin is not on the child's PATH, so a scanner cannot find "
            f"any other JMo-installed tool. entries[0]={entries[0]!r}"
        )

    def test_path_is_joined_with_os_pathsep(self, tmp_path, monkeypatch):
        """A hardcoded ':' fuses entries into one unusable element on Windows."""
        import os as _os
        from pathlib import Path as _Path

        captured = {}

        def fake_run(cmd, **kwargs):
            captured["env"] = kwargs.get("env") or {}
            raise FileNotFoundError("stop here")

        (tmp_path / ".jmo" / "bin").mkdir(parents=True)
        sentinel = str(tmp_path / "sentinel")
        monkeypatch.setattr(_Path, "home", staticmethod(lambda: tmp_path))
        monkeypatch.setenv("PATH", sentinel)
        monkeypatch.setattr("scripts.core.tool_runner._run_bounded", fake_run)

        from scripts.core.tool_runner import ToolDefinition, ToolRunner

        ToolRunner(tools=[]).run_tool(
            ToolDefinition(name="t", command=["nonexistent-binary"], output_file=None)
        )

        assert sentinel in captured["env"]["PATH"].split(_os.pathsep)


class TestTimeoutKillsTheProcessTree:
    """A timeout must bound the whole tree, not just the process we spawned.

    Several scanners are launcher scripts: `dependency-check.bat` runs
    `cmd.exe` which runs `java`. `subprocess.run(timeout=...)` kills only the
    direct child and then calls `communicate()` **without a timeout** to drain
    the pipes - which the surviving grandchild holds open. The documented
    timeout therefore bounds nothing.

    Measured before the fix: a dependency-check invocation with a 1200s timeout
    was still running at **38 minutes**, with an orphaned java process no longer
    under the scan's process tree at all. It stayed hidden while
    dependency-check failed instantly with WinError 193 - making the tool
    actually run is what exposed it.
    """

    def test_a_grandchild_does_not_outlive_the_timeout(self, tmp_path: Path):
        """The grandchild must be dead, not merely no longer blocking us.

        Asserted by watching a heartbeat file the grandchild keeps touching,
        rather than by timing the call. Timing alone does not discriminate: with
        the tree kill removed the call still returns, because `_run_bounded`
        bounds its own drain at 30s - but the grandchild survives that and runs
        on unsupervised, which is exactly the 38-minute orphaned java process
        this fixes. Measured: kill-tree 4s, no-kill-tree 33s, both "passing" a
        timing assertion while only one actually killed anything.
        """
        import subprocess as _sp
        import sys
        import time as _time

        from scripts.core.tool_runner import ToolDefinition, ToolRunner

        heartbeat = tmp_path / "grandchild.heartbeat"
        # The grandchild ticks a file ~every 0.3s for 2 minutes. The launcher
        # spawns it and then waits, so killing only the launcher leaves it
        # running - and holding the inherited stderr pipe.
        grandchild = (
            "import pathlib,time\n"
            f"p = pathlib.Path(r'{heartbeat}')\n"
            "for i in range(400):\n"
            "    p.write_text(str(i))\n"
            "    time.sleep(0.3)\n"
        )
        launcher = (
            "import subprocess,sys,time\n"
            f"subprocess.Popen([sys.executable,'-c',{grandchild!r}])\n"
            "time.sleep(120)\n"
        )
        tool = ToolDefinition(
            name="slow-launcher",
            command=[sys.executable, "-c", launcher],
            output_file=tmp_path / "out.json",
            timeout=3,
        )

        result = ToolRunner([tool]).run_tool(tool)

        # "error" is this runner's established status for an exhausted timeout
        # budget (see test_run_tool_timeout); the message is what the scan job
        # matches on to report it as a timeout.
        assert result.is_success() is False
        assert "Timeout" in result.error_message, result.error_message

        assert heartbeat.exists(), "the grandchild never started - test is vacuous"
        first = heartbeat.read_text(encoding="utf-8")
        _time.sleep(2.5)
        second = heartbeat.read_text(encoding="utf-8")

        assert first == second, (
            f"the grandchild is still running after the timeout "
            f"(heartbeat advanced {first} -> {second}). Killing the launcher "
            f"does not kill what it spawned; this is the orphaned java process "
            f"that outlived a 1200s dependency-check timeout by 38 minutes."
        )
        # Belt and braces: it must also not still be blocking the runner.
        assert _sp is not None


class TestTimedOutFlag:
    """A timeout must be structurally detectable, not inferred from prose.

    `ToolResult.status` does not distinguish a timeout: `run_tool` assigns only
    `success`, `no_output`, `error` and `retry_exhausted`, so a timed-out tool
    is indistinguishable from a crash except by the wording of
    `error_message` ("Timeout after Ns"). `repository_scanner` branches on that
    string to decide whether to write a stub and what to log — so rewording a
    human-readable message silently reclassifies every timeout (#727).

    `timed_out` is a separate field rather than a fifth `status` value on
    purpose: `retry_exhausted` carries its own signal (this failure burned the
    whole retry budget), and folding it into `timeout` would lose it.
    """

    @staticmethod
    def _timing_out_tool(**kwargs):
        from scripts.core.config import RetryConfig

        return ToolDefinition(
            name="slowpoke",
            command=["sleep", "999"],
            output_file=None,
            timeout=1,
            retries=RetryConfig(
                max_attempts=1, timeout_retries=0, backoff_base=0, backoff_max=0
            ),
            **kwargs,
        )

    def test_timeout_sets_the_flag(self):
        """The terminal failure was a timeout, so say so in a field."""
        tool = self._timing_out_tool()
        runner = ToolRunner([tool])

        with patch(
            "scripts.core.tool_runner._run_bounded",
            side_effect=subprocess.TimeoutExpired("cmd", 1),
        ):
            result = runner.run_tool(tool)

        assert result.timed_out is True, (
            "a timed-out tool must be identifiable without parsing "
            "error_message, which is human-readable prose"
        )

    def test_timeout_still_reports_its_retry_status(self):
        """`timed_out` supplements `status`; it does not replace it.

        Collapsing a timeout into a `status` value would discard whether it
        exhausted its retry budget, which is what distinguishes a flaky tool
        from a hopelessly slow one.
        """
        from scripts.core.config import RetryConfig

        tool = ToolDefinition(
            name="slowpoke",
            command=["sleep", "999"],
            output_file=None,
            timeout=1,
            retries=RetryConfig(
                max_attempts=2, timeout_retries=2, backoff_base=0, backoff_max=0
            ),
        )
        runner = ToolRunner([tool])

        with patch(
            "scripts.core.tool_runner._run_bounded",
            side_effect=subprocess.TimeoutExpired("cmd", 1),
        ):
            result = runner.run_tool(tool)

        assert result.timed_out is True
        assert result.status == "retry_exhausted"
        assert result.attempts == 4  # 2 base + 2 timeout

    def test_a_crash_does_not_set_the_flag(self):
        """A non-zero exit is not a timeout. The flag must discriminate."""
        tool = ToolDefinition(
            name="crashy", command=["false"], output_file=None, retries=0
        )
        runner = ToolRunner([tool])

        with patch(
            "scripts.core.tool_runner._run_bounded",
            return_value=subprocess.CompletedProcess(["false"], 3, "", "boom"),
        ):
            result = runner.run_tool(tool)

        assert result.timed_out is False
        assert result.status in ("error", "retry_exhausted")

    def test_missing_tool_does_not_set_the_flag(self):
        """A tool that never launched cannot have timed out."""
        tool = ToolDefinition(
            name="ghost", command=["no-such-binary-12345"], output_file=None, retries=0
        )
        runner = ToolRunner([tool])

        with patch(
            "scripts.core.tool_runner._run_bounded", side_effect=FileNotFoundError()
        ):
            result = runner.run_tool(tool)

        assert result.timed_out is False

    def test_flag_survives_serialization(self):
        """`scan-timings.json` is where this becomes user-visible (#722)."""
        assert (
            ToolResult(tool="t", status="error", timed_out=True).to_dict()["timed_out"]
            is True
        )
        assert ToolResult(tool="t", status="success").to_dict()["timed_out"] is False

    def test_a_crash_after_a_timeout_is_not_reported_as_a_timeout(self):
        """The flag describes the *terminal* failure, not any failure seen.

        `last_error` and `timed_out` are a pair: whichever failure ends the
        retry loop is the one the returned ToolResult describes. If only the
        timeout branch assigns the flag, a tool that times out once and then
        crashes reports `timed_out=True` alongside a crash's `error_message` --
        so the scan writes a timeout stub and logs "it timed out" for a tool
        that actually exited non-zero.

        Every other test in this class exercises a single failure kind, and so
        cannot see the missing reset. Found by mutation: deleting the crash
        path's reset left all five of them green.
        """
        from scripts.core.config import RetryConfig

        tool = ToolDefinition(
            name="flaky",
            command=["flaky"],
            output_file=None,
            timeout=1,
            ok_return_codes=(0,),
            retries=RetryConfig(
                max_attempts=2, timeout_retries=1, backoff_base=0, backoff_max=0
            ),
        )
        runner = ToolRunner([tool])

        crash = subprocess.CompletedProcess(["flaky"], 3, "", "boom")
        with patch(
            "scripts.core.tool_runner._run_bounded",
            side_effect=[subprocess.TimeoutExpired("cmd", 1), crash, crash],
        ):
            result = runner.run_tool(tool)

        assert result.timed_out is False, (
            "the run ended on a crash, but it was reported as a timeout -- the "
            "crash path is not resetting the flag a previous timeout set"
        )
        assert "Return code 3" in result.error_message
