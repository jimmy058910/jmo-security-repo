"""
Unit tests for scripts/core/tool_runner.py

Tests the ToolRunner class extracted from cmd_scan() as part of PHASE 1 refactoring.
"""

import pytest
from pathlib import Path
import time
from scripts.core.tool_runner import (
    ToolDefinition,
    ToolResult,
    ToolRunner,
    run_tools,
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
        """Test creating a failed result"""
        result = ToolResult(
            tool="semgrep",
            status="timeout",
            returncode=-1,
            error_message="Timeout after 600s",
        )

        assert result.is_success() is False
        assert result.status == "timeout"
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
        assert data["output_file"] == "/tmp/trivy.json"


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
            output_file=Path("/tmp/echo.json"),
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
        assert "timeout" in result.error_message.lower() or "Timeout" in result.error_message

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
            output_file=Path("/tmp/false.json"),
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
                output_file=Path("/tmp/echo1.json"),
            ),
            ToolDefinition(
                name="echo2",
                command=["echo", "test2"],
                output_file=Path("/tmp/echo2.json"),
            ),
            ToolDefinition(
                name="echo3",
                command=["echo", "test3"],
                output_file=Path("/tmp/echo3.json"),
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
                output_file=Path("/tmp/echo1.json"),
            ),
            ToolDefinition(
                name="echo2",
                command=["echo", "test2"],
                output_file=Path("/tmp/echo2.json"),
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
            output_file=Path("/tmp/echo.json"),
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
                output_file=Path("/tmp/test1.json"),
            ),
            ToolDefinition(
                name="test2",
                command=["echo", "test2"],
                output_file=Path("/tmp/test2.json"),
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
                output_file=Path("/tmp/test1.json"),
            ),
            ToolDefinition(
                name="test2",
                command=["echo", "test2"],
                output_file=Path("/tmp/test2.json"),
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
                output_file=Path("/tmp/echo.json"),
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
                output_file=Path(f"/tmp/echo{i}.json"),
            )
            for i in range(num_tools)
        ]

        runner = ToolRunner(tools, max_workers=4)
        results = runner.run_all_parallel()

        assert len(results) == num_tools
        assert all(r.is_success() for r in results)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
