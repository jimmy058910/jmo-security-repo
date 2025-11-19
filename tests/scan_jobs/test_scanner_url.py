"""
Tests for url_scanner.py - Web URL scanning functionality (DAST).

Coverage targets:
- OWASP ZAP scanning
- Nuclei vulnerability scanning
- Akto API security testing
- URL validation and scheme checking
- URL sanitization for directory names
- Tool invocation with correct arguments
- Error handling
- Per-tool configuration
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from scripts.cli.scan_jobs.url_scanner import scan_url
from scripts.core.tool_runner import ToolResult


def test_scan_url_basic_success(tmp_path):
    """Test basic URL scan with ZAP and Nuclei."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="zap",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=30.0,
                    attempts=1,
                    output_file=results_dir / "example.com" / "zap.json",
                    capture_stdout=False,
                    error_message="",
                ),
                ToolResult(
                    tool="nuclei",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=15.0,
                    attempts=1,
                    output_file=results_dir / "example.com" / "nuclei.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            url, statuses = scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["zap", "nuclei"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert url == "https://example.com"
            assert statuses["zap"] is True
            assert statuses["nuclei"] is True


def test_scan_url_with_akto(tmp_path):
    """Test URL scan with Akto API security testing."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="akto",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "api.example.com" / "akto.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            url, statuses = scan_url(
                url="https://api.example.com",
                results_dir=results_dir,
                tools=["akto"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["akto"] is True


def test_scan_url_scheme_validation_http(tmp_path):
    """Test URL scheme validation allows HTTP."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            url, statuses = scan_url(
                url="http://example.com",
                results_dir=results_dir,
                tools=["zap"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert url == "http://example.com"


def test_scan_url_scheme_validation_https(tmp_path):
    """Test URL scheme validation allows HTTPS."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            url, statuses = scan_url(
                url="https://secure.example.com",
                results_dir=results_dir,
                tools=["zap"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert url == "https://secure.example.com"


def test_scan_url_scheme_validation_rejects_invalid(tmp_path):
    """Test URL scheme validation rejects non-HTTP schemes."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    # Should reject file:// scheme
    with pytest.raises(ValueError, match="Invalid URL scheme"):
        scan_url(
            url="file:///path/to/repo",
            results_dir=results_dir,
            tools=["zap"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )

    # Should reject ftp:// scheme
    with pytest.raises(ValueError, match="Invalid URL scheme"):
        scan_url(
            url="ftp://example.com",
            results_dir=results_dir,
            tools=["zap"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=False,
        )


def test_scan_url_sanitization(tmp_path):
    """Test URL sanitization for directory creation."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="zap",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=30.0,
                    attempts=1,
                    output_file=results_dir / "api.example.com_8080" / "zap.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_url(
                url="https://api.example.com:8080/path",
                results_dir=results_dir,
                tools=["zap"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify sanitized directory created
            sanitized_dir = results_dir / "api.example.com_8080"
            assert sanitized_dir.exists()


def test_scan_url_missing_tools_no_allow(tmp_path):
    """Test scan behavior when tools missing and allow_missing_tools=False."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            url, statuses = scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["zap", "nuclei"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert "zap" not in statuses
            assert "nuclei" not in statuses


def test_scan_url_missing_tools_with_allow(tmp_path):
    """Test scan writes stubs when tools missing and allow_missing_tools=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.url_scanner.write_stub") as mock_stub:
            with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
                MockRunner.return_value.run_all_parallel.return_value = []

                url, statuses = scan_url(
                    url="https://example.com",
                    results_dir=results_dir,
                    tools=["zap", "nuclei"],
                    timeout=300,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=True,
                )

                assert statuses["zap"] is True
                assert statuses["nuclei"] is True
                assert mock_stub.call_count == 2


def test_scan_url_per_tool_timeout(tmp_path):
    """Test per-tool timeout configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "zap": {"timeout": 600},
    }

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="zap",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=30.0,
                    attempts=1,
                    output_file=results_dir / "example.com" / "zap.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["zap"],
                timeout=300,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            zap_def = next(t for t in tools_passed if t.name == "zap")
            assert zap_def.timeout == 600


def test_scan_url_per_tool_flags(tmp_path):
    """Test per-tool flags configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "nuclei": {"flags": ["-severity", "high,critical"]},
    }

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="nuclei",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=15.0,
                    attempts=1,
                    output_file=results_dir / "example.com" / "nuclei.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["nuclei"],
                timeout=300,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            nuclei_def = next(t for t in tools_passed if t.name == "nuclei")
            assert "-severity" in nuclei_def.command
            assert "high,critical" in nuclei_def.command


def test_scan_url_tool_failure(tmp_path):
    """Test handling of tool execution failures."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="zap",
                    status="error",
                    stdout="",
                    stderr="timeout",
                    returncode=124,
                    duration=300.0,
                    attempts=1,
                    output_file=results_dir / "example.com" / "zap.json",
                    capture_stdout=False,
                    error_message="Timeout after 300s",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            url, statuses = scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["zap"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["zap"] is False


def test_scan_url_retry_tracking(tmp_path):
    """Test retry tracking in __attempts__ metadata."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="nuclei",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=15.0,
                    attempts=2,
                    output_file=results_dir / "example.com" / "nuclei.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            url, statuses = scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["nuclei"],
                timeout=300,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["nuclei"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["nuclei"] == 2


def test_scan_url_output_dir_creation(tmp_path):
    """Test output directory created correctly for URL."""
    results_dir = tmp_path / "results"

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=[],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
            )

            output_dir = results_dir / "example.com"
            assert output_dir.exists()
            assert output_dir.is_dir()


def test_scan_url_custom_tool_exists_func(tmp_path):
    """Test using custom tool_exists_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    def mock_tool_exists(tool: str) -> bool:
        return tool == "zap"

    with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
        mock_results = [
            ToolResult(
                tool="zap",
                status="success",
                stdout="",
                stderr="",
                returncode=0,
                duration=30.0,
                attempts=1,
                output_file=results_dir / "example.com" / "zap.json",
                capture_stdout=False,
                error_message="",
            ),
        ]
        MockRunner.return_value.run_all_parallel.return_value = mock_results

        url, statuses = scan_url(
            url="https://example.com",
            results_dir=results_dir,
            tools=["zap", "nuclei"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            tool_exists_func=mock_tool_exists,
        )

        assert "zap" in statuses
        assert "nuclei" in statuses


def test_scan_url_custom_write_stub_func(tmp_path):
    """Test using custom write_stub_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    stub_calls = []

    def mock_write_stub(tool: str, path: Path) -> None:
        stub_calls.append((tool, path))

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["zap", "nuclei"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                write_stub_func=mock_write_stub,
            )

            assert len(stub_calls) == 2


def test_scan_url_zap_command_selection(tmp_path):
    """Test ZAP command selection (zap.sh vs zap)."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="zap",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=30.0,
                    attempts=1,
                    output_file=results_dir / "example.com" / "zap.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["zap"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify ZAP tool was invoked successfully
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            zap_def = next(t for t in tools_passed if t.name == "zap")
            # Command should contain either "zap" or "zap.sh"
            assert zap_def.command[0] in ["zap", "zap.sh"]


def test_scan_url_akto_missing_tool_with_stub(tmp_path):
    """Test Akto missing tool writes stub when allow_missing_tools=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    def mock_tool_exists(tool: str) -> bool:
        # Akto doesn't exist
        return tool != "akto"

    with patch("scripts.cli.scan_jobs.url_scanner.write_stub") as mock_stub:
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            url, statuses = scan_url(
                url="https://api.example.com",
                results_dir=results_dir,
                tools=["akto"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                tool_exists_func=mock_tool_exists,
            )

            # Stub should be written for missing Akto
            assert statuses["akto"] is True
            mock_stub.assert_called()


def test_scan_url_tool_not_found_error(tmp_path):
    """Test handling of 'Tool not found' error from ToolRunner."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            # Mock "Tool not found" error
            mock_results = [
                ToolResult(
                    tool="zap",
                    status="error",
                    stdout="",
                    stderr="",
                    returncode=127,
                    duration=0.1,
                    attempts=1,
                    output_file=results_dir / "example.com" / "zap.json",
                    capture_stdout=False,
                    error_message="Tool not found: zap",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            url, statuses = scan_url(
                url="https://example.com",
                results_dir=results_dir,
                tools=["zap"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
            )

            # Should write stub for tool not found error
            assert statuses["zap"] is True
