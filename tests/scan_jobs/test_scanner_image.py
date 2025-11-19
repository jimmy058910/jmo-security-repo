"""
Tests for image_scanner.py - Container image scanning functionality.

Coverage targets:
- Trivy image scanning
- Syft SBOM generation for images
- Image name sanitization
- Tool invocation with correct arguments
- Error handling
- Per-tool configuration
"""

from pathlib import Path
from unittest.mock import patch

from scripts.cli.scan_jobs.image_scanner import scan_image
from scripts.core.tool_runner import ToolResult


def test_scan_image_basic_success(tmp_path):
    """Test basic image scan with trivy and syft."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=10.0,
                    attempts=1,
                    output_file=results_dir / "nginx_latest" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
                ToolResult(
                    tool="syft",
                    status="success",
                    stdout='{"artifacts": []}',
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "nginx_latest" / "syft.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            image_name, statuses = scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["trivy", "syft"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert image_name == "nginx:latest"
            assert statuses["trivy"] is True
            assert statuses["syft"] is True


def test_scan_image_name_sanitization(tmp_path):
    """Test image name sanitization for directory creation."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=10.0,
                    attempts=1,
                    output_file=results_dir
                    / "gcr.io_myproject_myimage_v1.2.3"
                    / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_image(
                image="gcr.io/myproject/myimage:v1.2.3",
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify sanitized directory created
            sanitized_dir = results_dir / "gcr.io_myproject_myimage_v1.2.3"
            assert sanitized_dir.exists()


def test_scan_image_missing_tools_no_allow(tmp_path):
    """Test scan behavior when tools missing and allow_missing_tools=False."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            image_name, statuses = scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["trivy", "syft"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Tools not in statuses when missing and not allowed
            assert "trivy" not in statuses
            assert "syft" not in statuses


def test_scan_image_missing_tools_with_allow(tmp_path):
    """Test scan writes stubs when tools missing and allow_missing_tools=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.image_scanner.write_stub") as mock_stub:
            with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
                MockRunner.return_value.run_all_parallel.return_value = []

                image_name, statuses = scan_image(
                    image="nginx:latest",
                    results_dir=results_dir,
                    tools=["trivy", "syft"],
                    timeout=300,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=True,
                )

                assert statuses["trivy"] is True
                assert statuses["syft"] is True
                assert mock_stub.call_count == 2


def test_scan_image_per_tool_timeout(tmp_path):
    """Test per-tool timeout configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "trivy": {"timeout": 1200},
    }

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=10.0,
                    attempts=1,
                    output_file=results_dir / "nginx_latest" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            # Verify custom timeout used
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert trivy_def.timeout == 1200


def test_scan_image_per_tool_flags(tmp_path):
    """Test per-tool flags configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "trivy": {"flags": ["--severity", "HIGH,CRITICAL"]},
    }

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=10.0,
                    attempts=1,
                    output_file=results_dir / "nginx_latest" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            # Verify custom flags passed
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert "--severity" in trivy_def.command
            assert "HIGH,CRITICAL" in trivy_def.command


def test_scan_image_tool_failure(tmp_path):
    """Test handling of tool execution failures."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="error",
                    stdout="",
                    stderr="timeout",
                    returncode=124,
                    duration=300.0,
                    attempts=1,
                    output_file=results_dir / "nginx_latest" / "trivy.json",
                    capture_stdout=False,
                    error_message="Timeout after 300s",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            image_name, statuses = scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is False


def test_scan_image_retry_tracking(tmp_path):
    """Test retry tracking in __attempts__ metadata."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=10.0,
                    attempts=3,
                    output_file=results_dir / "nginx_latest" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            image_name, statuses = scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["trivy"] == 3


def test_scan_image_syft_stdout_capture(tmp_path):
    """Test syft captures stdout for SBOM output."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="syft",
                    status="success",
                    stdout='{"artifacts": [{"name": "nginx"}]}',
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "nginx_latest" / "syft.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["syft"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify syft configured with capture_stdout=True
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            syft_def = next(t for t in tools_passed if t.name == "syft")
            assert syft_def.capture_stdout is True


def test_scan_image_output_dir_creation(tmp_path):
    """Test output directory created correctly for image."""
    results_dir = tmp_path / "results"

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=[],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
            )

            # Verify output directory created
            output_dir = results_dir / "nginx_latest"
            assert output_dir.exists()
            assert output_dir.is_dir()


def test_scan_image_custom_tool_exists_func(tmp_path):
    """Test using custom tool_exists_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    def mock_tool_exists(tool: str) -> bool:
        return tool == "trivy"

    with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
        mock_results = [
            ToolResult(
                tool="trivy",
                status="success",
                stdout="",
                stderr="",
                returncode=0,
                duration=10.0,
                attempts=1,
                output_file=results_dir / "nginx_latest" / "trivy.json",
                capture_stdout=False,
                error_message="",
            ),
        ]
        MockRunner.return_value.run_all_parallel.return_value = mock_results

        image_name, statuses = scan_image(
            image="nginx:latest",
            results_dir=results_dir,
            tools=["trivy", "syft"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            tool_exists_func=mock_tool_exists,
        )

        assert "trivy" in statuses
        assert "syft" in statuses


def test_scan_image_custom_write_stub_func(tmp_path):
    """Test using custom write_stub_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    stub_calls = []

    def mock_write_stub(tool: str, path: Path) -> None:
        stub_calls.append((tool, path))

    with patch("scripts.cli.scan_jobs.image_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_image(
                image="nginx:latest",
                results_dir=results_dir,
                tools=["trivy", "syft"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                write_stub_func=mock_write_stub,
            )

            assert len(stub_calls) == 2
