"""
Tests for k8s_scanner.py - Kubernetes cluster scanning functionality.

Coverage targets:
- Trivy Kubernetes scanning
- Context and namespace selection
- All-namespaces flag handling
- Tool invocation with correct arguments
- Error handling
- Per-tool configuration
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from scripts.cli.scan_jobs.k8s_scanner import scan_k8s_resource
from scripts.core.tool_runner import ToolResult


@pytest.fixture
def k8s_info():
    """Create mock Kubernetes cluster info."""
    return {
        "context": "prod",
        "namespace": "default",
        "all_namespaces": "False",
    }


def test_scan_k8s_resource_basic_success(tmp_path, k8s_info):
    """Test basic Kubernetes cluster scan with trivy."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "prod_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            cluster_id, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert cluster_id == "prod:default"
            assert statuses["trivy"] is True


def test_scan_k8s_resource_custom_context(tmp_path):
    """Test Kubernetes scan with custom context."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    k8s_info = {
        "context": "staging",
        "namespace": "app",
        "all_namespaces": "False",
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "staging_app" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify trivy command includes --context flag
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert "--context" in trivy_def.command
            assert "staging" in trivy_def.command


def test_scan_k8s_resource_current_context(tmp_path):
    """Test Kubernetes scan with current context (no --context flag)."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    k8s_info = {
        "context": "current",
        "namespace": "default",
        "all_namespaces": "False",
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "current_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify trivy command does NOT include --context flag
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert "--context" not in trivy_def.command


def test_scan_k8s_resource_specific_namespace(tmp_path):
    """Test Kubernetes scan with specific namespace."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    k8s_info = {
        "context": "prod",
        "namespace": "monitoring",
        "all_namespaces": "False",
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "prod_monitoring" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify trivy command includes -n flag with namespace
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert "-n" in trivy_def.command
            assert "monitoring" in trivy_def.command


def test_scan_k8s_resource_default_namespace(tmp_path):
    """Test Kubernetes scan with default namespace (no -n flag)."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    k8s_info = {
        "context": "prod",
        "namespace": "default",
        "all_namespaces": "False",
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "prod_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify trivy command does NOT include -n flag
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert "-n" not in trivy_def.command


def test_scan_k8s_resource_all_namespaces(tmp_path):
    """Test Kubernetes scan with all-namespaces flag."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    k8s_info = {
        "context": "prod",
        "namespace": "default",
        "all_namespaces": "True",
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=30.0,
                    attempts=1,
                    output_file=results_dir / "prod_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify trivy command includes --all-namespaces flag
            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            trivy_def = next(t for t in tools_passed if t.name == "trivy")
            assert "--all-namespaces" in trivy_def.command


def test_scan_k8s_resource_missing_tools_no_allow(tmp_path, k8s_info):
    """Test scan behavior when tools missing and allow_missing_tools=False."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            cluster_id, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert "trivy" not in statuses


def test_scan_k8s_resource_missing_tools_with_allow(tmp_path, k8s_info):
    """Test scan writes stubs when tools missing and allow_missing_tools=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.k8s_scanner.write_stub") as mock_stub:
            with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
                MockRunner.return_value.run_all_parallel.return_value = []

                cluster_id, statuses = scan_k8s_resource(
                    k8s_info=k8s_info,
                    results_dir=results_dir,
                    tools=["trivy"],
                    timeout=300,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=True,
                )

                assert statuses["trivy"] is True
                assert mock_stub.call_count == 1


def test_scan_k8s_resource_per_tool_timeout(tmp_path, k8s_info):
    """Test per-tool timeout configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "trivy": {"timeout": 600},
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "prod_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
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
            assert trivy_def.timeout == 600


def test_scan_k8s_resource_per_tool_flags(tmp_path, k8s_info):
    """Test per-tool flags configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "trivy": {"flags": ["--severity", "HIGH,CRITICAL"]},
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "prod_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
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


def test_scan_k8s_resource_tool_failure(tmp_path, k8s_info):
    """Test handling of tool execution failures."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="error",
                    stdout="",
                    stderr="timeout",
                    returncode=124,
                    duration=300.0,
                    attempts=1,
                    output_file=results_dir / "prod_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="Timeout after 300s",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            cluster_id, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is False


def test_scan_k8s_resource_retry_tracking(tmp_path, k8s_info):
    """Test retry tracking in __attempts__ metadata."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=3,
                    output_file=results_dir / "prod_default" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            cluster_id, statuses = scan_k8s_resource(
                k8s_info=k8s_info,
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


def test_scan_k8s_resource_output_dir_creation(tmp_path, k8s_info):
    """Test output directory created correctly for K8s cluster."""
    results_dir = tmp_path / "results"

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=[],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
            )

            # Verify output directory created
            output_dir = results_dir / "prod_default"
            assert output_dir.exists()
            assert output_dir.is_dir()


def test_scan_k8s_resource_sanitized_directory(tmp_path):
    """Test directory name sanitization for special characters."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    k8s_info = {
        "context": "prod/west",
        "namespace": "app*",
        "all_namespaces": "False",
    }

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=20.0,
                    attempts=1,
                    output_file=results_dir / "prod_west_appall" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Verify sanitized directory created (/ -> _, * -> all)
            sanitized_dir = results_dir / "prod_west_appall"
            assert sanitized_dir.exists()


def test_scan_k8s_resource_custom_tool_exists_func(tmp_path, k8s_info):
    """Test using custom tool_exists_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    def mock_tool_exists(tool: str) -> bool:
        return tool == "trivy"

    with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
        mock_results = [
            ToolResult(
                tool="trivy",
                status="success",
                stdout="",
                stderr="",
                returncode=0,
                duration=20.0,
                attempts=1,
                output_file=results_dir / "prod_default" / "trivy.json",
                capture_stdout=False,
                error_message="",
            ),
        ]
        MockRunner.return_value.run_all_parallel.return_value = mock_results

        cluster_id, statuses = scan_k8s_resource(
            k8s_info=k8s_info,
            results_dir=results_dir,
            tools=["trivy"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            tool_exists_func=mock_tool_exists,
        )

        assert "trivy" in statuses


def test_scan_k8s_resource_custom_write_stub_func(tmp_path, k8s_info):
    """Test using custom write_stub_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    stub_calls = []

    def mock_write_stub(tool: str, path: Path) -> None:
        stub_calls.append((tool, path))

    with patch("scripts.cli.scan_jobs.k8s_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.k8s_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_k8s_resource(
                k8s_info=k8s_info,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                write_stub_func=mock_write_stub,
            )

            assert len(stub_calls) == 1
