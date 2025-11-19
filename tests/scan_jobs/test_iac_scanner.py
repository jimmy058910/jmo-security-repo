"""
Tests for iac_scanner.py - Infrastructure-as-Code scanning functionality.

Coverage targets:
- Checkov IaC scanning
- Trivy config scanning
- IaC file type handling (terraform, cloudformation, k8s)
- Tool invocation with correct arguments
- Error handling
- Per-tool configuration
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from scripts.cli.scan_jobs.iac_scanner import scan_iac_file
from scripts.core.tool_runner import ToolResult


@pytest.fixture
def terraform_file(tmp_path):
    """Create a mock Terraform file."""
    tf_file = tmp_path / "main.tf"
    tf_file.write_text(
        """
resource "aws_s3_bucket" "example" {
  bucket = "my-bucket"
}
"""
    )
    return tf_file


def test_scan_iac_file_basic_success(tmp_path, terraform_file):
    """Test basic IaC file scan with checkov and trivy."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="checkov",
                    status="success",
                    stdout='{"check_type": "terraform"}',
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "main" / "checkov.json",
                    capture_stdout=True,
                    error_message="",
                ),
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=3.0,
                    attempts=1,
                    output_file=results_dir / "main" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            iac_id, statuses = scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov", "trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert iac_id == "terraform:main.tf"
            assert statuses["checkov"] is True
            assert statuses["trivy"] is True


def test_scan_iac_file_cloudformation(tmp_path):
    """Test CloudFormation file scanning."""
    cf_file = tmp_path / "template.yaml"
    cf_file.write_text(
        """
AWSTemplateFormatVersion: "2010-09-09"
Resources:
  MyBucket:
    Type: AWS::S3::Bucket
"""
    )

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="checkov",
                    status="success",
                    stdout='{"check_type": "cloudformation"}',
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "template" / "checkov.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            iac_id, statuses = scan_iac_file(
                iac_type="cloudformation",
                iac_path=cf_file,
                results_dir=results_dir,
                tools=["checkov"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert iac_id == "cloudformation:template.yaml"
            assert statuses["checkov"] is True


def test_scan_iac_file_k8s_manifest(tmp_path):
    """Test Kubernetes manifest scanning."""
    k8s_file = tmp_path / "deployment.yaml"
    k8s_file.write_text(
        """
apiVersion: apps/v1
kind: Deployment
metadata:
  name: nginx
spec:
  replicas: 3
"""
    )

    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="trivy",
                    status="success",
                    stdout="",
                    stderr="",
                    returncode=0,
                    duration=3.0,
                    attempts=1,
                    output_file=results_dir / "deployment" / "trivy.json",
                    capture_stdout=False,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            iac_id, statuses = scan_iac_file(
                iac_type="k8s",
                iac_path=k8s_file,
                results_dir=results_dir,
                tools=["trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert iac_id == "k8s:deployment.yaml"
            assert statuses["trivy"] is True


def test_scan_iac_file_missing_tools_no_allow(tmp_path, terraform_file):
    """Test scan behavior when tools missing and allow_missing_tools=False."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            iac_id, statuses = scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov", "trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert "checkov" not in statuses
            assert "trivy" not in statuses


def test_scan_iac_file_missing_tools_with_allow(tmp_path, terraform_file):
    """Test scan writes stubs when tools missing and allow_missing_tools=True."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.iac_scanner.write_stub") as mock_stub:
            with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
                MockRunner.return_value.run_all_parallel.return_value = []

                iac_id, statuses = scan_iac_file(
                    iac_type="terraform",
                    iac_path=terraform_file,
                    results_dir=results_dir,
                    tools=["checkov", "trivy"],
                    timeout=300,
                    retries=0,
                    per_tool_config={},
                    allow_missing_tools=True,
                )

                assert statuses["checkov"] is True
                assert statuses["trivy"] is True
                assert mock_stub.call_count == 2


def test_scan_iac_file_per_tool_timeout(tmp_path, terraform_file):
    """Test per-tool timeout configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "checkov": {"timeout": 600},
    }

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="checkov",
                    status="success",
                    stdout="{}",
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "main" / "checkov.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov"],
                timeout=300,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            checkov_def = next(t for t in tools_passed if t.name == "checkov")
            assert checkov_def.timeout == 600


def test_scan_iac_file_per_tool_flags(tmp_path, terraform_file):
    """Test per-tool flags configuration."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    per_tool_config = {
        "checkov": {"flags": ["--framework", "terraform"]},
    }

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="checkov",
                    status="success",
                    stdout="{}",
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "main" / "checkov.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov"],
                timeout=300,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            checkov_def = next(t for t in tools_passed if t.name == "checkov")
            assert "--framework" in checkov_def.command
            assert "terraform" in checkov_def.command


def test_scan_iac_file_tool_failure(tmp_path, terraform_file):
    """Test handling of tool execution failures."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="checkov",
                    status="error",
                    stdout="",
                    stderr="timeout",
                    returncode=124,
                    duration=300.0,
                    attempts=1,
                    output_file=results_dir / "main" / "checkov.json",
                    capture_stdout=True,
                    error_message="Timeout after 300s",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            iac_id, statuses = scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["checkov"] is False


def test_scan_iac_file_retry_tracking(tmp_path, terraform_file):
    """Test retry tracking in __attempts__ metadata."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="checkov",
                    status="success",
                    stdout="{}",
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=2,
                    output_file=results_dir / "main" / "checkov.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            iac_id, statuses = scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov"],
                timeout=300,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["checkov"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["checkov"] == 2


def test_scan_iac_file_checkov_stdout_capture(tmp_path, terraform_file):
    """Test checkov captures stdout for JSON output."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=True):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_results = [
                ToolResult(
                    tool="checkov",
                    status="success",
                    stdout='{"results": []}',
                    stderr="",
                    returncode=0,
                    duration=5.0,
                    attempts=1,
                    output_file=results_dir / "main" / "checkov.json",
                    capture_stdout=True,
                    error_message="",
                ),
            ]
            MockRunner.return_value.run_all_parallel.return_value = mock_results

            scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            call_args = MockRunner.call_args
            tools_passed = call_args[1]["tools"]
            checkov_def = next(t for t in tools_passed if t.name == "checkov")
            assert checkov_def.capture_stdout is True


def test_scan_iac_file_output_dir_creation(tmp_path, terraform_file):
    """Test output directory created correctly for IaC file."""
    results_dir = tmp_path / "results"

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=[],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
            )

            output_dir = results_dir / "main"
            assert output_dir.exists()
            assert output_dir.is_dir()


def test_scan_iac_file_custom_tool_exists_func(tmp_path, terraform_file):
    """Test using custom tool_exists_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    def mock_tool_exists(tool: str) -> bool:
        return tool == "checkov"

    with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
        mock_results = [
            ToolResult(
                tool="checkov",
                status="success",
                stdout="{}",
                stderr="",
                returncode=0,
                duration=5.0,
                attempts=1,
                output_file=results_dir / "main" / "checkov.json",
                capture_stdout=True,
                error_message="",
            ),
        ]
        MockRunner.return_value.run_all_parallel.return_value = mock_results

        iac_id, statuses = scan_iac_file(
            iac_type="terraform",
            iac_path=terraform_file,
            results_dir=results_dir,
            tools=["checkov", "trivy"],
            timeout=300,
            retries=0,
            per_tool_config={},
            allow_missing_tools=True,
            tool_exists_func=mock_tool_exists,
        )

        assert "checkov" in statuses
        assert "trivy" in statuses


def test_scan_iac_file_custom_write_stub_func(tmp_path, terraform_file):
    """Test using custom write_stub_func."""
    results_dir = tmp_path / "results"
    results_dir.mkdir()

    stub_calls = []

    def mock_write_stub(tool: str, path: Path) -> None:
        stub_calls.append((tool, path))

    with patch("scripts.cli.scan_jobs.iac_scanner.tool_exists", return_value=False):
        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            MockRunner.return_value.run_all_parallel.return_value = []

            scan_iac_file(
                iac_type="terraform",
                iac_path=terraform_file,
                results_dir=results_dir,
                tools=["checkov", "trivy"],
                timeout=300,
                retries=0,
                per_tool_config={},
                allow_missing_tools=True,
                write_stub_func=mock_write_stub,
            )

            assert len(stub_calls) == 2
