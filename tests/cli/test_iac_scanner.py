"""
Tests for IaC Scanner

Tests the iac_scanner module with various scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.iac_scanner import scan_iac_file


class TestIacScanner:
    """Test IaC scanner functionality"""

    def test_scan_iac_basic(self, tmp_path):
        """Test basic IaC scanning with checkov and trivy"""
        iac_file = tmp_path / "infrastructure.tf"
        iac_file.write_text('resource "aws_instance" "example" {}')

        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="checkov", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            identifier, statuses = scan_iac_file(
                iac_type="terraform",
                iac_path=iac_file,
                results_dir=tmp_path,
                tools=["checkov", "trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert identifier == "terraform:infrastructure.tf"
            assert statuses["checkov"] is True
            assert statuses["trivy"] is True
            assert "__attempts__" not in statuses

    def test_scan_iac_with_retries(self, tmp_path):
        """Test IaC scanning with retries"""
        iac_file = tmp_path / "template.yaml"
        iac_file.write_text("AWSTemplateFormatVersion: '2010-09-09'")

        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="checkov", status="success", attempts=2),  # Retried
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            identifier, statuses = scan_iac_file(
                iac_type="cloudformation",
                iac_path=iac_file,
                results_dir=tmp_path,
                tools=["checkov", "trivy"],
                timeout=600,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["checkov"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["checkov"] == 2

    def test_scan_iac_uses_filename_as_dirname(self, tmp_path):
        """Test that IaC file stem is used for directory name"""
        iac_file = tmp_path / "my-infrastructure.tf"
        iac_file.write_text('resource "null_resource" "test" {}')

        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="checkov", status="success", attempts=1),
            ]

            scan_iac_file(
                iac_type="terraform",
                iac_path=iac_file,
                results_dir=tmp_path,
                tools=["checkov"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check that directory was created with file stem
            expected_dir = tmp_path / "individual-iac" / "my-infrastructure"
            assert expected_dir.exists()

    def test_scan_iac_with_tool_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        iac_file = tmp_path / "deployment.yaml"
        iac_file.write_text("apiVersion: v1\nkind: Pod")

        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {
                "trivy": {"timeout": 900, "flags": ["--severity", "HIGH"]}
            }

            scan_iac_file(
                iac_type="k8s",
                iac_path=iac_file,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            # Verify ToolRunner was called
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args

            # Check that tool definitions have correct timeout
            # ToolRunner is called with positional arg: ToolRunner(tools=tool_defs)
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None, "trivy tool definition not found"
            assert trivy_def.timeout == 900
            assert "--severity" in trivy_def.command
            assert "HIGH" in trivy_def.command

    def test_scan_iac_tool_failure(self, tmp_path):
        """Test handling of tool failures"""
        iac_file = tmp_path / "main.tf"
        iac_file.write_text("terraform {}")

        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="checkov", status="error", returncode=2, attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            identifier, statuses = scan_iac_file(
                iac_type="terraform",
                iac_path=iac_file,
                results_dir=tmp_path,
                tools=["checkov", "trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["checkov"] is False  # Failed
            assert statuses["trivy"] is True  # Succeeded

    def test_scan_iac_only_checkov(self, tmp_path):
        """Test scanning with only checkov (no trivy)"""
        iac_file = tmp_path / "security.tf"
        iac_file.write_text("")

        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="checkov", status="success", attempts=1),
            ]

            identifier, statuses = scan_iac_file(
                iac_type="terraform",
                iac_path=iac_file,
                results_dir=tmp_path,
                tools=["checkov"],  # Only checkov
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert "checkov" in statuses
            assert "trivy" not in statuses

    def test_scan_iac_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        iac_file = tmp_path / "network.tf"
        iac_file.write_text('resource "aws_vpc" "main" {}')

        with patch("scripts.cli.scan_jobs.iac_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="checkov", status="success", attempts=1),
            ]

            scan_iac_file(
                iac_type="terraform",
                iac_path=iac_file,
                results_dir=tmp_path,
                tools=["checkov"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check directory structure
            assert (tmp_path / "individual-iac").exists()
            assert (tmp_path / "individual-iac" / "network").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
