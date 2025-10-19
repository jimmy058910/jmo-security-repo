"""
Tests for Container Image Scanner

Tests the image_scanner module with various scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.image_scanner import scan_image


class TestImageScanner:
    """Test image scanner functionality"""

    def test_scan_image_basic(self, tmp_path):
        """Test basic image scanning with trivy and syft"""
        # Mock ToolRunner to avoid actual execution
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            # Mock successful results
            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
                ToolResult(tool="syft", status="success", attempts=1),
            ]

            image, statuses = scan_image(
                image="nginx:latest",
                results_dir=tmp_path,
                tools=["trivy", "syft"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert image == "nginx:latest"
            assert statuses["trivy"] is True
            assert statuses["syft"] is True
            assert "__attempts__" not in statuses  # No retries

    def test_scan_image_with_retries(self, tmp_path):
        """Test image scanning with retries"""
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=2),  # Retried
                ToolResult(tool="syft", status="success", attempts=1),
            ]

            image, statuses = scan_image(
                image="nginx:latest",
                results_dir=tmp_path,
                tools=["trivy", "syft"],
                timeout=600,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["trivy"] == 2

    def test_scan_image_sanitizes_name(self, tmp_path):
        """Test that image names are sanitized for directory names"""
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            # Image with special characters
            scan_image(
                image="registry.example.com:5000/my-app:v1.2.3",
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check that directory was created with sanitized name
            expected_dir = (
                tmp_path
                / "individual-images"
                / "registry.example.com_5000_my-app_v1.2.3"
            )
            assert expected_dir.exists()

    def test_scan_image_with_tool_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        # Mock tool_exists to return True for trivy
        def mock_tool_exists(tool_name):
            return tool_name == "trivy"

        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {"trivy": {"timeout": 1200, "flags": ["--no-progress"]}}

            scan_image(
                image="nginx:latest",
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            # Verify ToolRunner was called
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args

            # Check that tool definitions have correct timeout
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trivy_def = next((t for t in tool_defs if t.name == "trivy"), None)
            assert trivy_def is not None, "trivy tool definition not found"
            assert trivy_def.timeout == 1200
            assert "--no-progress" in trivy_def.command

    def test_scan_image_tool_failure(self, tmp_path):
        """Test handling of tool failures"""
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="error", returncode=1, attempts=1),
                ToolResult(tool="syft", status="success", attempts=1),
            ]

            image, statuses = scan_image(
                image="nginx:latest",
                results_dir=tmp_path,
                tools=["trivy", "syft"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trivy"] is False  # Failed
            assert statuses["syft"] is True  # Succeeded

    def test_scan_image_only_trivy(self, tmp_path):
        """Test scanning with only trivy (no syft)"""
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            image, statuses = scan_image(
                image="nginx:latest",
                results_dir=tmp_path,
                tools=["trivy"],  # Only trivy
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert "trivy" in statuses
            assert "syft" not in statuses

    def test_scan_image_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        with patch("scripts.cli.scan_jobs.image_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            scan_image(
                image="alpine:latest",
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check directory structure
            assert (tmp_path / "individual-images").exists()
            assert (tmp_path / "individual-images" / "alpine_latest").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
