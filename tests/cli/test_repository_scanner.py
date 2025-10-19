"""
Tests for Repository Scanner

Tests the repository_scanner module with various scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.repository_scanner import scan_repository


class TestRepositoryScanner:
    """Test repository scanner functionality"""

    def test_scan_repository_basic(self, tmp_path):
        """Test basic repository scanning with trufflehog and semgrep"""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / ".git").mkdir()
        (repo / "README.md").write_text("# Test Repo")

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
                ToolResult(tool="semgrep", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert name == "test-repo"
            assert statuses["trufflehog"] is True
            assert statuses["semgrep"] is True

    def test_scan_repository_with_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        repo = tmp_path / "my-app"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trivy", status="success", attempts=1),
            ]

            per_tool_config = {
                "trivy": {"timeout": 1200, "flags": ["--severity", "HIGH,CRITICAL"]}
            }

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trivy"],
                timeout=600,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs["tools"]
            trivy_def = next(t for t in tool_defs if t.name == "trivy")
            assert trivy_def.timeout == 1200
            assert "--severity" in trivy_def.command

    def test_scan_repository_multiple_tools(self, tmp_path):
        """Test scanning with multiple tools"""
        repo = tmp_path / "multi-tool-repo"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
                ToolResult(tool="semgrep", status="success", attempts=1),
                ToolResult(tool="trivy", status="success", attempts=1),
                ToolResult(tool="syft", status="success", attempts=1),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog", "semgrep", "trivy", "syft"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert len(statuses) == 4
            assert all(statuses[tool] for tool in ["trufflehog", "semgrep", "trivy", "syft"])

    def test_scan_repository_with_retries(self, tmp_path):
        """Test repository scanning with retries"""
        repo = tmp_path / "retry-repo"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="semgrep", status="success", attempts=3),
            ]

            name, statuses = scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["semgrep"],
                timeout=600,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["semgrep"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["semgrep"] == 3

    def test_scan_repository_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        repo = tmp_path / "output-test"
        repo.mkdir()

        with patch("scripts.cli.scan_jobs.repository_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
            ]

            scan_repository(
                repo=repo,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check directory was created with repo name
            assert (tmp_path / "output-test").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
