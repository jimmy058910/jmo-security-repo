"""
Tests for GitLab Scanner

Tests the gitlab_scanner module with various scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import MagicMock, patch

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.gitlab_scanner import scan_gitlab_repo


class TestGitlabScanner:
    """Test GitLab scanner functionality"""

    def test_scan_gitlab_basic(self, tmp_path):
        """Test basic GitLab repo scanning with trufflehog"""
        with patch("scripts.cli.scan_jobs.gitlab_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
            ]

            gitlab_info = {
                "full_path": "mygroup/myrepo",
                "url": "https://gitlab.com",
                "token": "glpat-abc123",
                "repo": "myrepo",
                "group": "mygroup",
            }

            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert full_path == "mygroup/myrepo"
            assert statuses["trufflehog"] is True

    def test_scan_gitlab_group_scan(self, tmp_path):
        """Test GitLab group scan (wildcard repo)"""
        with patch("scripts.cli.scan_jobs.gitlab_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
            ]

            gitlab_info = {
                "full_path": "engineering/*",
                "url": "https://gitlab.com",
                "token": "glpat-xyz789",
                "repo": "*",
                "group": "engineering",
            }

            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert "engineering" in full_path
            # Verify group scan uses --group flag
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs["tools"]
            trufflehog_def = tool_defs[0]
            assert "--group" in trufflehog_def.command
            assert "engineering" in trufflehog_def.command

    def test_scan_gitlab_sanitizes_path(self, tmp_path):
        """Test that GitLab paths are sanitized for directory names"""
        with patch("scripts.cli.scan_jobs.gitlab_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
            ]

            gitlab_info = {
                "full_path": "my-group/sub-group/project",
                "url": "https://gitlab.example.com",
                "token": "glpat-test",
                "repo": "project",
                "group": "my-group/sub-group",
            }

            scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check sanitized directory (/ replaced with _)
            expected_dir = tmp_path / "individual-gitlab" / "my-group_sub-group_project"
            assert expected_dir.exists()

    def test_scan_gitlab_with_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""

        # Mock tool_exists to return True for trufflehog
        def mock_tool_exists(tool_name):
            return tool_name == "trufflehog"

        with patch("scripts.cli.scan_jobs.gitlab_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
            ]

            per_tool_config = {
                "trufflehog": {"timeout": 900, "flags": ["--concurrency", "4"]}
            }

            gitlab_info = {
                "full_path": "org/repo",
                "url": "https://gitlab.com",
                "token": "glpat-123",
                "repo": "repo",
                "group": "org",
            }

            scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
                tool_exists_func=mock_tool_exists,
            )

            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args
            tool_defs = kwargs.get("tools") or (args[0] if args else [])
            trufflehog_def = next(
                (t for t in tool_defs if t.name == "trufflehog"), None
            )
            assert trufflehog_def is not None, "trufflehog tool definition not found"
            assert trufflehog_def.timeout == 900
            assert "--concurrency" in trufflehog_def.command
            assert "4" in trufflehog_def.command

    def test_scan_gitlab_tool_failure(self, tmp_path):
        """Test handling of tool failures"""
        with patch("scripts.cli.scan_jobs.gitlab_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="error", returncode=1, attempts=1),
            ]

            gitlab_info = {
                "full_path": "fail/test",
                "url": "https://gitlab.com",
                "token": "glpat-fail",
                "repo": "test",
                "group": "fail",
            }

            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trufflehog"] is False

    def test_scan_gitlab_with_retries(self, tmp_path):
        """Test GitLab scanning with retries"""
        with patch("scripts.cli.scan_jobs.gitlab_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=3),
            ]

            gitlab_info = {
                "full_path": "retry/test",
                "url": "https://gitlab.com",
                "token": "glpat-retry",
                "repo": "test",
                "group": "retry",
            }

            full_path, statuses = scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=2,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["trufflehog"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["trufflehog"] == 3

    def test_scan_gitlab_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        with patch("scripts.cli.scan_jobs.gitlab_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult

            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="trufflehog", status="success", attempts=1),
            ]

            gitlab_info = {
                "full_path": "security/scanner",
                "url": "https://gitlab.com",
                "token": "glpat-test",
                "repo": "scanner",
                "group": "security",
            }

            scan_gitlab_repo(
                gitlab_info=gitlab_info,
                results_dir=tmp_path,
                tools=["trufflehog"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert (tmp_path / "individual-gitlab").exists()
            assert (tmp_path / "individual-gitlab" / "security_scanner").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
