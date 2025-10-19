"""
Tests for URL Scanner

Tests the url_scanner module with various scenarios.
"""

import pytest
from pathlib import Path
from unittest.mock import Mock, MagicMock, patch

import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.cli.scan_jobs.url_scanner import scan_url


class TestUrlScanner:
    """Test URL scanner functionality"""

    def test_scan_url_basic(self, tmp_path):
        """Test basic URL scanning with ZAP"""
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="success", attempts=1),
            ]

            url, statuses = scan_url(
                url="https://example.com",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert url == "https://example.com"
            assert statuses["zap"] is True
            assert "__attempts__" not in statuses

    def test_scan_url_with_retries(self, tmp_path):
        """Test URL scanning with retries"""
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="success", attempts=2),  # Retried
            ]

            url, statuses = scan_url(
                url="https://api.example.com",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=1,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["zap"] is True
            assert "__attempts__" in statuses
            assert statuses["__attempts__"]["zap"] == 2

    def test_scan_url_sanitizes_domain(self, tmp_path):
        """Test that domain names are sanitized for directory names"""
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="success", attempts=1),
            ]

            # URL with special characters
            scan_url(
                url="https://sub.example.com:8080/path",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check that directory was created with sanitized domain
            expected_dir = tmp_path / "individual-web" / "sub.example.com_8080"
            assert expected_dir.exists()

    def test_scan_url_file_protocol(self, tmp_path):
        """Test scanning file:// URLs"""
        test_file = tmp_path / "test.html"
        test_file.write_text("<html><body>Test</body></html>")

        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="success", attempts=1),
            ]

            scan_url(
                url=f"file://{test_file}",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check that directory was created with filename
            expected_dir = tmp_path / "individual-web" / "test"
            assert expected_dir.exists()

    def test_scan_url_with_tool_timeout_override(self, tmp_path):
        """Test per-tool timeout overrides"""
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner, \
             patch("scripts.cli.scan_jobs.url_scanner.tool_exists", return_value=True):
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="success", attempts=1),
            ]

            per_tool_config = {
                "zap": {
                    "timeout": 1200,
                    "flags": ["-config", "api.disablekey=true"]
                }
            }

            scan_url(
                url="https://app.example.com",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config=per_tool_config,
                allow_missing_tools=False,
            )

            # Verify ToolRunner was called
            MockRunner.assert_called_once()
            args, kwargs = MockRunner.call_args

            # Check that tool definitions have correct timeout
            tool_defs = kwargs["tools"]
            zap_def = next((t for t in tool_defs if t.name == "zap"), None)
            assert zap_def is not None, "zap tool definition not found"
            assert zap_def.timeout == 1200
            assert "-config" in zap_def.command
            assert "api.disablekey=true" in zap_def.command

    def test_scan_url_tool_failure(self, tmp_path):
        """Test handling of tool failures"""
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="timeout", returncode=124, attempts=1),
            ]

            url, statuses = scan_url(
                url="https://timeout.example.com",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=10,  # Short timeout to trigger failure
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            assert statuses["zap"] is False  # Failed

    def test_scan_url_creates_output_directory(self, tmp_path):
        """Test that output directories are created"""
        with patch("scripts.cli.scan_jobs.url_scanner.ToolRunner") as MockRunner:
            mock_runner = MagicMock()
            MockRunner.return_value = mock_runner

            from scripts.core.tool_runner import ToolResult
            mock_runner.run_all_parallel.return_value = [
                ToolResult(tool="zap", status="success", attempts=1),
            ]

            scan_url(
                url="https://secure.example.com",
                results_dir=tmp_path,
                tools=["zap"],
                timeout=600,
                retries=0,
                per_tool_config={},
                allow_missing_tools=False,
            )

            # Check directory structure
            assert (tmp_path / "individual-web").exists()
            assert (tmp_path / "individual-web" / "secure.example.com").exists()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
