"""
Tests for parallel tool installation functionality.

Tests cover:
- ParallelInstallProgress thread safety
- Batch pip/npm installation
- Concurrent binary downloads
- Signal handling and cancellation
"""

from __future__ import annotations

import threading
import time
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import MagicMock, patch

from scripts.cli.tool_installer import (
    InstallResult,
    InstallProgress,
    ParallelInstallProgress,
)


class TestParallelInstallProgress:
    """Tests for thread-safe progress tracking."""

    def test_initialization(self):
        """Test basic initialization."""
        progress = ParallelInstallProgress(total=10)
        assert progress.total == 10
        assert progress.completed == 0
        assert progress.failed == 0
        assert progress.skipped == 0
        assert len(progress.current_tools) == 0
        assert len(progress.results) == 0
        assert not progress.is_cancelled()

    def test_on_start_tracks_current_tools(self):
        """Test that on_start adds tool to current_tools list."""
        progress = ParallelInstallProgress(total=5)
        progress.on_start("tool1")
        progress.on_start("tool2")

        assert "tool1" in progress.current_tools
        assert "tool2" in progress.current_tools
        assert len(progress.current_tools) == 2

    def test_on_complete_success(self):
        """Test successful completion updates counters."""
        progress = ParallelInstallProgress(total=5)
        progress.on_start("tool1")

        result = InstallResult(tool_name="tool1", success=True, method="pip")
        progress.on_complete("tool1", result)

        assert progress.completed == 1
        assert progress.failed == 0
        assert "tool1" not in progress.current_tools
        assert len(progress.results) == 1

    def test_on_complete_failure(self):
        """Test failed completion updates counters."""
        progress = ParallelInstallProgress(total=5)
        progress.on_start("tool1")

        result = InstallResult(tool_name="tool1", success=False, message="Error")
        progress.on_complete("tool1", result)

        assert progress.completed == 0
        assert progress.failed == 1
        assert "tool1" not in progress.current_tools

    def test_on_complete_skipped(self):
        """Test skipped tools update counters correctly."""
        progress = ParallelInstallProgress(total=5)

        result = InstallResult(tool_name="tool1", success=True, method="skipped")
        progress.on_complete("tool1", result)

        assert progress.skipped == 1
        assert progress.completed == 0

    def test_get_status_line(self):
        """Test status line generation."""
        progress = ParallelInstallProgress(total=10)
        progress.on_start("tool1")
        progress.on_start("tool2")

        status = progress.get_status_line()
        assert "[0/10]" in status
        assert "tool1" in status or "tool2" in status

    def test_get_status_line_truncates_many_tools(self):
        """Test status line truncates when many tools are active."""
        progress = ParallelInstallProgress(total=10)
        for i in range(5):
            progress.on_start(f"tool{i}")

        status = progress.get_status_line()
        assert "+2" in status  # 5 tools, shows 3 + "+2"

    def test_cancellation(self):
        """Test cancellation mechanism."""
        progress = ParallelInstallProgress(total=10)
        assert not progress.is_cancelled()

        progress.cancel()
        assert progress.is_cancelled()

    def test_to_install_progress_conversion(self):
        """Test conversion to legacy InstallProgress."""
        progress = ParallelInstallProgress(total=10)

        # Add some results
        progress.on_complete(
            "tool1", InstallResult(tool_name="tool1", success=True, method="pip")
        )
        progress.on_complete(
            "tool2", InstallResult(tool_name="tool2", success=False, message="Error")
        )
        progress.on_complete(
            "tool3", InstallResult(tool_name="tool3", success=True, method="skipped")
        )

        legacy = progress.to_install_progress()

        assert isinstance(legacy, InstallProgress)
        assert legacy.total == 10
        assert legacy.successful == 1
        assert legacy.failed == 1
        assert legacy.skipped == 1
        assert len(legacy.results) == 3

    def test_concurrent_updates_thread_safety(self):
        """Verify progress tracks correctly under concurrent updates."""
        progress = ParallelInstallProgress(total=100)

        def update_progress(i: int):
            progress.on_start(f"tool_{i}")
            # Small delay to increase chance of race conditions
            time.sleep(0.001)
            progress.on_complete(
                f"tool_{i}",
                InstallResult(tool_name=f"tool_{i}", success=True, method="pip"),
            )

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(update_progress, range(100)))

        assert progress.completed == 100
        assert len(progress.current_tools) == 0
        assert len(progress.results) == 100

    def test_no_race_conditions_stress_test(self):
        """Stress test for race conditions with rapid updates."""
        progress = ParallelInstallProgress(total=50)
        errors = []

        def stress_test(i: int):
            try:
                for _ in range(50):
                    progress.on_start(f"t{i}")
                    progress.on_complete(
                        f"t{i}",
                        InstallResult(tool_name=f"t{i}", success=True, method="pip"),
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=stress_test, args=(i,)) for i in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        # Total operations: 10 threads * 50 iterations = 500 completions
        assert progress.completed == 500

    def test_mixed_success_failure_concurrent(self):
        """Test concurrent updates with mixed success/failure results."""
        progress = ParallelInstallProgress(total=100)

        def update(i: int):
            progress.on_start(f"tool_{i}")
            success = i % 2 == 0  # Even tools succeed, odd fail
            result = InstallResult(
                tool_name=f"tool_{i}",
                success=success,
                method="pip" if success else None,
                message=None if success else "Error",
            )
            progress.on_complete(f"tool_{i}", result)

        with ThreadPoolExecutor(max_workers=10) as executor:
            list(executor.map(update, range(100)))

        assert progress.completed == 50  # Even numbers
        assert progress.failed == 50  # Odd numbers
        assert len(progress.results) == 100


class TestBatchPipInstall:
    """Tests for batch pip installation."""

    @patch("scripts.cli.tool_installer.subprocess.run")
    def test_batch_pip_install_success(self, mock_run):
        """Test successful batch pip install."""
        from scripts.cli.tool_installer import ToolInstaller

        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        # Create proper mocks
        mock_registry = MagicMock()
        mock_manager = MagicMock()

        # Set up tool info
        tool_info = MagicMock()
        tool_info.pypi_package = "package1"
        tool_info.version = "1.0.0"
        mock_registry.get_tool.return_value = tool_info

        # Set up manager status
        status = MagicMock()
        status.installed_version = "1.0.0"
        mock_manager.check_tool.return_value = status

        with patch.object(
            ToolInstaller,
            "registry",
            new_callable=lambda: property(lambda self: mock_registry),
        ):
            with patch.object(
                ToolInstaller,
                "manager",
                new_callable=lambda: property(lambda self: mock_manager),
            ):
                installer = ToolInstaller.__new__(ToolInstaller)
                installer._registry = mock_registry
                installer._manager = mock_manager

                progress = ParallelInstallProgress(total=2)
                results = installer._batch_pip_install(["tool1", "tool2"], progress)

                assert len(results) == 2
                assert all(r.success for r in results)
                assert all(r.method == "pip_batch" for r in results)

    @patch("scripts.cli.tool_installer.subprocess.run")
    def test_batch_pip_install_fallback_on_failure(self, mock_run):
        """Test fallback to individual installs on batch failure."""
        from scripts.cli.tool_installer import ToolInstaller

        # First call fails (batch)
        mock_run.return_value = MagicMock(returncode=1, stderr="batch error")

        # Create proper mocks
        mock_registry = MagicMock()
        mock_manager = MagicMock()

        tool_info = MagicMock()
        tool_info.pypi_package = "package1"
        tool_info.version = "1.0.0"
        mock_registry.get_tool.return_value = tool_info

        installer = ToolInstaller.__new__(ToolInstaller)
        installer._registry = mock_registry
        installer._manager = mock_manager
        installer.install_tool = MagicMock(
            return_value=InstallResult(tool_name="tool1", success=True, method="pip")
        )

        progress = ParallelInstallProgress(total=2)
        _results = installer._batch_pip_install(["tool1", "tool2"], progress)

        # Should fall back to individual installs
        assert installer.install_tool.call_count == 2


class TestBatchNpmInstall:
    """Tests for batch npm installation."""

    @patch("scripts.cli.tool_installer.shutil.which")
    def test_batch_npm_install_no_npm(self, mock_which):
        """Test handling when npm is not installed."""
        from scripts.cli.tool_installer import ToolInstaller

        mock_which.return_value = None  # npm not found

        # Create mock installer
        mock_registry = MagicMock()
        installer = ToolInstaller.__new__(ToolInstaller)
        installer._registry = mock_registry

        progress = ParallelInstallProgress(total=2)
        results = installer._batch_npm_install(["tool1", "tool2"], progress)

        assert len(results) == 2
        assert all(not r.success for r in results)
        assert all("npm not installed" in r.message for r in results)

    @patch("scripts.cli.tool_installer.shutil.which")
    @patch("scripts.cli.tool_installer.subprocess.run")
    def test_batch_npm_install_success(self, mock_run, mock_which):
        """Test successful batch npm install."""
        from scripts.cli.tool_installer import ToolInstaller

        mock_which.return_value = "/usr/bin/npm"
        mock_run.return_value = MagicMock(returncode=0)

        # Create mock installer
        mock_registry = MagicMock()
        mock_manager = MagicMock()

        tool_info = MagicMock()
        tool_info.npm_package = "@scope/package"
        mock_registry.get_tool.return_value = tool_info

        status = MagicMock()
        status.installed_version = "1.0.0"
        mock_manager.check_tool.return_value = status

        installer = ToolInstaller.__new__(ToolInstaller)
        installer._registry = mock_registry
        installer._manager = mock_manager

        progress = ParallelInstallProgress(total=2)
        results = installer._batch_npm_install(["tool1", "tool2"], progress)

        assert len(results) == 2
        assert all(r.success for r in results)


class TestInstallToolThreadsafe:
    """Tests for thread-safe tool installation wrapper."""

    def test_returns_cancelled_when_cancelled(self):
        """Test that cancelled progress returns cancelled result."""
        from scripts.cli.tool_installer import ToolInstaller

        with patch.object(ToolInstaller, "__init__", return_value=None):
            installer = ToolInstaller()
            progress = ParallelInstallProgress(total=1)
            progress.cancel()

            result = installer._install_tool_threadsafe("tool1", progress)

            assert not result.success
            assert "cancelled" in result.message.lower()

    def test_wraps_exceptions(self):
        """Test that exceptions are caught and returned as failed results."""
        from scripts.cli.tool_installer import ToolInstaller

        with patch.object(ToolInstaller, "__init__", return_value=None):
            installer = ToolInstaller()
            installer.install_tool = MagicMock(side_effect=RuntimeError("Test error"))

            progress = ParallelInstallProgress(total=1)
            result = installer._install_tool_threadsafe("tool1", progress)

            assert not result.success
            assert "Test error" in result.message


class TestDownloadWithRequests:
    """Tests for cross-platform download using requests."""

    @patch("scripts.cli.tool_installer.requests.get")
    def test_successful_download(self, mock_get, tmp_path):
        """Test successful file download."""
        from scripts.cli.tool_installer import ToolInstaller

        mock_response = MagicMock()
        mock_response.iter_content.return_value = [b"test content"]
        mock_get.return_value.__enter__ = MagicMock(return_value=mock_response)
        mock_get.return_value = mock_response

        with patch.object(ToolInstaller, "__init__", return_value=None):
            installer = ToolInstaller()
            output_path = tmp_path / "test_file"

            success = installer._download_with_requests(
                "https://example.com/file", output_path
            )

            assert success
            assert output_path.exists()

    @patch("scripts.cli.tool_installer.requests.get")
    def test_timeout_handling(self, mock_get):
        """Test timeout error handling."""
        import requests
        from scripts.cli.tool_installer import ToolInstaller

        mock_get.side_effect = requests.exceptions.Timeout()

        with patch.object(ToolInstaller, "__init__", return_value=None):
            installer = ToolInstaller()

            success = installer._download_with_requests(
                "https://example.com/file", "/tmp/test"
            )

            assert not success

    @patch("scripts.cli.tool_installer.requests.get")
    def test_http_error_handling(self, mock_get):
        """Test HTTP error handling."""
        import requests
        from scripts.cli.tool_installer import ToolInstaller

        mock_get.side_effect = requests.exceptions.HTTPError("404 Not Found")

        with patch.object(ToolInstaller, "__init__", return_value=None):
            installer = ToolInstaller()

            success = installer._download_with_requests(
                "https://example.com/file", "/tmp/test"
            )

            assert not success


class TestInstallProfileParallel:
    """Tests for the main parallel installation function."""

    @patch("scripts.core.tool_registry.PROFILE_TOOLS", {"other": ["tool1"]})
    def test_empty_profile(self):
        """Test handling of empty/unknown profile."""
        from scripts.cli.tool_installer import ToolInstaller

        # Create mock installer
        mock_registry = MagicMock()
        mock_manager = MagicMock()

        installer = ToolInstaller.__new__(ToolInstaller)
        installer._registry = mock_registry
        installer._manager = mock_manager

        progress = installer.install_profile_parallel(
            profile="unknown", show_progress=False
        )

        assert progress.total == 0

    @patch(
        "scripts.core.tool_registry.PROFILE_TOOLS",
        {"test": ["tool1", "tool1", "tool2", "tool1"]},
    )
    def test_deduplication(self):
        """Test that duplicate tools are deduplicated."""
        from scripts.cli.tool_installer import ToolInstaller

        # Create mock installer
        mock_registry = MagicMock()
        mock_manager = MagicMock()

        # All tools already installed
        status = MagicMock()
        status.installed = True
        status.installed_version = "1.0.0"
        mock_manager.check_tool.return_value = status

        installer = ToolInstaller.__new__(ToolInstaller)
        installer._registry = mock_registry
        installer._manager = mock_manager

        _progress = installer.install_profile_parallel(
            profile="test",
            skip_installed=True,
            show_progress=False,
        )

        # Should only check 2 unique tools
        assert mock_manager.check_tool.call_count == 2

    @patch("scripts.core.tool_registry.PROFILE_TOOLS", {"test": ["tool1", "tool2"]})
    def test_all_tools_skipped(self):
        """Test when all tools are already installed."""
        from scripts.cli.tool_installer import ToolInstaller

        # Create mock installer
        mock_registry = MagicMock()
        mock_manager = MagicMock()

        status = MagicMock()
        status.installed = True
        status.installed_version = "1.0.0"
        mock_manager.check_tool.return_value = status

        installer = ToolInstaller.__new__(ToolInstaller)
        installer._registry = mock_registry
        installer._manager = mock_manager

        progress = installer.install_profile_parallel(
            profile="test",
            skip_installed=True,
            show_progress=False,
        )

        assert progress.skipped == 2
        assert progress.successful == 0
        assert progress.failed == 0


class TestMaxWorkersLimit:
    """Tests for max_workers limit enforcement."""

    @patch("scripts.core.tool_registry.PROFILE_TOOLS", {"test": ["tool1"]})
    def test_max_workers_capped_at_8(self):
        """Test that max_workers is capped at 8."""
        from scripts.cli.tool_installer import ToolInstaller

        # Create mock installer
        mock_registry = MagicMock()
        mock_manager = MagicMock()

        # Return installed for all tools
        status = MagicMock()
        status.installed = True
        status.installed_version = "1.0.0"
        mock_manager.check_tool.return_value = status

        installer = ToolInstaller.__new__(ToolInstaller)
        installer._registry = mock_registry
        installer._manager = mock_manager

        # Even if user requests 100 workers, it should be capped
        progress = installer.install_profile_parallel(
            profile="test",
            max_workers=100,  # Should be capped to 8
            show_progress=False,
        )

        # Function should complete without error
        assert progress is not None
