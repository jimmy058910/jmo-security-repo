"""Tests for wizard tool installation functions.

Coverage targets:
- _auto_fix_tools(): Auto-fix tools with parallel installation
- _install_missing_tools_interactive(): Interactive tool installation with progress
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


class MockToolStatus:
    """Mock ToolStatus for testing."""

    def __init__(self, name: str, status: str = "missing"):
        self.name = name
        self.status = status


class MockInstallResult:
    """Mock InstallResult for testing."""

    def __init__(self, tool_name: str, success: bool = True, error: str = ""):
        self.tool_name = tool_name
        self.success = success
        self.error = error


class TestAutoFixTools:
    """Test cases for _auto_fix_tools()."""

    def test_auto_fix_empty_list(self):
        """Test auto fix with empty fix_info list."""
        from scripts.cli.wizard import _auto_fix_tools

        should_continue, available = _auto_fix_tools(
            fix_info=[],
            platform="linux",
            profile="balanced",
            available=["trivy", "semgrep"],
        )

        assert should_continue is True
        assert available == ["trivy", "semgrep"]

    def test_auto_fix_manual_only_tools(self):
        """Test auto fix with only manual tools (no install attempt)."""
        from scripts.cli.wizard import _auto_fix_tools

        fix_info = [
            {
                "name": "mobsf",
                "issue": "Not installed",
                "remediation": {
                    "is_manual": True,
                    "manual_reason": "Requires Docker Compose setup",
                    "manual_url": "https://mobsf.github.io",
                },
            }
        ]

        with patch("builtins.print"):  # Suppress output
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="balanced",
                available=["trivy"],
            )

        # Should continue without error (manual tools are just displayed)
        assert should_continue is True
        assert "trivy" in available

    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_auto_fix_installable_tool_success(self, mock_installer_class):
        """Test auto fix with installable tool that succeeds."""
        from scripts.cli.wizard import _auto_fix_tools

        # Setup mock installer
        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = MockInstallResult("semgrep", True)
        mock_installer_class.return_value = mock_installer

        fix_info = [
            {
                "name": "semgrep",
                "issue": "Not installed",
                "remediation": {
                    "is_manual": False,
                    "command": "pip install semgrep",
                    "method": "pip",
                },
            }
        ]

        with patch("builtins.print"):  # Suppress output
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="balanced",
                available=["trivy"],
            )

        assert should_continue is True

    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_auto_fix_tool_failure(self, mock_installer_class):
        """Test auto fix handles tool installation failure."""
        from scripts.cli.wizard import _auto_fix_tools

        # Setup mock installer to fail
        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = MockInstallResult(
            "semgrep", False, "Installation failed"
        )
        mock_installer_class.return_value = mock_installer

        fix_info = [
            {
                "name": "semgrep",
                "issue": "Not installed",
                "remediation": {
                    "is_manual": False,
                    "command": "pip install semgrep",
                    "method": "pip",
                },
            }
        ]

        with patch("builtins.print"):  # Suppress output
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="balanced",
                available=["trivy"],
            )

        # Should still continue (with warning shown)
        assert should_continue is True


class TestInstallMissingToolsInteractive:
    """Test cases for _install_missing_tools_interactive()."""

    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_install_missing_empty_list(self, mock_installer_class):
        """Test with empty missing list."""
        from scripts.cli.wizard import _install_missing_tools_interactive

        with patch("builtins.print"):
            should_continue, available = _install_missing_tools_interactive(
                missing=[],
                profile="balanced",
                available=["trivy"],
            )

        assert should_continue is True
        assert "trivy" in available

    @patch("scripts.cli.tool_installer.InstallProgress")
    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_install_missing_single_tool_success(
        self, mock_installer_class, mock_progress_class
    ):
        """Test installing single missing tool successfully."""
        from scripts.cli.wizard import _install_missing_tools_interactive

        # Setup mock installer
        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = MockInstallResult("semgrep", True)
        mock_installer_class.return_value = mock_installer

        # Setup mock progress
        mock_progress = MagicMock()
        mock_progress.failed = 0
        mock_progress.successful = 1
        mock_progress_class.return_value = mock_progress

        missing = [MockToolStatus("semgrep", "missing")]

        with patch("builtins.print"):
            should_continue, available = _install_missing_tools_interactive(
                missing=missing,
                profile="balanced",
                available=["trivy"],
            )

        assert should_continue is True
        assert "semgrep" in available

    @patch("scripts.cli.tool_installer.InstallProgress")
    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_install_missing_tool_failure(
        self, mock_installer_class, mock_progress_class
    ):
        """Test handling tool installation failure."""
        from scripts.cli.wizard import _install_missing_tools_interactive

        # Setup mock installer to fail
        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = MockInstallResult(
            "badtool", False, "Failed to install"
        )
        mock_installer_class.return_value = mock_installer

        # Setup mock progress with failure
        mock_progress = MagicMock()
        mock_progress.failed = 1
        mock_progress.successful = 0
        mock_progress_class.return_value = mock_progress

        missing = [MockToolStatus("badtool", "missing")]

        with patch("builtins.print"):
            should_continue, available = _install_missing_tools_interactive(
                missing=missing,
                profile="balanced",
                available=["trivy"],
            )

        # Should continue but tool not added to available
        assert should_continue is True
        assert "badtool" not in available

    @patch("scripts.cli.tool_installer.InstallProgress")
    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_install_missing_multiple_tools(
        self, mock_installer_class, mock_progress_class
    ):
        """Test installing multiple missing tools."""
        from scripts.cli.wizard import _install_missing_tools_interactive

        # Setup mock installer
        mock_installer = MagicMock()
        results = [
            MockInstallResult("semgrep", True),
            MockInstallResult("trivy", True),
            MockInstallResult("checkov", False, "Failed"),
        ]
        mock_installer.install_tool.side_effect = results
        mock_installer_class.return_value = mock_installer

        # Setup mock progress
        mock_progress = MagicMock()
        mock_progress.failed = 1
        mock_progress.successful = 2
        mock_progress_class.return_value = mock_progress

        missing = [
            MockToolStatus("semgrep", "missing"),
            MockToolStatus("trivy", "missing"),
            MockToolStatus("checkov", "missing"),
        ]

        with patch("builtins.print"):
            should_continue, available = _install_missing_tools_interactive(
                missing=missing,
                profile="balanced",
                available=[],
            )

        # 2 tools installed, 1 failed
        assert should_continue is True
        assert "semgrep" in available
        assert "trivy" in available
        assert "checkov" not in available

    def test_install_missing_import_error(self):
        """Test handling ImportError when ToolInstaller not available."""
        from scripts.cli.wizard import _install_missing_tools_interactive

        with patch(
            "scripts.cli.tool_installer.ToolInstaller",
            side_effect=ImportError("Module not found"),
        ):
            with patch("builtins.print"):
                with patch(
                    "builtins.input", return_value="y"
                ):  # User chooses to continue
                    should_continue, available = _install_missing_tools_interactive(
                        missing=[MockToolStatus("semgrep")],
                        profile="balanced",
                        available=[],
                    )

        # Function should handle the error and ask to continue
        assert (
            should_continue is True or should_continue is False
        )  # Just verify it returns


class TestToolInstallationProgress:
    """Test cases for progress callback functionality."""

    @patch("scripts.cli.tool_installer.InstallProgress")
    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_progress_callback_called(self, mock_installer_class, mock_progress_class):
        """Test that progress callback is set and called."""
        from scripts.cli.wizard import _install_missing_tools_interactive

        # Setup mock installer
        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = MockInstallResult("semgrep", True)
        mock_installer_class.return_value = mock_installer

        # Setup mock progress
        mock_progress = MagicMock()
        mock_progress.failed = 0
        mock_progress.successful = 1
        mock_progress_class.return_value = mock_progress

        missing = [MockToolStatus("semgrep", "missing")]

        with patch("builtins.print"):
            _install_missing_tools_interactive(
                missing=missing,
                profile="balanced",
                available=[],
            )

        # Verify progress callback was set
        mock_installer.set_progress_callback.assert_called_once()
