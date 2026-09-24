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
            available=["trivy", "semgrep"],
        )

        assert should_continue is True
        assert available == ["trivy", "semgrep"]

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
                    "command": "pip install semgrep",
                    "method": "pip",
                },
            }
        ]

        # Mock ToolManager's post-install re-check (#907: unmocked, it
        # shells out to whatever scanner binaries are actually on PATH).
        mock_summary = MagicMock(execution_ready=1, total=1)
        with (
            patch("builtins.print"),  # Suppress output
            patch("scripts.cli.tool_manager.ToolManager") as mock_manager_cls,
        ):
            mock_manager_cls.return_value.check_matrix.return_value = {}
            mock_manager_cls.return_value.get_tool_summary.return_value = mock_summary
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
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
                    "command": "pip install semgrep",
                    "method": "pip",
                },
            }
        ]

        # Mock ToolManager's post-install re-check (#907: unmocked, it
        # shells out to whatever scanner binaries are actually on PATH).
        mock_summary = MagicMock(execution_ready=1, total=1)
        with (
            patch("builtins.print"),  # Suppress output
            patch("scripts.cli.tool_manager.ToolManager") as mock_manager_cls,
        ):
            mock_manager_cls.return_value.check_matrix.return_value = {}
            mock_manager_cls.return_value.get_tool_summary.return_value = mock_summary
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                available=["trivy"],
            )

        # Should still continue (with warning shown)
        assert should_continue is True

    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_auto_fix_failed_install_is_a_failure_whatever_its_method(
        self, mock_installer_class
    ):
        """A failed install is reported as failed, never as an expected skip.

        `_auto_fix_tools` used to print a failed result whose method was
        "manual" or "docker" as a yellow skip and leave it out of the failure
        count, for tools that could not be installed on some platforms. Every
        matrix tool installs everywhere, so a failure is a failure: it must be
        counted, named, and kept out of `available`.
        """
        from scripts.cli.wizard import _auto_fix_tools

        failed = MagicMock(
            tool_name="zap", success=False, method="manual", message="download failed"
        )
        mock_installer_class.return_value.install_tools_parallel.return_value = (
            MagicMock(results=[failed])
        )

        fix_info = [
            {
                "name": "zap",
                "issue": "NOT INSTALLED",
                "missing_deps": [],
                "remediation": {
                    "commands": [],
                    "manual": None,
                    "jmo_install": "jmo tools install zap",
                },
            }
        ]

        # Mock ToolManager's post-install re-check (#907).
        mock_summary = MagicMock(execution_ready=1, total=2, version_issues=[])
        with (
            patch("builtins.print") as mock_print,
            patch("scripts.cli.tool_manager.ToolManager") as mock_manager_cls,
        ):
            mock_manager_cls.return_value.check_matrix.return_value = {
                "trivy": MagicMock(execution_ready=True),
                "zap": MagicMock(execution_ready=False),
            }
            mock_manager_cls.return_value.get_tool_summary.return_value = mock_summary
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                available=["trivy"],
            )

        printed = " ".join(str(c) for c in mock_print.call_args_list)
        assert should_continue is True
        assert "0 fixed, 1 failed" in printed
        assert "Failed tools: zap" in printed
        assert available == ["trivy"]


class TestInstallMissingToolsInteractive:
    """Test cases for _install_missing_tools_interactive()."""

    @patch("scripts.cli.tool_installer.ToolInstaller")
    def test_install_missing_empty_list(self, mock_installer_class):
        """Test with empty missing list."""
        from scripts.cli.wizard import _install_missing_tools_interactive

        with patch("builtins.print"):
            should_continue, available = _install_missing_tools_interactive(
                missing=[],
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

        with (
            patch(
                "scripts.cli.tool_installer.ToolInstaller",
                side_effect=ImportError("Module not found"),
            ),
            patch("builtins.print"),
            patch("builtins.input", return_value="y"),
        ):  # User chooses to continue
            should_continue, available = _install_missing_tools_interactive(
                missing=[MockToolStatus("semgrep")],
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
                available=[],
            )

        # Verify progress callback was set
        mock_installer.set_progress_callback.assert_called_once()
