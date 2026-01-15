"""Tests for tool_installer dependency auto-install functionality (Chunk 4).

These tests verify that runtime dependencies (Java, Node.js) can be
detected and installed via package managers.

CRITICAL: All subprocess calls are mocked - tests never actually install anything.
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock
import subprocess

from scripts.cli.tool_installer import (
    DEPENDENCY_INSTALL_COMMANDS,
    DEPENDENCY_VERIFY_COMMANDS,
    DEPENDENCY_DISPLAY_NAMES,
    DEPENDENCY_MANUAL_COMMANDS,
    _is_package_manager_available,
    install_dependency,
    get_manual_dependency_command,
)


class TestDependencyConstants:
    """Test that dependency constants are properly structured."""

    def test_dependency_install_commands_has_java_and_node(self):
        """Verify java and node are both configured."""
        assert "java" in DEPENDENCY_INSTALL_COMMANDS
        assert "node" in DEPENDENCY_INSTALL_COMMANDS

    def test_dependency_install_commands_has_all_platforms(self):
        """Verify all platforms are covered for each dependency."""
        platforms = ["windows", "linux", "macos"]
        for dep in ["java", "node"]:
            for platform in platforms:
                assert (
                    platform in DEPENDENCY_INSTALL_COMMANDS[dep]
                ), f"{dep} missing {platform} platform configuration"

    def test_dependency_verify_commands_structure(self):
        """Verify verify commands exist for all dependencies."""
        assert "java" in DEPENDENCY_VERIFY_COMMANDS
        assert "node" in DEPENDENCY_VERIFY_COMMANDS
        # Verify they're lists of command args
        assert isinstance(DEPENDENCY_VERIFY_COMMANDS["java"], list)
        assert isinstance(DEPENDENCY_VERIFY_COMMANDS["node"], list)

    def test_dependency_display_names(self):
        """Verify display names exist for all dependencies."""
        assert "java" in DEPENDENCY_DISPLAY_NAMES
        assert "node" in DEPENDENCY_DISPLAY_NAMES
        assert "17" in DEPENDENCY_DISPLAY_NAMES["java"]  # Java 17+
        assert "20" in DEPENDENCY_DISPLAY_NAMES["node"]  # Node.js 20+

    def test_dependency_manual_commands_structure(self):
        """Verify manual commands exist for fallback."""
        assert "java" in DEPENDENCY_MANUAL_COMMANDS
        assert "node" in DEPENDENCY_MANUAL_COMMANDS
        for dep in ["java", "node"]:
            for platform in ["windows", "linux", "macos"]:
                assert platform in DEPENDENCY_MANUAL_COMMANDS[dep]


class TestPackageManagerDetection:
    """Test _is_package_manager_available function."""

    def test_unknown_package_manager_returns_false(self):
        """Unknown package manager should return False without calling subprocess."""
        assert _is_package_manager_available("unknown_manager") is False

    @patch("subprocess.run")
    def test_chocolatey_available(self, mock_run):
        """Test chocolatey detection when available."""
        mock_run.return_value = MagicMock(returncode=0)
        assert _is_package_manager_available("chocolatey") is True
        mock_run.assert_called_once()
        # Verify shell=False is used
        call_kwargs = mock_run.call_args.kwargs
        assert call_kwargs.get("shell") is False

    @patch("subprocess.run")
    def test_chocolatey_not_available(self, mock_run):
        """Test chocolatey detection when not available."""
        mock_run.return_value = MagicMock(returncode=1)
        assert _is_package_manager_available("chocolatey") is False

    @patch("subprocess.run")
    def test_package_manager_file_not_found(self, mock_run):
        """Test handling when package manager executable not found."""
        mock_run.side_effect = FileNotFoundError("Command not found")
        assert _is_package_manager_available("brew") is False

    @patch("subprocess.run")
    def test_package_manager_timeout(self, mock_run):
        """Test handling when package manager check times out."""
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="brew", timeout=10)
        assert _is_package_manager_available("brew") is False

    @patch("subprocess.run")
    def test_package_manager_os_error(self, mock_run):
        """Test handling of OS errors."""
        mock_run.side_effect = OSError("Permission denied")
        assert _is_package_manager_available("apt") is False


class TestInstallDependency:
    """Test install_dependency function."""

    def test_unknown_dependency_returns_false(self):
        """Unknown dependency should return error message."""
        success, msg = install_dependency("unknown_dep", "linux")
        assert success is False
        assert "Unknown dependency" in msg

    def test_unsupported_platform_returns_false(self):
        """Unsupported platform should return error message."""
        success, msg = install_dependency("java", "freebsd")
        assert success is False
        assert "No install method" in msg

    @patch("scripts.cli.tool_installer._is_package_manager_available")
    def test_no_package_manager_available(self, mock_available):
        """Test when no package manager is available."""
        mock_available.return_value = False
        success, msg = install_dependency("java", "linux")
        assert success is False
        assert "No package manager available" in msg

    @patch("subprocess.run")
    @patch("scripts.cli.tool_installer._is_package_manager_available")
    def test_successful_install_with_verification(self, mock_available, mock_run):
        """Test successful install with verification."""
        mock_available.return_value = True
        # First call: install, second call: verify
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=""),  # install
            MagicMock(returncode=0),  # verify
        ]

        success, msg = install_dependency("java", "linux")
        assert success is True
        assert "Installed via" in msg
        # Should have called subprocess twice (install + verify)
        assert mock_run.call_count == 2

    @patch("subprocess.run")
    @patch("scripts.cli.tool_installer._is_package_manager_available")
    def test_install_success_but_verify_fails(self, mock_available, mock_run):
        """Test when install succeeds but verification fails (terminal restart needed)."""
        mock_available.return_value = True
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr=""),  # install
            MagicMock(returncode=1),  # verify fails
        ]

        success, msg = install_dependency("java", "windows")
        assert success is True
        assert "restart terminal" in msg.lower()

    @patch("subprocess.run")
    @patch("scripts.cli.tool_installer._is_package_manager_available")
    def test_install_fails_tries_next_package_manager(self, mock_available, mock_run):
        """Test that install tries multiple package managers on failure."""
        # On Windows, we have chocolatey and winget
        mock_available.return_value = True
        # First package manager fails, second succeeds
        mock_run.side_effect = [
            MagicMock(returncode=1, stderr="Failed"),  # choco fails
            MagicMock(returncode=0, stderr=""),  # winget install
            MagicMock(returncode=0),  # winget verify
        ]

        success, msg = install_dependency("java", "windows")
        assert success is True

    @patch("subprocess.run")
    @patch("scripts.cli.tool_installer._is_package_manager_available")
    def test_install_timeout_handling(self, mock_available, mock_run):
        """Test timeout handling during install."""
        mock_available.return_value = True
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="apt", timeout=300)

        success, msg = install_dependency("java", "linux")
        assert success is False
        assert "No package manager available" in msg

    @patch("subprocess.run")
    @patch("scripts.cli.tool_installer._is_package_manager_available")
    def test_shell_false_always_used(self, mock_available, mock_run):
        """CRITICAL: Verify shell=False is always used for security."""
        mock_available.return_value = True
        mock_run.return_value = MagicMock(returncode=0, stderr="")

        install_dependency("node", "linux")

        # Check all subprocess.run calls used shell=False
        for call in mock_run.call_args_list:
            assert (
                call.kwargs.get("shell") is False
            ), "SECURITY: shell=True must never be used in subprocess calls"


class TestGetManualDependencyCommand:
    """Test get_manual_dependency_command function."""

    def test_java_windows_command(self):
        """Test Java manual command for Windows."""
        cmd = get_manual_dependency_command("java", "windows")
        assert "choco" in cmd or "winget" in cmd

    def test_node_linux_command(self):
        """Test Node.js manual command for Linux."""
        cmd = get_manual_dependency_command("node", "linux")
        assert "apt" in cmd or "dnf" in cmd

    def test_java_macos_command(self):
        """Test Java manual command for macOS."""
        cmd = get_manual_dependency_command("java", "macos")
        assert "brew" in cmd

    def test_unknown_dependency_fallback(self):
        """Test fallback message for unknown dependency."""
        cmd = get_manual_dependency_command("unknown", "linux")
        assert "Install unknown manually" in cmd

    def test_unknown_platform_fallback(self):
        """Test fallback message for unknown platform."""
        cmd = get_manual_dependency_command("java", "freebsd")
        assert "Install java manually" in cmd


class TestCollectMissingDependencies:
    """Test _collect_missing_dependencies function from wizard.py."""

    def test_empty_fix_info_returns_empty(self):
        """Empty input returns empty dict."""
        from scripts.cli.wizard import _collect_missing_dependencies

        result = _collect_missing_dependencies([])
        assert result == {}

    def test_collects_java_dependency(self):
        """Test collection of Java dependency."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "dependency-check",
                "missing_deps": ["java"],
            }
        ]
        result = _collect_missing_dependencies(fix_info)
        assert "java" in result
        assert "dependency-check" in result["java"]

    def test_collects_node_dependency(self):
        """Test collection of Node.js dependency."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "cdxgen",
                "missing_deps": ["node"],
            }
        ]
        result = _collect_missing_dependencies(fix_info)
        assert "node" in result
        assert "cdxgen" in result["node"]

    def test_normalizes_node20_to_node(self):
        """Test that node20 is normalized to node."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "cdxgen",
                "missing_deps": ["node20"],
            }
        ]
        result = _collect_missing_dependencies(fix_info)
        # node20 should be normalized to node
        assert "node" in result
        assert "node20" not in result

    def test_multiple_tools_same_dependency(self):
        """Test multiple tools requiring same dependency."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {"name": "dependency-check", "missing_deps": ["java"]},
            {"name": "zap", "missing_deps": ["java"]},
        ]
        result = _collect_missing_dependencies(fix_info)
        assert "java" in result
        assert "dependency-check" in result["java"]
        assert "zap" in result["java"]

    def test_skips_tools_without_missing_deps(self):
        """Test that tools without missing_deps are skipped."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {"name": "trivy", "missing_deps": []},
            {"name": "semgrep"},  # No missing_deps key
        ]
        result = _collect_missing_dependencies(fix_info)
        assert result == {}
