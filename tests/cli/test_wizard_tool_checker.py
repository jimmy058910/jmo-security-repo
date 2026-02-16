"""Tests for wizard_flows/tool_checker.py functions.

Coverage targets (TASK-004):
- check_tools_for_profile(): Main tool availability check
- _check_policy_tools(): OPA availability check
- _install_opa_tool(): OPA installation helper
- _show_all_fix_commands(): Command display for manual fixes
- _collect_missing_dependencies(): Dependency grouping logic
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch


# ============================================================================
# Mock classes for testing
# ============================================================================


class MockToolStatus:
    """Mock ToolStatus for testing."""

    def __init__(
        self,
        name: str,
        installed: bool = True,
        execution_ready: bool = True,
        is_outdated: bool = False,
        version_error: str = "",
        execution_warning: str = "",
        missing_deps: list[str] | None = None,
        status_type: str = "OK",
        status_icon: str = "+",
        status_color: str = "green",
    ):
        self.name = name
        self.installed = installed
        self.execution_ready = execution_ready
        self.is_outdated = is_outdated
        self.version_error = version_error
        self.execution_warning = execution_warning
        self.missing_deps = missing_deps
        self.status_type = status_type
        self.status_icon = status_icon
        self.status_color = status_color


class MockInstallResult:
    """Mock InstallResult for testing."""

    def __init__(
        self,
        tool_name: str,
        success: bool = True,
        message: str = "",
        method: str = "pip",
    ):
        self.tool_name = tool_name
        self.success = success
        self.message = message
        self.method = method


class MockInstallProgress:
    """Mock InstallProgress for testing."""

    def __init__(self, results: list[MockInstallResult] | None = None):
        self.results = results or []
        self.successful = sum(1 for r in self.results if r.success)
        self.failed = sum(1 for r in self.results if not r.success)


class MockToolStatusSummary:
    """Mock ToolStatusSummary for testing (unified tool counting)."""

    def __init__(
        self,
        profile_name: str = "fast",
        profile_total: int = 9,
        platform_applicable: int = 9,
        installed: int = 9,
        execution_ready: int = 9,
        platform_skipped: list[str] | None = None,
        manual_install: list[str] | None = None,
        missing_dependency: list[str] | None = None,
        not_installed: list[str] | None = None,
        version_issues: list[str] | None = None,
        content_triggered: list[str] | None = None,
    ):
        self.profile_name = profile_name
        self.profile_total = profile_total
        self.platform_applicable = platform_applicable
        self.installed = installed
        self.execution_ready = execution_ready
        self.platform_skipped = platform_skipped or []
        self.manual_install = manual_install or []
        self.missing_dependency = missing_dependency or []
        self.not_installed = not_installed or []
        self.version_issues = version_issues or []
        self.content_triggered = content_triggered or []

    @property
    def needs_attention_count(self) -> int:
        return (
            len(self.manual_install)
            + len(self.missing_dependency)
            + len(self.not_installed)
            + len(self.version_issues)
        )

    @property
    def skipped_count(self) -> int:
        return (
            len(self.platform_skipped)
            + len(self.manual_install)
            + len(self.content_triggered)
        )

    def format_status_line(self) -> str:
        if self.execution_ready == self.platform_applicable:
            return f"All {self.platform_applicable} tools ready"
        return f"{self.execution_ready}/{self.platform_applicable} tools ready ({self.needs_attention_count} need attention)"


# ============================================================================
# check_tools_for_profile() tests
# ============================================================================


class TestCheckToolsForProfile:
    """Test cases for check_tools_for_profile()."""

    def test_docker_mode_skips_check(self):
        """Docker mode should skip tool check entirely."""
        from scripts.cli.wizard import check_tools_for_profile

        should_continue, available = check_tools_for_profile(
            profile="balanced",
            yes=False,
            use_docker=True,
        )

        assert should_continue is True
        assert available == []

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.core.tool_registry.detect_platform")
    @patch("scripts.core.tool_registry.get_tools_for_profile_filtered")
    @patch("scripts.core.tool_registry.get_skipped_tools_for_profile")
    def test_all_tools_ready(
        self,
        mock_get_skipped,
        mock_get_filtered,
        mock_detect_platform,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
    ):
        """All tools ready should return True with list of available tools."""
        from scripts.cli.wizard import check_tools_for_profile

        # Setup mocks
        mock_detect_platform.return_value = "linux"
        mock_get_filtered.return_value = ["trivy", "semgrep"]
        mock_get_skipped.return_value = []
        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "~": "~"}
        mock_print_step.return_value = lambda s, t, m: None

        # Create ready tools
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "trivy": MockToolStatus("trivy", installed=True, execution_ready=True),
            "semgrep": MockToolStatus("semgrep", installed=True, execution_ready=True),
        }
        # Mock get_tool_summary to return proper summary object
        manager_instance.get_tool_summary.return_value = MockToolStatusSummary(
            profile_name="fast",
            profile_total=2,
            platform_applicable=2,
            installed=2,
            execution_ready=2,
        )
        mock_tool_manager.return_value = manager_instance

        with patch("builtins.print"):
            should_continue, available = check_tools_for_profile(
                profile="fast",
                yes=False,
                use_docker=False,
            )

        assert should_continue is True
        assert "trivy" in available
        assert "semgrep" in available

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.tool_manager.get_remediation_for_tool")
    @patch("scripts.core.tool_registry.detect_platform")
    @patch("scripts.core.tool_registry.get_tools_for_profile_filtered")
    @patch("scripts.core.tool_registry.get_skipped_tools_for_profile")
    def test_yes_mode_continues_with_missing(
        self,
        mock_get_skipped,
        mock_get_filtered,
        mock_detect_platform,
        mock_get_remediation,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
    ):
        """Non-interactive (yes) mode should continue with available tools."""
        from scripts.cli.wizard import check_tools_for_profile
        from scripts.cli.tool_manager import ToolStatusType

        # Setup mocks
        mock_detect_platform.return_value = "linux"
        mock_get_filtered.return_value = ["trivy", "semgrep", "bandit"]
        mock_get_skipped.return_value = []
        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "~": "~"}
        mock_print_step.return_value = lambda s, t, m: None
        mock_get_remediation.return_value = {
            "is_manual": False,
            "commands": ["pip install bandit"],
            "jmo_install": "jmo tools install bandit",
        }

        # Create status with one missing tool
        bandit_status = MockToolStatus(
            "bandit",
            installed=False,
            execution_ready=False,
        )
        bandit_status.status_type = ToolStatusType.MISSING

        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "trivy": MockToolStatus("trivy", installed=True, execution_ready=True),
            "semgrep": MockToolStatus("semgrep", installed=True, execution_ready=True),
            "bandit": bandit_status,
        }
        # Mock get_tool_summary to return proper summary object with missing tool
        manager_instance.get_tool_summary.return_value = MockToolStatusSummary(
            profile_name="fast",
            profile_total=3,
            platform_applicable=3,
            installed=2,
            execution_ready=2,
            not_installed=["bandit"],
        )
        mock_tool_manager.return_value = manager_instance

        with patch("builtins.print"):
            should_continue, available = check_tools_for_profile(
                profile="fast",
                yes=True,  # Non-interactive mode
                use_docker=False,
            )

        assert should_continue is True
        # Only ready tools should be in available list
        assert "trivy" in available
        assert "semgrep" in available
        assert "bandit" not in available

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_import_error_handled(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
    ):
        """ImportError should be handled gracefully."""
        from scripts.cli.wizard import check_tools_for_profile

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {}
        mock_print_step.return_value = lambda s, t, m: None

        # Patch ToolManager at its source module to raise ImportError
        with patch(
            "scripts.cli.tool_manager.ToolManager",
            side_effect=ImportError("Module not available"),
        ):
            with patch("builtins.print"):
                should_continue, available = check_tools_for_profile(
                    profile="fast",
                    yes=False,
                    use_docker=False,
                )

        # Should continue with empty available list
        assert should_continue is True
        assert available == []

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    def test_generic_exception_handled(
        self,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
    ):
        """Generic exceptions should be handled gracefully."""
        from scripts.cli.wizard import check_tools_for_profile

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {}
        mock_print_step.return_value = lambda s, t, m: None
        mock_tool_manager.side_effect = RuntimeError("Unexpected error")

        with patch("builtins.print"):
            should_continue, available = check_tools_for_profile(
                profile="fast",
                yes=False,
                use_docker=False,
            )

        assert should_continue is True
        assert available == []

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.core.tool_registry.detect_platform")
    @patch(
        "scripts.core.tool_registry.PROFILE_TOOLS",
        {"fast": ["trivy", "falco", "lynis"]},
    )
    def test_skipped_tools_displayed(
        self,
        mock_detect_platform,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
        capsys,
    ):
        """Platform-skipped tools should be displayed separately."""
        from scripts.cli.wizard import check_tools_for_profile

        # Setup mocks
        mock_detect_platform.return_value = "windows"
        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "~": "~", "○": "o"}
        mock_print_step.return_value = lambda s, t, m: None

        # Create mock ToolStatusSummary with platform-skipped tools
        mock_summary = MockToolStatusSummary(
            profile_name="fast",
            profile_total=3,
            platform_applicable=1,
            installed=1,
            execution_ready=1,
            platform_skipped=["falco", "lynis"],
        )

        manager_instance = MagicMock()
        manager_instance.get_tool_summary.return_value = mock_summary
        manager_instance.check_profile.return_value = {
            "trivy": MockToolStatus("trivy", installed=True, execution_ready=True),
        }
        mock_tool_manager.return_value = manager_instance

        should_continue, available = check_tools_for_profile(
            profile="fast",
            yes=False,
            use_docker=False,
        )

        assert should_continue is True
        # Check output contains skipped tools info
        captured = capsys.readouterr()
        assert "falco" in captured.out or "lynis" in captured.out


# ============================================================================
# _check_policy_tools() tests
# ============================================================================


class TestCheckPolicyTools:
    """Test cases for _check_policy_tools()."""

    def test_no_policies_configured(self):
        """No policies returns True without check."""
        from scripts.cli.wizard import _check_policy_tools

        should_continue, policies_enabled = _check_policy_tools(
            policies=None,
            skip_policies=False,
            yes=False,
            use_docker=False,
        )

        assert should_continue is True
        assert policies_enabled is False

    def test_policies_skipped(self):
        """Skip policies flag disables policy check."""
        from scripts.cli.wizard import _check_policy_tools

        should_continue, policies_enabled = _check_policy_tools(
            policies=["owasp-top-10"],
            skip_policies=True,  # Explicit skip
            yes=False,
            use_docker=False,
        )

        assert should_continue is True
        assert policies_enabled is False

    def test_docker_mode_enables_policies(self):
        """Docker mode should enable policies (OPA bundled)."""
        from scripts.cli.wizard import _check_policy_tools

        should_continue, policies_enabled = _check_policy_tools(
            policies=["owasp-top-10"],
            skip_policies=False,
            yes=False,
            use_docker=True,
        )

        assert should_continue is True
        assert policies_enabled is True

    @patch("scripts.cli.scan_utils.tool_exists")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_available(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_tool_exists,
    ):
        """OPA available should enable policies."""
        from scripts.cli.wizard import _check_policy_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]"}
        mock_tool_exists.return_value = True

        with patch("builtins.print"):
            should_continue, policies_enabled = _check_policy_tools(
                policies=["owasp-top-10", "zero-secrets"],
                skip_policies=False,
                yes=False,
                use_docker=False,
            )

        assert should_continue is True
        assert policies_enabled is True
        mock_tool_exists.assert_called_once_with("opa", warn=False)

    @patch("scripts.cli.scan_utils.tool_exists")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_missing_yes_mode(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_tool_exists,
    ):
        """OPA missing in yes mode should continue without policies."""
        from scripts.cli.wizard import _check_policy_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"⚠": "[!]"}
        mock_tool_exists.return_value = False

        with patch("builtins.print"):
            should_continue, policies_enabled = _check_policy_tools(
                policies=["owasp-top-10"],
                skip_policies=False,
                yes=True,  # Non-interactive
                use_docker=False,
            )

        assert should_continue is True
        assert policies_enabled is False

    @patch("scripts.cli.scan_utils.tool_exists")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_missing_interactive_continue(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_tool_exists,
    ):
        """Interactive mode - user chooses to continue without OPA."""
        from scripts.cli.wizard import _check_policy_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"⚠": "[!]"}
        mock_tool_exists.return_value = False

        with patch("builtins.print"):
            with patch("builtins.input", return_value="1"):  # Continue without OPA
                should_continue, policies_enabled = _check_policy_tools(
                    policies=["owasp-top-10"],
                    skip_policies=False,
                    yes=False,
                    use_docker=False,
                )

        assert should_continue is True
        assert policies_enabled is False

    @patch("scripts.cli.scan_utils.tool_exists")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_missing_interactive_cancel(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_tool_exists,
    ):
        """Interactive mode - user chooses to cancel."""
        from scripts.cli.wizard import _check_policy_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"⚠": "[!]"}
        mock_tool_exists.return_value = False

        with patch("builtins.print"):
            with patch("builtins.input", return_value="3"):  # Cancel
                should_continue, policies_enabled = _check_policy_tools(
                    policies=["owasp-top-10"],
                    skip_policies=False,
                    yes=False,
                    use_docker=False,
                )

        assert should_continue is False
        assert policies_enabled is False

    @patch("scripts.cli.wizard_flows.tool_checker._install_opa_tool")
    @patch("scripts.cli.scan_utils.tool_exists")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_missing_interactive_install(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_tool_exists,
        mock_install_opa,
    ):
        """Interactive mode - user chooses to install OPA."""
        from scripts.cli.wizard import _check_policy_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"⚠": "[!]"}
        mock_tool_exists.return_value = False
        mock_install_opa.return_value = (True, True)  # Success, policies enabled

        with patch("builtins.print"):
            with patch("builtins.input", return_value="2"):  # Install OPA
                should_continue, policies_enabled = _check_policy_tools(
                    policies=["owasp-top-10"],
                    skip_policies=False,
                    yes=False,
                    use_docker=False,
                )

        assert should_continue is True
        assert policies_enabled is True
        mock_install_opa.assert_called_once()


# ============================================================================
# _install_opa_tool() tests
# ============================================================================


class TestInstallOpaTool:
    """Test cases for _install_opa_tool()."""

    @patch("scripts.cli.tool_installer.ToolInstaller")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_install_success(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_installer_class,
    ):
        """Successful OPA installation."""
        from scripts.cli.wizard import _install_opa_tool

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "❌": "[X]"}

        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = MockInstallResult(
            "opa", success=True, message="Installed"
        )
        mock_installer_class.return_value = mock_installer

        with patch("builtins.print"):
            should_continue, policies_enabled = _install_opa_tool()

        assert should_continue is True
        assert policies_enabled is True
        mock_installer.install_tool.assert_called_once_with("opa")

    @patch("scripts.cli.tool_installer.ToolInstaller")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_install_failure(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_installer_class,
    ):
        """Failed OPA installation continues without policies."""
        from scripts.cli.wizard import _install_opa_tool

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "❌": "[X]"}

        mock_installer = MagicMock()
        mock_installer.install_tool.return_value = MockInstallResult(
            "opa", success=False, message="Download failed"
        )
        mock_installer_class.return_value = mock_installer

        with patch("builtins.print"):
            should_continue, policies_enabled = _install_opa_tool()

        assert should_continue is True
        assert policies_enabled is False

    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_install_import_error(
        self,
        mock_colorize,
        mock_fallbacks,
    ):
        """ImportError during OPA install continues without policies."""
        from scripts.cli.wizard import _install_opa_tool

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {}

        # Patch ToolInstaller at its source module to raise ImportError
        with patch(
            "scripts.cli.tool_installer.ToolInstaller",
            side_effect=ImportError("Not available"),
        ):
            with patch("builtins.print"):
                should_continue, policies_enabled = _install_opa_tool()

        assert should_continue is True
        assert policies_enabled is False

    @patch("scripts.cli.tool_installer.ToolInstaller")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_opa_install_exception(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_installer_class,
    ):
        """Exception during OPA install continues without policies."""
        from scripts.cli.wizard import _install_opa_tool

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {}

        mock_installer_class.side_effect = RuntimeError("Network error")

        with patch("builtins.print"):
            should_continue, policies_enabled = _install_opa_tool()

        assert should_continue is True
        assert policies_enabled is False


# ============================================================================
# _show_all_fix_commands() tests
# ============================================================================


class TestShowAllFixCommands:
    """Test cases for _show_all_fix_commands()."""

    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_show_commands_with_remediation(self, mock_colorize, capsys):
        """Display fix commands for tools with remediation."""
        from scripts.cli.wizard import _show_all_fix_commands

        mock_colorize.return_value = lambda text, color: text

        fix_info = [
            {
                "name": "semgrep",
                "issue": "Not installed",
                "remediation": {
                    "commands": ["pip install semgrep"],
                    "jmo_install": None,
                },
            },
            {
                "name": "trivy",
                "issue": "Missing",
                "remediation": {
                    "commands": ["brew install trivy"],
                    "jmo_install": None,
                },
            },
        ]

        _show_all_fix_commands(fix_info, "linux")

        captured = capsys.readouterr()
        assert "semgrep" in captured.out
        assert "pip install semgrep" in captured.out
        assert "trivy" in captured.out
        assert "brew install trivy" in captured.out
        assert "FIX COMMANDS" in captured.out

    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_show_jmo_install_command(self, mock_colorize, capsys):
        """Display jmo install command when no platform commands."""
        from scripts.cli.wizard import _show_all_fix_commands

        mock_colorize.return_value = lambda text, color: text

        fix_info = [
            {
                "name": "bandit",
                "issue": "Not installed",
                "remediation": {
                    "commands": [],
                    "jmo_install": "jmo tools install bandit",
                },
            },
        ]

        _show_all_fix_commands(fix_info, "windows")

        captured = capsys.readouterr()
        assert "bandit" in captured.out
        assert "jmo tools install bandit" in captured.out

    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_show_empty_fix_info(self, mock_colorize, capsys):
        """Empty fix info should still display header."""
        from scripts.cli.wizard import _show_all_fix_commands

        mock_colorize.return_value = lambda text, color: text

        _show_all_fix_commands([], "linux")

        captured = capsys.readouterr()
        assert "FIX COMMANDS" in captured.out
        assert "jmo wizard" in captured.out  # Instructions to restart


# ============================================================================
# _collect_missing_dependencies() tests
# ============================================================================


class TestCollectMissingDependencies:
    """Test cases for _collect_missing_dependencies()."""

    def test_empty_fix_info(self):
        """Empty fix info returns empty dict."""
        from scripts.cli.wizard import _collect_missing_dependencies

        result = _collect_missing_dependencies([])
        assert result == {}

    def test_no_missing_deps(self):
        """Tools without missing deps return empty dict."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "semgrep",
                "issue": "Not installed",
                "missing_deps": [],
            },
            {
                "name": "trivy",
                "issue": "Not installed",
                "missing_deps": None,
            },
        ]

        result = _collect_missing_dependencies(fix_info)
        assert result == {}

    def test_single_dependency(self):
        """Single missing dependency for one tool."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing Java",
                "missing_deps": ["java"],
            },
        ]

        result = _collect_missing_dependencies(fix_info)
        assert "java" in result
        assert "dependency-check" in result["java"]

    def test_multiple_tools_same_dependency(self):
        """Multiple tools requiring same dependency."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing Java",
                "missing_deps": ["java"],
            },
            {
                "name": "zap",
                "issue": "Missing Java",
                "missing_deps": ["java"],
            },
        ]

        result = _collect_missing_dependencies(fix_info)
        assert "java" in result
        assert "dependency-check" in result["java"]
        assert "zap" in result["java"]

    def test_node_version_normalization(self):
        """Node.js versions should be normalized to 'node'."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "cdxgen",
                "issue": "Missing Node",
                "missing_deps": ["node20"],
            },
            {
                "name": "eslint",
                "issue": "Missing Node",
                "missing_deps": ["node18"],
            },
        ]

        result = _collect_missing_dependencies(fix_info)
        # Both should be normalized to "node"
        assert "node" in result
        assert "cdxgen" in result["node"]
        assert "eslint" in result["node"]
        # No separate node20/node18 keys
        assert "node20" not in result
        assert "node18" not in result

    def test_multiple_different_dependencies(self):
        """Tools with different dependencies."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing runtime",
                "missing_deps": ["java"],
            },
            {
                "name": "cdxgen",
                "issue": "Missing runtime",
                "missing_deps": ["node"],
            },
            {
                "name": "bash-tool",
                "issue": "Missing bash",
                "missing_deps": ["bash"],
            },
        ]

        result = _collect_missing_dependencies(fix_info)
        assert len(result) == 3
        assert "java" in result
        assert "node" in result
        assert "bash" in result

    def test_tool_with_multiple_deps(self):
        """Tool requiring multiple dependencies."""
        from scripts.cli.wizard import _collect_missing_dependencies

        fix_info = [
            {
                "name": "complex-tool",
                "issue": "Missing multiple",
                "missing_deps": ["java", "node", "bash"],
            },
        ]

        result = _collect_missing_dependencies(fix_info)
        assert "complex-tool" in result["java"]
        assert "complex-tool" in result["node"]
        assert "complex-tool" in result["bash"]

    def test_no_duplicate_tools_per_dep(self):
        """Same tool shouldn't appear twice for same dependency."""
        from scripts.cli.wizard import _collect_missing_dependencies

        # Simulate a tool appearing twice in fix_info with same dep
        fix_info = [
            {
                "name": "cdxgen",
                "issue": "Issue 1",
                "missing_deps": ["node"],
            },
            {
                "name": "cdxgen",
                "issue": "Issue 2",
                "missing_deps": ["node"],
            },
        ]

        result = _collect_missing_dependencies(fix_info)
        # Tool should only appear once
        assert result["node"].count("cdxgen") == 1


# ============================================================================
# Interactive choice handling tests (lines 310-340)
# ============================================================================


class TestInteractiveChoices:
    """Test interactive menu choices in check_tools_for_profile."""

    @patch("scripts.cli.wizard_flows.tool_checker._auto_fix_tools")
    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.tool_manager.get_remediation_for_tool")
    @patch("scripts.core.tool_registry.detect_platform")
    @patch("scripts.core.tool_registry.PROFILE_TOOLS", {"fast": ["trivy", "bandit"]})
    def test_choice_1_auto_fix(
        self,
        mock_detect_platform,
        mock_get_remediation,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
        mock_auto_fix,
    ):
        """Choice 1 triggers auto-fix."""
        from scripts.cli.wizard import check_tools_for_profile
        from scripts.cli.tool_manager import ToolStatusType

        # Setup
        mock_detect_platform.return_value = "linux"
        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "○": "o"}
        mock_print_step.return_value = lambda s, t, m: None
        mock_get_remediation.return_value = {
            "is_manual": False,
            "commands": [],
            "jmo_install": "jmo tools install bandit",
        }
        mock_auto_fix.return_value = (True, ["trivy", "bandit"])

        bandit_status = MockToolStatus("bandit", installed=False, execution_ready=False)
        bandit_status.status_type = ToolStatusType.MISSING

        # Create mock summary showing one tool needs attention
        mock_summary = MockToolStatusSummary(
            profile_name="fast",
            profile_total=2,
            platform_applicable=2,
            installed=1,
            execution_ready=1,
            not_installed=["bandit"],
        )

        manager_instance = MagicMock()
        manager_instance.get_tool_summary.return_value = mock_summary
        manager_instance.check_profile.return_value = {
            "trivy": MockToolStatus("trivy"),
            "bandit": bandit_status,
        }
        mock_tool_manager.return_value = manager_instance

        with patch("builtins.print"):
            with patch("builtins.input", return_value="1"):  # Auto-fix
                should_continue, available = check_tools_for_profile(
                    profile="fast",
                    yes=False,
                    use_docker=False,
                )

        mock_auto_fix.assert_called_once()
        assert should_continue is True

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.tool_manager.get_remediation_for_tool")
    @patch("scripts.core.tool_registry.detect_platform")
    @patch("scripts.core.tool_registry.PROFILE_TOOLS", {"fast": ["trivy", "bandit"]})
    def test_choice_2_continue_with_available(
        self,
        mock_detect_platform,
        mock_get_remediation,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
    ):
        """Choice 2 continues with available tools only."""
        from scripts.cli.wizard import check_tools_for_profile
        from scripts.cli.tool_manager import ToolStatusType

        mock_detect_platform.return_value = "linux"
        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "○": "o"}
        mock_print_step.return_value = lambda s, t, m: None
        mock_get_remediation.return_value = {
            "is_manual": False,
            "commands": [],
            "jmo_install": "jmo tools install bandit",
        }

        bandit_status = MockToolStatus("bandit", installed=False, execution_ready=False)
        bandit_status.status_type = ToolStatusType.MISSING

        # Create mock summary showing one tool needs attention
        mock_summary = MockToolStatusSummary(
            profile_name="fast",
            profile_total=2,
            platform_applicable=2,
            installed=1,
            execution_ready=1,
            not_installed=["bandit"],
        )

        manager_instance = MagicMock()
        manager_instance.get_tool_summary.return_value = mock_summary
        manager_instance.check_profile.return_value = {
            "trivy": MockToolStatus("trivy"),
            "bandit": bandit_status,
        }
        mock_tool_manager.return_value = manager_instance

        with patch("builtins.print"):
            with patch("builtins.input", return_value="2"):  # Continue with available
                should_continue, available = check_tools_for_profile(
                    profile="fast",
                    yes=False,
                    use_docker=False,
                )

        assert should_continue is True
        assert "trivy" in available
        assert "bandit" not in available

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.tool_manager.get_remediation_for_tool")
    @patch("scripts.core.tool_registry.detect_platform")
    @patch("scripts.core.tool_registry.PROFILE_TOOLS", {"fast": ["trivy", "bandit"]})
    def test_choice_4_cancel(
        self,
        mock_detect_platform,
        mock_get_remediation,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
    ):
        """Choice 4 cancels the wizard."""
        from scripts.cli.wizard import check_tools_for_profile
        from scripts.cli.tool_manager import ToolStatusType

        mock_detect_platform.return_value = "linux"
        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "○": "o"}
        mock_print_step.return_value = lambda s, t, m: None
        mock_get_remediation.return_value = {
            "is_manual": False,
            "commands": [],
            "jmo_install": "",
        }

        bandit_status = MockToolStatus("bandit", installed=False, execution_ready=False)
        bandit_status.status_type = ToolStatusType.MISSING

        # Create mock summary showing one tool needs attention
        mock_summary = MockToolStatusSummary(
            profile_name="fast",
            profile_total=2,
            platform_applicable=2,
            installed=1,
            execution_ready=1,
            not_installed=["bandit"],
        )

        manager_instance = MagicMock()
        manager_instance.get_tool_summary.return_value = mock_summary
        manager_instance.check_profile.return_value = {
            "trivy": MockToolStatus("trivy"),
            "bandit": bandit_status,
        }
        mock_tool_manager.return_value = manager_instance

        with patch("builtins.print"):
            with patch("builtins.input", return_value="4"):  # Cancel
                should_continue, available = check_tools_for_profile(
                    profile="fast",
                    yes=False,
                    use_docker=False,
                )

        assert should_continue is False
        assert available == []


# ============================================================================
# Crash detection tests (lines 248-274)
# ============================================================================


class TestCrashDetection:
    """Test crash detection for startup crashes (pydantic conflicts, etc)."""

    @patch("scripts.cli.wizard_flows.tool_checker._get_print_step")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.tool_manager.get_remediation_for_tool")
    @patch("scripts.core.tool_registry.detect_platform")
    @patch("scripts.core.tool_registry.get_tools_for_profile_filtered")
    @patch("scripts.core.tool_registry.get_skipped_tools_for_profile")
    def test_tool_with_startup_crash(
        self,
        mock_get_skipped,
        mock_get_filtered,
        mock_detect_platform,
        mock_get_remediation,
        mock_tool_manager,
        mock_colorize,
        mock_fallbacks,
        mock_print_step,
        capsys,
    ):
        """Tool with startup crash should display crash info."""
        from scripts.cli.wizard import check_tools_for_profile
        from scripts.cli.tool_manager import ToolStatusType

        mock_detect_platform.return_value = "linux"
        mock_get_filtered.return_value = ["checkov"]
        mock_get_skipped.return_value = []
        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]"}
        mock_print_step.return_value = lambda s, t, m: None
        mock_get_remediation.return_value = {
            "is_manual": False,
            "commands": [],
            "jmo_install": "",
        }

        # Simulate a tool with startup crash (pydantic conflict)
        crash_status = MockToolStatus(
            "checkov",
            installed=True,
            execution_ready=False,
            version_error="ImportError: cannot import name 'BaseSettings'",
            status_type=(
                ToolStatusType.CRASH if hasattr(ToolStatusType, "CRASH") else "CRASH"
            ),
            status_icon="!",
            status_color="red",
        )

        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "checkov": crash_status,
        }
        # Mock get_tool_summary to return proper summary object with crashed tool
        manager_instance.get_tool_summary.return_value = MockToolStatusSummary(
            profile_name="fast",
            profile_total=1,
            platform_applicable=1,
            installed=1,
            execution_ready=0,
            version_issues=["checkov"],
        )
        mock_tool_manager.return_value = manager_instance

        with patch("builtins.input", return_value="2"):  # Continue with available
            should_continue, available = check_tools_for_profile(
                profile="fast",
                yes=False,
                use_docker=False,
            )

        captured = capsys.readouterr()
        # Crash info should be displayed
        assert "CRASH" in captured.out or "checkov" in captured.out
        assert should_continue is True


# ============================================================================
# _auto_fix_tools() dependency installation tests (lines 460-508)
# ============================================================================


class TestAutoFixToolsDependencies:
    """Test cases for dependency installation in _auto_fix_tools (TASK-016).

    Tests cover _auto_fix_tools() lines 460-508:
    - Menu display for missing dependencies
    - Choice 1: Auto-install dependencies (success/failure)
    - Choice 2: Skip tools requiring deps
    - Choice 3: Cancel
    - Manual command display on install failure
    """

    @patch("scripts.cli.tool_installer.install_dependency")
    @patch("scripts.cli.tool_installer.get_manual_dependency_command")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_dependency_menu_displayed_with_missing_deps(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_get_manual_cmd,
        mock_install_dep,
        capsys,
    ):
        """Missing dependencies should trigger menu display."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "❌": "[X]"}
        mock_install_dep.return_value = (True, "Installed via apt")
        mock_get_manual_cmd.return_value = "apt install openjdk-17-jdk"

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing",
                "missing_deps": ["java"],
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "jmo tools install dependency-check",
                },
            }
        ]

        # Choice 1: auto-install deps
        with patch("builtins.input", return_value="1"):
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="fast",
                available=[],
            )

        captured = capsys.readouterr()
        # Menu should show dependency requirement
        assert "runtime dependencies" in captured.out or "Java" in captured.out
        assert should_continue is True

    @patch("scripts.cli.tool_installer.install_dependency")
    @patch("scripts.cli.tool_installer.get_manual_dependency_command")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_choice_1_auto_install_success(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_get_manual_cmd,
        mock_install_dep,
        capsys,
    ):
        """Choice 1 auto-installs dependencies successfully."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "❌": "[X]"}
        mock_install_dep.return_value = (True, "Installed via apt")
        mock_get_manual_cmd.return_value = "apt install openjdk-17-jdk"

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing",
                "missing_deps": ["java"],
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "jmo tools install dependency-check",
                },
            }
        ]

        # Choice 1: auto-install deps
        with patch("builtins.input", return_value="1"):
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="fast",
                available=[],
            )

        # install_dependency should have been called
        mock_install_dep.assert_called_once_with("java", "linux")
        captured = capsys.readouterr()
        assert "installed" in captured.out.lower()

    @patch("scripts.cli.tool_installer.install_dependency")
    @patch("scripts.cli.tool_installer.get_manual_dependency_command")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_choice_1_auto_install_failure_shows_manual(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_get_manual_cmd,
        mock_install_dep,
        capsys,
    ):
        """Choice 1 with install failure shows manual command."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "❌": "[X]"}
        mock_install_dep.return_value = (False, "Package manager not found")
        mock_get_manual_cmd.return_value = "sudo apt install openjdk-17-jdk"

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing",
                "missing_deps": ["java"],
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "jmo tools install dependency-check",
                },
            }
        ]

        # Choice 1: auto-install deps
        with patch("builtins.input", return_value="1"):
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="fast",
                available=[],
            )

        captured = capsys.readouterr()
        # Manual command should be displayed on failure
        assert "Manual" in captured.out
        assert "apt install" in captured.out
        mock_get_manual_cmd.assert_called_once_with("java", "linux")

    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_choice_2_skip_deps_continues(
        self,
        mock_colorize,
        mock_fallbacks,
    ):
        """Choice 2 skips dependency installation and continues."""
        from unittest.mock import MagicMock

        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "❌": "[X]"}

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing",
                "missing_deps": ["java"],
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "jmo tools install dependency-check",
                },
            }
        ]

        # Mock ToolInstaller (Phase 1) and ToolManager (re-check) since
        # no real tools are installed in CI
        mock_progress = MagicMock()
        mock_progress.results = []

        mock_status = MagicMock()
        mock_status.execution_ready = True
        mock_summary = MagicMock()
        mock_summary.execution_ready = 1
        mock_summary.platform_applicable = 1

        # Choice 2: skip deps
        with (
            patch("builtins.print"),
            patch("builtins.input", return_value="2"),
            patch("scripts.cli.tool_installer.ToolInstaller") as mock_installer_cls,
            patch("scripts.cli.tool_manager.ToolManager") as mock_manager_cls,
        ):
            mock_installer_cls.return_value.install_tools_parallel.return_value = (
                mock_progress
            )
            mock_manager_cls.return_value.check_profile.return_value = {
                "trivy": mock_status
            }
            mock_manager_cls.return_value.get_tool_summary.return_value = mock_summary

            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="fast",
                available=["trivy"],
            )

        # Should continue (didn't call cancel)
        assert should_continue is True
        # Available tools should still be present
        assert "trivy" in available

    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_choice_3_cancel(
        self,
        mock_colorize,
        mock_fallbacks,
    ):
        """Choice 3 cancels the wizard."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "❌": "[X]"}

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing",
                "missing_deps": ["java"],
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "jmo tools install dependency-check",
                },
            }
        ]

        # Choice 3: cancel
        with patch("builtins.print"):
            with patch("builtins.input", return_value="3"):
                should_continue, available = _auto_fix_tools(
                    fix_info=fix_info,
                    platform="linux",
                    profile="fast",
                    available=["trivy"],
                )

        assert should_continue is False
        # Original available should be returned
        assert available == ["trivy"]

    @patch("scripts.cli.tool_installer.install_dependency")
    @patch("scripts.cli.tool_installer.get_manual_dependency_command")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_multiple_dependencies_installed(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_get_manual_cmd,
        mock_install_dep,
    ):
        """Multiple dependencies are installed in sequence."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "❌": "[X]"}
        mock_install_dep.return_value = (True, "Installed")
        mock_get_manual_cmd.return_value = "manual install"

        fix_info = [
            {
                "name": "dependency-check",
                "issue": "Missing",
                "missing_deps": ["java"],
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "",
                },
            },
            {
                "name": "cdxgen",
                "issue": "Missing",
                "missing_deps": ["node"],
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "",
                },
            },
        ]

        # Choice 1: auto-install deps
        with patch("builtins.print"):
            with patch("builtins.input", return_value="1"):
                should_continue, available = _auto_fix_tools(
                    fix_info=fix_info,
                    platform="linux",
                    profile="fast",
                    available=[],
                )

        # Both java and node should be installed
        assert mock_install_dep.call_count == 2
        call_args = [call[0][0] for call in mock_install_dep.call_args_list]
        assert "java" in call_args
        assert "node" in call_args

    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_no_deps_skips_menu(
        self,
        mock_colorize,
        mock_fallbacks,
        capsys,
    ):
        """No missing deps should skip the dependency menu entirely."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {"✅": "[OK]", "⚠": "[!]", "❌": "[X]"}

        fix_info = [
            {
                "name": "bandit",
                "issue": "Not installed",
                "missing_deps": [],  # No missing deps
                "remediation": {
                    "is_manual": False,
                    "commands": [],
                    "jmo_install": "jmo tools install bandit",
                },
            }
        ]

        with patch("builtins.print"):
            # No input needed since menu should be skipped
            should_continue, available = _auto_fix_tools(
                fix_info=fix_info,
                platform="linux",
                profile="fast",
                available=["trivy"],
            )

        captured = capsys.readouterr()
        # Dependency menu should not appear
        assert "runtime dependencies" not in captured.out


# ============================================================================
# Platform command execution tests (TASK-017, lines 655-727)
# ============================================================================


class TestPlatformCommandExecution:
    """Test cases for platform command execution in _auto_fix_tools.

    Targets:
    - Platform command execution loop (lines 655-727)
    - TimeoutExpired exception path (lines 696-704)
    - Generic exception path (lines 705-713)
    - Command truncation display for long commands
    - Success/failure tracking per platform command
    """

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_success(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Platform commands execute successfully and track fixed tools."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        # Mock re-check at end of _auto_fix_tools
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "bandit": MockToolStatus("bandit", installed=True, execution_ready=True),
        }
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "bandit",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["pip install bandit"],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        assert should_continue is True
        # Tool should be marked as fixed
        assert "bandit" in available
        assert "fixed" in captured.out.lower()
        # Command should have been run
        mock_run.assert_called_once()
        call_args = mock_run.call_args
        assert "pip install bandit" in call_args[0][0]

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_failure_with_error_stderr(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Platform command failure with error in stderr tracks failed tools."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.return_value = MagicMock(
            returncode=1, stderr="error: package not found", stdout=""
        )

        # Mock re-check - no tools ready after failure
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {}
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "missing-tool",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["pip install missing-tool"],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        assert should_continue is True
        # Tool should NOT be in available (failed)
        assert "missing-tool" not in available
        assert "Failed" in captured.out

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_nonzero_return_no_error_continues(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Non-zero return without 'error' in stderr continues execution."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        # Non-zero return but no error/failed keywords in stderr
        mock_run.return_value = MagicMock(
            returncode=1, stderr="warning: some note", stdout=""
        )

        # Mock re-check - tool now ready
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "some-tool": MockToolStatus(
                "some-tool", installed=True, execution_ready=True
            ),
        }
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "some-tool",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["brew install some-tool"],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="darwin",
            profile="fast",
            available=[],
        )

        # Should still mark as success since no error/failed in stderr
        assert should_continue is True
        assert "some-tool" in available

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_timeout_expired(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """TimeoutExpired exception shows timeout message and marks failure."""
        import subprocess

        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.side_effect = subprocess.TimeoutExpired(
            cmd="slow-install", timeout=300
        )

        # Mock re-check - no tools ready
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {}
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "slow-tool",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["pip install slow-tool"],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        assert should_continue is True
        # Tool should NOT be in available (timed out)
        assert "slow-tool" not in available
        assert "Timeout" in captured.out or "5 minutes" in captured.out

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_generic_exception(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Generic exception shows error message and marks failure."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.side_effect = OSError("Permission denied")

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {}
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "protected-tool",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["/protected/install.sh"],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        assert should_continue is True
        # Tool should NOT be in available (error)
        assert "protected-tool" not in available
        assert "Error" in captured.out or "Permission denied" in captured.out

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_truncation_long_command(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Long commands are truncated in display with '...'."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "long-pkg": MockToolStatus(
                "long-pkg", installed=True, execution_ready=True
            ),
        }
        mock_tool_manager.return_value = manager_instance

        # Create a command longer than 60 chars
        long_cmd = (
            "pip install some-very-long-package-name-that-exceeds-sixty-characters"
        )
        assert len(long_cmd) > 60

        fix_info = [
            {
                "name": "long-pkg",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": [long_cmd],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        # Command should be truncated with ...
        assert "..." in captured.out
        # But the full command is still executed
        call_args = mock_run.call_args[0][0]
        assert long_cmd in call_args

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_adds_yes_flag_to_jmo_install(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """jmo tools install commands get --yes flag added."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "trivy": MockToolStatus("trivy", installed=True, execution_ready=True),
        }
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "trivy",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["jmo tools install trivy"],  # No --yes
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        # --yes flag should be added
        call_args = mock_run.call_args[0][0]
        assert "--yes" in call_args
        assert "trivy" in available

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_skips_empty_commands(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Empty commands in list are skipped."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "sparse-tool": MockToolStatus(
                "sparse-tool", installed=True, execution_ready=True
            ),
        }
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "sparse-tool",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["", "pip install sparse-tool", ""],  # Empty commands
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        # Only the real command should have been executed
        assert mock_run.call_count == 1
        assert "sparse-tool" in available

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_multiple_commands_per_tool(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Tool with multiple commands executes all in sequence."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "multi-cmd": MockToolStatus(
                "multi-cmd", installed=True, execution_ready=True
            ),
        }
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "multi-cmd",
                "issue": "Needs setup",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": [
                        "pip install multi-cmd",
                        "multi-cmd --init",
                    ],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        # Both commands should have been executed
        assert mock_run.call_count == 2
        assert "multi-cmd" in available

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_platform_command_second_command_fails(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Second command failing breaks out of loop for that tool."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        # First succeeds, second fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(returncode=1, stderr="error: init failed", stdout=""),
        ]

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {}
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "fail-init",
                "issue": "Needs setup",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": [
                        "pip install fail-init",
                        "fail-init --init",
                    ],
                    "jmo_install": "",
                },
            }
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        # Tool should NOT be in available (second cmd failed)
        assert "fail-init" not in available
        assert "Failed" in captured.out

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_summary_output_all_fixed(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Summary shows all tools fixed successfully."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        mock_run.return_value = MagicMock(returncode=0, stderr="", stdout="")

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "tool-a": MockToolStatus("tool-a", installed=True, execution_ready=True),
            "tool-b": MockToolStatus("tool-b", installed=True, execution_ready=True),
        }
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "tool-a",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["pip install a"],
                    "jmo_install": "",
                },
            },
            {
                "name": "tool-b",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["pip install b"],
                    "jmo_install": "",
                },
            },
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        # Summary should show all fixed
        assert "2" in captured.out  # 2 tools fixed
        assert "tool-a" in available
        assert "tool-b" in available

    @patch("scripts.cli.tool_manager.ToolManager")
    @patch("scripts.cli.wizard_flows.tool_checker.subprocess.run")
    @patch("scripts.cli.wizard_flows.tool_checker._get_unicode_fallbacks")
    @patch("scripts.cli.wizard_flows.tool_checker._get_colorize")
    def test_summary_output_partial_failure(
        self,
        mock_colorize,
        mock_fallbacks,
        mock_run,
        mock_tool_manager,
        capsys,
    ):
        """Summary shows partial failure with manual fix instructions."""
        from scripts.cli.wizard_flows.tool_checker import _auto_fix_tools

        mock_colorize.return_value = lambda text, color: text
        mock_fallbacks.return_value = {
            "✅": "[OK]",
            "⚠": "[!]",
            "❌": "[X]",
            "🔧": "[*]",
            "⏳": "[.]",
        }
        # First succeeds, second fails
        mock_run.side_effect = [
            MagicMock(returncode=0, stderr="", stdout=""),
            MagicMock(returncode=1, stderr="error: not found", stdout=""),
        ]

        # Mock re-check
        manager_instance = MagicMock()
        manager_instance.check_profile.return_value = {
            "success-tool": MockToolStatus(
                "success-tool", installed=True, execution_ready=True
            ),
        }
        mock_tool_manager.return_value = manager_instance

        fix_info = [
            {
                "name": "success-tool",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["pip install a"],
                    "jmo_install": "",
                },
            },
            {
                "name": "fail-tool",
                "issue": "Not installed",
                "missing_deps": [],
                "remediation": {
                    "is_manual": False,
                    "commands": ["pip install b"],
                    "jmo_install": "",
                },
            },
        ]

        should_continue, available = _auto_fix_tools(
            fix_info=fix_info,
            platform="linux",
            profile="fast",
            available=[],
        )

        captured = capsys.readouterr()
        # Should show 1 fixed, 1 failed
        assert "success-tool" in available
        assert "fail-tool" not in available
        assert "1" in captured.out  # At least "1" mentioned (for fixed count)
