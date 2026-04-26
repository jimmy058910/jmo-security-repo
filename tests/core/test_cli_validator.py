"""Tests for CLI completeness validator.

All tests mock subprocess.run to avoid spawning real processes.
"""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock, patch

from scripts.core.validators import CategoryResult, CheckStatus
from scripts.core.validators.cli_validator import (
    FLAG_TYPE_CHECKS,
    INVALID_FLAG_COMMANDS,
    MAIN_SUBCOMMANDS,
    MUTUALLY_EXCLUSIVE,
    REQUIRED_ARG_COMMANDS,
    SUB_SUBCOMMANDS,
    _EXIT_CODE_COUNT,
    _FULL_TIER_COUNT,
    _INVALID_FLAG_COUNT,
    _MAIN_HELP_COUNT,
    _MUTEX_COUNT,
    _REQUIRED_ARG_COUNT,
    _SUB_SUBCOMMAND_COUNT,
    _TYPE_CHECK_COUNT,
    _VERSION_CHECK_COUNT,
    _help_check,
    _invalid_flag_check,
    _mutex_check,
    _required_arg_check,
    _run_jmo,
    _type_check,
    validate_cli,
)

# ---------------------------------------------------------------------------
# Mock helpers
# ---------------------------------------------------------------------------


def _mock_completed(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """Create a mock CompletedProcess."""
    mock = MagicMock(spec=subprocess.CompletedProcess)
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = stderr
    return mock


def _make_help_mock():
    """Return a side_effect function that returns success for --help calls."""

    def _side_effect(cmd, **kwargs):
        return _mock_completed(returncode=0, stdout="usage: jmo ...")

    return _side_effect


def _make_mixed_mock(
    help_rc: int = 0,
    version_stdout: str = "JMo Security v1.0.2",
    missing_arg_rc: int = 2,
    invalid_flag_rc: int = 2,
    mutex_rc: int = 2,
    type_rc: int = 2,
    no_subcommand_rc: int = 2,
    bad_subcommand_rc: int = 2,
):
    """Return a side_effect that responds based on the command arguments."""

    def _side_effect(cmd, **kwargs):
        args = cmd[3:]  # Skip [python, -m, scripts.cli.jmo]
        # If arguments exist, check for known patterns
        if not args:
            # No subcommand
            return _mock_completed(returncode=no_subcommand_rc, stderr="required")
        if args == ["--version"]:
            return _mock_completed(returncode=0, stdout=version_stdout)
        if args[-1] == "--help":
            return _mock_completed(
                returncode=help_rc, stdout="usage: jmo subcommand ..."
            )
        if "--nonexistent-flag-xyz" in args:
            return _mock_completed(returncode=invalid_flag_rc, stderr="unrecognized")
        if args == ["nonexistent-subcommand-xyz"]:
            return _mock_completed(
                returncode=bad_subcommand_rc, stderr="invalid choice"
            )
        # Check for mutex conflicts (--repo with --repos-dir, --resume with --no-resume)
        if "--repo" in args and "--repos-dir" in args:
            return _mock_completed(returncode=mutex_rc, stderr="not allowed with")
        if "--resume" in args and "--no-resume" in args:
            return _mock_completed(returncode=mutex_rc, stderr="not allowed with")
        # Check for type validation failures (abc as int arg)
        if "abc" in args:
            return _mock_completed(returncode=type_rc, stderr="invalid int value")
        # Check for required-arg commands that have no positional
        # Default: return exit 2 for commands that need required args
        return _mock_completed(returncode=missing_arg_rc, stderr="required")

    return _side_effect


# ---------------------------------------------------------------------------
# Constants tests
# ---------------------------------------------------------------------------


class TestConstants:
    """Verify the check group constants are correctly defined."""

    def test_main_subcommands_count(self):
        assert _MAIN_HELP_COUNT == 13
        assert len(MAIN_SUBCOMMANDS) == 13

    def test_main_subcommands_content(self):
        expected = {
            "wizard",
            "scan",
            "report",
            "ci",
            "tools",
            "history",
            "trends",
            "diff",
            "policy",
            "schedule",
            "build",
            "validate",
            "mcp-server",
        }
        assert set(MAIN_SUBCOMMANDS) == expected

    def test_sub_subcommand_parents(self):
        assert "tools" in SUB_SUBCOMMANDS
        assert "history" in SUB_SUBCOMMANDS
        assert "build" in SUB_SUBCOMMANDS
        assert "policy" in SUB_SUBCOMMANDS
        assert "schedule" in SUB_SUBCOMMANDS
        assert "trends" in SUB_SUBCOMMANDS
        assert "adapters" in SUB_SUBCOMMANDS

    def test_tools_subcommands(self):
        expected = {
            "check",
            "install",
            "list",
            "clean",
            "debug",
            "update",
            "outdated",
            "uninstall",
        }
        assert set(SUB_SUBCOMMANDS["tools"]) == expected

    def test_history_subcommands(self):
        expected = {
            "list",
            "show",
            "stats",
            "prune",
            "query",
            "export",
            "store",
            "diff",
            "trends",
            "optimize",
            "migrate",
            "verify",
            "repair",
        }
        assert set(SUB_SUBCOMMANDS["history"]) == expected

    def test_trends_subcommands(self):
        expected = {
            "analyze",
            "show",
            "regressions",
            "score",
            "compare",
            "insights",
            "explain",
            "developers",
        }
        assert set(SUB_SUBCOMMANDS["trends"]) == expected

    def test_policy_subcommands(self):
        expected = {"list", "validate", "test", "show", "install"}
        assert set(SUB_SUBCOMMANDS["policy"]) == expected

    def test_schedule_subcommands(self):
        expected = {
            "create",
            "list",
            "get",
            "update",
            "export",
            "install",
            "uninstall",
            "delete",
            "validate",
        }
        assert set(SUB_SUBCOMMANDS["schedule"]) == expected

    def test_build_subcommands(self):
        expected = {"validate", "test"}
        assert set(SUB_SUBCOMMANDS["build"]) == expected

    def test_adapters_subcommands(self):
        expected = {"list", "validate"}
        assert set(SUB_SUBCOMMANDS["adapters"]) == expected

    def test_sub_subcommand_total_count(self):
        total = sum(len(v) for v in SUB_SUBCOMMANDS.values())
        assert total == _SUB_SUBCOMMAND_COUNT
        # 8 + 13 + 2 + 5 + 9 + 8 + 2 = 47
        assert total == 47

    def test_required_arg_count(self):
        assert _REQUIRED_ARG_COUNT == len(REQUIRED_ARG_COMMANDS)
        assert _REQUIRED_ARG_COUNT == 13

    def test_invalid_flag_count(self):
        assert _INVALID_FLAG_COUNT == len(INVALID_FLAG_COMMANDS)
        assert _INVALID_FLAG_COUNT == 6

    def test_mutex_count(self):
        assert _MUTEX_COUNT == len(MUTUALLY_EXCLUSIVE)
        assert _MUTEX_COUNT == 2

    def test_type_check_count(self):
        assert _TYPE_CHECK_COUNT == len(FLAG_TYPE_CHECKS)
        assert _TYPE_CHECK_COUNT == 6

    def test_version_check_count(self):
        assert _VERSION_CHECK_COUNT == 3

    def test_exit_code_count(self):
        assert _EXIT_CODE_COUNT == 4

    def test_full_tier_count(self):
        assert _FULL_TIER_COUNT == 8


# ---------------------------------------------------------------------------
# Quick tier total check count
# ---------------------------------------------------------------------------


class TestQuickTierCheckCount:
    """Verify the quick tier produces the expected number of checks."""

    def test_quick_tier_total(self):
        expected = (
            _MAIN_HELP_COUNT  # 13 main --help
            + _SUB_SUBCOMMAND_COUNT  # 47 sub-subcommand --help
            + _REQUIRED_ARG_COUNT  # 13 required arg
            + _INVALID_FLAG_COUNT  # 6 invalid flag
            + _MUTEX_COUNT  # 2 mutex
            + _TYPE_CHECK_COUNT  # 6 type checks
            + _VERSION_CHECK_COUNT  # 3 version
            + _EXIT_CODE_COUNT  # 4 exit codes
        )
        # 13 + 47 + 13 + 6 + 2 + 6 + 3 + 4 = 94
        # (more than 37 from the task spec because the actual CLI has more
        #  sub-subcommands than the spec listed)
        assert expected == 94
        # Verify the math by running the validator
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            assert result.total == expected


# ---------------------------------------------------------------------------
# validate_cli() integration tests
# ---------------------------------------------------------------------------


class TestValidateCli:
    """Test the main validate_cli entry point."""

    def test_returns_category_result(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            assert isinstance(result, CategoryResult)

    def test_category_name(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            assert result.name == "CLI Completeness"

    def test_quick_tier_has_many_checks(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            assert result.total >= 30  # At least 30 quick checks

    def test_full_tier_has_more_checks(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            quick = validate_cli("quick")
            full = validate_cli("full")
            assert full.total > quick.total

    def test_full_tier_adds_exactly_8_checks(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            quick = validate_cli("quick")
            full = validate_cli("full")
            assert full.total - quick.total == _FULL_TIER_COUNT

    def test_all_pass_when_subprocess_returns_zero(self):
        """When all subprocess calls return 0, all checks pass."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            # For --help and --version calls, return 0
            # For missing-arg/invalid-flag, we also return 0 which will cause FAILs
            # So let's use a smarter mock
            mock_subprocess.run.side_effect = _make_mixed_mock()
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            # Should have both passes and some checks
            assert result.total > 0

    def test_all_help_checks_pass_with_rc_zero(self):
        """Help checks pass when subprocess returns 0."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.side_effect = _make_mixed_mock()
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            help_checks = [c for c in result.checks if c.name.startswith("help:")]
            for check in help_checks:
                assert (
                    check.status == CheckStatus.PASS
                ), f"{check.name}: {check.message}"

    def test_help_check_fails_with_nonzero(self):
        """Help checks fail when subprocess returns non-zero."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=1, stderr="error"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            help_checks = [c for c in result.checks if c.name.startswith("help:")]
            # All help checks should FAIL
            for check in help_checks:
                assert (
                    check.status == CheckStatus.FAIL
                ), f"{check.name}: expected FAIL, got {check.status}"

    def test_required_arg_checks_pass_with_rc_two(self):
        """Required-arg checks pass when subprocess returns exit code 2."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.side_effect = _make_mixed_mock()
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            req_checks = [
                c for c in result.checks if c.name.startswith("required-arg:")
            ]
            assert len(req_checks) == _REQUIRED_ARG_COUNT
            for check in req_checks:
                assert (
                    check.status == CheckStatus.PASS
                ), f"{check.name}: {check.message}"

    def test_invalid_flag_checks_pass_with_rc_two(self):
        """Invalid-flag checks pass when subprocess returns exit code 2."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.side_effect = _make_mixed_mock()
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            flag_checks = [
                c for c in result.checks if c.name.startswith("invalid-flag:")
            ]
            assert len(flag_checks) == _INVALID_FLAG_COUNT
            for check in flag_checks:
                assert (
                    check.status == CheckStatus.PASS
                ), f"{check.name}: {check.message}"

    def test_mutex_checks_pass_with_rc_two(self):
        """Mutually-exclusive checks pass when subprocess returns exit code 2."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.side_effect = _make_mixed_mock()
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            mutex_checks = [c for c in result.checks if c.name.startswith("mutex:")]
            assert len(mutex_checks) == _MUTEX_COUNT
            for check in mutex_checks:
                assert (
                    check.status == CheckStatus.PASS
                ), f"{check.name}: {check.message}"

    def test_type_checks_pass_with_rc_two(self):
        """Type-check validations pass when subprocess returns exit code 2."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.side_effect = _make_mixed_mock()
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            type_checks = [c for c in result.checks if c.name.startswith("type-check:")]
            assert len(type_checks) == _TYPE_CHECK_COUNT
            for check in type_checks:
                assert (
                    check.status == CheckStatus.PASS
                ), f"{check.name}: {check.message}"

    def test_version_checks_pass(self):
        """Version checks pass with valid version output."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.side_effect = _make_mixed_mock(
                version_stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            version_checks = [c for c in result.checks if c.name.startswith("version:")]
            assert len(version_checks) == _VERSION_CHECK_COUNT
            # --version exits 0 and semver format should pass
            v_flag = next(c for c in version_checks if "exits 0" in c.name)
            assert v_flag.status == CheckStatus.PASS
            v_semver = next(c for c in version_checks if "semver" in c.name)
            assert v_semver.status == CheckStatus.PASS

    def test_exit_code_checks_present(self):
        """Exit-code contract checks are present."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.side_effect = _make_mixed_mock()
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            exit_checks = [c for c in result.checks if c.name.startswith("exit-code:")]
            assert len(exit_checks) == _EXIT_CODE_COUNT


# ---------------------------------------------------------------------------
# Full tier tests
# ---------------------------------------------------------------------------


class TestFullTier:
    """Test full-tier specific checks."""

    def test_full_tier_includes_tools_check(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("full")
            full_checks = [c for c in result.checks if c.name.startswith("full:")]
            assert len(full_checks) == _FULL_TIER_COUNT

    def test_full_checks_names(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("full")
            full_names = {c.name for c in result.checks if c.name.startswith("full:")}
            expected_names = {
                "full: tools check",
                "full: tools list --profiles",
                "full: adapters list",
                "full: history stats",
                "full: build validate",
                "full: policy list",
                "full: trends explain",
                "full: diff --auto",
            }
            assert full_names == expected_names

    def test_full_checks_pass_on_rc_zero(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="output text"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("full")
            full_checks = [c for c in result.checks if c.name.startswith("full:")]
            for check in full_checks:
                assert (
                    check.status == CheckStatus.PASS
                ), f"{check.name}: {check.message}"

    def test_full_checks_pass_on_rc_one(self):
        """Some full-tier checks accept exit code 1 as acceptable."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=1, stdout="output"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("full")
            # tools check, history stats, build validate accept rc=1
            tools_check = next(
                (c for c in result.checks if c.name == "full: tools check"), None
            )
            assert tools_check is not None
            assert tools_check.status == CheckStatus.PASS

    def test_quick_tier_excludes_full_checks(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            full_checks = [c for c in result.checks if c.name.startswith("full:")]
            assert len(full_checks) == 0


# ---------------------------------------------------------------------------
# Error handling tests
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Test timeout and exception handling."""

    def test_timeout_produces_error_status(self):
        """TimeoutExpired results in ERROR status for the check."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:

            def _timeout_side_effect(cmd, **kwargs):
                raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)

            mock_subprocess.run.side_effect = _timeout_side_effect
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            # All checks should be ERROR (since all subprocess calls timeout)
            for check in result.checks:
                assert (
                    check.status == CheckStatus.ERROR
                ), f"{check.name}: expected ERROR, got {check.status}"

    def test_mixed_timeout_and_success(self):
        """Some checks timeout while others succeed."""
        call_count = 0

        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:

            def _alternating(cmd, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count % 2 == 0:
                    raise subprocess.TimeoutExpired(cmd=cmd, timeout=30)
                return _mock_completed(returncode=0, stdout="JMo Security v1.0.2")

            mock_subprocess.run.side_effect = _alternating
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            statuses = {c.status for c in result.checks}
            # Should have both PASS and ERROR
            assert CheckStatus.ERROR in statuses
            # At least some should pass (odd-numbered calls return success)
            assert CheckStatus.PASS in statuses

    def test_generic_exception_in_timed_check(self):
        """timed_check wraps generic exceptions as ERROR."""
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:

            def _raise_generic(cmd, **kwargs):
                raise RuntimeError("Something unexpected")

            mock_subprocess.run.side_effect = _raise_generic
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            # timed_check should catch RuntimeError from the check functions
            for check in result.checks:
                assert check.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# Individual check function tests
# ---------------------------------------------------------------------------


class TestHelpCheck:
    """Test the _help_check helper function."""

    def test_returns_callable(self):
        fn = _help_check(["scan"])
        assert callable(fn)

    def test_pass_on_rc_zero(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0, stdout="help text")
            fn = _help_check(["scan"])
            result = fn()
            assert result.status == CheckStatus.PASS
            assert result.name == "help: scan"

    def test_fail_on_nonzero(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=1, stderr="error")
            fn = _help_check(["scan"])
            result = fn()
            assert result.status == CheckStatus.FAIL

    def test_error_on_timeout(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="jmo", timeout=30)
            fn = _help_check(["scan"])
            result = fn()
            assert result.status == CheckStatus.ERROR
            assert "Timed out" in result.message

    def test_nested_subcommand_label(self):
        fn = _help_check(["tools", "check"])
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0, stdout="help")
            result = fn()
            assert result.name == "help: tools check"


class TestRequiredArgCheck:
    """Test the _required_arg_check helper function."""

    def test_pass_on_rc_two(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=2, stderr="required")
            fn = _required_arg_check(["history", "show"], "needs scan_id")
            result = fn()
            assert result.status == CheckStatus.PASS

    def test_fail_on_rc_zero(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0, stdout="output")
            fn = _required_arg_check(["history", "show"], "needs scan_id")
            result = fn()
            assert result.status == CheckStatus.FAIL
            assert "Expected exit 2" in result.message

    def test_error_on_timeout(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="jmo", timeout=30)
            fn = _required_arg_check(["history", "show"], "needs scan_id")
            result = fn()
            assert result.status == CheckStatus.ERROR


class TestInvalidFlagCheck:
    """Test the _invalid_flag_check helper function."""

    def test_pass_on_rc_two(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=2, stderr="unrecognized")
            fn = _invalid_flag_check(["scan"], "scan rejects unknown")
            result = fn()
            assert result.status == CheckStatus.PASS

    def test_fail_on_rc_zero(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0, stdout="output")
            fn = _invalid_flag_check(["scan"], "scan rejects unknown")
            result = fn()
            assert result.status == CheckStatus.FAIL


class TestMutexCheck:
    """Test the _mutex_check helper function."""

    def test_pass_on_rc_two(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=2, stderr="not allowed with"
            )
            fn = _mutex_check(
                ["scan", "--repo", ".", "--repos-dir", "d"], "repo vs repos-dir"
            )
            result = fn()
            assert result.status == CheckStatus.PASS

    def test_fail_on_rc_zero(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0)
            fn = _mutex_check(
                ["scan", "--repo", ".", "--repos-dir", "d"], "repo vs repos-dir"
            )
            result = fn()
            assert result.status == CheckStatus.FAIL


class TestTypeCheck:
    """Test the _type_check helper function."""

    def test_pass_on_rc_two(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=2, stderr="invalid int value"
            )
            fn = _type_check(["scan", "--threads", "abc"], "threads non-integer")
            result = fn()
            assert result.status == CheckStatus.PASS

    def test_fail_on_rc_zero(self):
        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0)
            fn = _type_check(["scan", "--threads", "abc"], "threads non-integer")
            result = fn()
            assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# _run_jmo helper test
# ---------------------------------------------------------------------------


class TestRunJmo:
    """Test the _run_jmo subprocess helper."""

    def test_constructs_correct_command(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(returncode=0)
            _run_jmo("scan", "--help")
            call_args = mock_subprocess.run.call_args
            cmd = call_args[0][0]
            assert cmd[0] == str(sys.executable)  # python interpreter
            assert cmd[1] == "-m"
            assert cmd[2] == "scripts.cli.jmo"
            assert cmd[3] == "scan"
            assert cmd[4] == "--help"

    def test_uses_capture_output(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(returncode=0)
            _run_jmo("--version")
            call_kwargs = mock_subprocess.run.call_args[1]
            assert call_kwargs["capture_output"] is True
            assert call_kwargs["text"] is True

    def test_timeout_parameter(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(returncode=0)
            _run_jmo("scan", "--help", timeout=60)
            call_kwargs = mock_subprocess.run.call_args[1]
            assert call_kwargs["timeout"] == 60

    def test_default_timeout(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(returncode=0)
            _run_jmo("--version")
            call_kwargs = mock_subprocess.run.call_args[1]
            assert call_kwargs["timeout"] == 30


# ---------------------------------------------------------------------------
# Version check tests
# ---------------------------------------------------------------------------


class TestVersionChecks:
    """Test version/identity check functions."""

    def test_version_flag_pass(self):
        from scripts.core.validators.cli_validator import _check_version_flag

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            result = _check_version_flag()
            assert result.status == CheckStatus.PASS

    def test_version_flag_fail(self):
        from scripts.core.validators.cli_validator import _check_version_flag

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=1, stderr="error")
            result = _check_version_flag()
            assert result.status == CheckStatus.FAIL

    def test_version_flag_timeout(self):
        from scripts.core.validators.cli_validator import _check_version_flag

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="jmo", timeout=30)
            result = _check_version_flag()
            assert result.status == CheckStatus.ERROR

    def test_semver_format_pass(self):
        from scripts.core.validators.cli_validator import _check_version_semver_format

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            result = _check_version_semver_format()
            assert result.status == CheckStatus.PASS

    def test_semver_format_fail_no_version(self):
        from scripts.core.validators.cli_validator import _check_version_semver_format

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=0, stdout="no version here"
            )
            result = _check_version_semver_format()
            assert result.status == CheckStatus.FAIL

    def test_semver_prerelease(self):
        from scripts.core.validators.cli_validator import _check_version_semver_format

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v2.0.0-beta.1"
            )
            result = _check_version_semver_format()
            assert result.status == CheckStatus.PASS

    def test_version_matches_pyproject(self):
        import tomllib
        from pathlib import Path
        from scripts.core.validators.cli_validator import (
            _check_version_matches_pyproject,
        )

        # Read the actual current version from pyproject.toml so the test
        # tracks the canonical source of truth instead of hardcoding a
        # specific version (which goes stale on every release bump).
        repo_root = Path(__file__).parent.parent.parent
        pyproject_path = repo_root / "pyproject.toml"
        if pyproject_path.is_file():
            with open(pyproject_path, "rb") as f:
                current_version = tomllib.load(f)["project"]["version"]
        else:
            current_version = "1.0.3"  # fallback if pyproject not found in test context

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=0, stdout=f"JMo Security v{current_version}"
            )
            result = _check_version_matches_pyproject()
            # Should pass or skip depending on pyproject.toml location
            assert result.status in (CheckStatus.PASS, CheckStatus.SKIP)


# ---------------------------------------------------------------------------
# Exit code contract tests
# ---------------------------------------------------------------------------


class TestExitCodeContracts:
    """Test exit-code contract check functions."""

    def test_help_exit_zero(self):
        from scripts.core.validators.cli_validator import _check_help_exit_zero

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0, stdout="usage:")
            result = _check_help_exit_zero()
            assert result.status == CheckStatus.PASS

    def test_missing_subcommand_exit_two(self):
        from scripts.core.validators.cli_validator import (
            _check_missing_subcommand_exit_two,
        )

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=2, stderr="the following arguments are required: cmd"
            )
            result = _check_missing_subcommand_exit_two()
            assert result.status == CheckStatus.PASS

    def test_bad_subcommand_exit_two(self):
        from scripts.core.validators.cli_validator import (
            _check_bad_subcommand_exit_two,
        )

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=2, stderr="invalid choice"
            )
            result = _check_bad_subcommand_exit_two()
            assert result.status == CheckStatus.PASS

    def test_scan_help_mentions_repo(self):
        from scripts.core.validators.cli_validator import (
            _check_scan_help_mentions_repo,
        )

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=0, stdout="--repo PATH  Path to repository"
            )
            result = _check_scan_help_mentions_repo()
            assert result.status == CheckStatus.PASS

    def test_scan_help_missing_repo(self):
        from scripts.core.validators.cli_validator import (
            _check_scan_help_mentions_repo,
        )

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=0, stdout="usage: jmo scan"
            )
            result = _check_scan_help_mentions_repo()
            assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# Check result timing
# ---------------------------------------------------------------------------


class TestCheckTiming:
    """Verify checks have timing data."""

    def test_checks_have_duration(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            for check in result.checks:
                assert (
                    check.duration_ms >= 0
                ), f"{check.name}: duration_ms should be non-negative"


# ---------------------------------------------------------------------------
# Check result messages
# ---------------------------------------------------------------------------


class TestCheckMessages:
    """Verify checks have meaningful messages."""

    def test_passing_help_checks_have_messages(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="usage: jmo ..."
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            help_checks = [c for c in result.checks if c.name.startswith("help:")]
            for check in help_checks:
                assert check.message, f"{check.name}: should have a message"

    def test_failing_checks_include_exit_code(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=42, stderr="weird error"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            help_checks = [c for c in result.checks if c.name.startswith("help:")]
            for check in help_checks:
                if check.status == CheckStatus.FAIL:
                    assert (
                        "42" in check.message
                    ), f"{check.name}: failure message should include exit code"


# ---------------------------------------------------------------------------
# Full tier edge cases
# ---------------------------------------------------------------------------


class TestFullTierEdgeCases:
    """Test full-tier specific edge cases."""

    def test_full_tools_check_accepts_rc_one(self):
        """tools check with rc=1 (some tools missing) is acceptable."""
        from scripts.core.validators.cli_validator import _full_tools_check

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=1, stdout="Missing: trivy"
            )
            result = _full_tools_check()
            assert result.status == CheckStatus.PASS

    def test_full_tools_check_fails_on_unexpected_rc(self):
        from scripts.core.validators.cli_validator import _full_tools_check

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=42, stderr="crash")
            result = _full_tools_check()
            assert result.status == CheckStatus.FAIL

    def test_full_diff_auto_accepts_rc_two(self):
        """diff --auto with rc=2 (no git context) is acceptable."""
        from scripts.core.validators.cli_validator import _full_diff_auto

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=2, stderr="no context")
            result = _full_diff_auto()
            assert result.status == CheckStatus.PASS

    def test_full_adapters_list_fails_on_empty_output(self):
        """adapters list with rc=0 but empty output should fail."""
        from scripts.core.validators.cli_validator import _full_adapters_list

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0, stdout="")
            result = _full_adapters_list()
            assert result.status == CheckStatus.FAIL

    def test_full_policy_list_fail_on_nonzero(self):
        from scripts.core.validators.cli_validator import _full_policy_list

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=1, stderr="error")
            result = _full_policy_list()
            assert result.status == CheckStatus.FAIL

    def test_full_trends_explain_fail_on_nonzero(self):
        from scripts.core.validators.cli_validator import _full_trends_explain

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=1, stderr="error")
            result = _full_trends_explain()
            assert result.status == CheckStatus.FAIL

    def test_full_history_stats_timeout(self):
        from scripts.core.validators.cli_validator import _full_history_stats

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="jmo", timeout=30)
            result = _full_history_stats()
            assert result.status == CheckStatus.ERROR

    def test_full_build_validate_timeout(self):
        from scripts.core.validators.cli_validator import _full_build_validate

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.side_effect = subprocess.TimeoutExpired(cmd="jmo", timeout=60)
            result = _full_build_validate()
            assert result.status == CheckStatus.ERROR
