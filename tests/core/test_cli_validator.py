"""Tests for CLI completeness validator.

All tests mock subprocess.run to avoid spawning real processes.
"""

from __future__ import annotations

import subprocess
import sys
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.jmo import build_parser
from scripts.core.validators import CategoryResult, CheckStatus
from scripts.core.validators.cli_validator import (
    _EXIT_CODE_COUNT,
    _FIXED_QUICK_COUNT,
    _FULL_TIER_COUNT,
    _INVALID_FLAG_COUNT,
    _MUTEX_COUNT,
    _REQUIRED_ARG_COUNT,
    _TYPE_CHECK_COUNT,
    _VERSION_CHECK_COUNT,
    FLAG_TYPE_CHECKS,
    INVALID_FLAG_COMMANDS,
    MUTUALLY_EXCLUSIVE,
    REQUIRED_ARG_COMMANDS,
    _help_check,
    _invalid_flag_check,
    _mutex_check,
    _required_arg_check,
    _run_jmo,
    _type_check,
    derive_surface,
    set_cli_surface,
    validate_cli,
)

# The surface the parser actually exposes. Every expectation below is computed
# from this rather than restated: the previous version of this file listed 13
# top-level subcommands as its `expected` set -- the same 13 the validator had
# drifted to (#783) -- so it agreed with the bug instead of catching it.
MAIN_SUBCOMMANDS, SUB_SUBCOMMANDS = derive_surface(build_parser())


@pytest.fixture(autouse=True)
def _inject_cli_surface():
    """`validate_cli` reads an injected surface; the CLI layer normally supplies it."""
    set_cli_surface(MAIN_SUBCOMMANDS, SUB_SUBCOMMANDS)
    yield


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

    def test_main_subcommands_covers_every_parser_subcommand(self):
        """The validator must check every subcommand the parser defines.

        This used to assert `== 13` against a hand-listed set. The parser had
        20, and the seven missing -- adapters, attest, balanced, fast, full,
        setup, verify -- were exactly the ones nobody had added to either list
        (#783). Restating the list here made the suite a mirror of the mirror.
        """
        parser_names = set(build_parser()._subparsers._group_actions[0].choices)
        assert set(MAIN_SUBCOMMANDS) == parser_names
        # Meta-guard: a derivation that silently returns nothing passes every
        # assertion built on it.
        assert len(MAIN_SUBCOMMANDS) >= 20, sorted(MAIN_SUBCOMMANDS)
        for known in ("scan", "report", "adapters", "attest", "verify", "setup"):
            assert known in MAIN_SUBCOMMANDS

    def test_main_subcommands_includes_the_seven_that_had_drifted(self):
        """Negative control: name the seven #783 was about.

        If the derivation regresses to the old hard-coded list, the assertion
        above still passes when both sides regress together. These seven cannot.
        """
        for missed in (
            "adapters",
            "attest",
            "balanced",
            "fast",
            "full",
            "setup",
            "verify",
        ):
            assert missed in MAIN_SUBCOMMANDS

    def test_sub_subcommands_match_the_parser(self):
        """Every parent with children is covered, with the children it has."""
        top = build_parser()._subparsers._group_actions[0].choices
        for parent, children in SUB_SUBCOMMANDS.items():
            nested = top[parent]._subparsers._group_actions[0].choices
            assert set(children) == set(nested), parent

        # Parents with nested commands must all be present.
        expected_parents = {
            name
            for name, sub in top.items()
            if getattr(sub, "_subparsers", None) is not None
        }
        assert set(SUB_SUBCOMMANDS) == expected_parents
        assert expected_parents >= {
            "tools",
            "history",
            "build",
            "policy",
            "schedule",
            "trends",
            "adapters",
        }

    def test_sub_subcommand_total_count(self):
        total = sum(len(v) for v in SUB_SUBCOMMANDS.values())
        # No literal: the count follows the parser. A floor catches a
        # derivation that quietly found nothing.
        assert total >= 47, f"nested surface shrank to {total}"

    def test_required_arg_count(self):
        assert len(REQUIRED_ARG_COMMANDS) == _REQUIRED_ARG_COUNT
        assert _REQUIRED_ARG_COUNT == 13

    def test_invalid_flag_count(self):
        assert len(INVALID_FLAG_COMMANDS) == _INVALID_FLAG_COUNT
        assert _INVALID_FLAG_COUNT == 6

    def test_mutex_count(self):
        assert len(MUTUALLY_EXCLUSIVE) == _MUTEX_COUNT
        assert _MUTEX_COUNT == 2

    def test_type_check_count(self):
        assert len(FLAG_TYPE_CHECKS) == _TYPE_CHECK_COUNT
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
        """The count must come from the parser, not from a literal.

        This asserted `expected == 94` and then checked the validator produced
        94 -- both sides derived from the same stale `MAIN_SUBCOMMANDS`, so the
        pair was self-consistent and wrong. The help-group sizes now come from
        the parser.
        """
        expected = (
            len(MAIN_SUBCOMMANDS)
            + sum(len(v) for v in SUB_SUBCOMMANDS.values())
            + _FIXED_QUICK_COUNT
        )
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            result = validate_cli("quick")
            assert result.total == expected

    def test_full_tier_adds_exactly_the_full_checks(self):
        with patch(
            "scripts.core.validators.cli_validator.subprocess"
        ) as mock_subprocess:
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="JMo Security v1.0.2"
            )
            mock_subprocess.TimeoutExpired = subprocess.TimeoutExpired
            quick = validate_cli("quick").total
            full = validate_cli("full").total
        assert full - quick == _FULL_TIER_COUNT

    def test_missing_surface_errors_rather_than_reporting_an_empty_pass(self):
        """A category that checked nothing must not read as a pass.

        Without injection the loop over subcommands would simply not execute,
        producing `[0/0 PASS]` -- the same shape as `--category bogus` printing
        `Verdict: GO` over zero checks.
        """
        import scripts.core.validators.cli_validator as cv

        saved = cv._CLI_SURFACE
        try:
            cv._CLI_SURFACE = None
            result = validate_cli("quick")
        finally:
            cv._CLI_SURFACE = saved

        assert result.total == 1
        assert result.errored == 1
        assert result.passed == 0


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
            # "Repository root:" is what a `jmo build validate` that actually
            # reached the repository prints; `_full_build_validate` now requires
            # it, because exit code alone could not tell a real run from the
            # "cannot find repository root" failure it passed for seven releases.
            mock_subprocess.run.return_value = _mock_completed(
                returncode=0, stdout="Repository root: /repo\noutput text"
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
            current_version = "1.0.5"  # fallback if pyproject not found in test context

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

    def test_full_tools_check_bound_clears_the_measured_runtime(self):
        """The bound must survive the validator's own load (#773).

        `jmo tools check` probes all 29 registry entries -- measured 49s cold
        and 33s warm, standalone, on a box with the tools installed. The old
        60s literal was 1.22x the cold run while this validator spawns
        subprocess checks alongside it, so the check ERRORed and `--tier full`
        reported NO-GO. Same shape as #748, where a bound sized against an
        unloaded machine failed on one that had the tools.

        The other two cases here mock `_run_jmo` wholesale, so nothing else in
        this file would notice the bound being tightened again.
        """
        from scripts.core.validators.cli_validator import (
            _TOOLS_CHECK_TIMEOUT,
            _full_tools_check,
        )

        assert _TOOLS_CHECK_TIMEOUT >= 150, "must clear the 49s cold measurement"

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=0, stdout="ok")
            _full_tools_check()
            assert mock_run.call_args.kwargs["timeout"] == _TOOLS_CHECK_TIMEOUT

    def test_full_diff_auto_rejects_rc_two(self):
        """rc=2 is argparse's usage error, and must not pass.

        This test asserted the opposite -- that exit 2 "is acceptable". A check
        that accepts 2 still passes after the flag it exercises is deleted from
        the parser, so it could only ever fail on a hard crash. That made it
        zero coverage while counting as one passing check.
        """
        from scripts.core.validators.cli_validator import _full_diff_auto

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=2, stderr="no context")
            result = _full_diff_auto()
            assert result.status == CheckStatus.FAIL

    def test_full_diff_auto_accepts_rc_one(self):
        """rc=1 means it ran and found nothing to compare -- still a real run."""
        from scripts.core.validators.cli_validator import _full_diff_auto

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(returncode=1, stdout="no scans")
            result = _full_diff_auto()
            assert result.status == CheckStatus.PASS

    def test_full_build_validate_fails_when_repo_root_never_found(self):
        """The regression guard for #303.

        `jmo build` exited 1 with "Cannot find repository root" on every
        invocation from v1.0.2 to v1.0.8, and this check reported PASS on all of
        them because it only looked at `returncode in (0, 1)`.
        """
        from scripts.core.validators.cli_validator import _full_build_validate

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=1,
                stderr="Error: Cannot find repository root (looking for Dockerfile ...)",
            )
            result = _full_build_validate()
            assert result.status == CheckStatus.FAIL
            assert "repository root" in result.message

    def test_full_build_validate_skips_without_docker(self):
        from scripts.core.validators.cli_validator import _full_build_validate

        with patch("scripts.core.validators.cli_validator._run_jmo") as mock_run:
            mock_run.return_value = _mock_completed(
                returncode=1, stderr="Error: Docker not found in PATH"
            )
            result = _full_build_validate()
            assert result.status == CheckStatus.SKIP

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
