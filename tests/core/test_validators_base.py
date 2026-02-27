"""Tests for validator base types and protocol."""

from scripts.core.validators import (
    CATEGORY_KEYS,
    CategoryResult,
    CheckResult,
    CheckStatus,
    run_validators,
    timed_check,
)


class TestCheckStatus:
    def test_status_values(self):
        assert CheckStatus.PASS.value == "pass"
        assert CheckStatus.FAIL.value == "fail"
        assert CheckStatus.WARN.value == "warn"
        assert CheckStatus.SKIP.value == "skip"
        assert CheckStatus.ERROR.value == "error"

    def test_all_statuses_unique(self):
        values = [s.value for s in CheckStatus]
        assert len(values) == len(set(values))


class TestCheckResult:
    def test_basic_creation(self):
        result = CheckResult(name="test", status=CheckStatus.PASS)
        assert result.name == "test"
        assert result.status == CheckStatus.PASS
        assert result.message == ""
        assert result.details == ""
        assert result.duration_ms == 0.0

    def test_with_message(self):
        result = CheckResult(
            name="test",
            status=CheckStatus.FAIL,
            message="Something failed",
            details="More info here",
        )
        assert result.message == "Something failed"
        assert result.details == "More info here"

    def test_with_timing(self):
        result = CheckResult(name="test", status=CheckStatus.PASS, duration_ms=42.5)
        assert result.duration_ms == 42.5


class TestCategoryResult:
    def test_counts(self):
        checks = [
            CheckResult(name="a", status=CheckStatus.PASS),
            CheckResult(name="b", status=CheckStatus.PASS),
            CheckResult(name="c", status=CheckStatus.FAIL),
            CheckResult(name="d", status=CheckStatus.WARN),
            CheckResult(name="e", status=CheckStatus.SKIP),
        ]
        result = CategoryResult(name="test", checks=checks)
        assert result.passed == 2
        assert result.failed == 1
        assert result.warned == 1
        assert result.skipped == 1
        assert result.errored == 0
        assert result.total == 5

    def test_empty(self):
        result = CategoryResult(name="empty", checks=[])
        assert result.passed == 0
        assert result.failed == 0
        assert result.warned == 0
        assert result.skipped == 0
        assert result.errored == 0
        assert result.total == 0

    def test_all_pass(self):
        checks = [CheckResult(name="a", status=CheckStatus.PASS)]
        result = CategoryResult(name="test", checks=checks)
        assert result.passed == 1
        assert result.failed == 0

    def test_all_error(self):
        checks = [
            CheckResult(name="a", status=CheckStatus.ERROR, message="boom"),
            CheckResult(name="b", status=CheckStatus.ERROR, message="crash"),
        ]
        result = CategoryResult(name="test", checks=checks)
        assert result.errored == 2
        assert result.passed == 0

    def test_default_checks_empty_list(self):
        result = CategoryResult(name="test")
        assert result.checks == []
        assert result.total == 0


class TestCategoryKeys:
    def test_all_four_categories_mapped(self):
        assert "CLI Completeness" in CATEGORY_KEYS
        assert "Scan Correctness" in CATEGORY_KEYS
        assert "Cross-Platform" in CATEGORY_KEYS
        assert "Release Artifacts" in CATEGORY_KEYS

    def test_short_keys(self):
        assert CATEGORY_KEYS["CLI Completeness"] == "cli"
        assert CATEGORY_KEYS["Scan Correctness"] == "scans"
        assert CATEGORY_KEYS["Cross-Platform"] == "platform"
        assert CATEGORY_KEYS["Release Artifacts"] == "release"


class TestRunValidators:
    def test_runs_all_categories(self):
        def fake_cli(tier):
            return CategoryResult(
                name="CLI Completeness",
                checks=[CheckResult(name="help", status=CheckStatus.PASS)],
            )

        def fake_scan(tier):
            return CategoryResult(
                name="Scan Correctness",
                checks=[CheckResult(name="adapter", status=CheckStatus.PASS)],
            )

        results = run_validators(
            validators=[fake_cli, fake_scan],
            tier="quick",
        )
        assert len(results) == 2
        assert results[0].name == "CLI Completeness"
        assert results[1].name == "Scan Correctness"

    def test_passes_tier_to_validators(self):
        received_tier = None

        def capture_tier(tier):
            nonlocal received_tier
            received_tier = tier
            return CategoryResult(name="CLI Completeness", checks=[])

        run_validators(validators=[capture_tier], tier="full")
        assert received_tier == "full"

    def test_fail_fast_stops_on_failure(self):
        call_count = 0

        def failing_validator(tier):
            nonlocal call_count
            call_count += 1
            return CategoryResult(
                name="CLI Completeness",
                checks=[CheckResult(name="ok", status=CheckStatus.FAIL)],
            )

        def never_reached(tier):
            nonlocal call_count
            call_count += 1
            return CategoryResult(
                name="Scan Correctness",
                checks=[CheckResult(name="x", status=CheckStatus.PASS)],
            )

        results = run_validators(
            validators=[failing_validator, never_reached],
            tier="quick",
            fail_fast=True,
        )
        assert call_count == 1
        assert len(results) == 1

    def test_fail_fast_continues_on_pass(self):
        call_count = 0

        def passing_validator(tier):
            nonlocal call_count
            call_count += 1
            return CategoryResult(
                name="CLI Completeness",
                checks=[CheckResult(name="ok", status=CheckStatus.PASS)],
            )

        def also_runs(tier):
            nonlocal call_count
            call_count += 1
            return CategoryResult(
                name="Scan Correctness",
                checks=[CheckResult(name="ok", status=CheckStatus.PASS)],
            )

        results = run_validators(
            validators=[passing_validator, also_runs],
            tier="quick",
            fail_fast=True,
        )
        assert call_count == 2
        assert len(results) == 2

    def test_category_filter_includes_matching(self):
        def cli_validator(tier):
            return CategoryResult(
                name="CLI Completeness",
                checks=[CheckResult(name="help", status=CheckStatus.PASS)],
            )

        def scan_validator(tier):
            return CategoryResult(
                name="Scan Correctness",
                checks=[CheckResult(name="adapter", status=CheckStatus.PASS)],
            )

        results = run_validators(
            validators=[cli_validator, scan_validator],
            tier="quick",
            categories=["cli"],
        )
        assert len(results) == 1
        assert results[0].name == "CLI Completeness"

    def test_category_filter_multiple(self):
        def cli_validator(tier):
            return CategoryResult(name="CLI Completeness", checks=[])

        def scan_validator(tier):
            return CategoryResult(name="Scan Correctness", checks=[])

        def platform_validator(tier):
            return CategoryResult(name="Cross-Platform", checks=[])

        results = run_validators(
            validators=[cli_validator, scan_validator, platform_validator],
            tier="quick",
            categories=["cli", "platform"],
        )
        assert len(results) == 2

    def test_no_category_filter_runs_all(self):
        def v1(tier):
            return CategoryResult(name="CLI Completeness", checks=[])

        def v2(tier):
            return CategoryResult(name="Scan Correctness", checks=[])

        results = run_validators(validators=[v1, v2], tier="quick", categories=None)
        assert len(results) == 2

    def test_empty_validators_list(self):
        results = run_validators(validators=[], tier="quick")
        assert results == []

    def test_unknown_category_filtered_out(self):
        def unknown(tier):
            return CategoryResult(name="Unknown Category", checks=[])

        results = run_validators(validators=[unknown], tier="quick", categories=["cli"])
        assert len(results) == 0


class TestTimedCheck:
    def test_passing_check(self):
        def fn():
            return CheckResult(name="test", status=CheckStatus.PASS)

        result = timed_check("test", fn)
        assert result.status == CheckStatus.PASS
        assert result.duration_ms > 0

    def test_none_return_becomes_pass(self):
        def fn():
            return None

        result = timed_check("test", fn)
        assert result.status == CheckStatus.PASS
        assert result.name == "test"

    def test_exception_becomes_error(self):
        def fn():
            raise ValueError("boom")

        result = timed_check("test", fn)
        assert result.status == CheckStatus.ERROR
        assert "boom" in result.message
        assert result.duration_ms > 0

    def test_preserves_check_result_fields(self):
        def fn():
            return CheckResult(name="inner", status=CheckStatus.WARN, message="careful")

        result = timed_check("outer", fn)
        assert result.status == CheckStatus.WARN
        assert result.message == "careful"
        # Name comes from the returned CheckResult, not the wrapper
        assert result.name == "inner"
