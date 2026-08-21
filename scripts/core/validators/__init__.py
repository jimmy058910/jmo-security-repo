"""Shared types and runner for the jmo validate system.

This module provides the protocol, result types, and orchestration
for the 4 validator categories (CLI, Scan, Platform, Release).
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass, field
from enum import Enum

# Category name -> short key mapping for --category filter
CATEGORY_KEYS: dict[str, str] = {
    "CLI Completeness": "cli",
    "Scan Correctness": "scans",
    "Cross-Platform": "platform",
    "Release Artifacts": "release",
}

# Validator function name -> short key. The key used to be read off the
# *result*, which meant it was only knowable after the validator had already
# run; see `run_validators`.
VALIDATOR_KEYS: dict[str, str] = {
    "validate_cli": "cli",
    "validate_scans": "scans",
    "validate_platform": "platform",
    "validate_release": "release",
}


class UnknownCategoryError(ValueError):
    """Raised when --category names a category that does not exist.

    Exists so the silent-empty case cannot come back. An unrecognised key used
    to filter every category out, and a run with zero categories has zero
    failures, so `jmo validate --category bogus` printed `0/0 PASS` and
    `Verdict: GO` and exited 0.
    """


def category_key_for(validator: ValidatorFn) -> str:
    """Return the --category key a validator answers to.

    Reads an explicit ``category_key`` attribute if the function carries one,
    otherwise falls back to ``VALIDATOR_KEYS`` by function name. A validator
    that matches neither raises rather than being skipped: dropping it silently
    would reintroduce the empty-run-reports-GO failure from the other
    direction, with the filter quietly excluding a category that exists.
    """
    key = getattr(validator, "category_key", None)
    if key is None:
        key = VALIDATOR_KEYS.get(getattr(validator, "__name__", ""))
    if key is None:
        raise UnknownCategoryError(
            f"Validator {getattr(validator, '__name__', validator)!r} has no "
            f"category key; set a `category_key` attribute or add it to "
            f"VALIDATOR_KEYS, otherwise --category would skip it silently."
        )
    return str(key)


class CheckStatus(Enum):
    """Status of a single validation check."""

    PASS = "pass"  # nosec B105 - not a password, validation status
    FAIL = "fail"
    WARN = "warn"
    SKIP = "skip"
    ERROR = "error"


@dataclass
class CheckResult:
    """Result of a single validation check."""

    name: str
    status: CheckStatus
    message: str = ""
    details: str = ""
    duration_ms: float = 0.0


@dataclass
class CategoryResult:
    """Aggregated result of a validator category."""

    name: str
    checks: list[CheckResult] = field(default_factory=list)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def warned(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.WARN)

    @property
    def skipped(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.SKIP)

    @property
    def errored(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.ERROR)

    @property
    def total(self) -> int:
        return len(self.checks)


# Type alias for a validator function
ValidatorFn = Callable[[str], CategoryResult]


def run_validators(
    validators: list[ValidatorFn],
    tier: str = "quick",
    fail_fast: bool = False,
    categories: list[str] | None = None,
) -> list[CategoryResult]:
    """Run validator functions and collect results.

    Args:
        validators: List of validator functions (each returns CategoryResult).
        tier: "quick" or "full".
        fail_fast: Stop after first category with failures.
        categories: Optional list of category short keys to run
                    (e.g., ["cli", "scans"]).

    Returns:
        List of CategoryResult from each validator that ran.

    Raises:
        UnknownCategoryError: if ``categories`` names a category that does not
            exist.

    The filter is applied **before** the validator runs. It used to be applied
    to the returned `CategoryResult`, so every category executed and the
    unwanted ones were then discarded: measured, `--category cli` took 45.4s
    against 47.1s for all four. Under `--tier full` that meant `--category cli`
    still attempted four Docker builds and a real scan.
    """
    if categories is not None:
        known = set(VALIDATOR_KEYS.values())
        unknown = [c for c in categories if c not in known]
        if unknown:
            raise UnknownCategoryError(
                f"Unknown category: {', '.join(sorted(unknown))}. "
                f"Valid categories: {', '.join(sorted(known))}"
            )

    results: list[CategoryResult] = []

    for validator in validators:
        if categories is not None:
            key = category_key_for(validator)
            if key not in categories:
                continue

        category_result = validator(tier)
        results.append(category_result)

        # ERROR counts toward the NO-GO verdict exactly as FAIL does, so
        # --fail-fast has to stop on it too; it used to test `failed` only and
        # ran on past a category that had already made the verdict NO-GO.
        if fail_fast and (category_result.failed > 0 or category_result.errored > 0):
            break

    return results


def timed_check(name: str, fn: Callable[[], CheckResult | None]) -> CheckResult:
    """Run a check function with timing.

    If fn returns a CheckResult, return it with timing added.
    If fn returns None, return a PASS result.
    If fn raises, return an ERROR result.
    """
    start = time.perf_counter()
    try:
        result = fn()
        if result is None:
            result = CheckResult(name=name, status=CheckStatus.PASS)
        elapsed = (time.perf_counter() - start) * 1000
        result.duration_ms = elapsed
        return result
    except Exception as exc:
        elapsed = (time.perf_counter() - start) * 1000
        return CheckResult(
            name=name,
            status=CheckStatus.ERROR,
            message=str(exc),
            duration_ms=elapsed,
        )
