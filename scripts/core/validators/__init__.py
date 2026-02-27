"""Shared types and runner for the jmo validate system.

This module provides the protocol, result types, and orchestration
for the 4 validator categories (CLI, Scan, Platform, Release).
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable

# Category name -> short key mapping for --category filter
CATEGORY_KEYS: dict[str, str] = {
    "CLI Completeness": "cli",
    "Scan Correctness": "scans",
    "Cross-Platform": "platform",
    "Release Artifacts": "release",
}


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
    """
    results: list[CategoryResult] = []

    for validator in validators:
        category_result = validator(tier)

        # Apply category filter
        if categories:
            key = CATEGORY_KEYS.get(category_result.name, "")
            if key not in categories:
                continue

        results.append(category_result)

        if fail_fast and category_result.failed > 0:
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
