"""CLI dispatcher and scorecard renderer for jmo validate.

Usage:
    jmo validate [--tier {quick,full}] [--category CAT] [-v] [--fail-fast] [--json]
"""

from __future__ import annotations

import argparse
import json
import platform
import sys
from typing import TYPE_CHECKING

from scripts.core.validators import (
    CategoryResult,
    CheckStatus,
    ValidatorFn,
    run_validators,
)

if TYPE_CHECKING:
    pass


def _get_validators() -> list[ValidatorFn]:
    """Return list of all validator functions.

    Lazy imports to keep jmo startup fast.
    """
    from scripts.core.validators.cli_validator import validate_cli
    from scripts.core.validators.platform_validator import validate_platform
    from scripts.core.validators.release_validator import validate_release
    from scripts.core.validators.scan_validator import validate_scans

    return [validate_cli, validate_scans, validate_platform, validate_release]


def cmd_validate(args: argparse.Namespace) -> int:
    """Main dispatcher for jmo validate."""
    tier = getattr(args, "tier", "quick")
    category_str = getattr(args, "category", None)
    verbose = getattr(args, "verbose", False)
    fail_fast = getattr(args, "fail_fast", False)
    json_output = getattr(args, "json", False)

    categories = None
    if category_str:
        categories = [c.strip() for c in category_str.split(",")]

    validators = _get_validators()

    results = run_validators(
        validators=validators,
        tier=tier,
        fail_fast=fail_fast,
        categories=categories,
    )

    return render_scorecard(results, verbose=verbose, json_output=json_output)


def render_scorecard(
    results: list[CategoryResult],
    verbose: bool = False,
    json_output: bool = False,
) -> int:
    """Render validation results and return exit code.

    Args:
        results: List of CategoryResult from validators.
        verbose: Show per-check details.
        json_output: Output as JSON instead of terminal.

    Returns:
        0 if all checks pass (GO), 1 if any failures (NO-GO).
    """
    if json_output:
        return _render_json(results)

    return _render_terminal(results, verbose=verbose)


def _render_json(results: list[CategoryResult]) -> int:
    """Render results as JSON to stdout."""
    total_pass = sum(r.passed for r in results)
    total_fail = sum(r.failed for r in results)
    total_warn = sum(r.warned for r in results)
    total_skip = sum(r.skipped for r in results)
    total_error = sum(r.errored for r in results)
    total = sum(r.total for r in results)

    has_failures = total_fail > 0 or total_error > 0
    verdict = "NO-GO" if has_failures else "GO"

    data = {
        "verdict": verdict,
        "tier": "quick",
        "platform": platform.system(),
        "python": platform.python_version(),
        "summary": {
            "total": total,
            "passed": total_pass,
            "failed": total_fail,
            "warned": total_warn,
            "skipped": total_skip,
            "errored": total_error,
        },
        "categories": [
            {
                "name": r.name,
                "passed": r.passed,
                "failed": r.failed,
                "warned": r.warned,
                "total": r.total,
                "checks": [
                    {
                        "name": c.name,
                        "status": c.status.value,
                        "message": c.message,
                        "duration_ms": round(c.duration_ms, 1),
                    }
                    for c in r.checks
                ],
            }
            for r in results
        ],
    }

    print(json.dumps(data, indent=2))
    return 1 if has_failures else 0


def _render_terminal(results: list[CategoryResult], verbose: bool) -> int:
    """Render results as terminal scorecard."""
    use_color = _supports_color()

    total_pass = sum(r.passed for r in results)
    total_fail = sum(r.failed for r in results)
    total_warn = sum(r.warned for r in results)
    total = sum(r.total for r in results)
    total_error = sum(r.errored for r in results)

    has_failures = total_fail > 0 or total_error > 0

    # Header
    _print_line("")
    _print_line("JMo Security Validation Report")
    _print_line("=" * 55)
    _print_line(
        f"Platform: {platform.system()} {platform.release()} | "
        f"Python: {platform.python_version()}"
    )
    _print_line("")

    # Categories
    for cat in results:
        status_str = _category_status(cat, use_color)
        _print_line(f"{cat.name:<40s} {status_str}")

        if verbose:
            for check in cat.checks:
                icon = _status_icon(check.status, use_color)
                msg = f"  {icon} {check.name}"
                if check.message:
                    msg += f" - {check.message}"
                _print_line(msg)
            _print_line("")

    # Summary
    _print_line("")
    _print_line("=" * 55)

    parts = [f"{total_pass}/{total} PASS"]
    if total_warn > 0:
        parts.append(f"{total_warn} WARN")
    if total_fail > 0:
        parts.append(f"{total_fail} FAIL")
    if total_error > 0:
        parts.append(f"{total_error} ERROR")

    _print_line(f"Result: {' | '.join(parts)}")

    if has_failures:
        verdict_display = _colorize("NO-GO", "red", use_color)
    else:
        verdict_display = _colorize("GO", "green", use_color)

    _print_line(f"Verdict: {verdict_display}")

    return 1 if has_failures else 0


def _category_status(cat: CategoryResult, use_color: bool) -> str:
    """Format category status like [12/12 PASS] or [10/12 FAIL]."""
    if cat.failed > 0 or cat.errored > 0:
        tag = _colorize(f"[{cat.passed}/{cat.total} FAIL]", "red", use_color)
    elif cat.warned > 0:
        tag = _colorize(f"[{cat.passed}/{cat.total} WARN]", "yellow", use_color)
    else:
        tag = _colorize(f"[{cat.passed}/{cat.total} PASS]", "green", use_color)
    return tag


def _status_icon(status: CheckStatus, use_color: bool) -> str:
    """Return a status icon for a single check."""
    icons = {
        CheckStatus.PASS: _colorize("v", "green", use_color),
        CheckStatus.FAIL: _colorize("X", "red", use_color),
        CheckStatus.WARN: _colorize("!", "yellow", use_color),
        CheckStatus.SKIP: "-",
        CheckStatus.ERROR: _colorize("E", "red", use_color),
    }
    return icons.get(status, "?")


def _colorize(text: str, color: str, use_color: bool) -> str:
    """Apply ANSI color if terminal supports it."""
    if not use_color:
        return text
    codes = {
        "red": "\033[0;31m",
        "green": "\033[0;32m",
        "yellow": "\033[1;33m",
    }
    code = codes.get(color, "")
    reset = "\033[0m"
    return f"{code}{text}{reset}"


def _supports_color() -> bool:
    """Check if terminal supports ANSI colors."""
    import os

    if not sys.stdout.isatty():
        return False
    if sys.platform == "win32":
        return bool(os.environ.get("TERM") or os.environ.get("WT_SESSION"))
    return True


def _print_line(text: str) -> None:
    """Print a line to stdout."""
    print(text)
