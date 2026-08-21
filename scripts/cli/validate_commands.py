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
    UnknownCategoryError,
    ValidatorFn,
    run_validators,
)

if TYPE_CHECKING:
    pass


def _get_validators() -> list[ValidatorFn]:
    """Return list of all validator functions.

    Lazy imports to keep jmo startup fast.

    Also injects the CLI surface into `cli_validator`. `scripts/core/` may not
    import `scripts.cli` (enforced by `scripts/dev/check_import_direction.py`),
    so the validator cannot fetch the parser itself -- but this module is in the
    CLI layer and can. Deriving it from the parser is what stops
    `MAIN_SUBCOMMANDS` drifting again (#783).
    """
    from scripts.cli.jmo import build_parser
    from scripts.core.validators.cli_validator import (
        derive_surface,
        set_cli_surface,
        validate_cli,
    )
    from scripts.core.validators.platform_validator import validate_platform
    from scripts.core.validators.release_validator import validate_release
    from scripts.core.validators.scan_validator import validate_scans

    set_cli_surface(*derive_surface(build_parser()))

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

    try:
        results = run_validators(
            validators=validators,
            tier=tier,
            fail_fast=fail_fast,
            categories=categories,
        )
    except UnknownCategoryError as exc:
        # Usage error, not a verdict. `--category` has no argparse `choices=`
        # because it is comma-separated, so this is where a typo is caught.
        print(f"Error: {exc}", file=sys.stderr)
        return 2

    return render_scorecard(
        results, verbose=verbose, json_output=json_output, tier=tier
    )


def render_scorecard(
    results: list[CategoryResult],
    verbose: bool = False,
    json_output: bool = False,
    tier: str = "quick",
) -> int:
    """Render validation results and return exit code.

    Args:
        results: List of CategoryResult from validators.
        verbose: Show per-check details.
        json_output: Output as JSON instead of terminal.
        tier: The tier that actually ran, for the report header.

    Returns:
        0 if all checks pass (GO), 1 if any failures (NO-GO).
    """
    if json_output:
        return _render_json(results, tier=tier)

    return _render_terminal(results, verbose=verbose, tier=tier)


def _render_json(results: list[CategoryResult], tier: str = "quick") -> int:
    """Render results as JSON to stdout."""
    total_pass = sum(r.passed for r in results)
    total_fail = sum(r.failed for r in results)
    total_warn = sum(r.warned for r in results)
    total_skip = sum(r.skipped for r in results)
    total_error = sum(r.errored for r in results)
    total = sum(r.total for r in results)

    has_failures = total_fail > 0 or total_error > 0 or total == 0
    verdict = "NO-GO" if has_failures else "GO"

    data = {
        "verdict": verdict,
        # Was hard-coded to "quick". `jmo validate --tier full --json` reported
        # `"tier": "quick"`, and this document is what release.yml consumes.
        "tier": tier,
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
                # `skipped` and `errored` were omitted, so the category rows did
                # not reconcile: passed + failed + warned < total whenever
                # anything skipped, with no key saying where the rest went.
                "skipped": r.skipped,
                "errored": r.errored,
                "total": r.total,
                "checks": [
                    {
                        "name": c.name,
                        "status": c.status.value,
                        "message": c.message,
                        # `details` is where the checks put the actionable part
                        # -- which file, which line. 28 checks populate it and
                        # nothing rendered it, in either output mode.
                        "details": c.details,
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


def _render_terminal(
    results: list[CategoryResult], verbose: bool, tier: str = "quick"
) -> int:
    """Render results as terminal scorecard."""
    use_color = _supports_color()

    total_pass = sum(r.passed for r in results)
    total_fail = sum(r.failed for r in results)
    total_warn = sum(r.warned for r in results)
    total = sum(r.total for r in results)
    total_error = sum(r.errored for r in results)
    total_skip = sum(r.skipped for r in results)

    # A run with no checks has no failures, so every "is anything wrong?" test
    # answered no and the verdict came out GO. `jmo validate --category bogus`
    # printed `0/0 PASS` / `Verdict: GO` and exited 0.
    has_failures = total_fail > 0 or total_error > 0 or total == 0

    # Header
    _print_line("")
    _print_line("JMo Security Validation Report")
    _print_line("=" * 55)
    _print_line(
        f"Platform: {platform.system()} {platform.release()} | "
        f"Python: {platform.python_version()} | Tier: {tier}"
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
                # `--verbose` promises "per-check details" and rendered only
                # `message`. The one thing that names the offending file lives
                # in `details`, and no output mode printed it -- so
                # `no-secret-patterns` reported "Potential secrets in 1 file(s)"
                # and the filename existed nowhere the user could reach.
                if check.details:
                    for line in str(check.details).splitlines():
                        _print_line(f"      {line}")
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
    # SKIP was absent from this line until #773, so the checks between
    # total_pass and total were simply unaccounted for -- `270/283 PASS |
    # 5 WARN` with no hint where the other 8 went. The JSON renderer has always
    # reported `skipped`; only the terminal scorecard dropped it.
    if total_skip > 0:
        parts.append(f"{total_skip} SKIP")

    _print_line(f"Result: {' | '.join(parts)}")

    if has_failures:
        verdict_display = _colorize("NO-GO", "red", use_color)
    else:
        verdict_display = _colorize("GO", "green", use_color)

    _print_line(f"Verdict: {verdict_display}")

    if total == 0:
        _print_line("  (no checks ran - a verdict over zero checks is never GO)")

    # A GO says nothing about checks that never ran, and `--tier full` degrades
    # quietly when a prerequisite is missing: with no Docker daemon all four
    # docker-build-* checks SKIP, so a green verdict can coexist with zero
    # images built. Say that where the verdict is read rather than leaving it
    # to be inferred from the rows above.
    if not has_failures and total_skip > 0:
        _print_line(f"  ({total_skip} check(s) skipped - GO covers only what ran)")

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
