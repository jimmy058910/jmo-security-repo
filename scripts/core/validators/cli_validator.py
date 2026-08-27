"""CLI Completeness validator for the jmo validate system.

Exercises every CLI subcommand, sub-subcommand, argument, and exit-code
contract to verify the CLI surface area is intact.

Check counts are derived, not fixed: the --help groups come from the parser, so
adding a subcommand adds checks. Measured on the current surface (20 top-level
subcommands, 47 nested): 101 quick-tier, 109 with --tier full.

`tests/core/test_cli_validator.py` recomputes these from the parser rather than
restating them, so the numbers above cannot drift silently the way the previous
"~37 / ~45" did.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
from collections.abc import Callable

from scripts.core.validators import (
    CategoryResult,
    CheckResult,
    CheckStatus,
    timed_check,
)

# ---------------------------------------------------------------------------
# CLI surface-area definitions
# ---------------------------------------------------------------------------


def derive_surface(
    parser: argparse.ArgumentParser,
) -> tuple[list[str], dict[str, list[str]]]:
    """Read the CLI surface off a real parser: (top-level, parent -> children).

    These two structures used to be hand-maintained lists. ``MAIN_SUBCOMMANDS``
    had drifted to **13 of 20** top-level subcommands (#783) -- `adapters`,
    `attest`, `balanced`, `fast`, `full`, `setup` and `verify` were never added
    -- and `tests/core/test_cli_validator.py` restated the same 13 as its
    expected set, so the suite agreed with the drift instead of catching it.

    A restated list cannot notice a subcommand nobody added it to. Walking the
    parser can, which is why `scripts.cli.jmo.build_parser` exists.

    This takes the parser as an argument rather than importing it:
    `scripts/dev/check_import_direction.py` forbids `scripts/core/` from
    importing `scripts.cli`, at any indentation, so the CLI layer injects it
    via `set_cli_surface`.
    """
    top = next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))
    main = sorted(top.choices)

    nested: dict[str, list[str]] = {}
    for name, subparser in top.choices.items():
        child = next(
            (
                a
                for a in subparser._actions
                if isinstance(a, argparse._SubParsersAction)
            ),
            None,
        )
        if child is not None:
            nested[name] = sorted(child.choices)
    return main, nested


# Top-level subcommands that must accept --help, and the parent -> child map.
# `None` until the CLI layer injects; deliberately not an empty list, because an
# empty surface would generate zero --help checks and a category that skipped
# every check it exists to run would still report PASS. See `validate_cli`.
_CLI_SURFACE: tuple[list[str], dict[str, list[str]]] | None = None


def set_cli_surface(main: list[str], nested: dict[str, list[str]]) -> None:
    """Inject the CLI surface derived from the real parser."""
    global _CLI_SURFACE
    _CLI_SURFACE = (main, nested)


# Commands that require arguments (run without args -> exit code 2)
REQUIRED_ARG_COMMANDS: list[tuple[list[str], str]] = [
    (["history", "show"], "history show needs scan_id"),
    (["history", "query"], "history query needs SQL query"),
    (["history", "diff"], "history diff needs two scan_ids"),
    (["policy", "validate"], "policy validate needs policy name"),
    (["policy", "test"], "policy test needs policy name"),
    (["policy", "show"], "policy show needs policy name"),
    (["policy", "install"], "policy install needs policy name"),
    (["schedule", "create"], "schedule create needs --name/--cron/--profile"),
    (["schedule", "get"], "schedule get needs name"),
    (["schedule", "delete"], "schedule delete needs name"),
    (["schedule", "export"], "schedule export needs name"),
    (["trends", "show"], "trends show needs scan_id"),
    (["trends", "compare"], "trends compare needs two scan_ids"),
]

# Commands to test invalid-arg rejection (--nonexistent-flag -> exit code 2)
INVALID_FLAG_COMMANDS: list[tuple[list[str], str]] = [
    (["scan"], "scan rejects unknown flags"),
    (["report"], "report rejects unknown flags"),
    (["tools"], "tools rejects unknown flags"),
    (["history"], "history rejects unknown flags"),
    (["build"], "build rejects unknown flags"),
    (["validate"], "validate rejects unknown flags"),
]

# Mutually exclusive groups: (args, description)
MUTUALLY_EXCLUSIVE: list[tuple[list[str], str]] = [
    (
        ["scan", "--repo", ".", "--repos-dir", "somedir"],
        "scan --repo vs --repos-dir are mutually exclusive",
    ),
    (
        ["scan", "--resume", "--no-resume"],
        "scan --resume vs --no-resume are mutually exclusive",
    ),
]

# Flag type validation: (args, description)
FLAG_TYPE_CHECKS: list[tuple[list[str], str]] = [
    (["scan", "--threads", "abc"], "scan --threads rejects non-integer"),
    (["scan", "--timeout", "abc"], "scan --timeout rejects non-integer"),
    (["report", "--threads", "abc"], "report --threads rejects non-integer"),
    (
        ["history", "list", "--limit", "abc"],
        "history list --limit rejects non-integer",
    ),
    (
        ["trends", "analyze", "--days", "abc"],
        "trends analyze --days rejects non-integer",
    ),
    (
        ["trends", "analyze", "--last", "abc"],
        "trends analyze --last rejects non-integer",
    ),
]


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _run_jmo(*args: str, timeout: int = 30) -> subprocess.CompletedProcess:
    """Run jmo CLI command in subprocess.

    `errors="replace"` rather than bare `text=True`: the decode happens in
    subprocess's reader thread, where a `UnicodeDecodeError` is raised and then
    swallowed, leaving `stdout` silently truncated. Several checks below now
    treat empty output as a failure, so a swallowed decode error would surface
    as a spurious FAIL naming the wrong cause.

    The codec used to be left as the locale default, because pinning the parent
    to UTF-8 without also pinning the child's `PYTHONIOENCODING` turns a clean
    cp1252 round-trip into mojibake. Both ends are pinned here now, which is the
    condition that note named (#963). Only `PYTHONIOENCODING` is set, not
    `PYTHONUTF8` -- the latter would also change the child's *file* handling,
    and this validator exists to observe how the real CLI behaves, not to hand
    it an environment no user has.
    """
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env={**os.environ, "PYTHONIOENCODING": "utf-8"},
        timeout=timeout,
    )


def _help_check(cmd_args: list[str]) -> Callable[[], CheckResult | None]:
    """Return a check function that runs ``jmo <cmd_args> --help``."""
    label = " ".join(cmd_args)

    def _check() -> CheckResult | None:
        try:
            result = _run_jmo(*cmd_args, "--help")
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"help: {label}",
                status=CheckStatus.ERROR,
                message="Timed out running --help",
            )
        if result.returncode == 0:
            return CheckResult(
                name=f"help: {label}",
                status=CheckStatus.PASS,
                message="Exit 0, help text returned",
            )
        return CheckResult(
            name=f"help: {label}",
            status=CheckStatus.FAIL,
            message=f"Exit {result.returncode}: {result.stderr[:200]}",
        )

    return _check


def _required_arg_check(
    cmd_args: list[str], description: str
) -> Callable[[], CheckResult | None]:
    """Return a check that verifies missing-arg enforcement (exit 2)."""

    def _check() -> CheckResult | None:
        try:
            result = _run_jmo(*cmd_args)
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"required-arg: {description}",
                status=CheckStatus.ERROR,
                message="Timed out",
            )
        if result.returncode == 2:
            return CheckResult(
                name=f"required-arg: {description}",
                status=CheckStatus.PASS,
                message="Exit 2 as expected for missing required arg",
            )
        return CheckResult(
            name=f"required-arg: {description}",
            status=CheckStatus.FAIL,
            message=f"Expected exit 2, got {result.returncode}",
        )

    return _check


def _invalid_flag_check(
    cmd_args: list[str], description: str
) -> Callable[[], CheckResult | None]:
    """Return a check that verifies unknown-flag rejection (exit 2)."""

    def _check() -> CheckResult | None:
        try:
            result = _run_jmo(*cmd_args, "--nonexistent-flag-xyz")
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"invalid-flag: {description}",
                status=CheckStatus.ERROR,
                message="Timed out",
            )
        if result.returncode == 2:
            return CheckResult(
                name=f"invalid-flag: {description}",
                status=CheckStatus.PASS,
                message="Exit 2 as expected for unknown flag",
            )
        return CheckResult(
            name=f"invalid-flag: {description}",
            status=CheckStatus.FAIL,
            message=f"Expected exit 2, got {result.returncode}",
        )

    return _check


def _mutex_check(
    cmd_args: list[str], description: str
) -> Callable[[], CheckResult | None]:
    """Return a check that verifies mutually-exclusive arg rejection."""

    def _check() -> CheckResult | None:
        try:
            result = _run_jmo(*cmd_args)
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"mutex: {description}",
                status=CheckStatus.ERROR,
                message="Timed out",
            )
        if result.returncode == 2:
            return CheckResult(
                name=f"mutex: {description}",
                status=CheckStatus.PASS,
                message="Exit 2 as expected for mutually exclusive args",
            )
        return CheckResult(
            name=f"mutex: {description}",
            status=CheckStatus.FAIL,
            message=f"Expected exit 2, got {result.returncode}",
        )

    return _check


def _type_check(
    cmd_args: list[str], description: str
) -> Callable[[], CheckResult | None]:
    """Return a check that verifies type-validation rejection (exit 2)."""

    def _check() -> CheckResult | None:
        try:
            result = _run_jmo(*cmd_args)
        except subprocess.TimeoutExpired:
            return CheckResult(
                name=f"type-check: {description}",
                status=CheckStatus.ERROR,
                message="Timed out",
            )
        if result.returncode == 2:
            return CheckResult(
                name=f"type-check: {description}",
                status=CheckStatus.PASS,
                message="Exit 2 as expected for invalid type",
            )
        return CheckResult(
            name=f"type-check: {description}",
            status=CheckStatus.FAIL,
            message=f"Expected exit 2, got {result.returncode}",
        )

    return _check


# ---------------------------------------------------------------------------
# Version / identity checks
# ---------------------------------------------------------------------------


def _check_version_flag() -> CheckResult | None:
    """Verify jmo --version exits 0."""
    try:
        result = _run_jmo("--version")
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="version: --version exits 0",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode != 0:
        return CheckResult(
            name="version: --version exits 0",
            status=CheckStatus.FAIL,
            message=f"Exit {result.returncode}",
        )
    return CheckResult(
        name="version: --version exits 0",
        status=CheckStatus.PASS,
        message=f"Output: {result.stdout.strip()[:80]}",
    )


def _check_version_matches_pyproject() -> CheckResult | None:
    """Verify --version output matches pyproject.toml version."""
    try:
        result = _run_jmo("--version")
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="version: matches pyproject.toml",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    output = result.stdout.strip()
    # Read pyproject.toml version
    try:
        import tomllib
        from pathlib import Path

        # Walk up from scripts/core/validators to find pyproject.toml
        here = Path(__file__).resolve()
        project_root = here.parent.parent.parent.parent
        pyproject_path = project_root / "pyproject.toml"
        if not pyproject_path.exists():
            return CheckResult(
                name="version: matches pyproject.toml",
                status=CheckStatus.SKIP,
                message="pyproject.toml not found",
            )
        with open(pyproject_path, "rb") as f:
            data = tomllib.load(f)
        expected = data.get("project", {}).get("version", "")
        if expected and expected in output:
            return CheckResult(
                name="version: matches pyproject.toml",
                status=CheckStatus.PASS,
                message=f"Version {expected} found in output",
            )
        return CheckResult(
            name="version: matches pyproject.toml",
            status=CheckStatus.FAIL,
            message=f"Expected '{expected}' in '{output}'",
        )
    except Exception as exc:
        return CheckResult(
            name="version: matches pyproject.toml",
            status=CheckStatus.ERROR,
            message=str(exc),
        )


def _check_version_semver_format() -> CheckResult | None:
    """Verify --version output contains valid semver."""
    try:
        result = _run_jmo("--version")
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="version: semver format",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    output = result.stdout.strip()
    # Match semver pattern (major.minor.patch with optional pre-release)
    pattern = r"\d+\.\d+\.\d+(-[a-zA-Z0-9.]+)?"
    if re.search(pattern, output):
        return CheckResult(
            name="version: semver format",
            status=CheckStatus.PASS,
            message=f"Semver found in: {output[:80]}",
        )
    return CheckResult(
        name="version: semver format",
        status=CheckStatus.FAIL,
        message=f"No semver pattern in: {output[:80]}",
    )


# ---------------------------------------------------------------------------
# Exit-code contract checks
# ---------------------------------------------------------------------------


def _check_help_exit_zero() -> CheckResult | None:
    """Verify --help exits 0."""
    try:
        result = _run_jmo("--help")
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="exit-code: --help returns 0",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 0:
        return CheckResult(
            name="exit-code: --help returns 0",
            status=CheckStatus.PASS,
        )
    return CheckResult(
        name="exit-code: --help returns 0",
        status=CheckStatus.FAIL,
        message=f"Exit {result.returncode}",
    )


def _check_missing_subcommand_exit_two() -> CheckResult | None:
    """Verify running jmo with no subcommand exits 2."""
    try:
        result = _run_jmo()
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="exit-code: no subcommand returns 2",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 2:
        return CheckResult(
            name="exit-code: no subcommand returns 2",
            status=CheckStatus.PASS,
        )
    return CheckResult(
        name="exit-code: no subcommand returns 2",
        status=CheckStatus.FAIL,
        message=f"Exit {result.returncode}, expected 2",
    )


def _check_bad_subcommand_exit_two() -> CheckResult | None:
    """Verify running jmo with invalid subcommand exits 2."""
    try:
        result = _run_jmo("nonexistent-subcommand-xyz")
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="exit-code: bad subcommand returns 2",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 2:
        return CheckResult(
            name="exit-code: bad subcommand returns 2",
            status=CheckStatus.PASS,
        )
    return CheckResult(
        name="exit-code: bad subcommand returns 2",
        status=CheckStatus.FAIL,
        message=f"Exit {result.returncode}, expected 2",
    )


def _check_scan_help_mentions_repo() -> CheckResult | None:
    """Verify scan --help mentions --repo flag."""
    try:
        result = _run_jmo("scan", "--help")
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="exit-code: scan --help mentions --repo",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if "--repo" in result.stdout:
        return CheckResult(
            name="exit-code: scan --help mentions --repo",
            status=CheckStatus.PASS,
        )
    return CheckResult(
        name="exit-code: scan --help mentions --repo",
        status=CheckStatus.FAIL,
        message="--repo not found in scan --help output",
    )


# ---------------------------------------------------------------------------
# Full-tier checks (exercise real commands, not just parsing)
# ---------------------------------------------------------------------------


# `jmo tools check` probes all 29 registry entries. Measured standalone on a
# Windows box with the tools actually installed: 49s cold, 33s warm. The bound
# here was 60s -- 1.22x the cold run -- and this validator is itself the load,
# spawning subprocess checks throughout, so the check ERRORed and `--tier full`
# reported NO-GO (#773). Same shape as #748, where a bound with 1.03-1.36x
# headroom passed on a machine with no tools installed and failed on one that
# had them. Sized at ~3.7x the cold measurement instead.
_TOOLS_CHECK_TIMEOUT = 180


def _full_tools_check() -> CheckResult | None:
    """Run 'jmo tools check' and verify it completes."""
    try:
        result = _run_jmo("tools", "check", timeout=_TOOLS_CHECK_TIMEOUT)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: tools check",
            status=CheckStatus.ERROR,
            message=f"Timed out ({_TOOLS_CHECK_TIMEOUT}s)",
        )
    # tools check may return non-zero if tools are missing, but it must produce
    # a report either way. Exit 1 alone is not evidence it ran -- an early crash
    # exits 1 with nothing on stdout -- so the output is part of the assertion
    # rather than only part of the message.
    if not result.stdout.strip():
        return CheckResult(
            name="full: tools check",
            status=CheckStatus.FAIL,
            message=f"Exit {result.returncode} with no output",
            details=result.stderr[:400],
        )
    if result.returncode in (0, 1):
        return CheckResult(
            name="full: tools check",
            status=CheckStatus.PASS,
            message=f"Exit {result.returncode}, output len={len(result.stdout)}",
        )
    return CheckResult(
        name="full: tools check",
        status=CheckStatus.FAIL,
        message=f"Unexpected exit {result.returncode}",
    )


def _full_tools_list_profiles() -> CheckResult | None:
    """Run 'jmo tools list --profiles' and verify output."""
    try:
        result = _run_jmo("tools", "list", "--profiles", timeout=30)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: tools list --profiles",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 0 and len(result.stdout) > 0:
        return CheckResult(
            name="full: tools list --profiles",
            status=CheckStatus.PASS,
            message=f"Output len={len(result.stdout)}",
        )
    return CheckResult(
        name="full: tools list --profiles",
        status=CheckStatus.FAIL,
        message=f"Exit {result.returncode}, stdout len={len(result.stdout)}",
    )


def _full_adapters_list() -> CheckResult | None:
    """Run 'jmo adapters list' and verify output."""
    try:
        result = _run_jmo("adapters", "list", timeout=30)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: adapters list",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 0 and len(result.stdout) > 0:
        return CheckResult(
            name="full: adapters list",
            status=CheckStatus.PASS,
            message=f"Output len={len(result.stdout)}",
        )
    return CheckResult(
        name="full: adapters list",
        status=CheckStatus.FAIL,
        message=f"Exit {result.returncode}",
    )


def _full_history_stats() -> CheckResult | None:
    """Run 'jmo history stats' and verify it completes."""
    try:
        result = _run_jmo("history", "stats", timeout=30)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: history stats",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    # May return 0 or 1 depending on db existence, but must say something either
    # way -- see the note on `full: tools check`.
    if not (result.stdout.strip() or result.stderr.strip()):
        return CheckResult(
            name="full: history stats",
            status=CheckStatus.FAIL,
            message=f"Exit {result.returncode} with no output",
        )
    if result.returncode in (0, 1):
        return CheckResult(
            name="full: history stats",
            status=CheckStatus.PASS,
            message=f"Exit {result.returncode}",
        )
    return CheckResult(
        name="full: history stats",
        status=CheckStatus.FAIL,
        message=f"Unexpected exit {result.returncode}",
    )


def _full_build_validate() -> CheckResult | None:
    """Run 'jmo build validate' and verify it reached the repository.

    This check accepted `returncode in (0, 1)` and reported PASS. `jmo build`
    had been unable to locate the repository root since #303 renamed
    `Dockerfile` to `Dockerfile.deep` -- every invocation exited 1 -- and this
    check reported PASS on every one of them, across seven releases.

    Exit 1 is still legitimate here (version validation can fail without a
    `GITHUB_TOKEN`, and Docker may be absent), so the exit code alone cannot
    separate the two. The discriminator is whether the command got far enough
    to print the repository root: both failure modes above exit *before* that
    line, and every real outcome prints it.
    """
    try:
        result = _run_jmo("build", "validate", timeout=60)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: build validate",
            status=CheckStatus.ERROR,
            message="Timed out (60s)",
        )
    combined = result.stdout + result.stderr
    if "Docker not found" in combined or "Docker daemon not running" in combined:
        return CheckResult(
            name="full: build validate",
            status=CheckStatus.SKIP,
            message="Docker not available",
        )
    if "Repository root:" not in combined:
        return CheckResult(
            name="full: build validate",
            status=CheckStatus.FAIL,
            message=f"Exit {result.returncode}, never located the repository root",
            details=combined[:400],
        )
    if result.returncode in (0, 1):
        return CheckResult(
            name="full: build validate",
            status=CheckStatus.PASS,
            message=f"Exit {result.returncode}, repository root located",
        )
    return CheckResult(
        name="full: build validate",
        status=CheckStatus.FAIL,
        message=f"Unexpected exit {result.returncode}",
    )


def _full_policy_list() -> CheckResult | None:
    """Run 'jmo policy list' and verify it completes."""
    try:
        result = _run_jmo("policy", "list", timeout=30)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: policy list",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 0:
        return CheckResult(
            name="full: policy list",
            status=CheckStatus.PASS,
            message=f"Output len={len(result.stdout)}",
        )
    return CheckResult(
        name="full: policy list",
        status=CheckStatus.FAIL,
        message=f"Exit {result.returncode}",
    )


def _full_trends_explain() -> CheckResult | None:
    """Run 'jmo trends explain' and verify it completes."""
    try:
        result = _run_jmo("trends", "explain", timeout=30)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: trends explain",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 0:
        return CheckResult(
            name="full: trends explain",
            status=CheckStatus.PASS,
            message=f"Output len={len(result.stdout)}",
        )
    return CheckResult(
        name="full: trends explain",
        status=CheckStatus.FAIL,
        message=f"Exit {result.returncode}",
    )


def _full_diff_auto() -> CheckResult | None:
    """Run 'jmo diff --auto' and verify it parsed and ran.

    This accepted `returncode in (0, 1, 2)`, which includes **2** -- argparse's
    usage error. A check that accepts 2 still passes when the flag it exists to
    exercise has been deleted from the parser, so it could only ever fail on a
    hard crash. 2 is now a FAIL; 0 and 1 remain legitimate, because `--auto`
    reports a real verdict on whether it found two scans to compare.
    """
    try:
        result = _run_jmo("diff", "--auto", timeout=30)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: diff --auto",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    if result.returncode == 2:
        return CheckResult(
            name="full: diff --auto",
            status=CheckStatus.FAIL,
            message="Exit 2 - `diff --auto` was rejected as a usage error",
            details=result.stderr[:400],
        )
    if result.returncode in (0, 1):
        return CheckResult(
            name="full: diff --auto",
            status=CheckStatus.PASS,
            message=f"Exit {result.returncode} (ran; 1 is valid without two scans)",
        )
    return CheckResult(
        name="full: diff --auto",
        status=CheckStatus.FAIL,
        message=f"Unexpected exit {result.returncode}",
    )


# ---------------------------------------------------------------------------
# Main validator entry point
# ---------------------------------------------------------------------------

# Count constants for testing. Deliberately no literal in a trailing comment:
# `_MAIN_HELP_COUNT = len(MAIN_SUBCOMMANDS)  # 13` was correct arithmetic over a
# stale list, and the comment is what made the staleness look intentional.
_INVALID_FLAG_COUNT = len(INVALID_FLAG_COMMANDS)
_REQUIRED_ARG_COUNT = len(REQUIRED_ARG_COMMANDS)
_MUTEX_COUNT = len(MUTUALLY_EXCLUSIVE)
_TYPE_CHECK_COUNT = len(FLAG_TYPE_CHECKS)
_VERSION_CHECK_COUNT = 3
_EXIT_CODE_COUNT = 4
_FULL_TIER_COUNT = 8

# Everything except the --help groups, which are sized by the parser.
_FIXED_QUICK_COUNT = (
    _REQUIRED_ARG_COUNT
    + _INVALID_FLAG_COUNT
    + _MUTEX_COUNT
    + _TYPE_CHECK_COUNT
    + _VERSION_CHECK_COUNT
    + _EXIT_CODE_COUNT
)


def validate_cli(tier: str) -> CategoryResult:
    """CLI Completeness validator. Returns CategoryResult with name='CLI Completeness'.

    Args:
        tier: "quick" or "full". Quick tier exercises CLI parsing only.
              Full tier adds live tool invocations.

    Returns:
        CategoryResult with all check results.
    """
    checks: list[CheckResult] = []

    if _CLI_SURFACE is None:
        # Not a skip. A category that quietly produced zero --help checks would
        # still report `[0/0 PASS]`, which is the exact failure mode this
        # validator exists to catch elsewhere.
        return CategoryResult(
            name="CLI Completeness",
            checks=[
                CheckResult(
                    name="cli-surface: injected",
                    status=CheckStatus.ERROR,
                    message="CLI surface was never injected; no subcommand was checked",
                    details=(
                        "scripts.cli.validate_commands must call "
                        "cli_validator.set_cli_surface(*derive_surface(build_parser()))"
                    ),
                )
            ],
        )

    main_subcommands, sub_subcommands = _CLI_SURFACE

    # ---- Group 1: Main subcommand --help (one per parser subcommand) ----
    for cmd in main_subcommands:
        check_fn = _help_check([cmd])
        checks.append(timed_check(f"help: {cmd}", check_fn))

    # ---- Group 2: Sub-subcommand --help ----
    for parent, children in sub_subcommands.items():
        for child in children:
            check_fn = _help_check([parent, child])
            checks.append(timed_check(f"help: {parent} {child}", check_fn))

    # ---- Group 3: Required arg enforcement ----
    for cmd_args, description in REQUIRED_ARG_COMMANDS:
        check_fn = _required_arg_check(cmd_args, description)
        checks.append(timed_check(f"required-arg: {description}", check_fn))

    # ---- Group 4: Invalid flag rejection ----
    for cmd_args, description in INVALID_FLAG_COMMANDS:
        check_fn = _invalid_flag_check(cmd_args, description)
        checks.append(timed_check(f"invalid-flag: {description}", check_fn))

    # ---- Group 5: Mutually exclusive groups ----
    for cmd_args, description in MUTUALLY_EXCLUSIVE:
        check_fn = _mutex_check(cmd_args, description)
        checks.append(timed_check(f"mutex: {description}", check_fn))

    # ---- Group 6: Flag type validation ----
    for cmd_args, description in FLAG_TYPE_CHECKS:
        check_fn = _type_check(cmd_args, description)
        checks.append(timed_check(f"type-check: {description}", check_fn))

    # ---- Group 7: Version/identity (3 checks) ----
    checks.append(timed_check("version: --version exits 0", _check_version_flag))
    checks.append(
        timed_check("version: matches pyproject.toml", _check_version_matches_pyproject)
    )
    checks.append(timed_check("version: semver format", _check_version_semver_format))

    # ---- Group 8: Exit code contracts (4 checks) ----
    checks.append(timed_check("exit-code: --help returns 0", _check_help_exit_zero))
    checks.append(
        timed_check(
            "exit-code: no subcommand returns 2", _check_missing_subcommand_exit_two
        )
    )
    checks.append(
        timed_check(
            "exit-code: bad subcommand returns 2", _check_bad_subcommand_exit_two
        )
    )
    checks.append(
        timed_check(
            "exit-code: scan --help mentions --repo", _check_scan_help_mentions_repo
        )
    )

    # ---- Full tier: live tool invocations (8 additional checks) ----
    if tier == "full":
        checks.append(timed_check("full: tools check", _full_tools_check))
        checks.append(
            timed_check("full: tools list --profiles", _full_tools_list_profiles)
        )
        checks.append(timed_check("full: adapters list", _full_adapters_list))
        checks.append(timed_check("full: history stats", _full_history_stats))
        checks.append(timed_check("full: build validate", _full_build_validate))
        checks.append(timed_check("full: policy list", _full_policy_list))
        checks.append(timed_check("full: trends explain", _full_trends_explain))
        checks.append(timed_check("full: diff --auto", _full_diff_auto))

    return CategoryResult(name="CLI Completeness", checks=checks)
