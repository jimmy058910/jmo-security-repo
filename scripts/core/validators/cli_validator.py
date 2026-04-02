"""CLI Completeness validator for the jmo validate system.

Exercises every CLI subcommand, sub-subcommand, argument, and exit-code
contract to verify the CLI surface area is intact.

Quick tier: ~37 checks (--help, arg enforcement, flag validation, version)
Full tier:  ~45 checks (adds live tool invocations)
"""

from __future__ import annotations

import re
import subprocess
import sys
from typing import Callable

from scripts.core.validators import (
    CategoryResult,
    CheckResult,
    CheckStatus,
    timed_check,
)

# ---------------------------------------------------------------------------
# CLI surface-area definitions
# ---------------------------------------------------------------------------

# Top-level subcommands that must accept --help
MAIN_SUBCOMMANDS: list[str] = [
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
]

# Nested subcommands: parent -> list of child subcommands
SUB_SUBCOMMANDS: dict[str, list[str]] = {
    "tools": [
        "check",
        "install",
        "list",
        "clean",
        "debug",
        "update",
        "outdated",
        "uninstall",
    ],
    "history": [
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
    ],
    "build": [
        "validate",
        "test",
    ],
    "policy": [
        "list",
        "validate",
        "test",
        "show",
        "install",
    ],
    "schedule": [
        "create",
        "list",
        "get",
        "update",
        "export",
        "install",
        "uninstall",
        "delete",
        "validate",
    ],
    "trends": [
        "analyze",
        "show",
        "regressions",
        "score",
        "compare",
        "insights",
        "explain",
        "developers",
    ],
    "adapters": [
        "list",
        "validate",
    ],
}

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
    """Run jmo CLI command in subprocess."""
    return subprocess.run(
        [sys.executable, "-m", "scripts.cli.jmo", *args],
        capture_output=True,
        text=True,
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


def _full_tools_check() -> CheckResult | None:
    """Run 'jmo tools check' and verify it completes."""
    try:
        result = _run_jmo("tools", "check", timeout=60)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: tools check",
            status=CheckStatus.ERROR,
            message="Timed out (60s)",
        )
    # tools check may return non-zero if tools are missing, but
    # it should at least produce output and not crash
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
    # May return 0 or 1 depending on db existence
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
    """Run 'jmo build validate' and verify it completes."""
    try:
        result = _run_jmo("build", "validate", timeout=60)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: build validate",
            status=CheckStatus.ERROR,
            message="Timed out (60s)",
        )
    # build validate may fail without GITHUB_TOKEN, that's acceptable
    if result.returncode in (0, 1):
        return CheckResult(
            name="full: build validate",
            status=CheckStatus.PASS,
            message=f"Exit {result.returncode}",
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
    """Run 'jmo diff --auto' and verify it completes (may fail without git context)."""
    try:
        result = _run_jmo("diff", "--auto", timeout=30)
    except subprocess.TimeoutExpired:
        return CheckResult(
            name="full: diff --auto",
            status=CheckStatus.ERROR,
            message="Timed out",
        )
    # diff --auto may return non-zero without proper git context
    if result.returncode in (0, 1, 2):
        return CheckResult(
            name="full: diff --auto",
            status=CheckStatus.PASS,
            message=f"Exit {result.returncode} (acceptable without git context)",
        )
    return CheckResult(
        name="full: diff --auto",
        status=CheckStatus.FAIL,
        message=f"Unexpected exit {result.returncode}",
    )


# ---------------------------------------------------------------------------
# Main validator entry point
# ---------------------------------------------------------------------------

# Count constants for testing
_MAIN_HELP_COUNT = len(MAIN_SUBCOMMANDS)  # 13
_INVALID_FLAG_COUNT = len(INVALID_FLAG_COMMANDS)  # 6
_REQUIRED_ARG_COUNT = len(REQUIRED_ARG_COMMANDS)  # 13
_MUTEX_COUNT = len(MUTUALLY_EXCLUSIVE)  # 2
_TYPE_CHECK_COUNT = len(FLAG_TYPE_CHECKS)  # 6
_VERSION_CHECK_COUNT = 3
_EXIT_CODE_COUNT = 4
_FULL_TIER_COUNT = 8

# Sub-subcommand count (varies with actual CLI surface)
_SUB_SUBCOMMAND_COUNT = sum(len(v) for v in SUB_SUBCOMMANDS.values())


def validate_cli(tier: str) -> CategoryResult:
    """CLI Completeness validator. Returns CategoryResult with name='CLI Completeness'.

    Args:
        tier: "quick" or "full". Quick tier exercises CLI parsing only.
              Full tier adds live tool invocations.

    Returns:
        CategoryResult with all check results.
    """
    checks: list[CheckResult] = []

    # ---- Group 1: Main subcommand --help (13 checks) ----
    for cmd in MAIN_SUBCOMMANDS:
        check_fn = _help_check([cmd])
        checks.append(timed_check(f"help: {cmd}", check_fn))

    # ---- Group 2: Sub-subcommand --help ----
    for parent, children in SUB_SUBCOMMANDS.items():
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
