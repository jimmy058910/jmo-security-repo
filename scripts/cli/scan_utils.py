"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any

# Re-export from core for backward compatibility.
# find_tool/tool_exists live in scripts.core.tool_utils to maintain clean
# dependency layering (core never imports from cli).
from scripts.core.tool_utils import (  # noqa: F401
    TOOL_INSTALL_HINTS,
    clear_tool_warnings,
    find_tool,
    tool_exists,
)

if TYPE_CHECKING:  # pragma: no cover - annotation only
    # Deferred: core must stay importable without cli, and this is the only
    # reference to it here.
    from scripts.core.tool_runner import ToolResult


def _run_inline_tool_update(drift_list: list[dict]) -> bool:
    """Run tool updates inline during wizard flow.

    Args:
        drift_list: List of drift dicts with 'tool' key for tools to update

    Returns:
        True if updates succeeded, False otherwise
    """
    if not drift_list:
        return True

    try:
        from scripts.cli.tool_installer import ToolInstaller

        installer = ToolInstaller()

        tools_to_update = [d["tool"] for d in drift_list]
        total = len(tools_to_update)
        success_count = 0
        fail_count = 0

        for i, tool_name in enumerate(tools_to_update, 1):
            print(f"  [{i}/{total}] Updating {tool_name}...", end=" ", flush=True)
            result = installer.install_tool(tool_name, force=True)
            if result.success:
                print(f"OK ({result.version_installed or 'installed'})")
                success_count += 1
            else:
                print(f"FAILED ({result.message})")
                fail_count += 1

        print(f"\nUpdate complete: {success_count} succeeded, {fail_count} failed")
        return fail_count == 0

    except Exception as e:
        logging.getLogger(__name__).error(f"Update failed: {e}")
        return False


def check_version_drift_before_scan(
    profile: str,
    interactive: bool = False,
) -> bool:
    """
    Pre-scan version check with context-aware behavior.

    Checks for version drift between installed tool versions and the pinned
    versions in versions.yaml. Behavior adapts based on context:
    - CLI mode (interactive=False): Log warning, continue
    - Wizard mode (interactive=True): Prompt user before continuing

    Args:
        profile: Scan profile ('fast', 'slim', 'balanced', 'deep')
        interactive: Whether to prompt user for confirmation

    Returns:
        True if scan should proceed, False if user cancelled in interactive mode
    """
    # Import here to avoid circular dependency
    from scripts.cli.tool_manager import ToolManager

    logger = logging.getLogger(__name__)
    manager = ToolManager()
    drift = manager.get_version_drift(profile)

    if not drift:
        return True  # All versions match

    # Categorize drift by direction
    ahead = [d for d in drift if d.get("direction") == "ahead"]
    behind = [d for d in drift if d.get("direction") == "behind"]
    unknown = [d for d in drift if d.get("direction") == "unknown"]

    # Log categorized drift
    if ahead:
        logger.info(
            f"{len(ahead)} tool(s) AHEAD of expected (newer versions installed):"
        )
        for d in ahead:
            logger.info(f"  {d['tool']}: {d['installed']} > {d['expected']}")

    if behind:
        level = logging.WARNING
        critical_behind = [d for d in behind if d["critical"]]
        if critical_behind:
            level = logging.ERROR
        logger.log(
            level, f"{len(behind)} tool(s) BEHIND expected (update recommended):"
        )
        for d in behind:
            marker = " [CRITICAL]" if d["critical"] else ""
            logger.log(
                level, f"  {d['tool']}: {d['installed']} < {d['expected']}{marker}"
            )

    if unknown:
        logger.warning(f"{len(unknown)} tool(s) with unknown version status:")
        for d in unknown:
            marker = " [CRITICAL]" if d["critical"] else ""
            # Clarify what "unknown" means
            if d["installed"] is None:
                status = "version detection failed"
            else:
                status = f"installed={d['installed']}"
            logger.warning(f"  {d['tool']}: {status} expected={d['expected']}{marker}")

    if interactive:
        # Wizard mode - improved display with consolidated info
        print(f"\n{'─' * 50}")
        print(f"Version Status ({len(drift)} tool(s) with differences):")

        if ahead:
            print(f"\n  ✓ {len(ahead)} ahead (newer installed - OK for security):")
            for d in ahead[:3]:
                print(f"    {d['tool']}: {d['installed']} > {d['expected']}")
            if len(ahead) > 3:
                print(f"    ... and {len(ahead) - 3} more")

        if behind:
            print(f"\n  ⚠ {len(behind)} behind (older - update recommended):")
            for d in behind:
                marker = " [CRITICAL]" if d["critical"] else ""
                print(f"    {d['tool']}: {d['installed']} < {d['expected']}{marker}")

        if unknown:
            print(f"\n  ? {len(unknown)} unknown (version detection failed):")
            for d in unknown:
                # Explain what unknown means
                explanation = (
                    "binary found, but --version parsing failed"
                    if d["installed"] is None
                    else f"got {d['installed']}"
                )
                print(f"    {d['tool']}: {explanation}")

        print(f"\n{'─' * 50}")

        # Only prompt if there are concerning issues (behind or critical unknown)
        critical_behind = [d for d in behind if d["critical"]]
        if not behind and not critical_behind:
            # Just ahead or unknown (non-critical) - auto-continue
            print("No critical version issues. Continuing with scan...")
            return True

        print("\nThis may affect scan reproducibility.\n")
        print("Options:")
        print("  [1] Continue anyway (recommended if versions are close)")
        print("  [2] Update outdated tools first")
        print("  [3] Cancel scan")

        try:
            choice = input("\nChoice [1]: ").strip() or "1"
            if choice == "3":
                print("Scan cancelled.")
                return False
            if choice == "2":
                # Run update inline and continue
                print("\nUpdating tools...")
                updated = _run_inline_tool_update(behind + unknown)
                if updated:
                    print("\nTools updated. Continuing with scan...\n")
                    return True
                else:
                    print(
                        "\nUpdate failed or cancelled. Continuing with current versions..."
                    )
                    return True
            # Default: continue
            print("Continuing with current tool versions...")
            return True
        except (KeyboardInterrupt, EOFError):
            print("\nScan cancelled.")
            return False
    else:
        # CLI mode - warn and continue
        if behind:
            logger.warning("Run 'jmo tools update' to synchronize versions")
        return True


# A tool's stderr is unbounded (semgrep and horusec are chatty). Keep the tail,
# where the fatal message is, rather than the head, where the banner is.
STDERR_TAIL_CHARS = 500


def report_tool_failure(result: ToolResult, reason: str) -> None:
    """State, on a durable stream, that a tool delivered no findings.

    Every scan job's results loop used to set ``statuses[tool] = False`` and
    discard ``result.error_message``. The only remaining trace was a ``x`` in
    the Rich progress display, which a non-TTY run - CI, cron, a detached scan -
    never renders at all. Measured on bridgecrewio/terragoat with the ``deep``
    profile: prowler, yara and dependency-check each failed leaving no record on
    any stream, while the scan exited 0 and the policy gate passed on the
    resulting empty finding set.

    Which tools land here is platform-dependent (dependency-check is silent on
    Windows and honest on Linux; noseyparker is the reverse), so this cannot be
    left to per-tool handling.

    It lives here, beside ``write_stub``, rather than as a private copy in each
    of the five scan jobs. Four modules each growing a private copy of one
    helper is the defect ``tests/cross_platform/test_encoding_drift_guard.py``
    exists to prevent; the reasoning is not specific to encoding.
    """
    logger = logging.getLogger(__name__)
    detail = result.error_message or f"status={result.status}"

    # error_message says what happened; stderr says why. For a non-zero exit it
    # is only "exited with return code 2", and ToolRunner captures the tool's
    # stderr into the result and nothing reads it - so the diagnosis is
    # collected and then dropped one line short of the log. yara exiting 2
    # writes "0 of 310 rule file(s) compiled - nothing was scanned" there;
    # without this the operator sees the code and never the cause.
    tail = (result.stderr or "").strip()
    if tail:
        if len(tail) > STDERR_TAIL_CHARS:
            tail = "..." + tail[-STDERR_TAIL_CHARS:]
        detail = f"{detail}; stderr: {tail}"

    logger.error(
        "%s: %s - it did NOT contribute findings to this scan (%s)",
        result.tool,
        reason,
        detail,
    )


# jmo.yml configures flags per *tool*, but trivy's flag surface is per
# *subcommand*, and JMo drives trivy with four of them (fs, image, config, k8s).
# Measured against trivy 0.70.0: `trivy config` is the only one that rejects
# --no-progress, and it rejects it fatally at argument parsing - so every IaC
# scan died before it started and contributed nothing. All four shipped profiles
# set that flag, so no profile escaped it.
#
# Only value-less flags belong here: dropping one must never orphan a value
# argument. --scanners is accepted by all four subcommands and is not listed.
TRIVY_UNSUPPORTED_FLAGS: dict[str, frozenset[str]] = {
    "config": frozenset({"--no-progress"}),
}


# Per-tool minimum timeouts (seconds) for tools that typically run long. A
# profile default may raise these but never lower them.
#
# Lived in repository_scanner.py, which is why only *repository* scans honoured
# it: the other four scanners had their own copy of `get_tool_timeout` with no
# floor at all. Measured consequence: `zap` carries a 900 s floor and also runs
# on `url` targets, so a `balanced` URL scan gave it the profile's 600 s -- 300 s
# short, a third of its budget -- while the identical tool on a repository
# target got 900 s. Shared here so one definition reaches every target type.
TOOL_TIMEOUT_DEFAULTS: dict[str, int] = {
    "cdxgen": 600,  # 10 min - with --no-install-deps optimization (was 30 min)
    "dependency-check": 1200,  # 20 min - NVD database sync can take a while
    "scancode": 1200,  # 20 min - license scanning large codebases
    "horusec": 900,  # 15 min - multi-language SAST
    "zap": 900,  # 15 min - DAST scanning
    "prowler": 600,  # 10 min - cloud config scanning
}


# Flags JMo passes itself to control **where a tool writes and in what format**.
# The adapter contract depends on both: `normalize_and_report` globs for a file
# at a path JMo chose and parses it as JSON.
#
# A `per_tool.<tool>.flags` entry repeating one of these wins, because JMo splices
# user flags in *after* its own and a scalar flag is last-one-wins. The tool then
# writes something the adapter cannot read, the file exists so the run grades as
# success, and the findings are gone. Measured on #822: `flags: ["-f","table"]`
# took a trivy target from **2 findings to 0**, `rc=0`, nothing on any stream.
#
# Derived from what the scanners actually pass rather than guessed:
#     git grep -oE '"(-o|--output|-f|--format|...)"' scripts/cli/scan_jobs/
#
# Deliberately narrow. Repeatable flags are **not** listed: `--scanners` unions
# rather than replaces (measured against trivy 0.70.0), and dropping a legitimate
# repeated `--exclude` would break working configs. Only the flags that decide
# whether the output is readable at all belong here.
RESERVED_OUTPUT_FLAGS: frozenset[str] = frozenset(
    {
        "-o",
        "--output",
        "--out",
        "--output-filename",
        "-f",
        "--format",
        "--output-formats",
    }
)


def tool_timeout(per_tool_config: Mapping[str, Any], tool: str, default: int) -> int:
    """Resolve one tool's timeout.

    Precedence: an explicit `per_tool.<tool>.timeout` wins outright; otherwise
    the profile default, raised to `TOOL_TIMEOUT_DEFAULTS` if the tool has a
    floor.

    Shared by all five scanners. It used to be copied into each, and only
    `repository_scanner`'s copy applied the floor.
    """
    tool_cfg = per_tool_config.get(tool, {})
    if isinstance(tool_cfg, dict):
        override = tool_cfg.get("timeout")
        if isinstance(override, int) and override > 0:
            return override
    return max(default, TOOL_TIMEOUT_DEFAULTS.get(tool, 0))


def tool_flags(per_tool_config: Mapping[str, Any], tool: str) -> list[str]:
    """Return a tool's configured extra flags, minus any JMo must own.

    Shared by all five scanners, which each carried an identical copy that did
    no filtering.

    A dropped flag takes its **value** with it. Removing only the flag from
    `["-f", "table"]` would leave a bare `table` in the argv, and trivy reads a
    bare word as a scan target -- strictly worse than the collision being
    fixed. `--format=json` is handled too, since there the value is not a
    separate token.
    """
    tool_cfg = per_tool_config.get(tool, {})
    if not isinstance(tool_cfg, dict):
        return []
    raw = tool_cfg.get("flags", [])
    if not isinstance(raw, list):
        return []
    flags = [str(f) for f in raw]

    kept: list[str] = []
    dropped: list[str] = []
    i = 0
    while i < len(flags):
        token = flags[i]
        if token.split("=", 1)[0] not in RESERVED_OUTPUT_FLAGS:
            kept.append(token)
            i += 1
            continue

        dropped.append(token)
        # `--format=json` carries its value inline; `-f json` does not. Only
        # consume a following token when it is a value rather than the next flag.
        if "=" not in token and i + 1 < len(flags) and not flags[i + 1].startswith("-"):
            dropped.append(flags[i + 1])
            i += 1
        i += 1

    if dropped:
        logging.getLogger(__name__).warning(
            "Ignoring %s flag(s) for %s that JMo must control -- they decide "
            "where it writes and in what format, and the report phase cannot "
            "read the output otherwise: %s",
            len(dropped),
            tool,
            " ".join(dropped),
        )
    return kept


def filter_trivy_flags(subcommand: str, flags: list[str]) -> list[str]:
    """Drop configured trivy flags that ``subcommand`` does not accept.

    Args:
        subcommand: The trivy subcommand being invoked ("config", "fs", ...).
        flags: Flags from per-tool configuration.

    Returns:
        The flags the subcommand actually accepts.
    """
    unsupported = TRIVY_UNSUPPORTED_FLAGS.get(subcommand)
    if not unsupported:
        return list(flags)

    kept = [f for f in flags if f not in unsupported]
    dropped = [f for f in flags if f in unsupported]
    if dropped:
        logging.getLogger(__name__).warning(
            "trivy %s does not accept %s; dropping so the scan can run. "
            "Configure it under a profile that does not reach this subcommand "
            "if you need it.",
            subcommand,
            ", ".join(dropped),
        )
    return kept


# The key a scanner's status map carries its not-attempted tools under.
# `__`-prefixed by the same convention as `__attempts__`: every consumer of the
# map already skips those, so adding this one cannot make an existing reader
# mistake it for a tool.
NOT_ATTEMPTED_KEY = "__not_attempted__"

# Why a tool was never executed. Two reasons, because they mean different
# things to whoever reads the scan: one is a gap in the environment the user can
# close, the other is a correct decision about this target. Both are still
# "did not run", which is the distinction #825 is about, and both were recorded
# as a success before it.
NOT_ATTEMPTED_MISSING = "not installed"
NOT_ATTEMPTED_NOTHING_APPLICABLE = "nothing for it to scan"


def record_not_attempted(
    statuses: dict, tool: str, reason: str = NOT_ATTEMPTED_MISSING
) -> None:
    """Record that `tool` never ran, distinctly from having run and failed.

    Under `--allow-missing-tools` every scanner used to write
    ``statuses[tool] = True`` beside its stub -- the same value a tool that ran
    successfully gets. So a secret scanner that was never executed produced an
    empty result and a success, which is the `zero-secrets` shape: a policy
    certifying "no secrets" because nothing looked (#825).

    `False` is the honest boolean -- the tool did not run, so it did not
    succeed -- and the tool is also listed under `NOT_ATTEMPTED_KEY`, so
    `classify_target_outcome` can leave it out of the vote entirely rather than
    counting it as a failure. Those are different things: a target where one
    tool ran cleanly and two were never installed has not partially failed.

    On a normal host the pre-flight removes missing tools before the scanners
    run, so this fires only when `find_tool` disagrees with it at scan time.
    **In a container the pre-flight is skipped entirely** (`jmo.py` gates it on
    `DOCKER_CONTAINER`), so this is the normal path there -- a `deep` image is
    expected to be missing the four MANUAL_INSTALL_TOOLS.
    """
    statuses[tool] = False
    statuses.setdefault(NOT_ATTEMPTED_KEY, {})[tool] = reason


def not_attempted_tools(statuses: Mapping[str, Any] | None) -> list[str]:
    """The tools a target never ran, sorted. Empty when everything was tried.

    Takes a `Mapping` rather than a `dict` because every caller reads a status
    map it does not own -- `classify_target_outcome` and both progress
    reporters annotate theirs as `Mapping`.
    """
    if not statuses:
        return []
    recorded = statuses.get(NOT_ATTEMPTED_KEY) or {}
    return sorted(recorded) if isinstance(recorded, dict) else []


def write_stub(tool: str, out_path: Path) -> None:
    """Write empty JSON stub for missing tool."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stubs = {
        "trufflehog": [],
        "semgrep": {"results": []},
        "noseyparker": {"matches": []},
        "syft": {"artifacts": []},
        "trivy": {"Results": []},
        "grype": {"matches": []},
        "hadolint": [],
        "checkov": {"results": {"failed_checks": []}},
        "bandit": {"results": []},
        "zap": {"site": []},
        "nuclei": "",  # NDJSON format - empty string for empty file
        "falco": [],
        "afl++": {"crashes": []},
    }
    payload = stubs.get(tool, {})
    if isinstance(payload, str):
        # For NDJSON tools like nuclei, write empty string
        out_path.write_text(payload, encoding="utf-8")
    else:
        # For JSON tools, write JSON-encoded stub
        out_path.write_text(json.dumps(payload), encoding="utf-8")
