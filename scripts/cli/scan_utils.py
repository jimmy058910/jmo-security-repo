"""
Utilities for scan jobs.

Centralized utility functions used by scan job modules.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

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


def write_stub(tool: str, out_path: Path) -> None:
    """Write empty JSON stub for missing tool."""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    stubs = {
        "gitleaks": [],
        "trufflehog": [],
        "semgrep": {"results": []},
        "noseyparker": {"matches": []},
        "syft": {"artifacts": []},
        "trivy": {"Results": []},
        "grype": {"matches": []},
        "hadolint": [],
        "checkov": {"results": {"failed_checks": []}},
        "tfsec": {"results": []},
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
