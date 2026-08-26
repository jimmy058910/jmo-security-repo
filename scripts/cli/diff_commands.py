"""CLI commands for diff functionality (jmo diff)."""

import os
import subprocess
import sys
from collections import Counter
from datetime import UTC
from pathlib import Path
from typing import Any

from scripts.core.diff_engine import DiffEngine, DiffResult, ModifiedFinding
from scripts.core.history_db import DEFAULT_DB_PATH
from scripts.core.jmo_version import get_jmo_version
from scripts.core.reporters import (
    diff_html_reporter,
    diff_json_reporter,
    diff_md_reporter,
    diff_sarif_reporter,
)
from scripts.core.unicode_utils import safe_print

# Severity levels a finding can carry. `--severity` is matched against these,
# so a value outside the set can never select anything.
VALID_SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Optional Rich library for enhanced terminal output
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table

    RICH_AVAILABLE = True
    # stderr=True is load-bearing, not cosmetic. `Console()` writes to stdout,
    # while the call site guards on `sys.stderr.isatty()` -- so the guard and
    # the target were different streams, and the summary panel landed in the
    # middle of `--format json` output whenever stderr happened to be a
    # character device. On Windows that includes `2>NUL`, i.e. the ordinary
    # way to silence a command in a pipeline.
    console = Console(stderr=True)
except ImportError:
    RICH_AVAILABLE = False
    console = None  # type: ignore[assignment]  # Graceful fallback when rich optional dep not installed


def detect_git_context() -> dict[str, Any] | None:
    """
    Detect Git context for auto-detection mode.

    Returns:
        Dict with git context or None if not in git repo
    """
    try:
        # Check if in git repo
        subprocess.run(
            ["git", "rev-parse", "--git-dir"],
            capture_output=True,
            check=True,
            timeout=5,
        )

        # Get current branch
        result = subprocess.run(
            ["git", "rev-parse", "--abbrev-ref", "HEAD"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        current_branch = result.stdout.strip() if result.returncode == 0 else None

        # Check if in PR/merge branch
        is_pr = False
        pr_target = None

        # GitHub PR detection (GITHUB_REF format: refs/pull/123/merge)
        github_ref = os.getenv("GITHUB_REF", "")
        if github_ref.startswith("refs/pull/"):
            is_pr = True
            pr_target = os.getenv("GITHUB_BASE_REF", "main")

        # GitLab MR detection
        gitlab_mr = os.getenv("CI_MERGE_REQUEST_IID")
        if gitlab_mr:
            is_pr = True
            pr_target = os.getenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "main")

        # Detect remote URL for format suggestion
        result = subprocess.run(
            ["git", "config", "--get", "remote.origin.url"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        remote_url = result.stdout.strip() if result.returncode == 0 else ""

        platform = None
        if "github.com" in remote_url:
            platform = "github"
        elif "gitlab.com" in remote_url or "gitlab" in remote_url:
            platform = "gitlab"

        return {
            "in_git_repo": True,
            "current_branch": current_branch,
            "is_pr": is_pr,
            "pr_target": pr_target or "main",
            "platform": platform,
        }
    except (
        subprocess.CalledProcessError,
        subprocess.TimeoutExpired,
        FileNotFoundError,
    ):
        return None


def auto_detect_scans(
    git_context: dict[str, Any] | None = None,
) -> tuple[str, str] | None:
    """
    Auto-detect baseline and current scan directories/IDs.

    Args:
        git_context: Git context from detect_git_context()

    Returns:
        Tuple of (baseline_path, current_path) or None if cannot detect
    """
    # Check for recent results directories
    cwd = Path.cwd()

    # Common patterns for baseline/current directories
    baseline_candidates = [
        cwd / "baseline-results",
        cwd / "results-baseline",
        cwd / "baseline",
        cwd / "main-results",
    ]

    current_candidates = [
        cwd / "current-results",
        cwd / "results-current",
        cwd / "current",
        cwd / "results",
    ]

    # Find first existing candidate
    baseline = None
    for candidate in baseline_candidates:
        if candidate.exists() and (candidate / "summaries" / "findings.json").exists():
            baseline = str(candidate)
            break

    current = None
    for candidate in current_candidates:
        if candidate.exists() and (candidate / "summaries" / "findings.json").exists():
            current = str(candidate)
            break

    if baseline and current:
        return (baseline, current)

    return None


def suggest_output_format(git_context: dict[str, Any] | None = None) -> str:
    """
    Suggest output format based on context.

    Args:
        git_context: Git context from detect_git_context()

    Returns:
        Suggested format: "sarif", "md", or "html"
    """
    if not git_context:
        return "html"

    # If in PR/MR context, suggest appropriate format for platform
    if git_context.get("is_pr"):
        platform = git_context.get("platform")
        if platform == "github":
            return "sarif"  # GitHub Code Scanning
        elif platform == "gitlab":
            return "md"  # GitLab MR comments
        else:
            return "md"  # Generic Markdown for comments

    return "html"


def print_diff_summary_rich(diff_result: DiffResult) -> None:
    """
    Print enhanced diff summary using Rich library.

    Args:
        diff_result: DiffResult object
    """
    if not RICH_AVAILABLE or not console:
        return

    stats = diff_result.statistics

    # Create summary panel
    summary_text = f"[bold cyan]{stats['total_new']}[/bold cyan] new  |  "
    summary_text += f"[bold green]{stats['total_resolved']}[/bold green] resolved  |  "
    summary_text += f"[bold yellow]{stats['total_modified']}[/bold yellow] modified"

    # Determine trend color. The engine emits exactly improving/stable/
    # worsening; "degrading" and "neutral" were never reachable, and
    # "worsening" -- the one that matters -- had no entry and fell through to
    # white.
    trend = stats.get("trend", "stable")
    trend_colors = {
        "improving": "green",
        "stable": "yellow",
        "worsening": "red",
    }
    trend_color = trend_colors.get(trend, "white")
    trend_text = f"Trend: [{trend_color}]{trend.upper()}[/{trend_color}]"

    console.print(
        Panel(
            f"{summary_text}\n{trend_text}",
            title="📊 Diff Summary",
            border_style="cyan",
        )
    )

    # Create severity breakdown table.
    #
    # These read `new_by_severity`/`resolved_by_severity`, which is what
    # `DiffEngine._calculate_statistics` emits. They previously read
    # `stats["new"]` and `stats["resolved"]` -- keys the engine has never
    # produced -- so the table could not render from a real diff. It rendered
    # in its unit test only because the test hand-built a statistics dict
    # containing those keys.
    #
    # A "Findings by Tool" tree sat here too, reading `stats["by_tool"]`.
    # Nothing anywhere computes that key, so it is removed rather than fed:
    # there is no data source to point it at.
    new_by_sev = stats.get("new_by_severity") or {}
    resolved_by_sev = stats.get("resolved_by_severity") or {}
    if new_by_sev or resolved_by_sev:
        table = Table(
            title="Findings by Severity",
            show_header=True,
            header_style="bold magenta",
        )
        table.add_column("Severity", style="cyan", no_wrap=True)
        table.add_column("New", justify="right", style="yellow")
        table.add_column("Resolved", justify="right", style="green")
        table.add_column("Change", justify="right")

        rows = 0
        for sev in VALID_SEVERITIES:
            new_count = new_by_sev.get(sev, 0)
            resolved_count = resolved_by_sev.get(sev, 0)
            if new_count > 0 or resolved_count > 0:
                delta = new_count - resolved_count
                change_style = "red" if delta > 0 else "green"
                table.add_row(
                    sev,
                    str(new_count),
                    str(resolved_count),
                    f"[{change_style}]{delta:+d}[/{change_style}]",
                )
                rows += 1

        if rows:
            console.print(table)


def cmd_diff(args) -> int:
    """
    Execute 'jmo diff' command.

    Supports three modes:
    1. Auto mode: Auto-detect scans based on context (--auto)
    2. Directory mode: Compare two scan result directories
    3. SQLite mode: Compare two historical scan IDs

    Returns:
        0 on success, 1 on error
    """
    # Auto-detection mode
    if getattr(args, "auto", False):
        git_context = detect_git_context()

        # Auto-detect scan directories
        detected = auto_detect_scans(git_context)

        if not detected:
            print("Error: Could not auto-detect scan directories", file=sys.stderr)
            print(file=sys.stderr)
            print("Auto-detection looks for:", file=sys.stderr)
            print(
                "  Baseline: baseline-results/, results-baseline/, main-results/",
                file=sys.stderr,
            )
            print(
                "  Current:  current-results/, results-current/, results/",
                file=sys.stderr,
            )
            print(file=sys.stderr)
            print("Run scans first or specify directories manually:", file=sys.stderr)
            print("  jmo diff baseline-results/ current-results/", file=sys.stderr)
            return 1

        baseline, current = detected

        # Auto-suggest output format. `--format` carries no argparse default,
        # so this is reachable: it previously defaulted to "md", which made
        # `args.format` permanently truthy and the suggestion dead code even
        # though `--auto`'s help advertises it.
        if not getattr(args, "format", None):
            args.format = suggest_output_format(git_context)

        # Set default output path based on format
        if not getattr(args, "output", None):
            args.output = f"diff-report.{args.format}"

        # Update args for standard processing
        args.directories = [baseline, current]
        args.scan_ids = None

        # Display auto-detection results
        safe_print("🔍 Auto-detected configuration:", stream=sys.stderr)
        print(f"   Baseline: {baseline}", file=sys.stderr)
        print(f"   Current:  {current}", file=sys.stderr)
        print(f"   Format:   {args.format}", file=sys.stderr)
        if git_context and git_context.get("is_pr"):
            print(
                f"   Context:  PR from {git_context['current_branch']} → {git_context['pr_target']}",
                file=sys.stderr,
            )
        print(file=sys.stderr)

    # Validate arguments
    if args.directories:
        if len(args.directories) != 2:
            print("Error: Provide exactly 2 directories to compare", file=sys.stderr)
            print("Usage: jmo diff baseline-results/ current-results/", file=sys.stderr)
            return 1
        baseline, current = args.directories
        mode = "directory"
    elif args.scan_ids:
        if len(args.scan_ids) != 2:
            print(
                "Error: Provide exactly 2 scan IDs (--scan abc123 --scan def456)",
                file=sys.stderr,
            )
            return 1
        baseline, current = args.scan_ids
        mode = "sqlite"
    else:
        print("Error: Provide directories or --scan IDs", file=sys.stderr)
        print("Usage: jmo diff baseline/ current/", file=sys.stderr)
        print("   OR: jmo diff --scan abc123 --scan def456", file=sys.stderr)
        return 1

    # Create diff engine
    detect_mods = not getattr(args, "no_modifications", False)
    engine = DiffEngine(detect_modifications=detect_mods)

    # Run comparison
    try:
        if mode == "directory":
            baseline_path = Path(baseline).resolve()
            current_path = Path(current).resolve()

            if not baseline_path.exists():
                print(
                    f"Error: Baseline directory not found: {baseline_path}",
                    file=sys.stderr,
                )
                return 1
            if not current_path.exists():
                print(
                    f"Error: Current directory not found: {current_path}",
                    file=sys.stderr,
                )
                return 1

            diff_result = engine.compare_directories(baseline_path, current_path)
        else:
            db_path = getattr(args, "db", None)
            if db_path:
                db_path = Path(db_path)
            else:
                # The history database is `.jmo/history.db`, which is what
                # `jmo scan`, `jmo report`, `jmo ci` and every `jmo history`
                # subcommand read and write. This defaulted to
                # `~/.jmo/scans.db` -- a filename and a location the product
                # never uses -- so `jmo diff --scan A --scan B`, the
                # invocation printed in this command's own --help, could only
                # ever fail.
                db_path = DEFAULT_DB_PATH

            if not db_path.exists():
                print(f"Error: Database not found: {db_path}", file=sys.stderr)
                return 1

            diff_result = engine.compare_scans(baseline, current, db_path)
    except FileNotFoundError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except ValueError as e:
        print(f"Error: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error during diff: {e}", file=sys.stderr)
        return 1

    # Apply filters.
    #
    # An unusable filter value produces an empty diff, which is indistinguishable
    # from "nothing changed" -- so say so rather than reporting a clean run.
    # Measured before this check: `--severity high` and `--severity NOPE` each
    # returned 0/0/0 with exit code 0 and no message, and
    # `--severity "HIGH, LOW"` silently dropped LOW because of the space.
    if getattr(args, "severity", None):
        severities = {s.strip().upper() for s in args.severity.split(",") if s.strip()}
        unknown = sorted(severities - set(VALID_SEVERITIES))
        if unknown:
            print(
                f"Warning: unrecognised severity {', '.join(unknown)} "
                f"(expected one of {', '.join(VALID_SEVERITIES)}); "
                "no finding can match it",
                file=sys.stderr,
            )
        diff_result = _filter_by_severity(diff_result, severities)

    if getattr(args, "tool", None):
        tools = {t.strip() for t in args.tool.split(",") if t.strip()}
        present = _tools_present(diff_result)
        unknown = sorted(tools - present)
        if unknown:
            print(
                f"Warning: no findings from {', '.join(unknown)} in either scan"
                + (f" (present: {', '.join(sorted(present))})" if present else ""),
                file=sys.stderr,
            )
        diff_result = _filter_by_tool(diff_result, tools)

    if getattr(args, "only", None):
        diff_result = _filter_by_category(diff_result, args.only)

    # Generate output
    output_path = getattr(args, "output", None)
    # `--format` has no argparse default so `--auto` can suggest one; resolve
    # the unset case here instead.
    format_type = getattr(args, "format", None) or "md"

    try:
        if format_type == "json":
            if output_path:
                diff_json_reporter.write_json_diff(diff_result, Path(output_path))
                safe_print(f"✅ JSON diff report: {output_path}")
            else:
                # Write to stdout
                import json

                output = _build_json_output(diff_result)
                print(json.dumps(output, indent=2, ensure_ascii=False))

        elif format_type == "md":
            if output_path:
                diff_md_reporter.write_markdown_diff(diff_result, Path(output_path))
                safe_print(f"✅ Markdown diff report: {output_path}")
            else:
                # Write to stdout using secure temp file (0o600 permissions, auto-cleanup)
                from scripts.core.secure_temp import secure_temp_file

                with secure_temp_file(prefix="jmo_diff_", suffix=".md") as tmp_path:
                    diff_md_reporter.write_markdown_diff(diff_result, tmp_path)
                    _write_document_to_stdout(tmp_path.read_text(encoding="utf-8"))

        elif format_type == "html":
            if not output_path:
                output_path = "diff-report.html"
            diff_html_reporter.write_html_diff(diff_result, Path(output_path))
            safe_print(f"✅ HTML diff report: {output_path}")
            # as_uri() rather than "file://" + path: on Windows the latter
            # produced `file://C:\Users\...`, where `C:` parses as the URI
            # authority and the backslashes are not separators. The correct
            # form is `file:///C:/Users/...`.
            print(f"   Open in browser: {Path(output_path).absolute().as_uri()}")

        elif format_type == "sarif":
            if not output_path:
                output_path = "diff.sarif"
            diff_sarif_reporter.write_sarif_diff(diff_result, Path(output_path))
            safe_print(f"✅ SARIF diff report: {output_path}")
            print("   Upload to GitHub Security or GitLab Code Scanning")

    except Exception as e:
        print(f"Error generating output: {e}", file=sys.stderr)
        return 1

    # Print summary to stderr (so stdout remains clean for piping)
    if not output_path or format_type in ["html", "sarif"]:
        # Use Rich if available, fallback to plain text
        if RICH_AVAILABLE and sys.stderr.isatty():
            print(file=sys.stderr)  # Blank line before Rich output
            print_diff_summary_rich(diff_result)
        else:
            stats = diff_result.statistics
            safe_print(
                f"\n📊 Summary: {stats['total_new']} new, {stats['total_resolved']} resolved, "
                f"{stats['total_modified']} modified (trend: {stats['trend']})",
                stream=sys.stderr,
            )

    return 0


def _build_json_output(diff: DiffResult) -> dict[str, Any]:
    """Build JSON output structure for stdout."""
    from datetime import datetime

    return {
        "meta": {
            "diff_version": "1.0.0",
            # Same value the file-writing path reports. These disagreed: the
            # stdout document said 1.0.0 while `--output` said the real
            # version, for the same command over the same data.
            "jmo_version": get_jmo_version(),
            "timestamp": datetime.now(UTC).isoformat(),
            "baseline": {
                "source_type": diff.baseline_source.source_type,
                "path": diff.baseline_source.path,
                "timestamp": diff.baseline_source.timestamp,
                "profile": diff.baseline_source.profile,
                "total_findings": diff.baseline_source.total_findings,
            },
            "current": {
                "source_type": diff.current_source.source_type,
                "path": diff.current_source.path,
                "timestamp": diff.current_source.timestamp,
                "profile": diff.current_source.profile,
                "total_findings": diff.current_source.total_findings,
            },
        },
        "statistics": diff.statistics,
        "new_findings": diff.new,
        "resolved_findings": diff.resolved,
        "modified_findings": [
            {
                "fingerprint": m.fingerprint,
                "changes": m.changes,
                "risk_delta": m.risk_delta,
                "baseline": m.baseline,
                "current": m.current,
            }
            for m in diff.modified
        ],
    }


def _write_document_to_stdout(text: str) -> None:
    """Write a generated document to stdout without console substitution.

    `jmo diff --format md` with no `--output` is how the Markdown is captured
    for a PR comment -- `jmo diff a/ b/ > report.md`. Passing it through
    `safe_print` applied the *console's* codec to a *file*: on a cp1252 box the
    captured document read `# [?] Security Diff Report`, with the trend arrows
    rendered as bare `?` and `[!]?`. GitHub and GitLab both consume UTF-8, so
    the substitution is pure loss (#784).

    Redirected or piped stdout therefore gets the document verbatim as UTF-8.
    A real terminal still goes through `safe_print`, because a cp437 console
    genuinely cannot render the characters and mojibake would be worse.
    """
    try:
        is_terminal = sys.stdout.isatty()
    except (AttributeError, ValueError):  # detached or replaced stream
        is_terminal = False

    buffer = getattr(sys.stdout, "buffer", None)
    if is_terminal or buffer is None:
        safe_print(text)
        return

    sys.stdout.flush()
    buffer.write(text.encode("utf-8"))
    if not text.endswith("\n"):
        buffer.write(b"\n")
    buffer.flush()


def _tools_present(diff: DiffResult) -> set[str]:
    """Every tool name appearing anywhere in a diff result."""
    names: set[str] = set()
    for finding in (*diff.new, *diff.resolved, *diff.unchanged):
        name = (finding.get("tool") or {}).get("name")
        if name:
            names.add(name)
    for mod in diff.modified:
        for finding in (mod.baseline, mod.current):
            name = (finding.get("tool") or {}).get("name")
            if name:
                names.add(name)
    return names


def _recalculate_statistics(
    new: list[dict[str, Any]],
    resolved: list[dict[str, Any]],
    unchanged: list[dict[str, Any]],
    modified: list[ModifiedFinding],
) -> dict[str, Any]:
    """Recompute diff statistics after filtering.

    Shared by all three filters. They each carried their own copy of this
    block, and all three omitted the zero-fill that
    `DiffEngine._calculate_statistics` applies -- so `new_by_severity` held all
    five levels in an unfiltered diff and only the non-zero ones after any
    filter. Same command, same artifact, two different shapes.
    """
    new_by_sev = Counter(f.get("severity", "INFO") for f in new)
    resolved_by_sev = Counter(f.get("severity", "INFO") for f in resolved)
    for sev in VALID_SEVERITIES:
        new_by_sev.setdefault(sev, 0)
        resolved_by_sev.setdefault(sev, 0)

    net_change = len(new) - len(resolved)
    trend = (
        "improving" if net_change < 0 else "worsening" if net_change > 0 else "stable"
    )

    mod_types: list[str] = []
    for m in modified:
        mod_types.extend(m.changes.keys())

    return {
        "total_new": len(new),
        "total_resolved": len(resolved),
        "total_unchanged": len(unchanged),
        "total_modified": len(modified),
        "net_change": net_change,
        "trend": trend,
        "new_by_severity": dict(new_by_sev),
        "resolved_by_severity": dict(resolved_by_sev),
        "modifications_by_type": dict(Counter(mod_types)),
    }


def _filter_by_severity(diff: DiffResult, severities: set[str]) -> DiffResult:
    """Filter diff result by severity levels."""
    new = [f for f in diff.new if f.get("severity") in severities]
    resolved = [f for f in diff.resolved if f.get("severity") in severities]
    unchanged = [f for f in diff.unchanged if f.get("severity") in severities]
    modified = [
        m
        for m in diff.modified
        if m.current.get("severity") in severities
        or m.baseline.get("severity") in severities
    ]

    statistics = _recalculate_statistics(new, resolved, unchanged, modified)

    return DiffResult(
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        modified=modified,
        baseline_source=diff.baseline_source,
        current_source=diff.current_source,
        statistics=statistics,
    )


def _filter_by_tool(diff: DiffResult, tools: set[str]) -> DiffResult:
    """Filter diff result by tool names."""
    new = [f for f in diff.new if f.get("tool", {}).get("name") in tools]
    resolved = [f for f in diff.resolved if f.get("tool", {}).get("name") in tools]
    unchanged = [f for f in diff.unchanged if f.get("tool", {}).get("name") in tools]
    modified = [
        m
        for m in diff.modified
        if m.current.get("tool", {}).get("name") in tools
        or m.baseline.get("tool", {}).get("name") in tools
    ]

    statistics = _recalculate_statistics(new, resolved, unchanged, modified)

    return DiffResult(
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        modified=modified,
        baseline_source=diff.baseline_source,
        current_source=diff.current_source,
        statistics=statistics,
    )


def _filter_by_category(diff: DiffResult, category: str) -> DiffResult:
    """Filter to show only specific category (new, resolved, or modified)."""
    # Initialize with proper types to satisfy mypy across all branches
    new: list[dict[str, Any]] = []
    resolved: list[dict[str, Any]] = []
    unchanged: list[dict[str, Any]] = []
    modified: list[ModifiedFinding] = []

    if category == "new":
        new = diff.new
    elif category == "resolved":
        resolved = diff.resolved
    elif category == "modified":
        modified = diff.modified
    else:
        # Invalid category, return unchanged
        return diff

    statistics = _recalculate_statistics(new, resolved, unchanged, modified)

    return DiffResult(
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        modified=modified,
        baseline_source=diff.baseline_source,
        current_source=diff.current_source,
        statistics=statistics,
    )
