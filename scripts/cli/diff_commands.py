"""CLI commands for diff functionality (jmo diff)."""

import os
import subprocess
import sys
from pathlib import Path
from typing import List, Dict, Any, Set, Optional, Tuple

from scripts.core.diff_engine import DiffEngine, DiffResult
from scripts.core.reporters import (
    diff_json_reporter,
    diff_md_reporter,
    diff_html_reporter,
    diff_sarif_reporter,
)

# Optional Rich library for enhanced terminal output
try:
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn
    from rich.panel import Panel
    from rich.tree import Tree

    RICH_AVAILABLE = True
    console = Console()
except ImportError:
    RICH_AVAILABLE = False
    console = None  # type: ignore[assignment]


def detect_git_context() -> Optional[Dict[str, Any]]:
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
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return None


def auto_detect_scans(git_context: Optional[Dict[str, Any]] = None) -> Optional[Tuple[str, str]]:
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


def suggest_output_format(git_context: Optional[Dict[str, Any]] = None) -> str:
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

    # Determine trend color
    trend = stats.get("trend", "neutral")
    trend_colors = {"improving": "green", "stable": "yellow", "degrading": "red", "neutral": "white"}
    trend_color = trend_colors.get(trend, "white")
    trend_text = f"Trend: [{trend_color}]{trend.upper()}[/{trend_color}]"

    console.print(Panel(f"{summary_text}\n{trend_text}", title="📊 Diff Summary", border_style="cyan"))

    # Create severity breakdown table
    if stats.get("new", {}):
        table = Table(title="New Findings by Severity", show_header=True, header_style="bold magenta")
        table.add_column("Severity", style="cyan", no_wrap=True)
        table.add_column("Count", justify="right", style="yellow")
        table.add_column("Change", justify="right")

        severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        for sev in severity_order:
            new_count = stats.get("new", {}).get(sev, 0)
            resolved_count = stats.get("resolved", {}).get(sev, 0)
            if new_count > 0 or resolved_count > 0:
                change = f"+{new_count - resolved_count}" if new_count > resolved_count else f"{new_count - resolved_count}"
                change_style = "red" if new_count > resolved_count else "green"
                table.add_row(sev, str(new_count), f"[{change_style}]{change}[/{change_style}]")

        console.print(table)

    # Tool breakdown
    if stats.get("by_tool", {}):
        tool_tree = Tree("🔧 Findings by Tool")
        for tool, count in sorted(stats.get("by_tool", {}).items(), key=lambda x: x[1], reverse=True):
            tool_tree.add(f"[cyan]{tool}[/cyan]: {count} findings")

        console.print(tool_tree)


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
            print("", file=sys.stderr)
            print("Auto-detection looks for:", file=sys.stderr)
            print("  Baseline: baseline-results/, results-baseline/, main-results/", file=sys.stderr)
            print("  Current:  current-results/, results-current/, results/", file=sys.stderr)
            print("", file=sys.stderr)
            print("Run scans first or specify directories manually:", file=sys.stderr)
            print("  jmo diff baseline-results/ current-results/", file=sys.stderr)
            return 1

        baseline, current = detected

        # Auto-suggest output format
        if not getattr(args, "format", None):
            args.format = suggest_output_format(git_context)

        # Set default output path based on format
        if not getattr(args, "output", None):
            args.output = f"diff-report.{args.format}"

        # Update args for standard processing
        args.directories = [baseline, current]
        args.scan_ids = None

        # Display auto-detection results
        print(f"🔍 Auto-detected configuration:", file=sys.stderr)
        print(f"   Baseline: {baseline}", file=sys.stderr)
        print(f"   Current:  {current}", file=sys.stderr)
        print(f"   Format:   {args.format}", file=sys.stderr)
        if git_context and git_context.get("is_pr"):
            print(f"   Context:  PR from {git_context['current_branch']} → {git_context['pr_target']}", file=sys.stderr)
        print("", file=sys.stderr)

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
                print(f"Error: Baseline directory not found: {baseline_path}", file=sys.stderr)
                return 1
            if not current_path.exists():
                print(f"Error: Current directory not found: {current_path}", file=sys.stderr)
                return 1

            diff_result = engine.compare_directories(baseline_path, current_path)
        else:
            db_path = getattr(args, "db", None)
            if db_path:
                db_path = Path(db_path)
            else:
                db_path = Path.home() / ".jmo" / "scans.db"

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

    # Apply filters
    if getattr(args, "severity", None):
        severities = set(args.severity.split(","))
        diff_result = _filter_by_severity(diff_result, severities)

    if getattr(args, "tool", None):
        tools = set(args.tool.split(","))
        diff_result = _filter_by_tool(diff_result, tools)

    if getattr(args, "only", None):
        diff_result = _filter_by_category(diff_result, args.only)

    # Generate output
    output_path = getattr(args, "output", None)
    format_type = getattr(args, "format", "md")

    try:
        if format_type == "json":
            if output_path:
                diff_json_reporter.write_json_diff(diff_result, Path(output_path))
                print(f"✅ JSON diff report: {output_path}")
            else:
                # Write to stdout
                import json
                from datetime import datetime, timezone

                output = _build_json_output(diff_result)
                print(json.dumps(output, indent=2, ensure_ascii=False))

        elif format_type == "md":
            if output_path:
                diff_md_reporter.write_markdown_diff(diff_result, Path(output_path))
                print(f"✅ Markdown diff report: {output_path}")
            else:
                # Write to stdout
                import tempfile

                with tempfile.NamedTemporaryFile(
                    mode="w", suffix=".md", delete=False
                ) as tmp:
                    tmp_path = Path(tmp.name)
                diff_md_reporter.write_markdown_diff(diff_result, tmp_path)
                print(tmp_path.read_text())
                tmp_path.unlink()

        elif format_type == "html":
            if not output_path:
                output_path = "diff-report.html"
            diff_html_reporter.write_html_diff(diff_result, Path(output_path))
            print(f"✅ HTML diff report: {output_path}")
            print(f"   Open in browser: file://{Path(output_path).absolute()}")

        elif format_type == "sarif":
            if not output_path:
                output_path = "diff.sarif"
            diff_sarif_reporter.write_sarif_diff(diff_result, Path(output_path))
            print(f"✅ SARIF diff report: {output_path}")
            print(f"   Upload to GitHub Security or GitLab Code Scanning")

    except Exception as e:
        print(f"Error generating output: {e}", file=sys.stderr)
        return 1

    # Print summary to stderr (so stdout remains clean for piping)
    if not output_path or format_type in ["html", "sarif"]:
        # Use Rich if available, fallback to plain text
        if RICH_AVAILABLE and sys.stderr.isatty():
            print("", file=sys.stderr)  # Blank line before Rich output
            print_diff_summary_rich(diff_result)
        else:
            stats = diff_result.statistics
            print(
                f"\n📊 Summary: {stats['total_new']} new, {stats['total_resolved']} resolved, "
                f"{stats['total_modified']} modified (trend: {stats['trend']})",
                file=sys.stderr,
            )

    return 0


def _build_json_output(diff: DiffResult) -> Dict[str, Any]:
    """Build JSON output structure for stdout."""
    from datetime import datetime, timezone

    return {
        "meta": {
            "diff_version": "1.0.0",
            "jmo_version": "1.0.0",
            "timestamp": datetime.now(timezone.utc).isoformat(),
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


def _filter_by_severity(
    diff: DiffResult, severities: Set[str]
) -> DiffResult:
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

    # Recalculate statistics
    from collections import Counter

    new_by_sev = Counter(f.get("severity", "INFO") for f in new)
    resolved_by_sev = Counter(f.get("severity", "INFO") for f in resolved)
    net_change = len(new) - len(resolved)
    trend = "improving" if net_change < 0 else "worsening" if net_change > 0 else "stable"

    mod_types = []  # type: ignore[var-annotated]
    for m in modified:
        mod_types.extend(m.changes.keys())
    mod_by_type = Counter(mod_types)

    statistics = {
        "total_new": len(new),
        "total_resolved": len(resolved),
        "total_unchanged": len(unchanged),
        "total_modified": len(modified),
        "net_change": net_change,
        "trend": trend,
        "new_by_severity": dict(new_by_sev),
        "resolved_by_severity": dict(resolved_by_sev),
        "modifications_by_type": dict(mod_by_type),
    }

    return DiffResult(
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        modified=modified,
        baseline_source=diff.baseline_source,
        current_source=diff.current_source,
        statistics=statistics,
    )


def _filter_by_tool(diff: DiffResult, tools: Set[str]) -> DiffResult:
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

    # Recalculate statistics
    from collections import Counter

    new_by_sev = Counter(f.get("severity", "INFO") for f in new)
    resolved_by_sev = Counter(f.get("severity", "INFO") for f in resolved)
    net_change = len(new) - len(resolved)
    trend = "improving" if net_change < 0 else "worsening" if net_change > 0 else "stable"

    mod_types = []  # type: ignore[var-annotated]
    for m in modified:
        mod_types.extend(m.changes.keys())
    mod_by_type = Counter(mod_types)

    statistics = {
        "total_new": len(new),
        "total_resolved": len(resolved),
        "total_unchanged": len(unchanged),
        "total_modified": len(modified),
        "net_change": net_change,
        "trend": trend,
        "new_by_severity": dict(new_by_sev),
        "resolved_by_severity": dict(resolved_by_sev),
        "modifications_by_type": dict(mod_by_type),
    }

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
    if category == "new":
        new = diff.new
        resolved = []
        unchanged = []  # type: ignore[var-annotated]
        modified = []  # type: ignore[var-annotated]
    elif category == "resolved":
        new = []
        resolved = diff.resolved
        unchanged = []
        modified = []
    elif category == "modified":
        new = []
        resolved = []
        unchanged = []
        modified = diff.modified
    else:
        # Invalid category, return unchanged
        return diff

    # Recalculate statistics
    from collections import Counter

    new_by_sev = Counter(f.get("severity", "INFO") for f in new)
    resolved_by_sev = Counter(f.get("severity", "INFO") for f in resolved)
    net_change = len(new) - len(resolved)
    trend = "improving" if net_change < 0 else "worsening" if net_change > 0 else "stable"

    mod_types = []  # type: ignore[var-annotated]
    for m in modified:
        mod_types.extend(m.changes.keys())
    mod_by_type = Counter(mod_types)

    statistics = {
        "total_new": len(new),
        "total_resolved": len(resolved),
        "total_unchanged": len(unchanged),
        "total_modified": len(modified),
        "net_change": net_change,
        "trend": trend,
        "new_by_severity": dict(new_by_sev),
        "resolved_by_severity": dict(resolved_by_sev),
        "modifications_by_type": dict(mod_by_type),
    }

    return DiffResult(
        new=new,
        resolved=resolved,
        unchanged=unchanged,
        modified=modified,
        baseline_source=diff.baseline_source,
        current_source=diff.current_source,
        statistics=statistics,
    )
