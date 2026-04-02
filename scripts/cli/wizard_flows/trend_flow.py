"""Interactive trend analysis flow for the wizard.

Provides post-scan analysis options including trend viewing,
scan comparison, and export functionality.

Functions:
- offer_trend_analysis_after_scan(): Entry point after scan completes
- explore_trends_interactive(): Main trend menu loop
- _run_trend_command_interactive(): Execute trend commands
- _compare_scans_interactive(): Compare two scans
- _export_trends_interactive(): Export trend reports
- _explain_metrics_interactive(): Display metrics help
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.cli.wizard_flows.ui_helpers import safe_print, prompt_choice

if TYPE_CHECKING:
    pass  # No type-only imports needed currently

logger = logging.getLogger(__name__)


# Lazy colorize accessor to avoid import cycles
_colorize_fn = None


def _get_colorize():
    """Get the colorize function, initializing lazily."""
    global _colorize_fn
    if _colorize_fn is None:
        from scripts.cli.wizard_flows.base_flow import PromptHelper

        _colorize_fn = PromptHelper().colorize
    return _colorize_fn


def _get_prompt_yes_no():
    """Get the prompt_yes_no function, initializing lazily."""
    from scripts.cli.wizard_flows.base_flow import PromptHelper

    return PromptHelper().prompt_yes_no


def _get_db_path() -> Path:
    """Get the history database path, respecting custom --db flag.

    Returns:
        Path to SQLite history database
    """
    from scripts.cli.wizard_flows.config_models import WizardConfig

    return WizardConfig.get_db_path()


@dataclass
class TrendArgs:
    """Argument container for trend analysis workflows in the interactive wizard.

    This class stores user preferences collected during the wizard's trend analysis
    flow, enabling post-scan trend analysis and security posture tracking.

    Attributes:
        db: Path to SQLite history database.
        last: Number of most recent scans to analyze.
        format: Output format ('terminal', 'json', 'html', 'csv', 'prometheus', 'grafana', 'dashboard').
        output: Output file path (None = stdout).
        top: Number of top items to display (default: 10).
        team_file: Path to team mapping file (default: None).
        threshold: Threshold for regression detection (default: None).
        repo: Repository path for git blame attribution (default: current directory).

    Example:
        >>> args = TrendArgs(db="/path/to/history.db", last=50, format="html")
        >>> # Used internally by wizard to generate trend commands

    See Also:
        - jmo trends analyze: Core trend analysis command
        - scripts/cli/trend_commands.py: Trend command implementations
        - scripts/core/trend_analyzer.py: Statistical trend analysis engine

    Note:
        This class is used internally by the wizard and not exposed as a public API.
        For programmatic access, use `jmo trends` commands directly.
    """

    db: str = ""
    last: int = 30
    format: str = "terminal"
    output: str | None = None
    top: int = 10
    team_file: str | None = None
    threshold: int | None = None
    repo: str = field(default_factory=lambda: str(Path.cwd()))


@dataclass
class CompareArgs:
    """Argument container for historical scan comparison workflows in the wizard.

    Stores user selections for comparing two historical scans from the SQLite
    database, enabling regression detection and remediation tracking.

    Attributes:
        db: Path to SQLite history database.
        scan_ids: List of two scan IDs to compare [baseline_id, current_id].
        format: Output format ('terminal', 'json', 'md', 'html').
        output: Output file path (None = stdout).

    Example:
        >>> args = CompareArgs(
        ...     db="/path/to/history.db",
        ...     scan_ids=["baseline_abc123", "current_def456"],
        ...     format="md"
        ... )
        >>> # Generates: jmo history compare baseline_abc123 current_def456 --format md

    See Also:
        - jmo history compare: Historical scan comparison
        - jmo diff: Result directory comparison
        - scripts/core/diff_engine.py: Diff computation engine

    Note:
        Wizard validates that both scan IDs exist in database before execution.
    """

    db: str = ""
    scan_ids: list[str] = field(default_factory=list)
    format: str = "terminal"
    output: str | None = None


def offer_trend_analysis_after_scan(results_dir: str) -> None:
    """Offer trend analysis after scan completes (if >= 2 scans exist).

    Checks SQLite history for scan count and offers interactive trend exploration.
    Only shown if user has run at least 2 scans.

    Args:
        results_dir: Results directory from completed scan
    """
    colorize = _get_colorize()
    prompt_yes_no = _get_prompt_yes_no()

    # Check if history database exists and has >= 2 scans
    history_db_path = _get_db_path()

    if not history_db_path.exists():
        # No history yet, skip trend offer
        return

    try:
        from scripts.core.history_db import get_connection

        conn = get_connection(history_db_path)
        cursor = conn.execute("SELECT COUNT(*) FROM scans")
        scan_count = cursor.fetchone()[0]

        if scan_count < 2:
            # Not enough scans for trends
            return

        print("\n" + colorize("=" * 60, "blue"))
        safe_print(colorize("📊 Trend Analysis Available", "bold"))
        print(colorize("=" * 60, "blue"))
        print(f"\nYou have {colorize(str(scan_count), 'green')} scans in history.")
        print("Would you like to explore security trends?")
        safe_print("  • View overall security trend")
        safe_print("  • Identify regressions")
        safe_print("  • Track remediation velocity")
        safe_print("  • See top remediators")

        if prompt_yes_no("\nExplore trends now?", default=False):
            explore_trends_interactive(history_db_path, results_dir)

    except Exception as e:
        # Don't block user if trend offer fails
        logger.debug(f"Trend offer failed: {e}")


def explore_trends_interactive(db_path: Path, results_dir: str = "results") -> None:
    """Interactive menu for exploring trend analysis.

    9-option menu with:
    1. Overall security trend
    2. Regressions
    3. Remediation velocity
    4. Top remediators
    5. Security score history
    6. Compare two scans
    7. Export report
    8. Explain metrics
    9. Back to main menu

    Args:
        db_path: Path to SQLite history database
        results_dir: Results directory for exports
    """
    colorize = _get_colorize()

    while True:
        print("\n" + colorize("=" * 60, "blue"))
        safe_print(colorize("📊 Trend Analysis Menu", "bold"))
        print(colorize("=" * 60, "blue"))

        print("\n  [1] Overall security trend (last 30 days)")
        print("  [2] Show regressions (new CRITICAL/HIGH findings)")
        print("  [3] Remediation velocity (fixes per day)")
        print("  [4] Top remediators (developer rankings)")
        print("  [5] Security score history (0-100 scale)")
        print("  [6] Compare two specific scans")
        print("  [7] Export trend report (HTML/JSON)")
        print("  [8] Explain metrics (help)")
        print("  [9] Back to main menu")

        choice = prompt_choice(
            "\nSelect option:",
            [
                ("1", "Overall trend"),
                ("2", "Regressions"),
                ("3", "Remediation velocity"),
                ("4", "Top remediators"),
                ("5", "Security score"),
                ("6", "Compare scans"),
                ("7", "Export report"),
                ("8", "Explain metrics"),
                ("9", "Back"),
            ],
            default="1",
        )

        if choice == "9":
            print(colorize("\nReturning to main menu...", "yellow"))
            break

        if choice == "1":
            _run_trend_command_interactive(db_path, "analyze", last_n=30)
        elif choice == "2":
            _run_trend_command_interactive(db_path, "regressions", last_n=30)
        elif choice == "3":
            _run_trend_command_interactive(db_path, "velocity", last_n=30)
        elif choice == "4":
            _run_trend_command_interactive(db_path, "developers", last_n=30)
        elif choice == "5":
            _run_trend_command_interactive(db_path, "score", last_n=30)
        elif choice == "6":
            _compare_scans_interactive(db_path)
        elif choice == "7":
            _export_trends_interactive(db_path, results_dir)
        elif choice == "8":
            _explain_metrics_interactive()


def _run_trend_command_interactive(
    db_path: Path, command: str, last_n: int = 30
) -> None:
    """Execute a trend analysis command interactively.

    Args:
        db_path: Path to SQLite history database
        command: Trend command (analyze/regressions/velocity/developers/score)
        last_n: Number of days to analyze
    """
    colorize = _get_colorize()

    try:
        from scripts.cli.trend_commands import (  # type: ignore[attr-defined]  # Dynamic import for optional trend analysis
            cmd_trends_analyze,
            cmd_trends_regressions,
            cmd_trends_velocity,
            cmd_trends_developers,
            cmd_trends_score,
        )

        # Build args using dataclass
        args = TrendArgs(
            db=str(db_path),
            last=last_n,
            format="terminal",
            output=None,
            top=10,
            team_file=None,
            threshold=None,
            repo=str(Path.cwd()),
        )

        # Dispatch to appropriate command
        command_map = {
            "analyze": cmd_trends_analyze,
            "regressions": cmd_trends_regressions,
            "velocity": cmd_trends_velocity,
            "developers": cmd_trends_developers,
            "score": cmd_trends_score,
        }

        cmd_func = command_map.get(command)
        if not cmd_func:
            print(colorize(f"Unknown command: {command}", "red"))
            return

        print(colorize(f"\n=== {command.title()} ===\n", "bold"))
        result = cmd_func(args)

        if result != 0:
            safe_print(
                colorize(f"\n⚠ Command failed with exit code {result}", "yellow")
            )

        # Pause for user to read output
        input(colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        safe_print(
            colorize(
                "\n⚠ Trend analysis not available (missing dependencies)", "yellow"
            )
        )
        input(colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        safe_print(colorize(f"\n✗ Error: {e}", "red"))
        logger.error(f"Trend command failed: {e}", exc_info=True)
        input(colorize("\nPress Enter to continue...", "blue"))


def _compare_scans_interactive(db_path: Path) -> None:
    """Interactive scan comparison workflow.

    Lists recent scans and prompts user to select two for comparison.
    Uses diff-engine for detailed comparison.

    Args:
        db_path: Path to SQLite history database
    """
    colorize = _get_colorize()

    try:
        from scripts.core.history_db import list_recent_scans
        from scripts.cli.trend_commands import cmd_trends_compare

        # Load recent scans
        scans = list_recent_scans(db_path, limit=20)

        if len(scans) < 2:
            safe_print(colorize("\n⚠ Need at least 2 scans in history", "yellow"))
            input(colorize("\nPress Enter to continue...", "blue"))
            return

        # Display scans
        print("\n" + colorize("Recent Scans:", "bold"))
        print(
            f"{'#':<4} {'ID':<10} {'Timestamp':<20} {'Profile':<12} {'Branch':<15} {'Findings':<10}"
        )
        print("-" * 80)

        for i, scan in enumerate(scans, 1):
            scan_id = scan.get("id", "")[:8]
            timestamp = scan.get("timestamp_iso", "unknown")[:19]
            profile = scan.get("profile", "unknown")
            branch = scan.get("branch", "unknown")[:14]
            total = scan.get("total_findings", 0)

            print(
                f"{i:<4} {scan_id:<10} {timestamp:<20} {profile:<12} {branch:<15} {total:<10}"
            )

        # Select scans
        print()
        while True:
            try:
                baseline_choice = input(
                    colorize("Select baseline scan number: ", "bold")
                ).strip()
                baseline_idx = int(baseline_choice) - 1
                if 0 <= baseline_idx < len(scans):
                    break
                print(colorize("Invalid selection", "red"))
            except ValueError:
                print(colorize("Invalid input", "red"))

        while True:
            try:
                current_choice = input(
                    colorize("Select current scan number: ", "bold")
                ).strip()
                current_idx = int(current_choice) - 1
                if 0 <= current_idx < len(scans):
                    if current_idx != baseline_idx:
                        break
                    print(colorize("Must select different scans", "red"))
                else:
                    print(colorize("Invalid selection", "red"))
            except ValueError:
                print(colorize("Invalid input", "red"))

        baseline_id = scans[baseline_idx]["id"]
        current_id = scans[current_idx]["id"]

        # Build args using dataclass
        args = CompareArgs(
            db=str(db_path),
            scan_ids=[baseline_id, current_id],
            format="terminal",
            output=None,
        )

        safe_print(
            colorize(
                f"\n=== Comparing {baseline_id[:8]} → {current_id[:8]} ===\n", "bold"
            )
        )
        result = cmd_trends_compare(args)

        if result != 0:
            safe_print(
                colorize(f"\n⚠ Comparison failed with exit code {result}", "yellow")
            )

        input(colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        safe_print(
            colorize(
                "\n⚠ Trend comparison not available (missing dependencies)", "yellow"
            )
        )
        input(colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        safe_print(colorize(f"\n✗ Error: {e}", "red"))
        logger.error(f"Scan comparison failed: {e}", exc_info=True)
        input(colorize("\nPress Enter to continue...", "blue"))


def _export_trends_interactive(db_path: Path, results_dir: str) -> None:
    """Export trend report interactively.

    Prompts for format (HTML/JSON) and time range, then exports report.

    Args:
        db_path: Path to SQLite history database
        results_dir: Results directory for output
    """
    colorize = _get_colorize()
    prompt_yes_no = _get_prompt_yes_no()

    try:
        from scripts.cli.trend_formatters import format_html_report, format_json_report
        from scripts.core.trend_analyzer import TrendAnalyzer

        # Select format
        format_choice = prompt_choice(
            "\nSelect export format:",
            [
                ("html", "Interactive HTML report"),
                ("json", "Machine-readable JSON"),
            ],
            default="html",
        )

        # Select time range
        print("\nTime range:")
        print("  [1] Last 7 days")
        print("  [2] Last 30 days")
        print("  [3] Last 90 days")
        print("  [4] All time")

        range_choice = prompt_choice(
            "Select range:",
            [("1", "7 days"), ("2", "30 days"), ("3", "90 days"), ("4", "All")],
            default="2",
        )

        last_n = {"1": 7, "2": 30, "3": 90, "4": None}[range_choice]

        # Generate report
        print(colorize("\n=== Generating Trend Report ===\n", "bold"))

        analyzer = TrendAnalyzer(db_path)
        report = analyzer.analyze_trends(last_n=last_n)

        if format_choice == "html":
            output_file = Path(results_dir) / "summaries" / "trend_report.html"
            output_file.parent.mkdir(parents=True, exist_ok=True)

            html_content = format_html_report(report)
            output_file.write_text(html_content, encoding="utf-8")

            safe_print(colorize(f"✓ HTML report exported: {output_file}", "green"))

            if prompt_yes_no("\nOpen report in browser?", default=True):
                import webbrowser

                webbrowser.open(f"file://{output_file.resolve()}")
        else:
            output_file = Path(results_dir) / "summaries" / "trend_report.json"
            output_file.parent.mkdir(parents=True, exist_ok=True)

            json_content = format_json_report(report)
            output_file.write_text(json_content, encoding="utf-8")

            safe_print(colorize(f"✓ JSON report exported: {output_file}", "green"))

        input(colorize("\nPress Enter to continue...", "blue"))

    except ImportError:
        safe_print(
            colorize("\n⚠ Trend export not available (missing dependencies)", "yellow")
        )
        input(colorize("\nPress Enter to continue...", "blue"))
    except Exception as e:
        safe_print(colorize(f"\n✗ Error: {e}", "red"))
        logger.error(f"Trend export failed: {e}", exc_info=True)
        input(colorize("\nPress Enter to continue...", "blue"))


def _explain_metrics_interactive() -> None:
    """Explain trend analysis metrics to users.

    Displays help text for each metric with examples.
    """
    colorize = _get_colorize()

    print("\n" + colorize("=" * 60, "bold"))
    safe_print(colorize("📖 Trend Analysis Metrics Explained", "bold"))
    print(colorize("=" * 60, "bold"))

    safe_print("""
1. OVERALL SECURITY TREND
   • Shows direction: improving, worsening, stable
   • Mann-Kendall test validates statistical significance
   • p < 0.05 = trend is significant (not random)

2. REGRESSIONS
   • New CRITICAL or HIGH findings in latest scan
   • Indicates code changes introducing vulnerabilities
   • Requires immediate action

3. REMEDIATION VELOCITY
   • Measures fixes per day (average)
   • Higher velocity = faster security improvements
   • Tracks team productivity

4. TOP REMEDIATORS
   • Developers who fixed most security issues
   • Based on git blame analysis
   • Shows focus areas and tool expertise

5. SECURITY SCORE
   • 0-100 scale: 100 = no findings, 0 = critical issues
   • Tracks progress over time
   • Weighted by severity (CRITICAL > HIGH > MEDIUM > LOW)

6. COMPARISON
   • Detailed diff between two scans
   • Shows new, resolved, modified findings
   • Identifies root causes of changes

Examples:
  • Trend: "Downward" = findings decreasing (good!)
  • Velocity: "3.2 fixes/day" = team resolving ~3 issues daily
  • Score: "85/100" = mostly clean, some medium issues

For more details, see: docs/USER_GUIDE.md#trend-analysis
""")

    input(colorize("\nPress Enter to continue...", "blue"))
