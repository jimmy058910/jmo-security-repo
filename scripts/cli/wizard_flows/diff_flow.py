"""Diff wizard flow for comparing security scans.

Provides an interactive workflow for selecting and comparing
two scan results to identify regressions or improvements.

Supports two modes:
- History mode: Compare scans from SQLite history database
- Directory mode: Compare two result directories directly

Phase 4 of wizard.py refactoring.
"""

from __future__ import annotations

import logging
import webbrowser
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.cli.wizard_flows.base_flow import PromptHelper
from scripts.cli.wizard_flows.profile_config import DIFF_WIZARD_TOTAL_STEPS
from scripts.cli.wizard_flows.ui_helpers import (
    safe_print,
    select_mode,
    prompt_choice,
)

if TYPE_CHECKING:
    pass

logger = logging.getLogger(__name__)


# Initialize PromptHelper for consistent UI
_prompter = PromptHelper()
_colorize = _prompter.colorize
_print_step = _prompter.print_step
_prompt_yes_no = _prompter.prompt_yes_no


@dataclass
class DiffArgs:
    """Arguments for diff command.

    Mimics argparse namespace for compatibility with diff_commands.cmd_diff().

    This dataclass stores user selections for comparing two scan results,
    enabling regression detection in CI/CD pipelines and PR reviews.

    Attributes:
        directories: List of two result directories [baseline, current] (directory mode).
        scan_ids: List of two scan IDs [baseline, current] (history mode).
        db: Path to SQLite history database (for history mode).
        severity: Filter by severity levels (e.g., 'CRITICAL' or 'CRITICAL,HIGH').
        tool: Filter by specific tool (default: None = all tools).
        only: Filter by change type ('new', 'resolved', 'modified', or None for all).
        no_modifications: Skip modification detection for faster diffs.
        format: Output format ('json', 'md', 'html', 'sarif').
        output: Output file path.

    Example:
        >>> args = DiffArgs(
        ...     directories=['results-main', 'results-feature-branch'],
        ...     severity='CRITICAL,HIGH',
        ...     only='new',
        ...     format='md',
        ...     output='diff-report.md'
        ... )
    """

    directories: list[str] | None = None
    scan_ids: list[str] | None = None
    db: str = ""
    severity: str | None = None
    tool: str | None = None
    only: str | None = None
    no_modifications: bool = False
    format: str = "html"
    output: str = "diff-report.html"


def _get_db_path() -> Path:
    """Get the history database path.

    Delegates to WizardConfig.get_db_path() for consistency.

    Returns:
        Path to SQLite history database
    """
    from scripts.cli.wizard_flows.config_models import WizardConfig

    return WizardConfig.get_db_path()


def run_diff_wizard_impl(use_docker: bool = False) -> int:  # noqa: ARG001
    """Run the interactive diff wizard workflow.

    Guides user through:
    1. Scan selection from history (or directory paths)
    2. Filter options (severity, tools, categories)
    3. Output format selection
    4. Diff execution and preview

    Args:
        use_docker: Whether to use Docker for diff commands (currently unused,
                   reserved for future Docker-based diff support)

    Returns:
        Exit code (0 = success, 1 = error, 130 = cancelled)
    """
    # Lazy imports to avoid circular dependencies
    from scripts.core.history_db import list_recent_scans
    from scripts.cli.diff_commands import cmd_diff

    try:
        print(_colorize("\n=== JMo Security Diff Wizard ===\n", "bold"))
        print("This wizard helps you compare two security scan results.\n")

        # Step 1: Select comparison mode
        _print_step(1, DIFF_WIZARD_TOTAL_STEPS, "Select Comparison Mode")
        modes = [
            ("history", "Compare scans from history database"),
            ("directory", "Compare two result directories"),
        ]

        mode = select_mode("Comparison modes", modes, default="history")

        baseline_path: str | None = None
        current_path: str | None = None
        baseline_id: str | None = None
        current_id: str | None = None

        if mode == "history":
            # Load recent scans from SQLite
            history_db_path = _get_db_path()

            if not history_db_path.exists():
                print(
                    _colorize(
                        f"\nError: History database not found at {history_db_path}",
                        "red",
                    )
                )
                print("Run some scans first to populate the history database.")
                return 1

            try:
                scans = list_recent_scans(history_db_path, limit=20)

                if len(scans) < 2:
                    print(_colorize("\nError: Need at least 2 scans in history", "red"))
                    print("Run more scans or use directory mode instead.")
                    return 1

                # Display available scans
                print("\nRecent scans:")
                for i, scan in enumerate(scans, 1):
                    timestamp = scan.get("timestamp_iso", "unknown")
                    profile = scan.get("profile", "unknown")
                    branch = scan.get("branch", "unknown")
                    total = scan.get("total_findings", 0)
                    scan_id = scan.get("id", "")[:8]

                    print(
                        f"  [{i:2d}] {scan_id}  {timestamp}  {profile:10s}  {branch:15s}  ({total} findings)"
                    )

                # Select baseline
                while True:
                    try:
                        choice = input(
                            _colorize("\nSelect baseline scan number: ", "bold")
                        ).strip()
                        idx = int(choice) - 1
                        if 0 <= idx < len(scans):
                            baseline_id = scans[idx]["id"]
                            break
                        print(_colorize("Invalid selection", "red"))
                    except (ValueError, KeyboardInterrupt):
                        raise KeyboardInterrupt

                # Select current
                while True:
                    try:
                        choice = input(
                            _colorize("Select current scan number: ", "bold")
                        ).strip()
                        idx = int(choice) - 1
                        if 0 <= idx < len(scans):
                            current_id = scans[idx]["id"]
                            if current_id != baseline_id:
                                break
                            print(_colorize("Must select different scans", "red"))
                        else:
                            print(_colorize("Invalid selection", "red"))
                    except (ValueError, KeyboardInterrupt):
                        raise KeyboardInterrupt

            except Exception as e:
                print(_colorize(f"\nError loading scan history: {e}", "red"))
                return 1
        else:
            # Directory mode
            _print_step(2, DIFF_WIZARD_TOTAL_STEPS, "Select Directories")

            baseline_path = input(
                _colorize("Baseline results directory: ", "bold")
            ).strip()
            if not Path(baseline_path).exists():
                print(_colorize(f"Error: Directory not found: {baseline_path}", "red"))
                return 1

            current_path = input(
                _colorize("Current results directory: ", "bold")
            ).strip()
            if not Path(current_path).exists():
                print(_colorize(f"Error: Directory not found: {current_path}", "red"))
                return 1

        # Step 2: Filter options
        _print_step(3, DIFF_WIZARD_TOTAL_STEPS, "Configure Filters (optional)")

        print("\nSeverity filtering:")
        print("  [1] All severities")
        print("  [2] CRITICAL only")
        print("  [3] CRITICAL + HIGH")
        print("  [4] CRITICAL + HIGH + MEDIUM")

        sev_choice = prompt_choice(
            "Select severity filter:",
            [
                ("1", "All"),
                ("2", "CRITICAL"),
                ("3", "CRITICAL,HIGH"),
                ("4", "CRITICAL,HIGH,MEDIUM"),
            ],
            default="1",
        )
        severity_filter = {
            "1": "",
            "2": "CRITICAL",
            "3": "CRITICAL,HIGH",
            "4": "CRITICAL,HIGH,MEDIUM",
        }[sev_choice]

        print("\nCategory filtering:")
        print("  [1] All changes")
        print("  [2] New findings only")
        print("  [3] Resolved findings only")
        print("  [4] Modified findings only")

        cat_choice = prompt_choice(
            "Select category filter:",
            [("1", "All"), ("2", "New"), ("3", "Resolved"), ("4", "Modified")],
            default="1",
        )
        category_filter = {"1": None, "2": "new", "3": "resolved", "4": "modified"}[
            cat_choice
        ]

        # Step 3: Output format
        _print_step(4, DIFF_WIZARD_TOTAL_STEPS, "Select Output Format")

        formats = [
            ("json", "Machine-readable JSON"),
            ("md", "Markdown (GitHub/GitLab comments)"),
            ("html", "Interactive HTML dashboard"),
            ("sarif", "SARIF 2.1.0 (GitHub Security)"),
        ]

        output_format = select_mode("Output formats", formats, default="html")

        output_file = f"diff-report.{output_format}"
        custom_output = input(
            _colorize(f"Output file [{output_file}]: ", "bold")
        ).strip()
        if custom_output:
            output_file = custom_output

        # Step 4: Review and execute
        _print_step(5, DIFF_WIZARD_TOTAL_STEPS, "Review and Execute")

        print("\n" + _colorize("Diff Configuration:", "bold"))
        if mode == "history":
            print(f"  Mode: {_colorize('History Database', 'green')}")
            # IDs validated above, safe to slice
            print(f"  Baseline: {_colorize(baseline_id[:12], 'yellow')}")  # type: ignore[index]
            print(f"  Current: {_colorize(current_id[:12], 'yellow')}")  # type: ignore[index]
        else:
            print(f"  Mode: {_colorize('Directory Comparison', 'green')}")
            print(f"  Baseline: {baseline_path}")
            print(f"  Current: {current_path}")

        if severity_filter:
            print(f"  Severity: {_colorize(severity_filter, 'yellow')}")
        if category_filter:
            print(f"  Category: {_colorize(category_filter, 'yellow')}")

        print(f"  Format: {_colorize(output_format, 'green')}")
        print(f"  Output: {output_file}")

        if not _prompt_yes_no("\nGenerate diff report?", default=True):
            print(_colorize("\nDiff cancelled", "yellow"))
            return 0

        # Build DiffArgs for cmd_diff
        # Paths/IDs are validated above, cast is safe
        args = DiffArgs(
            directories=(
                [str(baseline_path), str(current_path)]
                if mode == "directory" and baseline_path and current_path
                else None
            ),
            scan_ids=(
                [str(baseline_id), str(current_id)]
                if mode == "history" and baseline_id and current_id
                else None
            ),
            db=str(_get_db_path()),
            severity=severity_filter if severity_filter else None,
            tool=None,
            only=category_filter,
            no_modifications=False,
            format=output_format,
            output=output_file,
        )

        # Execute diff
        print(_colorize("\n=== Generating Diff Report ===\n", "bold"))
        result = cmd_diff(args)

        if result == 0:
            safe_print(_colorize(f"\n✓ Diff report generated: {output_file}", "green"))

            # Auto-open HTML reports
            if output_format == "html" and Path(output_file).exists():
                if _prompt_yes_no("\nOpen report in browser?", default=True):
                    webbrowser.open(f"file://{Path(output_file).resolve()}")
        else:
            safe_print(_colorize("\n✗ Diff generation failed", "red"))

        return result

    except KeyboardInterrupt:
        print(_colorize("\n\nDiff wizard cancelled", "yellow"))
        return 130
    except Exception as e:
        print(_colorize(f"\n\nDiff wizard error: {e}", "red"))
        logger.error(f"Diff wizard failure: {e}", exc_info=True)
        return 1
