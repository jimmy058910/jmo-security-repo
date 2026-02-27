#!/usr/bin/env python3
"""Suppression Report Generator for JMo Security.

Generates reports documenting which security findings were suppressed during
the report phase based on rules defined in jmo.suppress.yml.

Output Format:
    - **SUPPRESSIONS.md**: Markdown table showing all suppressed findings with:
      - Fingerprint ID (unique finding identifier)
      - Suppression reason (from jmo.suppress.yml)
      - Expiration date (if set)
      - Active status (yes/no based on expiration)

v1.0.0 Metadata:
    Report includes summary metadata:
    - Total suppressions applied
    - Active vs expired suppression counts
    - Link back to jmo.suppress.yml for configuration

Suppression Rules (jmo.suppress.yml):
    Suppressions are defined in jmo.suppress.yml with:
    - `id`: Finding fingerprint to suppress
    - `reason`: Human-readable justification
    - `expires`: Optional expiration date (YYYY-MM-DD)
    - `author`: Who approved the suppression

Usage:
    >>> from scripts.core.reporters.suppression_reporter import write_suppression_report
    >>> from scripts.core.suppress import Suppression, load_suppressions
    >>>
    >>> # Load suppressions from config
    >>> suppressions = load_suppressions(Path("jmo.suppress.yml"))
    >>> suppressed_ids = ["fp-123", "fp-456"]
    >>>
    >>> # Generate report
    >>> write_suppression_report(
    ...     suppressed_ids,
    ...     suppressions,
    ...     Path("results/summaries/SUPPRESSIONS.md"),
    ... )

Functions:
    write_suppression_report: Generate Markdown report of suppressed findings

See Also:
    - jmo.suppress.yml for suppression configuration
    - scripts/core/suppress.py for Suppression dataclass and loading logic
    - docs/USER_GUIDE.md for suppression workflow documentation
"""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

from scripts.core.suppress import Suppression

if TYPE_CHECKING:
    from scripts.core.suppress import SuppressionSummary


def write_suppression_report(
    suppressed_ids: list[str],
    suppressions: dict[str, Suppression],
    out_path: str | Path,
    *,
    summary: SuppressionSummary | None = None,
) -> None:
    """Generate Markdown report summarizing suppressed findings.

    Creates SUPPRESSIONS.md with table showing all suppressed findings grouped
    by suppression rule, including fingerprint ID, reason, expiration date,
    and active status. Used during report phase when jmo.suppress.yml exists.

    Args:
        suppressed_ids (list[str]): List of finding fingerprint IDs that were suppressed
        suppressions (dict[str, Suppression]): Suppression rules keyed by finding ID
        out_path (str | Path): Path to write SUPPRESSIONS.md file
        summary (SuppressionSummary | None): Optional suppression summary for debt section

    Returns:
        None (writes file to disk)

    Raises:
        OSError: If output path is not writable

    Example:
        >>> suppressions = {
        ...     'fp-123': Suppression(id='fp-123', reason='False positive', expires='2025-12-31')
        ... }
        >>> suppressed_ids = ['fp-123']
        >>> write_suppression_report(suppressed_ids, suppressions, 'results/summaries')
        # Creates results/summaries/SUPPRESSIONS.md with table:
        # | Fingerprint | Reason          | Expires    | Active |
        # | fp-123      | False positive  | 2025-12-31 | yes    |

    Note:
        Report includes metadata: total suppressions, active vs expired counts.
        When summary is provided, a debt overview section is prepended.
        Suppressions with no expiration date show empty cell in Expires column.
        Only called when jmo.suppress.yml exists and contains suppressions.

    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Suppressions Applied", ""]

    # Add debt summary section if summary is provided
    if summary is not None and summary.total_suppressed > 0:
        lines.append(f"**{summary.debt_label}**")
        lines.append("")
        lines.append(
            f"Suppression rate: {summary.suppression_percentage:.1f}% "
            f"({summary.total_suppressed}/{summary.total_before_suppression} findings)"
        )
        lines.append("")
        if summary.by_severity:
            lines.append("### Severity Breakdown")
            lines.append("")
            lines.append("| Severity | Suppressed |")
            lines.append("|----------|-----------|")
            severity_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            for sev in severity_order:
                count = summary.by_severity.get(sev)
                if count:
                    lines.append(f"| {sev} | {count} |")
            # Include any severity not in standard order
            for sev, count in sorted(summary.by_severity.items()):
                if sev not in severity_order:
                    lines.append(f"| {sev} | {count} |")
            lines.append("")

    if not suppressed_ids:
        lines.append("No suppressions matched any findings.")
    else:
        lines.append("The following findings were suppressed:")
        lines.append("")
        lines.append("| Fingerprint | Reason | Expires | Active |")
        lines.append("|-------------|--------|---------|--------|")
        for fid in suppressed_ids:
            s = suppressions.get(fid)
            if not s:
                continue
            active = "yes" if s.is_active() else "no"
            lines.append(
                f"| `{fid}` | {s.reason or ''} | {s.expires or ''} | {active} |"
            )
    p.write_text("\n".join(lines) + "\n", encoding="utf-8")
