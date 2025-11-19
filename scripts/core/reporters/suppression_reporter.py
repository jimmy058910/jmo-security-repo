#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path

from scripts.core.suppress import Suppression


def write_suppression_report(
    suppressed_ids: list[str],
    suppressions: dict[str, Suppression],
    out_path: str | Path,
) -> None:
    """Generate Markdown report summarizing suppressed findings.

    Creates SUPPRESSIONS.md with table showing all suppressed findings grouped
    by suppression rule, including fingerprint ID, reason, expiration date,
    and active status. Used during report phase when jmo.suppress.yml exists.

    Args:
        suppressed_ids (list[str]): List of finding fingerprint IDs that were suppressed
        suppressions (dict[str, Suppression]): Suppression rules keyed by finding ID
        out_path (str | Path): Path to write SUPPRESSIONS.md file

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
        Suppressions with no expiration date show empty cell in Expires column.
        Only called when jmo.suppress.yml exists and contains suppressions.

    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = ["# Suppressions Applied", ""]
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
