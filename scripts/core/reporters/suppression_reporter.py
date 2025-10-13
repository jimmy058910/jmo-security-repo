#!/usr/bin/env python3
from __future__ import annotations

from pathlib import Path
from typing import Dict, List

from scripts.core.suppress import Suppression


def write_suppression_report(
    suppressed_ids: List[str],
    suppressions: Dict[str, Suppression],
    out_path: str | Path,
) -> None:
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
