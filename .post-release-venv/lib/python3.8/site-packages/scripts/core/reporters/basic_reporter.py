#!/usr/bin/env python3
"""
Basic reporters for CommonFindings: JSON dump and Markdown summary
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def write_json(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def to_markdown_summary(findings: List[Dict[str, Any]]) -> str:
    total = len(findings)
    sev_counts = Counter(f.get("severity", "INFO") for f in findings)
    lines = [
        "# Security Summary",
        "",
        f"Total findings: {total}",
        "",
        "## By Severity",
    ]
    for sev in SEV_ORDER:
        lines.append(f"- {sev}: {sev_counts.get(sev, 0)}")
    lines.append("")
    lines.append("## Top Rules")
    top_rules = Counter(f.get("ruleId", "unknown") for f in findings).most_common(5)
    for rule, count in top_rules:
        lines.append(f"- {rule}: {count}")
    lines.append("")
    return "\n".join(lines)


def write_markdown(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(to_markdown_summary(findings), encoding="utf-8")
