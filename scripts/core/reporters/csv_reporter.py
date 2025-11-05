#!/usr/bin/env python3
"""CSV reporter for CommonFindings: Enterprise-friendly Excel export.

Supports configurable columns for different use cases:
- Default: priority, severity, ruleId, path, line, message, tool
- Full: All fields including compliance, EPSS, KEV
- Minimal: severity, ruleId, path, message (for quick triage)
"""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Any

DEFAULT_COLUMNS = [
    "priority",
    "kev",
    "epss",
    "severity",
    "ruleId",
    "path",
    "line",
    "message",
    "tool",
    "triaged",
]

COMPLIANCE_COLUMNS = [
    "compliance_owasp",
    "compliance_cwe",
    "compliance_cis",
    "compliance_nist",
    "compliance_pci",
    "compliance_attack",
]

FULL_COLUMNS = DEFAULT_COLUMNS + COMPLIANCE_COLUMNS


def write_csv(
    findings: list[dict[str, Any]],
    out_path: str | Path,
    columns: list[str] | None = None,
    include_header: bool = True,
) -> None:
    """Write findings to CSV file.

    Args:
        findings: List of CommonFinding dictionaries
        out_path: Output file path
        columns: Column list (defaults to DEFAULT_COLUMNS)
        include_header: Include CSV header row

    Example:
        >>> findings = load_findings("results/findings.json")
        >>> write_csv(findings, "results/findings.csv")
        >>> # Custom columns
        >>> write_csv(findings, "results/brief.csv", columns=["severity", "ruleId", "path"])
    """
    cols = columns or DEFAULT_COLUMNS
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    with open(p, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f, quoting=csv.QUOTE_MINIMAL)

        if include_header:
            writer.writerow(cols)

        for finding in findings:
            row = _extract_row(finding, cols)
            writer.writerow(row)


def _extract_row(finding: dict[str, Any], columns: list[str]) -> list[str]:
    """Extract CSV row from finding based on column spec.

    Args:
        finding: CommonFinding dictionary
        columns: List of column names to extract

    Returns:
        List of string values for the CSV row
    """
    row = []
    for col in columns:
        if col == "priority":
            priority_data = finding.get("priority", {})
            if isinstance(priority_data, dict):
                row.append(f"{priority_data.get('priority', 0):.1f}")
            else:
                row.append("0.0")
        elif col == "kev":
            priority_data = finding.get("priority", {})
            if isinstance(priority_data, dict):
                is_kev = priority_data.get("is_kev", False)
                row.append("YES" if is_kev else "NO")
            else:
                row.append("NO")
        elif col == "epss":
            priority_data = finding.get("priority", {})
            if isinstance(priority_data, dict):
                epss = priority_data.get("epss")
                row.append(f"{epss*100:.2f}%" if epss else "")
            else:
                row.append("")
        elif col == "severity":
            row.append(finding.get("severity", "INFO"))
        elif col == "ruleId":
            row.append(finding.get("ruleId", ""))
        elif col == "path":
            location = finding.get("location", {})
            if isinstance(location, dict):
                row.append(location.get("path", ""))
            else:
                row.append("")
        elif col == "line":
            location = finding.get("location", {})
            if isinstance(location, dict):
                start_line = location.get("startLine", 0)
                row.append(str(start_line))
            else:
                row.append("0")
        elif col == "message":
            # Escape newlines and quotes for CSV
            msg = finding.get("message", "")
            # Replace newlines with spaces for single-line CSV cells
            msg = msg.replace("\n", " ").replace("\r", "")
            row.append(msg)
        elif col == "tool":
            tool_info = finding.get("tool", {})
            if isinstance(tool_info, dict):
                row.append(tool_info.get("name", ""))
            else:
                row.append("")
        elif col == "triaged":
            # TODO: Hook into history DB for triage state (Feature #3)
            # For now, placeholder
            row.append("NO")
        elif col == "compliance_owasp":
            compliance = finding.get("compliance", {})
            if isinstance(compliance, dict):
                owasp = compliance.get("owaspTop10_2021", [])
                row.append(", ".join(owasp) if owasp else "")
            else:
                row.append("")
        elif col == "compliance_cwe":
            compliance = finding.get("compliance", {})
            if isinstance(compliance, dict):
                cwe = compliance.get("cweTop25_2024", [])
                if cwe:
                    # Extract CWE IDs from dicts
                    cwe_ids = [
                        c["id"] if isinstance(c, dict) else str(c) for c in cwe
                    ]
                    row.append(", ".join(cwe_ids))
                else:
                    row.append("")
            else:
                row.append("")
        elif col == "compliance_cis":
            compliance = finding.get("compliance", {})
            if isinstance(compliance, dict):
                cis = compliance.get("cisControlsV8_1", [])
                if cis:
                    # Extract control IDs
                    controls = [
                        c["control"] if isinstance(c, dict) else str(c) for c in cis
                    ]
                    row.append(", ".join(controls))
                else:
                    row.append("")
            else:
                row.append("")
        elif col == "compliance_nist":
            compliance = finding.get("compliance", {})
            if isinstance(compliance, dict):
                nist = compliance.get("nistCsf2_0", [])
                if nist:
                    # Extract subcategories
                    subcats = [
                        n["subcategory"] if isinstance(n, dict) else str(n)
                        for n in nist
                    ]
                    row.append(", ".join(subcats))
                else:
                    row.append("")
            else:
                row.append("")
        elif col == "compliance_pci":
            compliance = finding.get("compliance", {})
            if isinstance(compliance, dict):
                pci = compliance.get("pciDss4_0", [])
                if pci:
                    # Extract requirements
                    reqs = [
                        p["requirement"] if isinstance(p, dict) else str(p) for p in pci
                    ]
                    row.append(", ".join(reqs))
                else:
                    row.append("")
            else:
                row.append("")
        elif col == "compliance_attack":
            compliance = finding.get("compliance", {})
            if isinstance(compliance, dict):
                attack = compliance.get("mitreAttack", [])
                if attack:
                    # Extract technique IDs
                    techniques = [
                        a["technique"] if isinstance(a, dict) else str(a)
                        for a in attack
                    ]
                    row.append(", ".join(techniques))
                else:
                    row.append("")
            else:
                row.append("")
        else:
            # Fallback: direct field access
            value = finding.get(col, "")
            row.append(str(value))

    return row
