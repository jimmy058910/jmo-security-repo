"""Markdown reporter for diff results (GitHub/GitLab PR comments)."""

from collections import defaultdict
from io import StringIO
from pathlib import Path
from typing import Dict, List

from scripts.core.diff_engine import DiffResult


# Emoji mapping for severities
SEVERITY_EMOJIS = {
    "CRITICAL": "🔴",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "🟢",
    "INFO": "ℹ️",
}

# Severity order for grouping
SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def write_markdown_diff(diff: DiffResult, out_path: Path) -> None:
    """
    Write human-readable Markdown report for PR comments.

    Args:
        diff: DiffResult object from DiffEngine
        out_path: Output file path for Markdown

    Output format:
        # 🔍 Security Diff Report
        ## 📊 Summary
        ## ⚠️ New Findings
        ## ✅ Resolved Findings
        ## 🔄 Modified Findings
    """
    md = StringIO()

    # Header
    _write_header(md, diff)

    # Summary table
    _write_summary(md, diff)

    # New findings (detailed, grouped by severity)
    if diff.new:
        _write_new_findings(md, diff)

    # Resolved findings (summary)
    if diff.resolved:
        _write_resolved_findings(md, diff)

    # Modified findings
    if diff.modified:
        _write_modified_findings(md, diff)

    # Footer
    _write_footer(md)

    # Write to file
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(md.getvalue())


def _write_header(md: StringIO, diff: DiffResult) -> None:
    """Write report header with metadata."""
    md.write("# 🔍 Security Diff Report\n\n")

    baseline_date = diff.baseline_source.timestamp[:10]
    current_date = diff.current_source.timestamp[:10]

    md.write(
        f"**Baseline:** `{diff.baseline_source.path}` "
        f"({baseline_date}, {diff.baseline_source.profile} profile)\n"
    )
    md.write(
        f"**Current:** `{diff.current_source.path}` "
        f"({current_date}, {diff.current_source.profile} profile)\n\n"
    )
    md.write("---\n\n")


def _write_summary(md: StringIO, diff: DiffResult) -> None:
    """Write summary statistics table."""
    md.write("## 📊 Summary\n\n")
    md.write("| Metric | Count | Change |\n")
    md.write("|--------|-------|--------|\n")

    stats = diff.statistics
    trend_emoji = {
        "improving": "✅",
        "worsening": "🔴",
        "stable": "➖",
    }.get(stats["trend"], "➖")

    md.write(
        f"| **New Findings** | {stats['total_new']} | 🔴 +{stats['total_new']} |\n"
    )
    md.write(
        f"| **Resolved Findings** | {stats['total_resolved']} | ✅ -{stats['total_resolved']} |\n"
    )
    md.write(
        f"| **Modified Findings** | {stats['total_modified']} | ⚠️ {stats['total_modified']} |\n"
    )

    net_sign = "+" if stats["net_change"] > 0 else ""
    md.write(
        f"| **Net Change** | {net_sign}{stats['net_change']} | {trend_emoji} {stats['trend'].capitalize()} |\n\n"
    )

    # Severity breakdown for new findings
    if stats.get("new_by_severity"):
        md.write("### New Findings by Severity\n")
        for sev in SEVERITY_ORDER:
            count = stats["new_by_severity"].get(sev, 0)
            if count > 0:
                emoji = SEVERITY_EMOJIS.get(sev, "❓")
                md.write(f"- {emoji} **{sev}**: {count}\n")
        md.write("\n")

    md.write("---\n\n")


def _write_new_findings(md: StringIO, diff: DiffResult) -> None:
    """Write new findings section (detailed, grouped by severity)."""
    stats = diff.statistics
    md.write(f"## ⚠️ New Findings ({stats['total_new']})\n\n")

    # Group by severity
    by_severity = _group_by_severity(diff.new)

    for severity in SEVERITY_ORDER:
        findings = by_severity.get(severity, [])
        if not findings:
            continue

        emoji = SEVERITY_EMOJIS.get(severity, "❓")
        md.write(f"### {emoji} {severity} ({len(findings)})\n\n")

        for finding in findings:
            _write_finding_details(md, finding)

        md.write("\n")

    md.write("---\n\n")


def _write_resolved_findings(md: StringIO, diff: DiffResult) -> None:
    """Write resolved findings section (summary)."""
    stats = diff.statistics
    md.write(f"## ✅ Resolved Findings ({stats['total_resolved']})\n\n")

    # Group by severity
    by_severity = _group_by_severity(diff.resolved)

    for severity in SEVERITY_ORDER:
        findings = by_severity.get(severity, [])
        if not findings:
            continue

        emoji = SEVERITY_EMOJIS.get(severity, "❓")
        md.write(f"### {emoji} {severity} ({len(findings)})\n\n")

        for finding in findings:
            location = finding.get("location", {})
            path = location.get("path", "unknown")
            line = location.get("startLine", "?")
            rule_id = finding.get("ruleId", "unknown")
            tool_name = finding.get("tool", {}).get("name", "unknown")
            message = finding.get("message", "")[:80]

            md.write(
                f"- ✅ **{message}** in `{path}:{line}` ({tool_name}, {rule_id})\n"
            )

        md.write("\n")

    md.write("---\n\n")


def _write_modified_findings(md: StringIO, diff: DiffResult) -> None:
    """Write modified findings section with before/after comparison."""
    stats = diff.statistics
    md.write(f"## 🔄 Modified Findings ({stats['total_modified']})\n\n")

    for mod in diff.modified:
        # Determine primary change type
        if "severity" in mod.changes:
            old_sev, new_sev = mod.changes["severity"]
            md.write(f"### ⚠️ Severity Upgraded: {old_sev} → {new_sev}\n\n")
        elif "priority" in mod.changes:
            old_pri, new_pri = mod.changes["priority"]
            md.write(f"### ⚠️ Priority Changed: {old_pri:.1f} → {new_pri:.1f}\n\n")
        elif "compliance_added" in mod.changes:
            added = mod.changes["compliance_added"]
            md.write(f"### 📋 Compliance Frameworks Added: {len(added)}\n\n")
        else:
            md.write("### 🔄 Metadata Changed\n\n")

        # Finding details
        current = mod.current
        location = current.get("location", {})
        path = location.get("path", "unknown")
        line = location.get("startLine", "?")
        rule_id = current.get("ruleId", "unknown")

        md.write(f"**Rule:** `{rule_id}`\n")
        md.write(f"**File:** `{path}:{line}`\n\n")

        # Changes summary
        md.write("**What changed:**\n")
        for change_type, change_value in mod.changes.items():
            if change_type == "severity":
                old, new = change_value
                md.write(f"- **Severity:** {old} → **{new}** (⚠️ {mod.risk_delta})\n")
            elif change_type == "priority":
                old, new = change_value
                md.write(
                    f"- **Priority:** {old:.1f} → {new:.1f} (⚠️ {mod.risk_delta})\n"
                )
            elif change_type == "compliance_added":
                md.write(f"- **Compliance:** +{len(change_value)} framework mappings\n")
            elif change_type == "cwe":
                old, new = change_value
                md.write(f"- **CWE:** {old} → {new}\n")
            elif change_type == "message":
                old, new = change_value
                md.write(f"- **Message:** Changed ({len(old)} → {len(new)} chars)\n")

        md.write("\n")

    md.write("---\n\n")


def _write_finding_details(md: StringIO, finding: Dict) -> None:
    """Write detailed finding information in collapsible details block."""
    location = finding.get("location", {})
    path = location.get("path", "unknown")
    line = location.get("startLine", "?")
    rule_id = finding.get("ruleId", "unknown")
    message = finding.get("message", "")
    tool = finding.get("tool", {})
    tool_name = tool.get("name", "unknown")
    tool_version = tool.get("version", "")

    # Collapsible details
    md.write("<details>\n")
    md.write(f"<summary><b>{message[:100]}</b></summary>\n\n")

    md.write(f"**Rule:** `{rule_id}`\n")
    md.write(f"**File:** `{path}:{line}`\n")
    md.write(f"**Tool:** {tool_name} v{tool_version}\n\n")

    md.write("**Message:**\n")
    md.write(f"{message}\n\n")

    # Remediation if available
    remediation = finding.get("remediation")
    if remediation:
        md.write("**Remediation:**\n")
        md.write(f"{remediation}\n\n")

    # Compliance frameworks if available
    compliance = finding.get("compliance", {})
    if compliance:
        md.write("**Compliance:**\n")
        if "owaspTop10_2021" in compliance and compliance["owaspTop10_2021"]:
            owasp = ", ".join(compliance["owaspTop10_2021"])
            md.write(f"- OWASP Top 10 2021: {owasp}\n")
        if "cweTop25_2024" in compliance and compliance["cweTop25_2024"]:
            cwe_items = compliance["cweTop25_2024"]
            if cwe_items:
                cwe_id = (
                    cwe_items[0].get("cweId", "")
                    if isinstance(cwe_items[0], dict)
                    else ""
                )
                rank = (
                    cwe_items[0].get("rank", "")
                    if isinstance(cwe_items[0], dict)
                    else ""
                )
                if cwe_id:
                    md.write(f"- CWE Top 25 2024: {cwe_id}, Rank #{rank}\n")
        md.write("\n")

    md.write("</details>\n\n")


def _write_footer(md: StringIO) -> None:
    """Write report footer."""
    md.write("**Generated by JMo Security v1.0.0**\n")


def _group_by_severity(findings: List[Dict]) -> Dict[str, List[Dict]]:
    """Group findings by severity level."""
    grouped: Dict[str, List[Dict]] = defaultdict(list)
    for finding in findings:
        severity = finding.get("severity", "INFO")
        grouped[severity].append(finding)
    return dict(grouped)
