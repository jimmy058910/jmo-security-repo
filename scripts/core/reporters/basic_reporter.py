#!/usr/bin/env python3
"""
Basic reporters for CommonFindings: JSON dump and Markdown summary
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Dict, List

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "⚪",
    "INFO": "🔵",
}


def write_json(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(
        json.dumps(findings, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )


def _get_severity_emoji(severity: str) -> str:
    """Get emoji badge for severity level."""
    return SEV_EMOJI.get(severity, "⚪")


def _truncate_path(path: str, max_len: int = 50) -> str:
    """Truncate long paths with ... in the middle."""
    if len(path) <= max_len:
        return path
    # Keep start and end, replace middle with ...
    keep = (max_len - 3) // 2
    return f"{path[:keep]}...{path[-keep:]}"


def _get_top_issue_summary(findings_for_file: List[Dict[str, Any]]) -> str:
    """Generate a summary of top issue for a file."""
    if not findings_for_file:
        return "N/A"

    # Group by rule to find most common issue
    rule_counts = Counter(f.get("ruleId", "unknown") for f in findings_for_file)
    top_rule, count = rule_counts.most_common(1)[0]

    # Simplify rule ID for display
    display_rule = top_rule.split(".")[-1] if "." in top_rule else top_rule

    if count > 1:
        return f"{display_rule} ({count}×)"
    return display_rule


def _get_remediation_priorities(findings: List[Dict[str, Any]]) -> List[str]:
    """Generate top 3-5 actionable remediation priorities."""
    priorities = []

    # Priority 1: Secrets (highest impact)
    secret_findings = [
        f
        for f in findings
        if "secret" in f.get("tags", []) or "secrets" in f.get("tags", [])
    ]
    if secret_findings:
        high_secrets = [
            f for f in secret_findings if f.get("severity") in ["CRITICAL", "HIGH"]
        ]
        if high_secrets:
            count = len(high_secrets)
            priorities.append(
                f"**Rotate {count} exposed secret{'s' if count > 1 else ''}** ({high_secrets[0].get('severity', 'HIGH')}) "
                f"→ See findings for rotation guide"
            )

    # Priority 2: Container security (common and actionable)
    container_findings = [
        f
        for f in findings
        if any(tag in f.get("tags", []) for tag in ["docker", "container", "iac"])
        or "dockerfile" in f.get("location", {}).get("path", "").lower()
        or "docker-compose" in f.get("location", {}).get("path", "").lower()
    ]
    if container_findings:
        high_container = [
            f for f in container_findings if f.get("severity") in ["CRITICAL", "HIGH"]
        ]
        if high_container:
            # Find most common issue
            rule_counts = Counter(f.get("ruleId", "unknown") for f in high_container)
            top_rule, count = rule_counts.most_common(1)[0]
            display_rule = top_rule.split(".")[-1] if "." in top_rule else top_rule
            priorities.append(
                f"**Fix {display_rule}** ({count} finding{'s' if count > 1 else ''}) → Review container security best practices"
            )

    # Priority 3: IaC misconfigurations
    iac_findings = [
        f
        for f in findings
        if any(
            tag in f.get("tags", [])
            for tag in ["iac", "terraform", "cloudformation", "kubernetes"]
        )
    ]
    if iac_findings and len(priorities) < 3:
        high_iac = [
            f for f in iac_findings if f.get("severity") in ["CRITICAL", "HIGH"]
        ]
        if high_iac:
            count = len(high_iac)
            priorities.append(
                f"**Harden IaC configurations** ({count} finding{'s' if count > 1 else ''}) → Apply security templates"
            )

    # Priority 4: Code quality / SAST findings
    sast_findings = [
        f
        for f in findings
        if any(tag in f.get("tags", []) for tag in ["sast", "code-quality", "security"])
        and not any(tag in f.get("tags", []) for tag in ["secret", "secrets", "iac"])
    ]
    if sast_findings and len(priorities) < 5:
        high_sast = [
            f for f in sast_findings if f.get("severity") in ["CRITICAL", "HIGH"]
        ]
        if high_sast:
            count = len(high_sast)
            priorities.append(
                f"**Address {count} code security issue{'s' if count > 1 else ''}** → Review SAST findings"
            )

    # Priority 5: Dependency vulnerabilities
    vuln_findings = [
        f
        for f in findings
        if any(
            tag in f.get("tags", []) for tag in ["vulnerability", "cve", "dependency"]
        )
    ]
    if vuln_findings and len(priorities) < 5:
        critical_vulns = [f for f in vuln_findings if f.get("severity") == "CRITICAL"]
        high_vulns = [f for f in vuln_findings if f.get("severity") == "HIGH"]
        if critical_vulns or high_vulns:
            count = len(critical_vulns) + len(high_vulns)
            priorities.append(
                f"**Update vulnerable dependencies** ({count} CRITICAL/HIGH CVE{'s' if count > 1 else ''}) → Run package updates"
            )

    return priorities[:5]  # Limit to top 5


def _get_category_summary(findings: List[Dict[str, Any]]) -> Dict[str, int]:
    """Group findings by category based on tags."""
    categories: Dict[str, int] = defaultdict(int)

    for f in findings:
        tags = f.get("tags", [])

        # Categorize based on tags (priority order matters)
        if any(tag in tags for tag in ["secret", "secrets"]):
            categories["🔑 Secrets"] += 1
        elif any(tag in tags for tag in ["vulnerability", "cve", "dependency"]):
            categories["🛡️ Vulnerabilities"] += 1
        elif any(
            tag in tags
            for tag in ["docker", "container", "iac", "terraform", "kubernetes"]
        ):
            categories["🐳 IaC/Container"] += 1
        elif any(tag in tags for tag in ["sast", "code-quality"]):
            categories["🔧 Code Quality"] += 1
        else:
            # Fallback: try to infer from tool or rule
            tool = f.get("tool", {}).get("name", "").lower()
            rule = f.get("ruleId", "").lower()

            if (
                tool in ["gitleaks", "trufflehog", "noseyparker"]
                or "secret" in rule
                or "key" in rule
            ):
                categories["🔑 Secrets"] += 1
            elif tool in ["trivy", "osv-scanner", "grype"] or "cve" in rule:
                categories["🛡️ Vulnerabilities"] += 1
            elif (
                tool in ["hadolint", "checkov", "tfsec"]
                or "dockerfile" in rule
                or "terraform" in rule
            ):
                categories["🐳 IaC/Container"] += 1
            elif tool in ["semgrep", "bandit", "eslint"]:
                categories["🔧 Code Quality"] += 1
            else:
                categories["📦 Other"] += 1

    return dict(sorted(categories.items(), key=lambda x: x[1], reverse=True))


def to_markdown_summary(findings: List[Dict[str, Any]]) -> str:
    """Generate enhanced markdown summary with actionable insights."""
    total = len(findings)
    sev_counts = Counter(f.get("severity", "INFO") for f in findings)

    lines = ["# Security Summary", ""]

    # Enhanced header with emoji badges
    severity_badges = []
    for sev in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        count = sev_counts.get(sev, 0)
        if count > 0:
            emoji = _get_severity_emoji(sev)
            severity_badges.append(f"{emoji} {count} {sev}")

    if severity_badges:
        lines.append(f"Total findings: {total} | {' | '.join(severity_badges)}")
    else:
        lines.append(f"Total findings: {total}")
    lines.append("")

    # Top Risks by File (if we have findings)
    if findings:
        lines.append("## Top Risks by File")
        lines.append("")

        # Group by file
        file_findings: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
        for f in findings:
            path = f.get("location", {}).get("path", "unknown")
            file_findings[path].append(f)

        # Sort files by: 1) highest severity, 2) count
        def file_sort_key(item):
            path, file_finds = item
            max_sev_idx = min(
                SEV_ORDER.index(f.get("severity", "INFO")) for f in file_finds
            )
            return (max_sev_idx, -len(file_finds))

        sorted_files = sorted(file_findings.items(), key=file_sort_key)

        # Show top 10 files
        lines.append("| File | Findings | Severity | Top Issue |")
        lines.append("|------|----------|----------|-----------|")

        for path, file_finds in sorted_files[:10]:
            count = len(file_finds)
            # Get highest severity
            max_sev = "INFO"
            for sev in SEV_ORDER:
                if any(f.get("severity") == sev for f in file_finds):
                    max_sev = sev
                    break
            emoji = _get_severity_emoji(max_sev)
            truncated_path = _truncate_path(path)
            top_issue = _get_top_issue_summary(file_finds)

            lines.append(
                f"| {truncated_path} | {count} | {emoji} {max_sev} | {top_issue} |"
            )

        lines.append("")

    # By Severity (traditional breakdown)
    lines.append("## By Severity")
    lines.append("")
    for sev in SEV_ORDER:
        count = sev_counts.get(sev, 0)
        emoji = _get_severity_emoji(sev)
        lines.append(f"- {emoji} {sev}: {count}")
    lines.append("")

    # By Tool (with severity breakdown)
    if findings:
        lines.append("## By Tool")
        lines.append("")

        tool_severity: Dict[str, Dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for f in findings:
            tool_name = f.get("tool", {}).get("name", "unknown")
            severity = f.get("severity", "INFO")
            tool_severity[tool_name][severity] += 1

        # Sort tools by total findings
        sorted_tools = sorted(
            tool_severity.items(), key=lambda x: sum(x[1].values()), reverse=True
        )

        for tool, sev_counts_tool in sorted_tools:
            total_tool = sum(sev_counts_tool.values())
            # Build severity breakdown string
            sev_parts = []
            for sev in SEV_ORDER:
                count = sev_counts_tool.get(sev, 0)
                if count > 0:
                    emoji = _get_severity_emoji(sev)
                    sev_parts.append(f"{emoji} {count} {sev}")

            sev_str = ", ".join(sev_parts) if sev_parts else "INFO"
            lines.append(
                f"- **{tool}**: {total_tool} finding{'s' if total_tool > 1 else ''} ({sev_str})"
            )

        lines.append("")

    # Remediation Priorities (actionable next steps)
    priorities = _get_remediation_priorities(findings)
    if priorities:
        lines.append("## Remediation Priorities")
        lines.append("")
        for i, priority in enumerate(priorities, 1):
            lines.append(f"{i}. {priority}")
        lines.append("")

    # By Category (tags-based grouping)
    categories = _get_category_summary(findings)
    if categories:
        lines.append("## By Category")
        lines.append("")
        for category, count in categories.items():
            percentage = (count / total * 100) if total > 0 else 0
            lines.append(
                f"- {category}: {count} finding{'s' if count > 1 else ''} ({percentage:.0f}% of total)"
            )
        lines.append("")

    # Top Rules (traditional - keep for reference)
    lines.append("## Top Rules")
    lines.append("")
    top_rules = Counter(f.get("ruleId", "unknown") for f in findings).most_common(10)
    for rule, count in top_rules:
        # Simplify long rule IDs
        display_rule = rule.split(".")[-1] if len(rule) > 40 and "." in rule else rule
        if display_rule != rule:
            lines.append(f"- {display_rule}: {count} *(full: {rule})*")
        else:
            lines.append(f"- {rule}: {count}")
    lines.append("")

    return "\n".join(lines)


def write_markdown(findings: List[Dict[str, Any]], out_path: str | Path) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(to_markdown_summary(findings), encoding="utf-8")
