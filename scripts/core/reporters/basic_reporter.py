#!/usr/bin/env python3
"""
Basic reporters for CommonFindings: JSON dump and Markdown summary
"""

from __future__ import annotations

import json
import platform
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SEV_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
SEV_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH": "🔴",
    "MEDIUM": "🟡",
    "LOW": "⚪",
    "INFO": "🔵",
}


def _get_jmo_version() -> str:
    """Read version from pyproject.toml.

    Returns:
        Version string (e.g., "1.0.0")
    """
    try:
        # Try tomllib first (Python 3.11+)
        try:
            import tomllib
        except ImportError:
            # Fallback to tomli for Python 3.10
            import tomli as tomllib

        pyproject_path = Path(__file__).parent.parent.parent.parent / "pyproject.toml"
        with open(pyproject_path, "rb") as f:
            pyproject = tomllib.load(f)
            return str(pyproject["project"]["version"])
    except Exception:
        # Fallback if pyproject.toml can't be read
        return "1.0.0"


def _generate_metadata(
    findings: list[dict[str, Any]],
    scan_id: str | None = None,
    profile: str | None = None,
    tools: list[str] | None = None,
    target_count: int | None = None,
) -> dict[str, Any]:
    """Generate metadata block for findings output.

    Args:
        findings: List of CommonFinding dictionaries
        scan_id: UUID of the scan (optional)
        profile: Profile name used (e.g., "balanced")
        tools: List of tool names used in scan
        target_count: Number of targets scanned

    Returns:
        Metadata dictionary with output version, jmo version, timestamp, etc.
    """
    return {
        "output_version": "1.0.0",
        "jmo_version": _get_jmo_version(),
        "schema_version": "1.2.0",
        "timestamp": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "scan_id": scan_id or "",
        "profile": profile or "",
        "tools": tools or [],
        "target_count": target_count or 0,
        "finding_count": len(findings),
        "platform": platform.system(),
    }


def write_json(
    findings: list[dict[str, Any]],
    out_path: str | Path,
    metadata: dict[str, Any] | None = None,
) -> None:
    """Write findings to JSON file with metadata wrapper.

    Args:
        findings: List of CommonFinding dictionaries
        out_path: Output file path
        metadata: Optional metadata dict (will be auto-generated if not provided)
    """
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)

    # Generate default metadata if not provided
    if metadata is None:
        metadata = _generate_metadata(findings)

    # Wrap findings in metadata structure (v1.0.0 format)
    output = {"meta": metadata, "findings": findings}

    p.write_text(
        json.dumps(output, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
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


def _get_top_issue_summary(findings_for_file: list[dict[str, Any]]) -> str:
    """Generate a summary of top issue for a file."""
    if not findings_for_file:
        return "N/A"

    # Group by rule to find most common issue
    rule_counts = Counter(f.get("ruleId", "unknown") for f in findings_for_file)
    top_rule, count = rule_counts.most_common(1)[0]

    # Simplify rule ID for display
    display_rule: str = str(top_rule.split(".")[-1] if "." in top_rule else top_rule)

    if count > 1:
        return f"{display_rule} ({count}×)"
    return display_rule


def _get_remediation_priorities(findings: list[dict[str, Any]]) -> list[str]:
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


def _get_category_summary(findings: list[dict[str, Any]]) -> dict[str, int]:
    """Group findings by category based on tags."""
    categories: dict[str, int] = defaultdict(int)

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


def to_markdown_summary(findings: list[dict[str, Any]]) -> str:
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
        file_findings: dict[str, list[dict[str, Any]]] = defaultdict(list)
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

    # Priority Analysis (EPSS/KEV) - Feature #5
    priority_findings = [f for f in findings if "priority" in f and f["priority"]]
    if priority_findings:
        lines.append("## Priority Analysis (EPSS/KEV)")
        lines.append("")
        lines.append("Real-world exploit intelligence to focus on actual threats:")
        lines.append("")

        # KEV findings (actively exploited)
        kev_findings = [
            f for f in priority_findings if f.get("priority", {}).get("is_kev", False)
        ]
        if kev_findings:
            lines.append(f"### ⚠️ CISA KEV: {len(kev_findings)} Actively Exploited")
            lines.append("")
            lines.append("These CVEs are being exploited in the wild **right now**:")
            lines.append("")

            # Sort KEV findings by priority score
            kev_findings.sort(
                key=lambda f: f.get("priority", {}).get("priority", 0), reverse=True
            )

            for f in kev_findings[:10]:  # Top 10 KEV findings
                priority_data = f.get("priority", {})
                rule_id = f.get("ruleId", "unknown")
                severity = f.get("severity", "HIGH")
                priority_score = priority_data.get("priority", 0)
                due_date = priority_data.get("kev_due_date", "N/A")
                path = f.get("location", {}).get("path", "unknown")

                emoji = _get_severity_emoji(severity)
                lines.append(
                    f"- {emoji} **{rule_id}** (Priority: {priority_score:.0f}/100, Due: {due_date})"
                )
                lines.append(f"  - File: `{_truncate_path(path)}`")

            lines.append("")

        # High EPSS findings (likely to be exploited)
        high_epss_findings = [
            f
            for f in priority_findings
            if (f.get("priority", {}).get("epss") or 0)
            > 0.5  # >50% exploit probability
            and not f.get("priority", {}).get(
                "is_kev", False
            )  # Exclude KEV (already shown)
        ]

        if high_epss_findings:
            lines.append(
                f"### 📊 High Exploit Probability: {len(high_epss_findings)} CVEs"
            )
            lines.append("")
            lines.append(
                "CVEs with >50% probability of being exploited in the next 30 days:"
            )
            lines.append("")

            # Sort by EPSS score
            high_epss_findings.sort(
                key=lambda f: f.get("priority", {}).get("epss", 0), reverse=True
            )

            for f in high_epss_findings[:10]:  # Top 10 high EPSS
                priority_data = f.get("priority", {})
                rule_id = f.get("ruleId", "unknown")
                severity = f.get("severity", "HIGH")
                epss = priority_data.get("epss", 0)
                percentile = priority_data.get("epss_percentile", 0)
                path = f.get("location", {}).get("path", "unknown")

                emoji = _get_severity_emoji(severity)
                lines.append(
                    f"- {emoji} **{rule_id}** (EPSS: {epss*100:.1f}%, {percentile*100:.0f}th percentile)"
                )
                lines.append(f"  - File: `{_truncate_path(path)}`")

            lines.append("")

        # Priority distribution
        priority_scores = [
            f.get("priority", {}).get("priority", 0) for f in priority_findings
        ]
        critical_priority = len([p for p in priority_scores if p >= 80])
        high_priority = len([p for p in priority_scores if 60 <= p < 80])
        medium_priority = len([p for p in priority_scores if 40 <= p < 60])
        low_priority = len([p for p in priority_scores if p < 40])

        lines.append("### Priority Distribution")
        lines.append("")
        lines.append(f"- 🔴 Critical Priority (≥80): {critical_priority}")
        lines.append(f"- 🟠 High Priority (60-79): {high_priority}")
        lines.append(f"- 🟡 Medium Priority (40-59): {medium_priority}")
        lines.append(f"- ⚪ Low Priority (<40): {low_priority}")
        lines.append("")

    # Cross-Tool Consensus (Phase 2 deduplication - v1.0.0)
    consensus_findings = [
        f for f in findings if "detected_by" in f and len(f.get("detected_by", [])) > 1
    ]
    if consensus_findings:
        lines.append("## Cross-Tool Consensus")
        lines.append("")
        lines.append(
            f"Found {len(consensus_findings)} issue{'s' if len(consensus_findings) > 1 else ''} "
            f"confirmed by multiple tools (Phase 2 deduplication):"
        )
        lines.append("")

        # Sort by number of tools detecting (most consensus first), then severity
        consensus_findings.sort(
            key=lambda f: (
                -len(f.get("detected_by", [])),
                SEV_ORDER.index(f.get("severity", "INFO")),
            )
        )

        for f in consensus_findings[:10]:  # Show top 10 consensus findings
            detected_by = f.get("detected_by", [])
            tool_names = [t.get("name", "unknown") for t in detected_by]
            count = len(tool_names)
            severity = f.get("severity", "INFO")
            emoji = _get_severity_emoji(severity)
            rule_id = f.get("ruleId", "unknown")
            path = f.get("location", {}).get("path", "unknown")

            lines.append(
                f"- {emoji} **{rule_id}** ({severity}) - detected by {count} tools: {', '.join(tool_names)}"
            )
            lines.append(f"  - File: `{_truncate_path(path)}`")

        lines.append("")

    # By Tool (with severity breakdown)
    if findings:
        lines.append("## By Tool")
        lines.append("")

        tool_severity: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        for f in findings:
            # For consensus findings, count once per detecting tool
            if "detected_by" in f:
                for tool_info in f.get("detected_by", []):
                    tool_name = tool_info.get("name", "unknown")
                    severity = f.get("severity", "INFO")
                    tool_severity[tool_name][severity] += 1
            else:
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


def write_markdown(findings: list[dict[str, Any]], out_path: str | Path) -> None:
    p = Path(out_path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(to_markdown_summary(findings), encoding="utf-8")
