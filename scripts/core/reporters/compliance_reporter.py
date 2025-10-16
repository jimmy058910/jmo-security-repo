#!/usr/bin/env python3
"""
Compliance-specific reporters for JMo Security Audit Tool Suite.

Generates compliance framework-specific reports:
- PCI DSS 4.0 Compliance Report
- MITRE ATT&CK Navigator JSON
- Compliance Summary Report (all frameworks)
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List


def write_pci_dss_report(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Generate PCI DSS 4.0 compliance report in Markdown format.

    Args:
        findings: List of CommonFindings (v1.2.0 with compliance field)
        output_path: Output file path for the report
    """
    # Filter findings with PCI DSS mappings
    pci_findings = [f for f in findings if f.get("compliance", {}).get("pciDss4_0")]

    # Group by requirement
    by_requirement = defaultdict(list)
    for f in pci_findings:
        pci_mappings = f.get("compliance", {}).get("pciDss4_0", [])
        for mapping in pci_mappings:
            req = mapping.get("requirement", "Unknown")
            by_requirement[req].append(
                {
                    "finding": f,
                    "description": mapping.get("description", ""),
                    "priority": mapping.get("priority", "MEDIUM"),
                }
            )

    # Count findings by severity
    total_critical = sum(1 for f in pci_findings if f.get("severity") == "CRITICAL")
    total_high = sum(1 for f in pci_findings if f.get("severity") == "HIGH")
    total_medium = sum(1 for f in pci_findings if f.get("severity") == "MEDIUM")
    total_low = sum(1 for f in pci_findings if f.get("severity") == "LOW")

    # Generate report
    lines = [
        "# PCI DSS 4.0 Compliance Report",
        "",
        f"**Total Findings:** {len(pci_findings)}",
        f"**Requirements Affected:** {len(by_requirement)}",
        "",
        "## Executive Summary",
        "",
        "| Severity | Count |",
        "|----------|-------|",
        f"| **CRITICAL** | {total_critical} |",
        f"| **HIGH** | {total_high} |",
        f"| **MEDIUM** | {total_medium} |",
        f"| **LOW** | {total_low} |",
        "",
        "## Findings by PCI DSS Requirement",
        "",
    ]

    # Sort requirements numerically
    sorted_requirements = sorted(
        by_requirement.keys(),
        key=lambda x: tuple(map(lambda y: int(y) if y.isdigit() else 0, x.split("."))),
    )

    for req in sorted_requirements:
        items = by_requirement[req]
        priority = items[0]["priority"] if items else "MEDIUM"
        description = items[0]["description"] if items else ""

        lines.append(f"### Requirement {req}: {description}")
        lines.append("")
        lines.append(f"**Priority:** {priority}")
        lines.append(f"**Findings:** {len(items)}")
        lines.append("")

        # Count by severity for this requirement
        req_critical = sum(
            1 for item in items if item["finding"].get("severity") == "CRITICAL"
        )
        req_high = sum(1 for item in items if item["finding"].get("severity") == "HIGH")
        req_medium = sum(
            1 for item in items if item["finding"].get("severity") == "MEDIUM"
        )

        if req_critical > 0:
            lines.append(f"- **CRITICAL**: {req_critical} findings")
        if req_high > 0:
            lines.append(f"- **HIGH**: {req_high} findings")
        if req_medium > 0:
            lines.append(f"- **MEDIUM**: {req_medium} findings")
        lines.append("")

        # List top 5 findings for this requirement
        if len(items) > 0:
            lines.append("**Top Findings:**")
            lines.append("")
            for i, item in enumerate(items[:5], 1):
                f = item["finding"]
                sev = f.get("severity", "UNKNOWN")
                rule_id = f.get("ruleId", "")
                msg = f.get("message", "")[:100]
                loc = f.get("location", {})
                path = (
                    loc.get("path", "unknown") if isinstance(loc, dict) else "unknown"
                )
                line = loc.get("startLine", 0) if isinstance(loc, dict) else 0

                lines.append(f"{i}. **[{sev}]** `{rule_id}` - {msg}")
                lines.append(f"   - Location: `{path}:{line}`")
                lines.append("")

        lines.append("---")
        lines.append("")

    # Recommendations section
    lines.extend(
        [
            "## Recommendations",
            "",
            "### Critical Actions Required",
            "",
        ]
    )

    # Group critical findings by requirement
    critical_by_req = defaultdict(int)
    for req, items in by_requirement.items():
        critical_count = sum(
            1 for item in items if item["finding"].get("severity") == "CRITICAL"
        )
        if critical_count > 0:
            critical_by_req[req] = critical_count

    if critical_by_req:
        lines.append(
            "The following PCI DSS requirements have CRITICAL findings that must be addressed immediately:"
        )
        lines.append("")
        for req, count in sorted(critical_by_req.items(), key=lambda x: -x[1]):
            description = by_requirement[req][0]["description"]
            lines.append(f"1. **Requirement {req}**: {description}")
            lines.append(f"   - {count} CRITICAL findings")
            lines.append("")
    else:
        lines.append(
            "No CRITICAL findings detected. Continue monitoring HIGH and MEDIUM findings."
        )
        lines.append("")

    lines.extend(
        [
            "### Compliance Status",
            "",
            "- **Requirements Passed**: N/A (manual validation required)",
            f"- **Requirements with Findings**: {len(by_requirement)}",
            "- **Requirements Not Tested**: N/A (scope determined by organization)",
            "",
            "### Next Steps",
            "",
            "1. **Remediate CRITICAL findings** within 24 hours (per PCI DSS remediation SLAs)",
            "2. **Remediate HIGH findings** within 7 days",
            "3. **Document compensating controls** for accepted risks",
            "4. **Re-scan** after remediation to verify fixes",
            "5. **Submit ASV scan report** to Qualified Security Assessor (if applicable)",
            "",
            "---",
            "",
            "*This report was generated by JMo Security Audit Tool Suite.*",
            "*Report generation date: Auto-generated*",
            "",
        ]
    )

    # Write report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")


def write_attack_navigator_json(
    findings: List[Dict[str, Any]], output_path: Path
) -> None:
    """Generate MITRE ATT&CK Navigator JSON for visualization.

    Args:
        findings: List of CommonFindings (v1.2.0 with compliance field)
        output_path: Output file path for the JSON
    """
    # Filter findings with ATT&CK mappings
    attack_findings = [
        f for f in findings if f.get("compliance", {}).get("mitreAttack")
    ]

    # Count techniques
    technique_counts = defaultdict(int)
    technique_metadata = {}

    for f in attack_findings:
        attack_mappings = f.get("compliance", {}).get("mitreAttack", [])
        for mapping in attack_mappings:
            tech_id = mapping.get("technique", "")
            if not tech_id:
                continue

            # Use subtechnique if available, else main technique
            sub_id = mapping.get("subtechnique", "")
            display_id = sub_id if sub_id else tech_id

            technique_counts[display_id] += 1

            if display_id not in technique_metadata:
                technique_metadata[display_id] = {
                    "technique": tech_id,
                    "subtechnique": sub_id,
                    "tactic": mapping.get("tactic", ""),
                    "techniqueName": mapping.get("techniqueName", ""),
                    "subtechniqueName": mapping.get("subtechniqueName", ""),
                }

    # Generate ATT&CK Navigator layer
    techniques_list = []
    max_count = max(technique_counts.values()) if technique_counts else 1

    for tech_id, count in technique_counts.items():
        meta = technique_metadata[tech_id]

        # Calculate score (0-100 based on finding count)
        score = min(100, (count / max_count) * 100)

        # Color based on severity
        if score >= 75:
            color = "#ff6666"  # Red (high)
        elif score >= 50:
            color = "#ff9966"  # Orange (medium-high)
        elif score >= 25:
            color = "#ffcc66"  # Yellow (medium)
        else:
            color = "#99ccff"  # Blue (low)

        techniques_list.append(
            {
                "techniqueID": tech_id,
                "tactic": meta["tactic"].lower().replace(" ", "-"),
                "score": score,
                "color": color,
                "comment": f"{count} finding(s) detected",
                "enabled": True,
                "metadata": [{"name": "Findings", "value": str(count)}],
                "showSubtechniques": bool(meta["subtechnique"]),
            }
        )

    # Build ATT&CK Navigator JSON
    navigator_layer = {
        "name": "JMo Security Scan Results",
        "versions": {"attack": "16", "navigator": "5.0.1", "layer": "4.5"},
        "domain": "enterprise-attack",
        "description": f"Security findings mapped to MITRE ATT&CK techniques. Total findings: {len(attack_findings)}, Techniques covered: {len(technique_counts)}",
        "filters": {"platforms": ["Linux", "macOS", "Windows", "Cloud", "Containers"]},
        "sorting": 3,
        "layout": {
            "layout": "side",
            "aggregateFunction": "average",
            "showID": True,
            "showName": True,
            "showAggregateScores": False,
            "countUnscored": False,
        },
        "hideDisabled": False,
        "techniques": techniques_list,
        "gradient": {
            "colors": ["#99ccff", "#ffcc66", "#ff9966", "#ff6666"],
            "minValue": 0,
            "maxValue": 100,
        },
        "legendItems": [
            {"label": f"Total Findings: {len(attack_findings)}", "color": "#ffffff"},
            {
                "label": f"Techniques Covered: {len(technique_counts)}",
                "color": "#ffffff",
            },
        ],
        "metadata": [
            {"name": "Generated by", "value": "JMo Security Audit Tool Suite"}
        ],
        "showTacticRowBackground": True,
        "tacticRowBackground": "#dddddd",
        "selectTechniquesAcrossTactics": True,
        "selectSubtechniquesWithParent": True,
    }

    # Write JSON
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(navigator_layer, indent=2), encoding="utf-8")


def write_compliance_summary(findings: List[Dict[str, Any]], output_path: Path) -> None:
    """Generate comprehensive compliance summary covering all frameworks.

    Args:
        findings: List of CommonFindings (v1.2.0 with compliance field)
        output_path: Output file path for the report
    """
    # Count findings with compliance mappings
    total_findings = len(findings)
    findings_with_compliance = sum(1 for f in findings if f.get("compliance"))

    # OWASP Top 10 2021 counts
    owasp_counts = defaultdict(int)
    for f in findings:
        owasp_list = f.get("compliance", {}).get("owaspTop10_2021", [])
        for owasp_cat in owasp_list:
            owasp_counts[owasp_cat] += 1

    # CWE Top 25 2024 counts
    cwe_top25_counts = defaultdict(int)
    for f in findings:
        cwe_list = f.get("compliance", {}).get("cweTop25_2024", [])
        for cwe_entry in cwe_list:
            if isinstance(cwe_entry, dict):
                cwe_id = cwe_entry.get("id", "")
                cwe_top25_counts[cwe_id] += 1

    # CIS Controls counts
    cis_controls = set()
    for f in findings:
        cis_list = f.get("compliance", {}).get("cisControlsV8_1", [])
        for cis_entry in cis_list:
            if isinstance(cis_entry, dict):
                control = cis_entry.get("control", "")
                cis_controls.add(control)

    # NIST CSF 2.0 counts by function
    nist_csf_functions = defaultdict(int)
    for f in findings:
        nist_list = f.get("compliance", {}).get("nistCsf2_0", [])
        for nist_entry in nist_list:
            if isinstance(nist_entry, dict):
                function = nist_entry.get("function", "")
                nist_csf_functions[function] += 1

    # PCI DSS 4.0 counts
    pci_dss_requirements = set()
    for f in findings:
        pci_list = f.get("compliance", {}).get("pciDss4_0", [])
        for pci_entry in pci_list:
            if isinstance(pci_entry, dict):
                req = pci_entry.get("requirement", "")
                pci_dss_requirements.add(req)

    # MITRE ATT&CK counts
    mitre_techniques = set()
    for f in findings:
        mitre_list = f.get("compliance", {}).get("mitreAttack", [])
        for mitre_entry in mitre_list:
            if isinstance(mitre_entry, dict):
                tech = mitre_entry.get("technique", "")
                mitre_techniques.add(tech)

    # Generate report
    lines = [
        "# Compliance Framework Summary",
        "",
        f"**Total Findings:** {total_findings}",
        f"**Findings with Compliance Mappings:** {findings_with_compliance} ({findings_with_compliance/total_findings*100 if total_findings else 0:.1f}%)",
        "",
        "## Framework Coverage",
        "",
        "| Framework | Coverage |",
        "|-----------|----------|",
        f"| **OWASP Top 10 2021** | {len(owasp_counts)}/10 categories |",
        f"| **CWE Top 25 2024** | {len(cwe_top25_counts)}/25 weaknesses |",
        f"| **CIS Controls v8.1** | {len(cis_controls)} controls |",
        f"| **NIST CSF 2.0** | {sum(nist_csf_functions.values())} mappings across {len(nist_csf_functions)} functions |",
        f"| **PCI DSS 4.0** | {len(pci_dss_requirements)} requirements |",
        f"| **MITRE ATT&CK** | {len(mitre_techniques)} techniques |",
        "",
    ]

    # OWASP Top 10 2021 breakdown
    if owasp_counts:
        lines.extend(
            [
                "## OWASP Top 10 2021",
                "",
                "| Category | Findings |",
                "|----------|----------|",
            ]
        )
        for cat in sorted(owasp_counts.keys()):
            count = owasp_counts[cat]
            lines.append(f"| {cat} | {count} |")
        lines.append("")

    # CWE Top 25 2024 breakdown (top 10)
    if cwe_top25_counts:
        lines.extend(
            [
                "## CWE Top 25 2024 (Top 10 Most Frequent)",
                "",
                "| CWE ID | Rank | Findings |",
                "|--------|------|----------|",
            ]
        )
        sorted_cwes = sorted(cwe_top25_counts.items(), key=lambda x: -x[1])[:10]
        for cwe_id, count in sorted_cwes:
            # Try to get rank from first finding with this CWE
            rank = "N/A"
            for f in findings:
                cwe_list = f.get("compliance", {}).get("cweTop25_2024", [])
                for cwe_entry in cwe_list:
                    if isinstance(cwe_entry, dict) and cwe_entry.get("id") == cwe_id:
                        rank = str(cwe_entry.get("rank", "N/A"))
                        break
                if rank != "N/A":
                    break
            lines.append(f"| {cwe_id} | {rank} | {count} |")
        lines.append("")

    # NIST CSF 2.0 breakdown
    if nist_csf_functions:
        lines.extend(
            [
                "## NIST Cybersecurity Framework 2.0",
                "",
                "| Function | Findings |",
                "|----------|----------|",
            ]
        )
        for func in ["GOVERN", "IDENTIFY", "PROTECT", "DETECT", "RESPOND", "RECOVER"]:
            count = nist_csf_functions.get(func, 0)
            if count > 0:
                lines.append(f"| {func} | {count} |")
        lines.append("")

    # PCI DSS 4.0 summary
    if pci_dss_requirements:
        lines.extend(
            [
                "## PCI DSS 4.0",
                "",
                f"**Requirements with Findings:** {len(pci_dss_requirements)}",
                "",
                "See `PCI_DSS_COMPLIANCE.md` for detailed PCI DSS compliance report.",
                "",
            ]
        )

    # MITRE ATT&CK summary
    if mitre_techniques:
        lines.extend(
            [
                "## MITRE ATT&CK",
                "",
                f"**Techniques Detected:** {len(mitre_techniques)}",
                "",
                "See `attack-navigator.json` for interactive ATT&CK Navigator visualization.",
                "",
                "**Top 5 Techniques:**",
                "",
            ]
        )

        # Count techniques across all findings
        tech_counts = defaultdict(int)
        tech_names = {}
        for f in findings:
            mitre_list = f.get("compliance", {}).get("mitreAttack", [])
            for mitre_entry in mitre_list:
                if isinstance(mitre_entry, dict):
                    tech = mitre_entry.get("technique", "")
                    if tech:
                        tech_counts[tech] += 1
                        tech_names[tech] = mitre_entry.get("techniqueName", "")

        sorted_techs = sorted(tech_counts.items(), key=lambda x: -x[1])[:5]
        for i, (tech, count) in enumerate(sorted_techs, 1):
            tech_name = tech_names.get(tech, "")
            lines.append(f"{i}. **{tech}** - {tech_name} ({count} findings)")

        lines.append("")

    lines.extend(
        [
            "---",
            "",
            "*Generated by JMo Security Audit Tool Suite*",
            "",
        ]
    )

    # Write report
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text("\n".join(lines), encoding="utf-8")
