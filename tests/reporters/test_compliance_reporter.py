"""Comprehensive tests for compliance_reporter module.

This test suite achieves 95%+ coverage by testing:
1. PCI DSS 4.0 report generation
2. MITRE ATT&CK Navigator JSON generation
3. Compliance summary report generation
4. Edge cases and error handling
5. Output format validation
"""

import json
from pathlib import Path
from typing import Any, Dict, Optional

from scripts.core.reporters.compliance_reporter import (
    write_attack_navigator_json,
    write_compliance_summary,
    write_pci_dss_report,
)


def create_finding(
    rule_id: str = "test-rule",
    severity: str = "HIGH",
    message: str = "Test finding",
    path: str = "test.py",
    line: int = 10,
    compliance: Optional[Dict[str, Any]] = None,
    **kwargs: Any,
) -> Dict[str, Any]:
    """Helper to create a test finding with compliance mappings."""
    finding: Dict[str, Any] = {
        "schemaVersion": "1.2.0",
        "id": f"test-{rule_id}",
        "ruleId": rule_id,
        "severity": severity,
        "message": message,
        "tool": {"name": "test-tool", "version": "1.0.0"},
        "location": {"path": path, "startLine": line},
        "tags": [],
    }
    if compliance:
        finding["compliance"] = compliance
    finding.update(kwargs)
    return finding


# ========== Category 1: PCI DSS Report Generation ==========


def test_pci_dss_basic(tmp_path: Path):
    """Test basic PCI DSS report generation."""
    findings = [
        create_finding(
            rule_id="hardcoded-key",
            severity="CRITICAL",
            compliance={
                "pciDss4_0": [
                    {
                        "requirement": "8.3.2",
                        "description": "Cryptographic keys must be secured",
                        "priority": "CRITICAL",
                    }
                ]
            },
        ),
        create_finding(
            rule_id="weak-crypto",
            severity="HIGH",
            compliance={
                "pciDss4_0": [
                    {
                        "requirement": "4.2.1",
                        "description": "Strong cryptography must be used",
                        "priority": "HIGH",
                    }
                ]
            },
        ),
    ]

    output = tmp_path / "pci_dss.md"
    write_pci_dss_report(findings, output)

    assert output.exists()
    content = output.read_text()

    # Verify structure
    assert "# PCI DSS 4.0 Compliance Report" in content
    assert "**Total Findings:** 2" in content
    assert "**Requirements Affected:** 2" in content

    # Verify executive summary
    assert "## Executive Summary" in content
    assert "**CRITICAL** | 1" in content
    assert "**HIGH** | 1" in content

    # Verify requirements sections
    assert "### Requirement 4.2.1:" in content
    assert "### Requirement 8.3.2:" in content


def test_pci_dss_empty_findings(tmp_path: Path):
    """Test PCI DSS report with no findings."""
    output = tmp_path / "pci_dss_empty.md"
    write_pci_dss_report([], output)

    assert output.exists()
    content = output.read_text()

    assert "**Total Findings:** 0" in content
    assert "**Requirements Affected:** 0" in content
    assert "No CRITICAL findings detected" in content


def test_pci_dss_no_compliance_mappings(tmp_path: Path):
    """Test PCI DSS report with findings but no PCI DSS mappings."""
    findings = [
        create_finding(rule_id="test", compliance={"owaspTop10_2021": ["A03:2021"]})
    ]

    output = tmp_path / "pci_dss_no_mappings.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    assert "**Total Findings:** 0" in content


def test_pci_dss_multiple_findings_same_requirement(tmp_path: Path):
    """Test PCI DSS report with multiple findings for same requirement."""
    findings = [
        create_finding(
            rule_id=f"vuln-{i}",
            severity="HIGH",
            compliance={
                "pciDss4_0": [
                    {
                        "requirement": "6.2.4",
                        "description": "Secure software development",
                        "priority": "HIGH",
                    }
                ]
            },
        )
        for i in range(10)
    ]

    output = tmp_path / "pci_dss_multi.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    assert "**Total Findings:** 10" in content
    assert "**Requirements Affected:** 1" in content
    assert "**Findings:** 10" in content
    # Should only show top 5
    assert "1. **[HIGH]**" in content
    assert "5. **[HIGH]**" in content


def test_pci_dss_sorting_requirements(tmp_path: Path):
    """Test PCI DSS requirements are sorted numerically."""
    findings = [
        create_finding(
            rule_id="req2",
            compliance={
                "pciDss4_0": [
                    {"requirement": "2.1.1", "description": "Req 2", "priority": "HIGH"}
                ]
            },
        ),
        create_finding(
            rule_id="req10",
            compliance={
                "pciDss4_0": [
                    {
                        "requirement": "10.2.1",
                        "description": "Req 10",
                        "priority": "MEDIUM",
                    }
                ]
            },
        ),
        create_finding(
            rule_id="req1",
            compliance={
                "pciDss4_0": [
                    {"requirement": "1.4.1", "description": "Req 1", "priority": "LOW"}
                ]
            },
        ),
    ]

    output = tmp_path / "pci_dss_sorted.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    # Check order appears correctly
    req1_pos = content.find("Requirement 1.4.1")
    req2_pos = content.find("Requirement 2.1.1")
    req10_pos = content.find("Requirement 10.2.1")

    assert req1_pos < req2_pos < req10_pos


def test_pci_dss_critical_recommendations(tmp_path: Path):
    """Test critical findings appear in recommendations section."""
    findings = [
        create_finding(
            rule_id="critical1",
            severity="CRITICAL",
            compliance={
                "pciDss4_0": [
                    {
                        "requirement": "8.3.2",
                        "description": "Key management",
                        "priority": "CRITICAL",
                    }
                ]
            },
        ),
        create_finding(
            rule_id="critical2",
            severity="CRITICAL",
            compliance={
                "pciDss4_0": [
                    {
                        "requirement": "8.3.2",
                        "description": "Key management",
                        "priority": "CRITICAL",
                    }
                ]
            },
        ),
        create_finding(
            rule_id="low1",
            severity="LOW",
            compliance={
                "pciDss4_0": [
                    {"requirement": "1.1.1", "description": "Docs", "priority": "LOW"}
                ]
            },
        ),
    ]

    output = tmp_path / "pci_dss_critical.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    assert "## Recommendations" in content
    assert "### Critical Actions Required" in content
    assert "**Requirement 8.3.2**" in content
    assert "2 CRITICAL findings" in content


def test_pci_dss_location_missing_fields(tmp_path: Path):
    """Test handling of missing location fields."""
    findings = [
        create_finding(
            rule_id="no-location",
            compliance={
                "pciDss4_0": [
                    {"requirement": "1.1.1", "description": "Test", "priority": "LOW"}
                ]
            },
        )
    ]
    # Remove location
    findings[0]["location"] = {}

    output = tmp_path / "pci_dss_no_loc.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    assert "Location: `unknown:0`" in content


def test_pci_dss_location_as_string(tmp_path: Path):
    """Test handling when location is string instead of dict."""
    findings = [
        create_finding(
            rule_id="string-loc",
            compliance={
                "pciDss4_0": [
                    {"requirement": "1.1.1", "description": "Test", "priority": "LOW"}
                ]
            },
        )
    ]
    findings[0]["location"] = "string instead of dict"

    output = tmp_path / "pci_dss_string_loc.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    assert "Location: `unknown:0`" in content


# ========== Category 2: MITRE ATT&CK Navigator JSON Generation ==========


def test_attack_navigator_basic(tmp_path: Path):
    """Test basic ATT&CK Navigator JSON generation."""
    findings = [
        create_finding(
            rule_id="cred-access",
            compliance={
                "mitreAttack": [
                    {
                        "technique": "T1003",
                        "subtechnique": "T1003.001",
                        "tactic": "Credential Access",
                        "techniqueName": "OS Credential Dumping",
                        "subtechniqueName": "LSASS Memory",
                    }
                ]
            },
        ),
        create_finding(
            rule_id="exec",
            compliance={
                "mitreAttack": [
                    {
                        "technique": "T1059",
                        "subtechnique": "",
                        "tactic": "Execution",
                        "techniqueName": "Command and Scripting Interpreter",
                        "subtechniqueName": "",
                    }
                ]
            },
        ),
    ]

    output = tmp_path / "attack-navigator.json"
    write_attack_navigator_json(findings, output)

    assert output.exists()
    data = json.loads(output.read_text())

    # Verify structure
    assert data["name"] == "JMo Security Scan Results"
    assert data["domain"] == "enterprise-attack"
    assert "techniques" in data

    # Verify techniques
    assert len(data["techniques"]) == 2
    tech_ids = [t["techniqueID"] for t in data["techniques"]]
    assert "T1003.001" in tech_ids  # Subtechnique
    assert "T1059" in tech_ids  # Main technique

    # Verify metadata
    assert data["techniques"][0]["metadata"][0]["value"] == "1"


def test_attack_navigator_empty_findings(tmp_path: Path):
    """Test ATT&CK Navigator with no findings."""
    output = tmp_path / "attack-empty.json"
    write_attack_navigator_json([], output)

    data = json.loads(output.read_text())
    assert len(data["techniques"]) == 0
    assert "Total findings: 0" in data["description"]


def test_attack_navigator_no_mitre_mappings(tmp_path: Path):
    """Test ATT&CK Navigator with no MITRE mappings."""
    findings = [create_finding(compliance={"owaspTop10_2021": ["A03:2021"]})]

    output = tmp_path / "attack-no-mitre.json"
    write_attack_navigator_json(findings, output)

    data = json.loads(output.read_text())
    assert len(data["techniques"]) == 0


def test_attack_navigator_scoring_and_colors(tmp_path: Path):
    """Test ATT&CK Navigator scoring and color assignment."""
    # Create 10 findings for T1059 (max count)
    findings = [
        create_finding(
            rule_id=f"exec-{i}",
            compliance={
                "mitreAttack": [
                    {
                        "technique": "T1059",
                        "subtechnique": "",
                        "tactic": "Execution",
                        "techniqueName": "Command Interpreter",
                        "subtechniqueName": "",
                    }
                ]
            },
        )
        for i in range(10)
    ]

    # Add 1 finding for T1003 (min count)
    findings.append(
        create_finding(
            rule_id="cred",
            compliance={
                "mitreAttack": [
                    {
                        "technique": "T1003",
                        "subtechnique": "",
                        "tactic": "Credential Access",
                        "techniqueName": "Credential Dumping",
                        "subtechniqueName": "",
                    }
                ]
            },
        )
    )

    output = tmp_path / "attack-scores.json"
    write_attack_navigator_json(findings, output)

    data = json.loads(output.read_text())

    # T1059 should have score 100 (max)
    t1059 = next(t for t in data["techniques"] if t["techniqueID"] == "T1059")
    assert t1059["score"] == 100
    assert t1059["color"] == "#ff6666"  # Red (high)
    assert t1059["comment"] == "10 finding(s) detected"

    # T1003 should have score 10 (min relative to max)
    t1003 = next(t for t in data["techniques"] if t["techniqueID"] == "T1003")
    assert t1003["score"] == 10
    assert t1003["color"] == "#99ccff"  # Blue (low)


def test_attack_navigator_missing_technique_id(tmp_path: Path):
    """Test handling of missing technique IDs."""
    findings = [
        create_finding(
            rule_id="no-tech",
            compliance={
                "mitreAttack": [
                    {
                        "technique": "",  # Missing
                        "tactic": "Execution",
                        "techniqueName": "Unknown",
                        "subtechniqueName": "",
                    }
                ]
            },
        )
    ]

    output = tmp_path / "attack-no-tech.json"
    write_attack_navigator_json(findings, output)

    data = json.loads(output.read_text())
    # Should skip findings without technique ID
    assert len(data["techniques"]) == 0


def test_attack_navigator_tactic_formatting(tmp_path: Path):
    """Test tactic name formatting (spaces to hyphens, lowercase)."""
    findings = [
        create_finding(
            compliance={
                "mitreAttack": [
                    {
                        "technique": "T1190",
                        "subtechnique": "",
                        "tactic": "Initial Access",  # Space in name
                        "techniqueName": "Exploit Public-Facing Application",
                        "subtechniqueName": "",
                    }
                ]
            }
        )
    ]

    output = tmp_path / "attack-tactic.json"
    write_attack_navigator_json(findings, output)

    data = json.loads(output.read_text())
    assert data["techniques"][0]["tactic"] == "initial-access"


# ========== Category 3: Compliance Summary Report ==========


def test_compliance_summary_basic(tmp_path: Path):
    """Test basic compliance summary generation."""
    findings = [
        create_finding(
            rule_id="xss",
            compliance={
                "owaspTop10_2021": ["A03:2021"],
                "cweTop25_2024": [{"id": "CWE-79", "rank": 1, "category": "Injection"}],
                "cisControlsV8_1": [
                    {
                        "control": "16.2",
                        "implementationGroup": "IG1",
                        "title": "Secure Development",
                    }
                ],
                "nistCsf2_0": [
                    {
                        "function": "PROTECT",
                        "category": "PR.DS",
                        "subcategory": "PR.DS-2",
                        "description": "Data-in-transit is protected",
                    }
                ],
                "pciDss4_0": [
                    {
                        "requirement": "6.2.4",
                        "description": "Secure development",
                        "priority": "HIGH",
                    }
                ],
                "mitreAttack": [
                    {
                        "technique": "T1059",
                        "subtechnique": "",
                        "tactic": "Execution",
                        "techniqueName": "Command Interpreter",
                        "subtechniqueName": "",
                    }
                ],
            },
        )
    ]

    output = tmp_path / "compliance-summary.md"
    write_compliance_summary(findings, output)

    assert output.exists()
    content = output.read_text()

    # Verify structure
    assert "# Compliance Framework Summary" in content
    assert "**Total Findings:** 1" in content
    assert "**Findings with Compliance Mappings:** 1 (100.0%)" in content

    # Verify all frameworks present
    assert "## Framework Coverage" in content
    assert "**OWASP Top 10 2021** | 1/10 categories" in content
    assert "**CWE Top 25 2024** | 1/25 weaknesses" in content
    assert "**CIS Controls v8.1** | 1 controls" in content
    assert "**NIST CSF 2.0**" in content
    assert "**PCI DSS 4.0** | 1 requirements" in content
    assert "**MITRE ATT&CK** | 1 techniques" in content


def test_compliance_summary_empty_findings(tmp_path: Path):
    """Test compliance summary with no findings."""
    output = tmp_path / "compliance-empty.md"
    write_compliance_summary([], output)

    content = output.read_text()
    assert "**Total Findings:** 0" in content
    assert "**Findings with Compliance Mappings:** 0" in content


def test_compliance_summary_no_compliance_field(tmp_path: Path):
    """Test compliance summary with findings but no compliance field."""
    findings = [create_finding(rule_id="test")]

    output = tmp_path / "compliance-no-field.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    assert "**Total Findings:** 1" in content
    assert "**Findings with Compliance Mappings:** 0 (0.0%)" in content


def test_compliance_summary_owasp_breakdown(tmp_path: Path):
    """Test OWASP Top 10 breakdown section."""
    findings = [
        create_finding(
            rule_id="xss1",
            compliance={"owaspTop10_2021": ["A03:2021"]},
        ),
        create_finding(
            rule_id="xss2",
            compliance={"owaspTop10_2021": ["A03:2021"]},
        ),
        create_finding(
            rule_id="auth",
            compliance={"owaspTop10_2021": ["A01:2021"]},
        ),
    ]

    output = tmp_path / "compliance-owasp.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    assert "## OWASP Top 10 2021" in content
    assert "| A01:2021 | 1 |" in content
    assert "| A03:2021 | 2 |" in content


def test_compliance_summary_cwe_top25_top10(tmp_path: Path):
    """Test CWE Top 25 shows only top 10 most frequent."""
    findings = [
        create_finding(
            rule_id=f"vuln-{i}",
            compliance={
                "cweTop25_2024": [{"id": f"CWE-{i}", "rank": i, "category": "Test"}]
            },
        )
        for i in range(1, 26)  # 25 different CWEs
    ]

    output = tmp_path / "compliance-cwe.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    assert "## CWE Top 25 2024 (Top 10 Most Frequent)" in content
    # Should show exactly 10 entries
    lines = [line for line in content.split("\n") if line.startswith("| CWE-")]
    assert len(lines) == 10


def test_compliance_summary_nist_csf_functions(tmp_path: Path):
    """Test NIST CSF 2.0 function breakdown."""
    findings = [
        create_finding(
            rule_id="protect",
            compliance={
                "nistCsf2_0": [
                    {
                        "function": "PROTECT",
                        "category": "PR.DS",
                        "subcategory": "PR.DS-1",
                        "description": "Test",
                    }
                ]
            },
        ),
        create_finding(
            rule_id="detect",
            compliance={
                "nistCsf2_0": [
                    {
                        "function": "DETECT",
                        "category": "DE.CM",
                        "subcategory": "DE.CM-1",
                        "description": "Test",
                    }
                ]
            },
        ),
    ]

    output = tmp_path / "compliance-nist.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    assert "## NIST Cybersecurity Framework 2.0" in content
    assert "| PROTECT | 1 |" in content
    assert "| DETECT | 1 |" in content


def test_compliance_summary_pci_dss_summary(tmp_path: Path):
    """Test PCI DSS summary section."""
    findings = [
        create_finding(
            compliance={
                "pciDss4_0": [
                    {
                        "requirement": "6.2.4",
                        "description": "Secure development",
                        "priority": "HIGH",
                    }
                ]
            }
        )
    ]

    output = tmp_path / "compliance-pci.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    assert "## PCI DSS 4.0" in content
    assert "**Requirements with Findings:** 1" in content
    assert "See `PCI_DSS_COMPLIANCE.md`" in content


def test_compliance_summary_mitre_top5(tmp_path: Path):
    """Test MITRE ATT&CK top 5 techniques."""
    # Create findings with different technique counts
    findings = []
    for i in range(10):
        findings.append(
            create_finding(
                rule_id=f"t1059-{i}",
                compliance={
                    "mitreAttack": [
                        {
                            "technique": "T1059",
                            "subtechnique": "",
                            "tactic": "Execution",
                            "techniqueName": "Command Interpreter",
                            "subtechniqueName": "",
                        }
                    ]
                },
            )
        )

    for i in range(5):
        findings.append(
            create_finding(
                rule_id=f"t1003-{i}",
                compliance={
                    "mitreAttack": [
                        {
                            "technique": "T1003",
                            "subtechnique": "",
                            "tactic": "Credential Access",
                            "techniqueName": "Credential Dumping",
                            "subtechniqueName": "",
                        }
                    ]
                },
            )
        )

    output = tmp_path / "compliance-mitre.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    assert "## MITRE ATT&CK" in content
    assert "**Techniques Detected:** 2" in content
    assert "**Top 5 Techniques:**" in content
    assert "1. **T1059** - Command Interpreter (10 findings)" in content
    assert "2. **T1003** - Credential Dumping (5 findings)" in content


# ========== Category 4: Edge Cases ==========


def test_pci_dss_creates_parent_directory(tmp_path: Path):
    """Test PCI DSS report creates parent directories."""
    nested_output = tmp_path / "nested" / "dir" / "pci_dss.md"
    write_pci_dss_report([], nested_output)
    assert nested_output.exists()


def test_attack_navigator_creates_parent_directory(tmp_path: Path):
    """Test ATT&CK Navigator creates parent directories."""
    nested_output = tmp_path / "nested" / "dir" / "attack.json"
    write_attack_navigator_json([], nested_output)
    assert nested_output.exists()


def test_compliance_summary_creates_parent_directory(tmp_path: Path):
    """Test compliance summary creates parent directories."""
    nested_output = tmp_path / "nested" / "dir" / "summary.md"
    write_compliance_summary([], nested_output)
    assert nested_output.exists()


def test_pci_dss_unicode_handling(tmp_path: Path):
    """Test PCI DSS report handles Unicode characters."""
    findings = [
        create_finding(
            rule_id="unicode-test",
            message="Test with emoji 🔒 and Chinese: 安全漏洞",
            compliance={
                "pciDss4_0": [
                    {"requirement": "1.1.1", "description": "Test", "priority": "LOW"}
                ]
            },
        )
    ]

    output = tmp_path / "pci_unicode.md"
    write_pci_dss_report(findings, output)

    content = output.read_text(encoding="utf-8")
    assert "🔒" in content
    assert "安全漏洞" in content


def test_compliance_summary_percentage_calculation(tmp_path: Path):
    """Test compliance summary calculates percentages correctly."""
    # 3 findings total, 2 with compliance
    findings = [
        create_finding(compliance={"owaspTop10_2021": ["A03:2021"]}),
        create_finding(compliance={"owaspTop10_2021": ["A01:2021"]}),
        create_finding(),  # No compliance
    ]

    output = tmp_path / "compliance-pct.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    assert "**Total Findings:** 3" in content
    assert "**Findings with Compliance Mappings:** 2 (66.7%)" in content


def test_attack_navigator_max_score_capping(tmp_path: Path):
    """Test ATT&CK Navigator caps scores at 100."""
    findings = [
        create_finding(
            rule_id=f"finding-{i}",
            compliance={
                "mitreAttack": [
                    {
                        "technique": "T1059",
                        "subtechnique": "",
                        "tactic": "Execution",
                        "techniqueName": "Test",
                        "subtechniqueName": "",
                    }
                ]
            },
        )
        for i in range(1000)  # Very high count
    ]

    output = tmp_path / "attack-max-score.json"
    write_attack_navigator_json(findings, output)

    data = json.loads(output.read_text())
    # Score should be capped at 100
    assert data["techniques"][0]["score"] == 100


def test_pci_dss_requirement_without_description(tmp_path: Path):
    """Test PCI DSS handles missing description field."""
    findings = [
        create_finding(
            compliance={
                "pciDss4_0": [
                    {"requirement": "1.1.1", "priority": "LOW"}  # Missing description
                ]
            }
        )
    ]

    output = tmp_path / "pci_no_desc.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    # Should handle gracefully (empty string)
    assert "### Requirement 1.1.1:" in content


def test_compliance_summary_cwe_rank_not_available(tmp_path: Path):
    """Test CWE Top 25 handles entries without rank."""
    findings = [
        create_finding(
            compliance={
                "cweTop25_2024": [
                    {"id": "CWE-79", "category": "Injection"}  # Missing rank
                ]
            }
        )
    ]

    output = tmp_path / "compliance-cwe-no-rank.md"
    write_compliance_summary(findings, output)

    content = output.read_text()
    # Should show N/A for rank
    assert "| CWE-79 | N/A |" in content


def test_pci_dss_message_truncation(tmp_path: Path):
    """Test PCI DSS truncates long messages."""
    long_message = "A" * 200  # 200 characters
    findings = [
        create_finding(
            message=long_message,
            compliance={
                "pciDss4_0": [
                    {"requirement": "1.1.1", "description": "Test", "priority": "LOW"}
                ]
            },
        )
    ]

    output = tmp_path / "pci_long_msg.md"
    write_pci_dss_report(findings, output)

    content = output.read_text()
    # Message should be truncated to 100 chars
    assert long_message[:100] in content
    assert len([line for line in content.split("\n") if "A" * 150 in line]) == 0


def test_compliance_summary_no_compliance_data(tmp_path: Path):
    """Test compliance summary when no compliance fields present."""
    # Findings without compliance field
    findings = [
        {
            "tool": {"name": "test"},
            "ruleId": "TEST-001",
            "severity": "HIGH",
            "location": {"path": "test.py"},
            "message": "Test finding without compliance data",
        }
    ]

    output_path = tmp_path / "COMPLIANCE_SUMMARY.md"
    write_compliance_summary(findings, output_path)

    # Should still write valid summary
    assert output_path.exists()
    content = output_path.read_text()
    # Should indicate findings with no compliance mappings
    assert "findings with compliance mappings:** 0" in content.lower()
    assert "total findings:** 1" in content.lower()


def test_compliance_summary_empty_findings(tmp_path: Path):
    """Test compliance summary with empty findings list."""
    findings = []

    output_path = tmp_path / "COMPLIANCE_SUMMARY_EMPTY.md"
    write_compliance_summary(findings, output_path)

    # Should write valid summary with zeros
    assert output_path.exists()
    content = output_path.read_text()
    assert "total findings:** 0" in content.lower()
    assert "findings with compliance mappings:** 0" in content.lower()
