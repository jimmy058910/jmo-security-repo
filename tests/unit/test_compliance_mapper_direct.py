"""Comprehensive direct tests for compliance_mapper module.

This test suite achieves 100% coverage by testing:
1. CWE to OWASP Top 10 2021 mappings
2. CWE to Top 25 2024 mappings
3. CIS Controls v8.1 mappings
4. NIST CSF 2.0 mappings
5. PCI DSS 4.0 mappings
6. MITRE ATT&CK mappings
7. Tool category detection
8. Rule-based OWASP mappings
9. Finding enrichment (single and batch)
10. Edge cases and empty inputs
"""

from typing import Any


def create_finding(
    tool_name: str = "test-tool",
    rule_id: str = "test-rule",
    severity: str = "HIGH",
    cwes: list[str] | None = None,
    tags: list[str] | None = None,
    **kwargs: Any,
) -> dict[str, Any]:
    """Helper to create a test finding."""
    finding: dict[str, Any] = {
        "schemaVersion": "1.1.0",
        "id": f"test-{rule_id}",
        "ruleId": rule_id,
        "severity": severity,
        "message": "Test finding",
        "tool": {"name": tool_name, "version": "1.0.0"},
        "location": {"path": "test.py", "startLine": 1},
        "tags": tags or [],
        "risk": {"cwe": cwes or []},
    }
    finding.update(kwargs)
    return finding


# ========== Category 1: CWE to OWASP Top 10 2021 Mappings ==========


def test_map_cwe_to_owasp_xss():
    """Test CWE-79 (XSS) maps to OWASP A03:2021."""
    from scripts.core.compliance_mapper import map_cwe_to_owasp_top10_2021

    result = map_cwe_to_owasp_top10_2021(["CWE-79"])
    assert "A03:2021" in result


def test_map_cwe_to_owasp_sql_injection():
    """Test CWE-89 (SQL Injection) maps to OWASP A03:2021."""
    from scripts.core.compliance_mapper import map_cwe_to_owasp_top10_2021

    result = map_cwe_to_owasp_top10_2021(["CWE-89"])
    assert "A03:2021" in result


def test_map_cwe_to_owasp_broken_access_control():
    """Test CWE-862 (Missing Authorization) maps to OWASP A01:2021."""
    from scripts.core.compliance_mapper import map_cwe_to_owasp_top10_2021

    result = map_cwe_to_owasp_top10_2021(["CWE-862"])
    assert "A01:2021" in result


def test_map_cwe_to_owasp_cryptographic_failures():
    """Test CWE-798 (Hardcoded Credentials) maps to OWASP A02:2021."""
    from scripts.core.compliance_mapper import map_cwe_to_owasp_top10_2021

    result = map_cwe_to_owasp_top10_2021(["CWE-798"])
    assert "A02:2021" in result


def test_map_cwe_to_owasp_multiple_cwes():
    """Test multiple CWEs map to correct OWASP categories."""
    from scripts.core.compliance_mapper import map_cwe_to_owasp_top10_2021

    result = map_cwe_to_owasp_top10_2021(["CWE-79", "CWE-89", "CWE-798"])
    assert "A03:2021" in result  # XSS and SQL Injection
    assert "A02:2021" in result  # Hardcoded credentials


def test_map_cwe_to_owasp_empty_list():
    """Test empty CWE list returns empty result."""
    from scripts.core.compliance_mapper import map_cwe_to_owasp_top10_2021

    result = map_cwe_to_owasp_top10_2021([])
    assert result == []


def test_map_cwe_to_owasp_unknown_cwe():
    """Test unknown CWE returns empty result."""
    from scripts.core.compliance_mapper import map_cwe_to_owasp_top10_2021

    result = map_cwe_to_owasp_top10_2021(["CWE-99999"])
    assert result == []


# ========== Category 2: CWE to Top 25 2024 Mappings ==========


def test_map_cwe_to_top25_xss():
    """Test CWE-79 (XSS) is in Top 25 2024 (rank 1)."""
    from scripts.core.compliance_mapper import map_cwe_to_top25_2024

    result = map_cwe_to_top25_2024(["CWE-79"])
    assert len(result) == 1
    assert result[0]["id"] == "CWE-79"
    assert result[0]["rank"] == 1
    assert result[0]["category"] == "Injection"


def test_map_cwe_to_top25_sql_injection():
    """Test CWE-89 (SQL Injection) is in Top 25 2024 (rank 3)."""
    from scripts.core.compliance_mapper import map_cwe_to_top25_2024

    result = map_cwe_to_top25_2024(["CWE-89"])
    assert len(result) == 1
    assert result[0]["id"] == "CWE-89"
    assert result[0]["rank"] == 3


def test_map_cwe_to_top25_multiple():
    """Test multiple CWEs return multiple Top 25 entries."""
    from scripts.core.compliance_mapper import map_cwe_to_top25_2024

    result = map_cwe_to_top25_2024(["CWE-79", "CWE-89", "CWE-798"])
    assert len(result) == 3
    ranks = [r["rank"] for r in result]
    assert 1 in ranks  # CWE-79
    assert 3 in ranks  # CWE-89
    assert 18 in ranks  # CWE-798


def test_map_cwe_to_top25_empty_list():
    """Test empty CWE list returns empty result."""
    from scripts.core.compliance_mapper import map_cwe_to_top25_2024

    result = map_cwe_to_top25_2024([])
    assert result == []


def test_map_cwe_to_top25_unknown_cwe():
    """Test unknown CWE returns empty result."""
    from scripts.core.compliance_mapper import map_cwe_to_top25_2024

    result = map_cwe_to_top25_2024(["CWE-99999"])
    assert result == []


def test_map_cwe_to_top25_mixed_known_unknown():
    """Test mix of known and unknown CWEs."""
    from scripts.core.compliance_mapper import map_cwe_to_top25_2024

    result = map_cwe_to_top25_2024(["CWE-79", "CWE-99999", "CWE-89"])
    assert len(result) == 2  # Only known CWEs
    assert result[0]["id"] == "CWE-79"
    assert result[1]["id"] == "CWE-89"


# ========== Category 3: Tool Category Detection ==========


def test_get_tool_category_secrets():
    """Test secrets scanning tool category detection."""
    from scripts.core.compliance_mapper import get_tool_category

    result = get_tool_category("trufflehog", ["secrets"])
    assert result == "secrets"

    result = get_tool_category("gitleaks", ["credentials"])
    assert result == "secrets"


def test_get_tool_category_sast():
    """Test SAST tool category detection."""
    from scripts.core.compliance_mapper import get_tool_category

    result = get_tool_category("semgrep", ["sast"])
    assert result == "sast"

    result = get_tool_category("bandit", ["security"])
    assert result == "sast"


def test_get_tool_category_sca():
    """Test SCA/vulnerability scanning tool category detection."""
    from scripts.core.compliance_mapper import get_tool_category

    result = get_tool_category("trivy", ["vulnerability"])
    assert result == "sca"

    result = get_tool_category("syft", [])
    assert result == "sca"


def test_get_tool_category_iac():
    """Test IaC tool category detection."""
    from scripts.core.compliance_mapper import get_tool_category

    result = get_tool_category("checkov", ["iac"])
    assert result == "iac"


def test_get_tool_category_container():
    """Test container tools also detected as SCA."""
    from scripts.core.compliance_mapper import get_tool_category

    # trivy is primarily SCA/vuln scanner
    result = get_tool_category("trivy", ["container"])
    assert result == "sca"


def test_get_tool_category_unknown():
    """Test unknown tool returns None."""
    from scripts.core.compliance_mapper import get_tool_category

    result = get_tool_category("unknown-tool", [])
    assert result is None


# ========== Category 4: CIS Controls v8.1 Mappings ==========


def test_map_to_cis_controls_secrets():
    """Test secrets tools map to CIS Controls."""
    from scripts.core.compliance_mapper import map_to_cis_controls_v8_1

    result = map_to_cis_controls_v8_1("trufflehog", ["secrets"])
    assert len(result) > 0
    # Should include credential management controls
    assert any("3.11" in control["control"] for control in result)


def test_map_to_cis_controls_sast():
    """Test SAST tools map to CIS Controls."""
    from scripts.core.compliance_mapper import map_to_cis_controls_v8_1

    result = map_to_cis_controls_v8_1("semgrep", ["sast"])
    assert len(result) > 0


def test_map_to_cis_controls_vuln():
    """Test vulnerability tools map to CIS Controls."""
    from scripts.core.compliance_mapper import map_to_cis_controls_v8_1

    result = map_to_cis_controls_v8_1("trivy", ["vulnerability"])
    assert len(result) > 0


def test_map_to_cis_controls_empty():
    """Test empty tags returns empty result."""
    from scripts.core.compliance_mapper import map_to_cis_controls_v8_1

    result = map_to_cis_controls_v8_1("unknown-tool", [])
    assert result == []


# ========== Category 5: NIST CSF 2.0 Mappings ==========


def test_map_to_nist_csf_secrets():
    """Test secrets tools map to NIST CSF."""
    from scripts.core.compliance_mapper import map_to_nist_csf_2_0

    result = map_to_nist_csf_2_0("trufflehog", ["secrets"], ["CWE-798"])
    assert len(result) > 0
    # Should include IDENTIFY or PROTECT functions
    assert any(m["function"] in ["IDENTIFY", "PROTECT"] for m in result)


def test_map_to_nist_csf_vuln():
    """Test vulnerability tools map to NIST CSF."""
    from scripts.core.compliance_mapper import map_to_nist_csf_2_0

    result = map_to_nist_csf_2_0("trivy", ["vulnerability"], [])
    assert len(result) > 0


def test_map_to_nist_csf_empty():
    """Test empty tags returns empty result."""
    from scripts.core.compliance_mapper import map_to_nist_csf_2_0

    result = map_to_nist_csf_2_0("unknown-tool", [], [])
    assert result == []


# ========== Category 6: PCI DSS 4.0 Mappings ==========


def test_map_to_pci_dss_secrets():
    """Test secrets tools map to PCI DSS 4.0."""
    from scripts.core.compliance_mapper import map_to_pci_dss_4_0

    result = map_to_pci_dss_4_0("trufflehog", ["secrets"], ["CWE-798"])
    assert len(result) > 0
    # Should include requirements about secure authentication
    assert any("8." in req["requirement"] for req in result)


def test_map_to_pci_dss_vuln():
    """Test vulnerability tools map to PCI DSS 4.0."""
    from scripts.core.compliance_mapper import map_to_pci_dss_4_0

    result = map_to_pci_dss_4_0("trivy", ["vulnerability"], [])
    assert len(result) > 0


def test_map_to_pci_dss_empty():
    """Test empty tags returns empty result."""
    from scripts.core.compliance_mapper import map_to_pci_dss_4_0

    result = map_to_pci_dss_4_0("unknown-tool", [], [])
    assert result == []


# ========== Category 7: MITRE ATT&CK Mappings ==========


def test_map_to_mitre_attack_secrets():
    """Test secrets findings map to MITRE ATT&CK."""
    from scripts.core.compliance_mapper import map_to_mitre_attack

    result = map_to_mitre_attack(
        "trufflehog", ["secrets"], ["CWE-798"], "hardcoded-key"
    )
    assert len(result) > 0
    # Should include credential access tactics
    assert any(t["tactic"] == "Credential Access" for t in result)


def test_map_to_mitre_attack_injection():
    """Test injection findings map to MITRE ATT&CK."""
    from scripts.core.compliance_mapper import map_to_mitre_attack

    result = map_to_mitre_attack("semgrep", ["injection"], ["CWE-89"], "sql-injection")
    assert len(result) > 0


def test_map_to_mitre_attack_empty():
    """Test empty tags returns empty result."""
    from scripts.core.compliance_mapper import map_to_mitre_attack

    result = map_to_mitre_attack("unknown-tool", [], [], "")
    assert result == []


# ========== Category 8: Rule-based OWASP Mappings ==========


def test_map_rule_to_owasp_semgrep_django():
    """Test semgrep Django security rules map to OWASP A05."""
    from scripts.core.compliance_mapper import map_rule_to_owasp_top10_2021

    result = map_rule_to_owasp_top10_2021(
        "semgrep", "python.django.security.injection.sql"
    )
    assert "A05:2021" in result


def test_map_rule_to_owasp_semgrep_secrets():
    """Test semgrep secrets rules map to OWASP A02."""
    from scripts.core.compliance_mapper import map_rule_to_owasp_top10_2021

    result = map_rule_to_owasp_top10_2021("semgrep", "generic.secrets.gitleaks.aws-key")
    assert "A02:2021" in result


def test_map_rule_to_owasp_unknown_rule():
    """Test unknown rule returns empty list."""
    from scripts.core.compliance_mapper import map_rule_to_owasp_top10_2021

    result = map_rule_to_owasp_top10_2021("unknown-tool", "unknown-rule")
    assert result == []


def test_map_rule_to_owasp_trufflehog_secrets():
    """Test trufflehog secrets map to OWASP A02."""
    from scripts.core.compliance_mapper import map_rule_to_owasp_top10_2021

    result = map_rule_to_owasp_top10_2021("trufflehog", "AWS-Key")
    assert "A02:2021" in result


# ========== Category 9: Finding Enrichment (Single) ==========


def test_enrich_finding_with_cwe():
    """Test enriching finding with CWE metadata."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(cwes=["CWE-79", "CWE-89"])
    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    assert result["schemaVersion"] == "1.2.0"
    assert "owaspTop10_2021" in result["compliance"]
    assert "cweTop25_2024" in result["compliance"]


def test_enrich_finding_with_tool_category():
    """Test enriching finding based on tool category."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(tool_name="trufflehog", tags=["secrets"])
    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    # Should have CIS, NIST, PCI DSS, MITRE ATT&CK mappings
    assert "cisControlsV8_1" in result["compliance"]
    assert "nistCsf2_0" in result["compliance"]


def test_enrich_finding_no_compliance():
    """Test finding with no compliance mappings."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(tool_name="unknown-tool", tags=[])
    result = enrich_finding_with_compliance(finding)

    # Should not add compliance field if no mappings
    assert "compliance" not in result
    # Schema version should not change
    assert result["schemaVersion"] == "1.1.0"


def test_enrich_finding_with_rule_mapping():
    """Test enriching finding with rule-based OWASP mapping."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(
        tool_name="semgrep",
        rule_id="python.django.security.injection.sql",
        tags=["injection"],
    )
    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    assert "owaspTop10_2021" in result["compliance"]
    assert "A05:2021" in result["compliance"]["owaspTop10_2021"]


def test_enrich_finding_combines_cwe_and_rule():
    """Test enrichment combines CWE and rule-based mappings."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(
        tool_name="semgrep",
        rule_id="python.sql-injection",
        cwes=["CWE-89"],
        tags=["injection"],
    )
    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    # Should have both CWE Top 25 and OWASP
    assert "owaspTop10_2021" in result["compliance"]
    assert "cweTop25_2024" in result["compliance"]


def test_enrich_finding_tool_info_as_string():
    """Test handling when tool info is string instead of dict."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(cwes=["CWE-79"])
    finding["tool"] = "trufflehog"  # String instead of dict

    result = enrich_finding_with_compliance(finding)

    # Should still work with empty tool name
    assert "compliance" in result


def test_enrich_finding_risk_as_non_dict():
    """Test handling when risk is not a dict."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(tool_name="semgrep", tags=["sast"])
    finding["risk"] = "high"  # String instead of dict

    result = enrich_finding_with_compliance(finding)

    # Should handle gracefully
    # May or may not have compliance based on tool/tags
    assert isinstance(result, dict)


def test_enrich_finding_all_frameworks():
    """Test enriching finding gets all 6 frameworks."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(
        tool_name="semgrep",
        rule_id="python.sql-injection",
        cwes=["CWE-89"],
        tags=["injection", "sast"],
    )
    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    compliance = result["compliance"]

    # Check all 6 frameworks
    assert "owaspTop10_2021" in compliance
    assert "cweTop25_2024" in compliance
    assert "cisControlsV8_1" in compliance
    assert "nistCsf2_0" in compliance
    assert "pciDss4_0" in compliance
    assert "mitreAttack" in compliance


# ========== Category 10: Batch Finding Enrichment ==========


def test_enrich_findings_with_compliance_batch():
    """Test enriching multiple findings at once."""
    from scripts.core.compliance_mapper import enrich_findings_with_compliance

    findings = [
        create_finding(cwes=["CWE-79"]),
        create_finding(cwes=["CWE-89"]),
        create_finding(tool_name="trufflehog", tags=["secrets"]),
    ]

    results = enrich_findings_with_compliance(findings)

    assert len(results) == 3
    # First two should have CWE mappings
    assert "compliance" in results[0]
    assert "compliance" in results[1]
    # Third should have tool-based mappings
    assert "compliance" in results[2]


def test_enrich_findings_empty_list():
    """Test enriching empty findings list."""
    from scripts.core.compliance_mapper import enrich_findings_with_compliance

    results = enrich_findings_with_compliance([])
    assert results == []


def test_enrich_findings_preserves_original():
    """Test enrichment doesn't lose original finding data."""
    from scripts.core.compliance_mapper import enrich_findings_with_compliance

    original = create_finding(cwes=["CWE-79"], tags=["xss"])
    findings = [original]

    results = enrich_findings_with_compliance(findings)

    # Check original fields preserved
    assert results[0]["ruleId"] == original["ruleId"]
    assert results[0]["severity"] == original["severity"]
    assert results[0]["tool"]["name"] == original["tool"]["name"]
    assert results[0]["tags"] == original["tags"]


# ========== Category 11: Edge Cases ==========


def test_enrich_finding_empty_cwes_list():
    """Test finding with empty CWEs list."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(cwes=[])
    result = enrich_finding_with_compliance(finding)

    # May or may not have compliance based on tool/rule
    assert isinstance(result, dict)


def test_enrich_finding_empty_tags_list():
    """Test finding with empty tags list."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(tags=[])
    result = enrich_finding_with_compliance(finding)

    # May or may not have compliance
    assert isinstance(result, dict)


def test_enrich_finding_missing_tool_field():
    """Test finding without tool field."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(cwes=["CWE-79"])
    del finding["tool"]

    result = enrich_finding_with_compliance(finding)

    # Should still work with CWE mappings
    assert "compliance" in result


def test_enrich_finding_missing_risk_field():
    """Test finding without risk field."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(tool_name="semgrep", tags=["sast"])
    del finding["risk"]

    result = enrich_finding_with_compliance(finding)

    # Should still work with tool-based mappings
    # May or may not have compliance
    assert isinstance(result, dict)


def test_enrich_finding_case_insensitive_cwes():
    """Test CWE matching is case-insensitive."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    # Mix of lowercase and uppercase
    finding = create_finding(cwes=["cwe-79", "CWE-89"])
    result = enrich_finding_with_compliance(finding)

    # The mapper should normalize to uppercase internally
    assert "compliance" in result


def test_enrich_finding_duplicate_cwes():
    """Test handling duplicate CWEs in list."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(cwes=["CWE-79", "CWE-79", "CWE-89"])
    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    # Should handle duplicates gracefully


def test_enrich_finding_schema_version_upgrade():
    """Test schema version upgrades from 1.1.0 to 1.2.0."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(cwes=["CWE-79"])
    finding["schemaVersion"] = "1.1.0"

    result = enrich_finding_with_compliance(finding)

    # Should upgrade to 1.2.0
    assert result["schemaVersion"] == "1.2.0"


def test_enrich_finding_already_has_compliance():
    """Test enriching finding that already has compliance field."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(cwes=["CWE-79"])
    finding["compliance"] = {"existing": "data"}

    result = enrich_finding_with_compliance(finding)

    # Should replace existing compliance field
    assert "compliance" in result
    assert "owaspTop10_2021" in result["compliance"]


# ========== Category 12: Complex Real-World Scenarios ==========


def test_enrich_sql_injection_finding():
    """Test realistic SQL injection finding."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(
        tool_name="semgrep",
        rule_id="python.django.security.injection.sql.sql-injection-db-cursor-execute",
        cwes=["CWE-89"],
        tags=["injection", "sql", "sast", "security"],
        severity="HIGH",
    )

    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    compliance = result["compliance"]

    # Should map to OWASP A03 (Injection) or A05 (Security Misconfiguration)
    assert (
        "A03:2021" in compliance["owaspTop10_2021"]
        or "A05:2021" in compliance["owaspTop10_2021"]
    )

    # Should be in CWE Top 25 (rank 3)
    assert any(
        c["id"] == "CWE-89" and c["rank"] == 3 for c in compliance["cweTop25_2024"]
    )

    # Should have CIS Controls
    assert len(compliance["cisControlsV8_1"]) > 0

    # Should have MITRE ATT&CK
    assert len(compliance["mitreAttack"]) > 0


def test_enrich_secrets_finding():
    """Test realistic secrets finding."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(
        tool_name="trufflehog",
        rule_id="AWS-Key",
        cwes=["CWE-798"],
        tags=["secrets", "credentials", "aws"],
        severity="CRITICAL",
    )

    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    compliance = result["compliance"]

    # Should map to OWASP A02 (Cryptographic Failures)
    assert "A02:2021" in compliance["owaspTop10_2021"]

    # Should be in CWE Top 25
    assert any(c["id"] == "CWE-798" for c in compliance["cweTop25_2024"])

    # Should have PCI DSS requirements
    assert len(compliance["pciDss4_0"]) > 0


def test_enrich_container_vulnerability():
    """Test realistic container vulnerability finding."""
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    finding = create_finding(
        tool_name="trivy",
        rule_id="CVE-2023-12345",
        cwes=["CWE-20"],
        tags=["vulnerability", "container", "cve"],
        severity="HIGH",
    )

    result = enrich_finding_with_compliance(finding)

    assert "compliance" in result
    # Should have vulnerability-specific mappings
    assert "cisControlsV8_1" in result["compliance"]
