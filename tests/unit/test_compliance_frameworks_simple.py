"""Simplified unit tests for compliance_frameworks.py data structures.

This module validates the compliance framework data exists and has valid structure.

NOTE: Framework data is organized by security tool category (secrets, sast, sca,
iac, dast, runtime, container) rather than traditional framework IDs.
"""

from scripts.core.compliance_frameworks import (
    CIS_CONTROLS_V8_1,
    CWE_TO_MITRE_ATTACK,
    CWE_TO_NIST_CSF_2_0,
    CWE_TO_OWASP_TOP10_2021,
    CWE_TO_PCI_DSS_4_0,
    CWE_TOP_25_2024,
    MITRE_ATTACK,
    NIST_CSF_2_0,
    PCI_DSS_4_0,
)

# ========== Category 1: CWE Top 25 2024 Validation ==========


def test_cwe_top_25_exists_and_has_entries():
    """Test CWE_TOP_25_2024 exists and contains entries."""
    assert CWE_TOP_25_2024
    assert len(CWE_TOP_25_2024) == 25


def test_cwe_top_25_structure():
    """Test CWE_TOP_25_2024 entries have valid structure."""
    for cwe_id, data in CWE_TOP_25_2024.items():
        assert cwe_id.startswith("CWE-")
        assert isinstance(data, dict)
        assert "rank" in data
        assert "category" in data
        assert "name" in data


# ========== Category 2: OWASP Top 10 2021 Mappings ==========


def test_cwe_to_owasp_exists():
    """Test CWE_TO_OWASP_TOP10_2021 exists and has mappings."""
    # A well-known mapping must be present (non-emptiness alone is vacuous).
    assert "A03:2021" in CWE_TO_OWASP_TOP10_2021["CWE-79"]


def test_cwe_to_owasp_structure():
    """Test CWE_TO_OWASP_TOP10_2021 has valid structure."""
    for cwe_id, owasp_list in CWE_TO_OWASP_TOP10_2021.items():
        assert cwe_id.startswith("CWE-")
        assert isinstance(owasp_list, list)
        for category in owasp_list:
            assert isinstance(category, str)


# ========== Category 3: CIS Controls v8.1 Validation ==========


def test_cis_controls_exists():
    """Test CIS_CONTROLS_V8_1 exists and has entries."""
    # The SAST tool category must map to at least one CIS control.
    assert "sast" in CIS_CONTROLS_V8_1


def test_cis_controls_has_tool_categories():
    """Test CIS_CONTROLS_V8_1 is organized by tool categories."""
    # Should have tool category keys
    assert isinstance(CIS_CONTROLS_V8_1, dict)

    # At least one category should exist
    for category, controls in CIS_CONTROLS_V8_1.items():
        assert isinstance(category, str)
        assert isinstance(controls, list)

        # Each control should have required fields
        if controls:
            first_control = controls[0]
            assert "control" in first_control
            assert "title" in first_control
            assert "implementationGroup" in first_control
        break  # Just validate structure, not all entries


# ========== Category 4: NIST CSF 2.0 Validation ==========


def test_nist_csf_exists():
    """Test NIST_CSF_2_0 exists and has entries."""
    # The SAST tool category must map to at least one NIST CSF function.
    assert "sast" in NIST_CSF_2_0


def test_nist_csf_has_tool_categories():
    """Test NIST_CSF_2_0 is organized by tool categories."""
    assert isinstance(NIST_CSF_2_0, dict)

    # Validate structure of first category
    for category, mappings in NIST_CSF_2_0.items():
        assert isinstance(category, str)
        assert isinstance(mappings, list)
        break


def test_cwe_to_nist_csf_exists():
    """Test CWE_TO_NIST_CSF_2_0 exists and has mappings."""
    # CWE-79 must map to Detect / continuous monitoring (DE.CM).
    assert any(m["category"] == "DE.CM" for m in CWE_TO_NIST_CSF_2_0["CWE-79"])


def test_cwe_to_nist_csf_structure():
    """Test CWE_TO_NIST_CSF_2_0 has valid structure."""
    for cwe_id, mappings in CWE_TO_NIST_CSF_2_0.items():
        assert cwe_id.startswith("CWE-")
        assert isinstance(mappings, list)


# ========== Category 5: PCI DSS 4.0 Validation ==========


def test_pci_dss_exists():
    """Test PCI_DSS_4_0 exists and has entries."""
    # The SAST tool category must map to at least one PCI DSS requirement.
    assert "sast" in PCI_DSS_4_0


def test_pci_dss_has_tool_categories():
    """Test PCI_DSS_4_0 is organized by tool categories."""
    assert isinstance(PCI_DSS_4_0, dict)

    # Validate structure
    for category, requirements in PCI_DSS_4_0.items():
        assert isinstance(category, str)
        assert isinstance(requirements, list)
        break


def test_cwe_to_pci_dss_exists():
    """Test CWE_TO_PCI_DSS_4_0 exists and has mappings."""
    # CWE-89 (SQL injection) must map to PCI DSS requirement 6.2.4.
    assert any(r["requirement"] == "6.2.4" for r in CWE_TO_PCI_DSS_4_0["CWE-89"])


def test_cwe_to_pci_dss_structure():
    """Test CWE_TO_PCI_DSS_4_0 has valid structure."""
    for cwe_id, requirements in CWE_TO_PCI_DSS_4_0.items():
        assert cwe_id.startswith("CWE-")
        assert isinstance(requirements, list)


# ========== Category 6: MITRE ATT&CK Validation ==========


def test_mitre_attack_exists():
    """Test MITRE_ATTACK exists and has entries."""
    # The SCA tool category must map to at least one MITRE ATT&CK technique.
    assert "sca" in MITRE_ATTACK


def test_mitre_attack_has_tool_categories():
    """Test MITRE_ATTACK is organized by tool categories."""
    assert isinstance(MITRE_ATTACK, dict)

    # Validate structure
    for category, techniques in MITRE_ATTACK.items():
        assert isinstance(category, str)
        assert isinstance(techniques, list)
        break


def test_cwe_to_mitre_attack_exists():
    """Test CWE_TO_MITRE_ATTACK exists and has mappings."""
    # CWE-89 (SQL injection) must map to technique T1190.
    assert any(t["technique"] == "T1190" for t in CWE_TO_MITRE_ATTACK["CWE-89"])


def test_cwe_to_mitre_attack_structure():
    """Test CWE_TO_MITRE_ATTACK has valid structure."""
    for cwe_id, techniques in CWE_TO_MITRE_ATTACK.items():
        assert cwe_id.startswith("CWE-")
        assert isinstance(techniques, list)


def test_cwe_top_25_all_imported():
    """Test all 25 CWE entries are imported and accessible."""
    cwe_ids = list(CWE_TOP_25_2024.keys())
    assert len(cwe_ids) == 25
    assert all(cwe_id.startswith("CWE-") for cwe_id in cwe_ids)
