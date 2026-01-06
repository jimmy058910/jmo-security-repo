import sys
from pathlib import Path

import pytest

from scripts.core.reporters.sarif_reporter import to_sarif, write_sarif

SAMPLE = [
    {
        "schemaVersion": "1.0.0",
        "id": "abc",
        "ruleId": "aws-key",
        "message": "Potential AWS key",
        "severity": "HIGH",
        "tool": {"name": "gitleaks", "version": "x"},
        "location": {"path": "a.txt", "startLine": 1},
    }
]


def test_to_sarif_basic():
    sarif = to_sarif(SAMPLE)
    assert sarif.get("version") == "2.1.0"
    assert sarif.get("runs")
    assert sarif["runs"][0]["results"][0]["ruleId"] == "aws-key"


def test_write_sarif(tmp_path: Path):
    out = tmp_path / "f.sarif"
    write_sarif(SAMPLE, out)
    s = out.read_text(encoding="utf-8")
    assert '"version": "2.1.0"' in s


@pytest.mark.skipif(
    sys.platform == "win32",
    reason="chmod(0o444) does not prevent writes on Windows (NTFS uses ACLs)",
)
def test_write_sarif_with_file_error(tmp_path: Path):
    """Test SARIF writer handles file write errors gracefully."""
    findings = [
        {
            "tool": {"name": "test"},
            "ruleId": "TEST-001",
            "severity": "HIGH",
            "location": {"path": "test.py"},
            "message": "test",
        }
    ]

    # Try to write to read-only directory
    ro_dir = tmp_path / "readonly"
    ro_dir.mkdir()
    ro_dir.chmod(0o444)  # Read-only

    output_path = ro_dir / "findings.sarif"

    with pytest.raises(PermissionError):
        write_sarif(findings, output_path)


def test_write_sarif_malformed_findings(tmp_path: Path):
    """Test SARIF writer handles malformed findings gracefully."""
    # Findings missing required fields
    findings = [{"invalid": "structure"}]

    output_path = tmp_path / "findings.sarif"
    write_sarif(findings, output_path)

    # Should write valid SARIF structure even with malformed input
    assert output_path.exists()
    content = output_path.read_text()
    assert '"version": "2.1.0"' in content


class TestSarifReporterCoverage:
    """Tests for uncovered code paths in sarif_reporter."""

    def test_to_sarif_skips_none_findings(self):
        """Test that None findings are skipped (lines 35-37)."""
        findings = [
            None,
            {
                "ruleId": "valid",
                "message": "msg",
                "severity": "HIGH",
                "location": {"path": "a.py"},
            },
            None,
        ]
        sarif = to_sarif(findings)
        # Should only have one result (the valid finding)
        assert len(sarif["runs"][0]["results"]) == 1
        assert sarif["runs"][0]["results"][0]["ruleId"] == "valid"

    def test_to_sarif_skips_non_dict_findings(self):
        """Test that non-dict findings are skipped (lines 35-37)."""
        findings = [
            "invalid string",
            123,
            {
                "ruleId": "valid",
                "message": "msg",
                "severity": "HIGH",
                "location": {"path": "a.py"},
            },
            ["list", "not", "dict"],
        ]
        sarif = to_sarif(findings)
        # Should only have one result
        assert len(sarif["runs"][0]["results"]) == 1

    def test_to_sarif_with_code_snippet(self):
        """Test code snippet inclusion in context (lines 71-74)."""
        findings = [
            {
                "ruleId": "snippet-rule",
                "message": "Found issue",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 10},
                "context": {"snippet": "vulnerable_code()"},
            }
        ]
        sarif = to_sarif(findings)
        location = sarif["runs"][0]["results"][0]["locations"][0]
        assert (
            location["physicalLocation"]["region"]["snippet"]["text"]
            == "vulnerable_code()"
        )

    def test_to_sarif_with_end_line(self):
        """Test end line handling (lines 77-80)."""
        findings = [
            {
                "ruleId": "endline-rule",
                "message": "Multi-line issue",
                "severity": "MEDIUM",
                "location": {"path": "test.py", "startLine": 10, "endLine": 15},
            }
        ]
        sarif = to_sarif(findings)
        region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"][
            "region"
        ]
        assert region["startLine"] == 10
        assert region["endLine"] == 15

    def test_to_sarif_with_remediation_fix(self):
        """Test fix suggestions with remediation (lines 90-96)."""
        findings = [
            {
                "ruleId": "fix-rule",
                "message": "Security issue",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "remediation": "Update to use parameterized queries",
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "fixes" in result
        assert (
            result["fixes"][0]["description"]["text"]
            == "Update to use parameterized queries"
        )

    def test_to_sarif_with_cwe_tag(self):
        """Test CWE taxonomy tag handling (lines 102-108)."""
        findings = [
            {
                "ruleId": "cwe-rule",
                "message": "SQL Injection",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "tags": ["CWE-89", "security"],
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "taxa" in result
        assert any(
            t["id"] == "CWE-89" and t["toolComponent"]["name"] == "CWE"
            for t in result["taxa"]
        )

    def test_to_sarif_with_owasp_tag(self):
        """Test OWASP taxonomy tag handling (lines 109-115)."""
        findings = [
            {
                "ruleId": "owasp-rule",
                "message": "Injection flaw",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "tags": ["OWASP-A03"],
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "taxa" in result
        assert any(
            t["id"] == "OWASP-A03" and t["toolComponent"]["name"] == "OWASP"
            for t in result["taxa"]
        )

    def test_to_sarif_with_cve_tag(self):
        """Test CVE taxonomy tag handling (lines 116-122)."""
        findings = [
            {
                "ruleId": "cve-rule",
                "message": "Known vulnerability",
                "severity": "CRITICAL",
                "location": {"path": "test.py", "startLine": 1},
                "tags": ["CVE-2021-44228"],
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "taxa" in result
        assert any(
            t["id"] == "CVE-2021-44228" and t["toolComponent"]["name"] == "CVE"
            for t in result["taxa"]
        )

    def test_to_sarif_with_multiple_taxonomy_tags(self):
        """Test multiple taxonomy tags (lines 100-124)."""
        findings = [
            {
                "ruleId": "multi-taxa",
                "message": "Multiple taxonomies",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "tags": ["CWE-79", "OWASP-A07", "CVE-2023-12345", "other-tag"],
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "taxa" in result
        assert len(result["taxa"]) == 3  # CWE, OWASP, CVE only

    def test_to_sarif_with_cvss_score(self):
        """Test CVSS score handling (lines 127-130)."""
        findings = [
            {
                "ruleId": "cvss-rule",
                "message": "Scored vulnerability",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "cvss": {
                    "score": 9.8,
                    "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                },
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "properties" in result
        assert result["properties"]["cvss"]["score"] == 9.8

    def test_to_sarif_with_cross_tool_consensus(self):
        """Test cross-tool consensus handling (lines 133-146)."""
        findings = [
            {
                "id": "consensus-finding-123",
                "ruleId": "consensus-rule",
                "message": "Detected by multiple tools",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "detected_by": [
                    {"name": "semgrep", "version": "1.0"},
                    {"name": "bandit", "version": "2.0"},
                ],
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "properties" in result
        assert result["properties"]["consensus"]["detectedByCount"] == 2
        assert len(result["properties"]["consensus"]["tools"]) == 2
        assert result["correlationGuid"] == "consensus-finding-123"

    def test_to_sarif_medium_severity(self):
        """Test MEDIUM severity maps to warning (line 196)."""
        findings = [
            {
                "ruleId": "medium-rule",
                "message": "Medium issue",
                "severity": "MEDIUM",
                "location": {"path": "test.py", "startLine": 1},
            }
        ]
        sarif = to_sarif(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "warning"

    def test_to_sarif_low_severity(self):
        """Test LOW severity maps to note."""
        findings = [
            {
                "ruleId": "low-rule",
                "message": "Low issue",
                "severity": "LOW",
                "location": {"path": "test.py", "startLine": 1},
            }
        ]
        sarif = to_sarif(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_to_sarif_info_severity(self):
        """Test INFO severity maps to note."""
        findings = [
            {
                "ruleId": "info-rule",
                "message": "Info issue",
                "severity": "INFO",
                "location": {"path": "test.py", "startLine": 1},
            }
        ]
        sarif = to_sarif(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_to_sarif_no_severity(self):
        """Test None severity defaults to note."""
        findings = [
            {
                "ruleId": "no-sev-rule",
                "message": "No severity",
                "location": {"path": "test.py", "startLine": 1},
            }
        ]
        sarif = to_sarif(findings)
        assert sarif["runs"][0]["results"][0]["level"] == "note"

    def test_to_sarif_empty_remediation_no_fix(self):
        """Test empty remediation doesn't add fix."""
        findings = [
            {
                "ruleId": "empty-rem",
                "message": "Issue",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "remediation": "",
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "fixes" not in result

    def test_to_sarif_single_detected_by_no_consensus(self):
        """Test single detected_by doesn't add consensus."""
        findings = [
            {
                "ruleId": "single-tool",
                "message": "Issue",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "detected_by": [{"name": "semgrep", "version": "1.0"}],
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        # Should not have consensus since only one tool
        assert "properties" not in result or "consensus" not in result.get(
            "properties", {}
        )

    def test_to_sarif_cvss_adds_to_existing_properties(self):
        """Test CVSS adds to existing properties dict (line 128-130)."""
        findings = [
            {
                "ruleId": "cvss-existing-props",
                "message": "Issue",
                "severity": "HIGH",
                "location": {"path": "test.py", "startLine": 1},
                "tags": ["CWE-79"],  # This creates taxa which doesn't use properties
                "cvss": {"score": 7.5},
            }
        ]
        sarif = to_sarif(findings)
        result = sarif["runs"][0]["results"][0]
        assert "properties" in result
        assert result["properties"]["cvss"]["score"] == 7.5

    def test_write_sarif_filters_invalid_findings(self, tmp_path: Path):
        """Test write_sarif filters None and invalid findings."""
        findings = [
            None,
            {
                "ruleId": "valid",
                "message": "msg",
                "severity": "HIGH",
                "location": {"path": "a.py"},
            },
            None,
        ]
        output = tmp_path / "filtered.sarif"
        write_sarif(findings, output)
        assert output.exists()
        import json

        sarif = json.loads(output.read_text())
        assert len(sarif["runs"][0]["results"]) == 1
