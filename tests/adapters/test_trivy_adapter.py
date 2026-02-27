"""Comprehensive tests for Trivy adapter.

Tests cover:
- Basic parsing of Trivy JSON output
- Vulnerabilities, secrets, and misconfigurations
- Multiple severity levels (LOW, MEDIUM, HIGH, CRITICAL)
- CWE mapping for vulnerabilities
- Edge cases (empty input, malformed JSON, missing fields)
- Code context extraction for misconfigurations
- Schema version and compliance enrichment
"""

import json
from pathlib import Path


from scripts.core.adapters.trivy_adapter import TrivyAdapter


def write(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temporary file."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestTrivyBasicParsing:
    """Tests for basic Trivy output parsing."""

    def test_vulnerability_parsing(self, tmp_path: Path):
        """Test parsing a single vulnerability."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-1234",
                            "Title": "Remote Code Execution",
                            "Description": "A critical RCE vulnerability",
                            "Severity": "CRITICAL",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-2023-1234",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        item = findings[0]
        assert item.ruleId == "CVE-2023-1234"
        assert item.severity == "CRITICAL"
        assert item.tool["name"] == "trivy"
        assert item.tool["version"] == "0.45.0"
        assert "vulnerability" in item.tags

    def test_secret_parsing(self, tmp_path: Path):
        """Test parsing a secret finding."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "app/.env",
                    "Secrets": [
                        {
                            "Title": "Hardcoded API key",
                            "Description": "API key found in source",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].severity == "HIGH"
        assert "secret" in findings[0].tags

    def test_misconfiguration_parsing(self, tmp_path: Path):
        """Test parsing a misconfiguration finding."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "Title": "User not specified",
                            "RuleID": "DS002",
                            "Description": "Running as root is insecure",
                            "Severity": "MEDIUM",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        # Note: Adapter prioritizes Title over RuleID for rule identification
        assert findings[0].ruleId == "User not specified"
        assert findings[0].severity == "MEDIUM"
        assert "misconfig" in findings[0].tags

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = TrivyAdapter()
        metadata = adapter.metadata
        assert metadata.name == "trivy"
        assert metadata.tool_name == "trivy"
        assert metadata.schema_version == "1.2.0"
        assert metadata.exit_codes == {0: "clean", 1: "findings", 2: "error"}


class TestTrivyMixedResults:
    """Tests for mixed result types."""

    def test_vuln_and_secret(self, tmp_path: Path):
        """Test Trivy adapter parses vulnerabilities and secrets."""
        sample = {
            "Version": "0",
            "Results": [
                {
                    "Target": "app/Dockerfile",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-123",
                            "Title": "Something",
                            "Severity": "CRITICAL",
                        }
                    ],
                    "Secrets": [
                        {
                            "Title": "Hardcoded token",
                            "Severity": "HIGH",
                            "Target": "app/.env",
                        }
                    ],
                }
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert any(f.ruleId == "CVE-123" and f.severity == "CRITICAL" for f in findings)
        assert any(
            f.ruleId == "Hardcoded token" or f.title == "Hardcoded token"
            for f in findings
        )

    def test_multiple_targets(self, tmp_path: Path):
        """Test parsing multiple targets."""
        sample = {
            "Version": "0.45.0",
            "Results": [
                {
                    "Target": "package.json",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2022-0001",
                            "Title": "JS vuln",
                            "Severity": "HIGH",
                        }
                    ],
                },
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2022-0002",
                            "Title": "Python vuln",
                            "Severity": "MEDIUM",
                        }
                    ],
                },
            ],
        }
        path = write(tmp_path, "trivy.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        targets = {f.location["path"] for f in findings}
        assert targets == {"package.json", "requirements.txt"}


class TestTrivySeverityMapping:
    """Tests for severity level mapping."""

    def test_low_severity(self, tmp_path: Path):
        """Test LOW severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [{"VulnerabilityID": "V001", "Severity": "LOW"}],
                }
            ]
        }
        path = write(tmp_path, "low.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "LOW"

    def test_medium_severity(self, tmp_path: Path):
        """Test MEDIUM severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V002", "Severity": "MEDIUM"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "medium.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "MEDIUM"

    def test_high_severity(self, tmp_path: Path):
        """Test HIGH severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V003", "Severity": "HIGH"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "high.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "HIGH"

    def test_critical_severity(self, tmp_path: Path):
        """Test CRITICAL severity."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V004", "Severity": "CRITICAL"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "critical.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "CRITICAL"


class TestTrivyEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test Trivy adapter handles empty input."""
        adapter = TrivyAdapter()
        path = write(tmp_path, "empty.json", "")
        assert adapter.parse(path) == []

    def test_malformed_json(self, tmp_path: Path):
        """Test Trivy adapter handles bad input."""
        adapter = TrivyAdapter()
        path = write(tmp_path, "bad.json", "{not json}")
        assert adapter.parse(path) == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test parsing nonexistent file."""
        adapter = TrivyAdapter()
        assert adapter.parse(tmp_path / "nonexistent.json") == []

    def test_results_not_list(self, tmp_path: Path):
        """Test parsing when Results is not a list."""
        sample = {"Version": "0.45.0", "Results": "not a list"}
        path = write(tmp_path, "not_list.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []

    def test_results_missing(self, tmp_path: Path):
        """Test parsing when Results key is missing."""
        sample = {"Version": "0.45.0"}
        path = write(tmp_path, "no_results.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []

    def test_empty_results_array(self, tmp_path: Path):
        """Test parsing with empty Results array."""
        sample = {"Version": "0.45.0", "Results": []}
        path = write(tmp_path, "empty_results.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []

    def test_empty_vulnerabilities_array(self, tmp_path: Path):
        """Test parsing with empty Vulnerabilities array."""
        sample = {
            "Results": [
                {"Target": "test", "Vulnerabilities": []},
            ]
        }
        path = write(tmp_path, "empty_vulns.json", json.dumps(sample))
        adapter = TrivyAdapter()
        assert adapter.parse(path) == []


class TestTrivyCweMapping:
    """Tests for CWE mapping in vulnerabilities."""

    def test_single_cwe_id(self, tmp_path: Path):
        """Test vulnerability with single CWE ID."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0001",
                            "Severity": "HIGH",
                            "CweIDs": ["CWE-79"],
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "cwe.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].risk is not None
        assert "CWE-79" in findings[0].risk["cwe"]

    def test_multiple_cwe_ids(self, tmp_path: Path):
        """Test vulnerability with multiple CWE IDs."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2023-0002",
                            "Severity": "CRITICAL",
                            "CweIDs": ["CWE-79", "CWE-352", "CWE-89"],
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "multi_cwe.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert len(findings[0].risk["cwe"]) == 3

    def test_no_cwe_ids(self, tmp_path: Path):
        """Test vulnerability without CWE IDs."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-2023-0003", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "no_cwe.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].risk is None


class TestTrivyCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is set correctly."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V-SCHEMA", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "schema.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].schemaVersion == "1.2.0"

    def test_tool_version_captured(self, tmp_path: Path):
        """Test tool version is captured from output."""
        sample = {
            "Version": "0.47.0",
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V-VER", "Severity": "LOW"}
                    ],
                }
            ],
        }
        path = write(tmp_path, "version.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].tool["version"] == "0.47.0"

    def test_missing_version_defaults_to_unknown(self, tmp_path: Path):
        """Test missing version defaults to unknown."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "V-NOVER", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "no_ver.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert findings[0].tool["version"] == "unknown"

    def test_remediation_url(self, tmp_path: Path):
        """Test remediation uses PrimaryURL when available."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-URL",
                            "Severity": "HIGH",
                            "PrimaryURL": "https://nvd.nist.gov/vuln/detail/CVE-URL",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "url.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert "nvd.nist.gov" in findings[0].remediation


class TestTrivyFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        sample = {
            "Results": [
                {
                    "Target": "file1.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-F1", "Severity": "LOW"}
                    ],
                },
                {
                    "Target": "file2.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-F2", "Severity": "LOW"}
                    ],
                },
            ]
        }
        path = write(tmp_path, "fingerprint.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        sample = {
            "Results": [
                {
                    "Target": "test.txt",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-CONS", "Severity": "MEDIUM"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "consistent.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings1 = adapter.parse(path)
        findings2 = adapter.parse(path)
        assert findings1[0].id == findings2[0].id


class TestTrivyUnicodeHandling:
    """Tests for Unicode and encoding edge cases."""

    def test_unicode_in_target(self, tmp_path: Path):
        """Test parsing with Unicode in target path."""
        sample = {
            "Results": [
                {
                    "Target": "packages/\u65e5\u672c\u8a9e/lib.js",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-UNI", "Severity": "LOW"}
                    ],
                }
            ]
        }
        path = write(tmp_path, "unicode.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u65e5\u672c\u8a9e" in findings[0].location["path"]

    def test_unicode_in_title(self, tmp_path: Path):
        """Test parsing with Unicode in title."""
        sample = {
            "Results": [
                {
                    "Target": "test",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-UNI2",
                            "Title": "Vuln\u00e9rabilit\u00e9 critique",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "unicode_title.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u00e9" in findings[0].message


class TestTrivyMisconfigurationDetails:
    """Tests for misconfiguration-specific features."""

    def test_misconfig_with_rule_id_only(self, tmp_path: Path):
        """Test misconfiguration with only RuleID (no Title)."""
        sample = {
            "Results": [
                {
                    "Target": "Dockerfile",
                    "Misconfigurations": [
                        {
                            "RuleID": "DS001",
                            "Description": "No healthcheck defined",
                            "Severity": "LOW",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "misconfig.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        # Without Title, RuleID is used
        assert findings[0].ruleId == "DS001"

    def test_misconfig_fallback_to_title(self, tmp_path: Path):
        """Test misconfiguration using Title as fallback rule ID."""
        sample = {
            "Results": [
                {
                    "Target": "docker-compose.yml",
                    "Misconfigurations": [
                        {
                            "Title": "Privileged container",
                            "Severity": "HIGH",
                        }
                    ],
                }
            ]
        }
        path = write(tmp_path, "misconfig_title.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "Privileged container" in findings[0].ruleId

    def test_secrets_not_vulnerabilities(self, tmp_path: Path):
        """Test that secrets and vulnerabilities are tagged differently."""
        sample = {
            "Results": [
                {
                    "Target": "app",
                    "Vulnerabilities": [
                        {"VulnerabilityID": "CVE-V", "Severity": "HIGH"}
                    ],
                    "Secrets": [{"Title": "API Key", "Severity": "HIGH"}],
                }
            ]
        }
        path = write(tmp_path, "mixed_tags.json", json.dumps(sample))
        adapter = TrivyAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        vuln_finding = [f for f in findings if "vulnerability" in f.tags][0]
        secret_finding = [f for f in findings if "secret" in f.tags][0]
        assert vuln_finding.ruleId == "CVE-V"
        assert secret_finding.ruleId == "API Key"
