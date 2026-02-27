"""Comprehensive tests for ZAP adapter.

Tests cover:
- Basic parsing of ZAP JSON output
- Multiple severity/risk levels (Informational, Low, Medium, High)
- Multiple instances per alert
- CWE and WASC tagging
- Edge cases (empty input, malformed JSON, missing fields)
- URI/method/param context extraction
- Evidence truncation
- Reference URL parsing
"""

import json
from pathlib import Path


from scripts.core.adapters.zap_adapter import ZapAdapter
from scripts.core.common_finding import map_tool_severity


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temporary file."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestZapBasicParsing:
    """Tests for basic ZAP output parsing."""

    def test_basic_alert(self, tmp_path: Path):
        """Test basic ZAP alert parsing."""
        sample = {
            "@version": "2.11.0",
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "SQL Injection",
                            "risk": "High",
                            "confidence": "Medium",
                            "desc": "SQL injection may be possible",
                            "solution": "Use parameterized queries",
                            "reference": "https://owasp.org/www-community/attacks/SQL_Injection",
                            "cweid": "89",
                            "wascid": "19",
                            "instances": [
                                {
                                    "uri": "http://example.com/page?id=1",
                                    "method": "GET",
                                    "param": "id",
                                    "evidence": "' OR 1=1",
                                }
                            ],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        item = findings[0]
        assert item.severity == "HIGH"
        assert item.title == "SQL Injection"
        assert "CWE-89" in item.tags
        assert item.context["method"] == "GET"
        assert item.context["param"] == "id"
        assert item.tool["version"] == "2.11.0"

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = ZapAdapter()
        metadata = adapter.metadata
        assert metadata.name == "zap"
        assert metadata.tool_name == "zap"
        assert metadata.schema_version == "1.2.0"
        assert metadata.output_format == "json"


class TestZapMultipleInstances:
    """Tests for alerts with multiple instances."""

    def test_multiple_instances(self, tmp_path: Path):
        """Test ZAP alert with multiple instances."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Cross Site Scripting (XSS)",
                            "risk": "Medium",
                            "confidence": "High",
                            "desc": "XSS vulnerability detected",
                            "instances": [
                                {
                                    "uri": "http://example.com/search?q=test",
                                    "method": "GET",
                                    "param": "q",
                                },
                                {
                                    "uri": "http://example.com/profile?name=user",
                                    "method": "GET",
                                    "param": "name",
                                },
                            ],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        # Should create 2 findings (one per instance)
        assert len(findings) == 2
        assert all(it.title == "Cross Site Scripting (XSS)" for it in findings)
        assert findings[0].context["param"] == "q"
        assert findings[1].context["param"] == "name"

    def test_no_instances(self, tmp_path: Path):
        """Test ZAP alert with no instances."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Missing Security Header",
                            "risk": "Low",
                            "confidence": "High",
                            "instances": [],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        # Should create 1 finding even with no instances
        assert len(findings) == 1
        assert findings[0].severity == "LOW"


class TestZapSeverityMapping:
    """Tests for severity level mapping."""

    def test_informational_severity(self, tmp_path: Path):
        """Test Informational risk mapping."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Info Alert",
                            "risk": "Informational",
                            "confidence": "Medium",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "INFO"

    def test_low_severity(self, tmp_path: Path):
        """Test Low risk mapping."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Low Alert",
                            "risk": "Low",
                            "confidence": "Medium",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "LOW"

    def test_medium_severity(self, tmp_path: Path):
        """Test Medium risk mapping."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Medium Alert",
                            "risk": "Medium",
                            "confidence": "Medium",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "MEDIUM"

    def test_high_severity(self, tmp_path: Path):
        """Test High risk mapping."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "High Alert",
                            "risk": "High",
                            "confidence": "Medium",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "HIGH"

    def test_unknown_severity_defaults_to_info(self, tmp_path: Path):
        """Test unknown risk level defaults to INFO via centralized mapping."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Unknown Risk Alert",
                            "risk": "UnknownLevel",
                            "confidence": "Medium",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ],
        }
        path = write_tmp(tmp_path, "zap.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "INFO"


class TestZapRiskFunction:
    """Tests for ZAP severity mapping via centralized map_tool_severity."""

    def test_informational_mapping(self):
        """Test informational risk mapping."""
        assert map_tool_severity("zap", "Informational") == "INFO"
        assert map_tool_severity("zap", "informational") == "INFO"
        assert map_tool_severity("zap", "INFORMATIONAL") == "INFO"

    def test_low_mapping(self):
        """Test low risk mapping."""
        assert map_tool_severity("zap", "Low") == "LOW"
        assert map_tool_severity("zap", "low") == "LOW"

    def test_medium_mapping(self):
        """Test medium risk mapping."""
        assert map_tool_severity("zap", "Medium") == "MEDIUM"
        assert map_tool_severity("zap", "medium") == "MEDIUM"

    def test_high_mapping(self):
        """Test high risk mapping."""
        assert map_tool_severity("zap", "High") == "HIGH"
        assert map_tool_severity("zap", "high") == "HIGH"

    def test_critical_mapping(self):
        """Test critical risk mapping."""
        assert map_tool_severity("zap", "Critical") == "CRITICAL"
        assert map_tool_severity("zap", "critical") == "CRITICAL"

    def test_unknown_defaults_to_info(self):
        """Test unknown risk defaults to INFO via centralized normalization."""
        assert map_tool_severity("zap", "Unknown") == "INFO"
        assert map_tool_severity("zap", "") == "INFO"


class TestZapEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test empty file handling."""
        empty = write_tmp(tmp_path, "empty.json", "")
        adapter = ZapAdapter()
        assert adapter.parse(empty) == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test nonexistent file handling."""
        nonexistent = tmp_path / "nonexistent.json"
        adapter = ZapAdapter()
        assert adapter.parse(nonexistent) == []

    def test_malformed_json(self, tmp_path: Path):
        """Test malformed JSON handling."""
        bad = write_tmp(tmp_path, "bad.json", "{not valid json}")
        adapter = ZapAdapter()
        assert adapter.parse(bad) == []

    def test_site_not_list(self, tmp_path: Path):
        """Test when site is not a list."""
        sample = {"site": "not a list"}
        path = write_tmp(tmp_path, "bad_site.json", json.dumps(sample))
        adapter = ZapAdapter()
        assert adapter.parse(path) == []

    def test_site_missing(self, tmp_path: Path):
        """Test when site key is missing."""
        sample = {"version": "2.11.0"}
        path = write_tmp(tmp_path, "no_site.json", json.dumps(sample))
        adapter = ZapAdapter()
        assert adapter.parse(path) == []

    def test_alerts_not_list(self, tmp_path: Path):
        """Test when alerts is not a list."""
        sample = {"site": [{"alerts": "not a list"}]}
        path = write_tmp(tmp_path, "bad_alerts.json", json.dumps(sample))
        adapter = ZapAdapter()
        assert adapter.parse(path) == []

    def test_site_item_not_dict(self, tmp_path: Path):
        """Test when site item is not a dictionary."""
        sample = {"site": ["not a dict", 123]}
        path = write_tmp(tmp_path, "bad_site_item.json", json.dumps(sample))
        adapter = ZapAdapter()
        assert adapter.parse(path) == []

    def test_alert_item_not_dict(self, tmp_path: Path):
        """Test when alert item is not a dictionary."""
        sample = {"site": [{"alerts": ["not a dict", 123]}]}
        path = write_tmp(tmp_path, "bad_alert_item.json", json.dumps(sample))
        adapter = ZapAdapter()
        assert adapter.parse(path) == []

    def test_instance_not_dict(self, tmp_path: Path):
        """Test when instance is not a dictionary."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": ["not a dict", 123],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "bad_instance.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        # Should skip non-dict instances
        assert len(findings) == 0


class TestZapTagging:
    """Tests for CWE and WASC tagging."""

    def test_cwe_tag(self, tmp_path: Path):
        """Test CWE tag is added."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "XSS",
                            "risk": "High",
                            "cweid": "79",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "cwe.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert "CWE-79" in findings[0].tags

    def test_wasc_tag(self, tmp_path: Path):
        """Test WASC tag is added."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "CSRF",
                            "risk": "Medium",
                            "wascid": "9",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "wasc.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert "WASC-9" in findings[0].tags

    def test_confidence_tag(self, tmp_path: Path):
        """Test confidence is captured in tags."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "confidence": "High",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "confidence.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert "confidence:high" in findings[0].tags

    def test_dast_and_web_security_tags(self, tmp_path: Path):
        """Test dast and web-security tags are present."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "tags.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert "dast" in findings[0].tags
        assert "web-security" in findings[0].tags


class TestZapContext:
    """Tests for context extraction."""

    def test_uri_context(self, tmp_path: Path):
        """Test URI is captured in context."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [
                                {
                                    "uri": "http://example.com/api/users",
                                    "method": "POST",
                                }
                            ],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "uri.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].context["uri"] == "http://example.com/api/users"

    def test_method_context(self, tmp_path: Path):
        """Test HTTP method is captured in context."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [
                                {"uri": "http://example.com", "method": "DELETE"}
                            ],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "method.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].context["method"] == "DELETE"

    def test_param_context(self, tmp_path: Path):
        """Test parameter name is captured in context."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [
                                {"uri": "http://example.com", "param": "user_id"}
                            ],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "param.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].context["param"] == "user_id"

    def test_evidence_truncation(self, tmp_path: Path):
        """Test long evidence is truncated to 200 chars."""
        long_evidence = "A" * 300
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [
                                {"uri": "http://example.com", "evidence": long_evidence}
                            ],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "evidence.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings[0].context["evidence"]) == 200

    def test_alternative_url_field(self, tmp_path: Path):
        """Test url field works as alternative to uri."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [{"url": "http://alt.example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "url.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].context["uri"] == "http://alt.example.com"

    def test_alternative_parameter_field(self, tmp_path: Path):
        """Test parameter field works as alternative to param."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [
                                {"uri": "http://example.com", "parameter": "token"}
                            ],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "parameter.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].context["param"] == "token"


class TestZapReferences:
    """Tests for reference URL parsing."""

    def test_single_reference(self, tmp_path: Path):
        """Test single reference URL parsing."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "reference": "https://owasp.org/xss",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "ref.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert "https://owasp.org/xss" in findings[0].references

    def test_multiple_references(self, tmp_path: Path):
        """Test multiple reference URLs separated by newlines."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "reference": "https://owasp.org/xss\nhttps://cwe.mitre.org/79",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "multi_ref.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings[0].references) == 2
        assert "https://owasp.org/xss" in findings[0].references
        assert "https://cwe.mitre.org/79" in findings[0].references

    def test_empty_reference(self, tmp_path: Path):
        """Test empty reference handling."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "reference": "",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "no_ref.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].references is None or len(findings[0].references) == 0


class TestZapCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is set correctly."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "schema.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].schemaVersion == "1.2.0"

    def test_tool_name(self, tmp_path: Path):
        """Test tool name is correct."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert findings[0].tool["name"] == "zap"

    def test_remediation_from_solution(self, tmp_path: Path):
        """Test remediation is extracted from solution field."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "solution": "Apply input validation",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "solution.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert "Apply input validation" in findings[0].remediation


class TestZapFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "XSS",
                            "risk": "High",
                            "cweid": "79",
                            "instances": [
                                {"uri": "http://example.com/page1", "param": "a"},
                                {"uri": "http://example.com/page2", "param": "b"},
                            ],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "fingerprint.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [{"uri": "http://example.com/same"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "consistent.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings1 = adapter.parse(path)
        findings2 = adapter.parse(path)
        assert findings1[0].id == findings2[0].id


class TestZapUnicodeHandling:
    """Tests for Unicode and encoding edge cases."""

    def test_unicode_in_alert_name(self, tmp_path: Path):
        """Test parsing with Unicode in alert name."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Vuln\u00e9rabilit\u00e9 XSS",
                            "risk": "High",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "unicode.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u00e9" in findings[0].title

    def test_unicode_in_uri(self, tmp_path: Path):
        """Test parsing with Unicode in URI."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Test",
                            "risk": "Low",
                            "instances": [
                                {"uri": "http://example.com/\u65e5\u672c\u8a9e/page"}
                            ],
                        }
                    ]
                }
            ]
        }
        path = write_tmp(tmp_path, "unicode_uri.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u65e5\u672c\u8a9e" in findings[0].context["uri"]


class TestZapMultipleSites:
    """Tests for multiple site handling."""

    def test_multiple_sites(self, tmp_path: Path):
        """Test parsing multiple sites."""
        sample = {
            "site": [
                {
                    "alerts": [
                        {
                            "alert": "Site1 Issue",
                            "risk": "Low",
                            "instances": [{"uri": "http://site1.com"}],
                        }
                    ]
                },
                {
                    "alerts": [
                        {
                            "alert": "Site2 Issue",
                            "risk": "High",
                            "instances": [{"uri": "http://site2.com"}],
                        }
                    ]
                },
            ]
        }
        path = write_tmp(tmp_path, "multi_site.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        titles = {f.title for f in findings}
        assert titles == {"Site1 Issue", "Site2 Issue"}

    def test_empty_alerts_in_site(self, tmp_path: Path):
        """Test site with empty alerts array."""
        sample = {
            "site": [
                {"alerts": []},
                {
                    "alerts": [
                        {
                            "alert": "Real Alert",
                            "risk": "Medium",
                            "instances": [{"uri": "http://example.com"}],
                        }
                    ]
                },
            ]
        }
        path = write_tmp(tmp_path, "empty_alerts.json", json.dumps(sample))
        adapter = ZapAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].title == "Real Alert"
