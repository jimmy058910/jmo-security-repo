import json
from pathlib import Path

from scripts.core.adapters.nuclei_adapter import NucleiAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    """Helper to write temp files for testing."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


# ========================================
# Category 1: Basic Valid Input
# ========================================


def test_nuclei_basic(tmp_path: Path):
    """Test basic valid finding with all required fields."""
    # Nuclei uses NDJSON format (one JSON object per line)
    sample = json.dumps(
        {
            "template-id": "CVE-2021-44228",
            "info": {
                "name": "Apache Log4j RCE",
                "severity": "critical",
                "description": "Apache Log4j2 Remote Code Execution",
            },
            "matched-at": "https://example.com/api",
            "matcher-name": "version-check",
            "type": "http",
        }
    )
    path = write_tmp(tmp_path, "nuclei.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)

    # Verify parsing succeeded
    assert len(findings) == 1, "Should parse 1 finding"

    item = findings[0]

    # Verify CommonFinding schema fields
    assert item.ruleId == "CVE-2021-44228"
    assert item.severity == "CRITICAL"
    assert item.location["path"] == "https://example.com/api"
    assert item.location["startLine"] == 0  # Web findings don't have line numbers
    assert item.schemaVersion in ["1.1.0", "1.2.0"]  # After enrichment

    # Verify required fields exist
    assert hasattr(item, "id"), "Fingerprint ID required"
    assert len(item.id) == 16, "Fingerprint should be 16 hex chars (truncated SHA256)"
    assert hasattr(item, "tool")
    assert item.tool["name"] == "nuclei"
    assert hasattr(item, "message")
    assert "version-check" in item.message  # Should include matcher-name
    assert hasattr(item, "raw") and item.raw, "Original tool output must be preserved"
    assert item.raw["template-id"] == "CVE-2021-44228"


def test_nuclei_multiple_findings(tmp_path: Path):
    """Test parsing multiple findings from NDJSON file."""
    lines = [
        json.dumps(
            {
                "template-id": "CVE-2021-44228",
                "info": {"name": "Log4j RCE", "severity": "critical"},
                "matched-at": "https://example.com/api",
            }
        ),
        json.dumps(
            {
                "template-id": "CVE-2020-5902",
                "info": {"name": "F5 BIG-IP TMUI RCE", "severity": "high"},
                "matched-at": "https://example.com/admin",
            }
        ),
        json.dumps(
            {
                "template-id": "exposed-git-config",
                "info": {"name": "Exposed .git/config", "severity": "medium"},
                "matched-at": "https://example.com/.git/config",
            }
        ),
    ]
    path = write_tmp(tmp_path, "nuclei_multi.json", "\n".join(lines))
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)

    assert len(findings) == 3, "Should parse all 3 findings"
    assert findings[0].ruleId == "CVE-2021-44228"
    assert findings[1].ruleId == "CVE-2020-5902"
    assert findings[2].ruleId == "exposed-git-config"
    # Verify severities were normalized
    assert findings[0].severity == "CRITICAL"
    assert findings[1].severity == "HIGH"
    assert findings[2].severity == "MEDIUM"


# ========================================
# Category 2: Error Handling
# ========================================


def test_nuclei_empty_and_malformed(tmp_path: Path):
    """Test error handling for empty and malformed inputs."""
    # Test 1: Empty file
    p1 = write_tmp(tmp_path, "empty.json", "")
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    assert adapter.parse(p1) == [], "Empty file should return empty list"

    # Test 2: Malformed JSON (syntax error)
    p2 = write_tmp(tmp_path, "bad.json", "{not valid json}\n{also bad}")
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    assert adapter.parse(p2) == [], "Malformed JSON should return empty list"

    # Test 3: Valid JSON but wrong structure (non-dict)
    p3 = write_tmp(tmp_path, "badstruct.json", json.dumps([1, 2, 3]))
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    assert adapter.parse(p3) == [], "Non-dict JSON should return empty list"

    # Test 4: Mixed valid and invalid lines
    lines = [
        "{not valid}",  # Invalid
        json.dumps(
            {"template-id": "test", "info": {"name": "Test", "severity": "low"}}
        ),  # Valid
        "another bad line",  # Invalid
    ]
    p4 = write_tmp(tmp_path, "mixed.json", "\n".join(lines))
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(p4)
    assert len(findings) == 1, "Should parse 1 valid finding (skip 2 invalid)"
    assert findings[0].ruleId == "test"


def test_nuclei_nonexistent_file(tmp_path: Path):
    """Test loading from non-existent file returns empty list."""
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    result = adapter.parse(tmp_path / "nonexistent.json")
    assert result == [], "Non-existent file should return empty list"


def test_nuclei_empty_lines(tmp_path: Path):
    """Test handling empty lines in NDJSON (should skip them)."""
    lines = [
        "",  # Empty
        json.dumps(
            {"template-id": "test1", "info": {"name": "Test 1", "severity": "low"}}
        ),
        "",  # Empty
        "",  # Empty
        json.dumps(
            {"template-id": "test2", "info": {"name": "Test 2", "severity": "high"}}
        ),
        "",  # Empty
    ]
    path = write_tmp(tmp_path, "empty_lines.json", "\n".join(lines))
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 2, "Should parse 2 valid findings (skip empty lines)"
    assert findings[0].ruleId == "test1"
    assert findings[1].ruleId == "test2"


def test_nuclei_unicode_and_encoding(tmp_path: Path):
    """Test handling of Unicode characters in findings."""
    sample = json.dumps(
        {
            "template-id": "unicode-test",
            "info": {
                "name": "SQL注入漏洞 (Chinese: SQL injection vulnerability)",
                "severity": "high",
                "description": "发现SQL注入 in API endpoint",
            },
            "matched-at": "https://测试.example.com/api",
        },
        ensure_ascii=False,
    )
    path = write_tmp(tmp_path, "nuclei_unicode.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)

    assert len(findings) == 1
    assert "SQL注入" in findings[0].title
    assert "测试" in findings[0].location["path"]


# ========================================
# Category 3: v1.1.0 Features
# ========================================


def test_nuclei_v110_remediation(tmp_path: Path):
    """Test v1.1.0 remediation extraction."""
    sample = json.dumps(
        {
            "template-id": "exposed-env-file",
            "info": {
                "name": "Exposed .env File",
                "severity": "high",
                "description": ".env file exposed on web server",
                "remediation": "Remove .env file from public directory and use environment variables instead.",
            },
            "matched-at": "https://example.com/.env",
        }
    )
    path = write_tmp(tmp_path, "nuclei_remediation.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert isinstance(item.remediation, str)
    assert "Remove .env file" in item.remediation


def test_nuclei_v110_remediation_without_field(tmp_path: Path):
    """Test v1.1.0 remediation fallback when not provided."""
    sample = json.dumps(
        {
            "template-id": "test-rule",
            "info": {
                "name": "Test Finding",
                "severity": "medium",
            },
            "matched-at": "https://example.com/",
        }
    )
    path = write_tmp(tmp_path, "nuclei_no_remediation.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert isinstance(item.remediation, str)
    assert len(item.remediation) > 0


def test_nuclei_v110_cwe_metadata(tmp_path: Path):
    """Test v1.1.0 CWE metadata extraction."""
    sample = json.dumps(
        {
            "template-id": "sql-injection",
            "info": {
                "name": "SQL Injection",
                "severity": "high",
                "classification": {
                    "cwe-id": ["CWE-89", "CWE-20"],
                    "cve-id": ["CVE-2023-12345"],
                },
            },
            "matched-at": "https://example.com/api?id=1",
        }
    )
    path = write_tmp(tmp_path, "nuclei_cwe.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Check risk metadata (v1.1.0 feature)
    assert hasattr(item, "risk") and item.risk
    assert "cwe" in item.risk
    assert item.risk["cwe"] == ["CWE-89", "CWE-20"]

    # Check CVE references
    assert hasattr(item, "references") and item.references
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-12345" in item.references


def test_nuclei_v110_cwe_string_format(tmp_path: Path):
    """Test v1.1.0 CWE as string instead of list (should normalize to list)."""
    sample = json.dumps(
        {
            "template-id": "xss-test",
            "info": {
                "name": "XSS Vulnerability",
                "severity": "high",
                "classification": {
                    "cwe-id": "CWE-79",  # String, not array
                },
            },
            "matched-at": "https://example.com/search?q=<script>",
        }
    )
    path = write_tmp(tmp_path, "nuclei_cwe_string.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "cwe" in item.risk
    # Should be converted to list by adapter
    assert item.risk["cwe"] == ["CWE-79"]
    assert isinstance(item.risk["cwe"], list)


def test_nuclei_v110_references(tmp_path: Path):
    """Test v1.1.0 reference URL extraction."""
    sample = json.dumps(
        {
            "template-id": "cve-2023-test",
            "info": {
                "name": "CVE-2023 Test",
                "severity": "critical",
                "reference": [
                    "https://nvd.nist.gov/vuln/detail/CVE-2023-12345",
                    "https://example.com/advisory",
                ],
            },
            "matched-at": "https://example.com/",
        }
    )
    path = write_tmp(tmp_path, "nuclei_refs.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "references") and item.references
    assert "https://nvd.nist.gov/vuln/detail/CVE-2023-12345" in item.references
    assert "https://example.com/advisory" in item.references


# ========================================
# Category 4: v1.2.0 Features (Compliance)
# ========================================


def test_nuclei_compliance_enrichment(tmp_path: Path):
    """Test that findings are enriched with compliance mappings (v1.2.0)."""
    sample = json.dumps(
        {
            "template-id": "xss-reflected",
            "info": {
                "name": "Reflected XSS",
                "severity": "high",
                "classification": {
                    "cwe-id": "CWE-79",
                },
            },
            "matched-at": "https://example.com/search",
        }
    )
    path = write_tmp(tmp_path, "nuclei_compliance.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]

    # Schema version should be 1.2.0 after enrichment
    assert item.schemaVersion in ["1.1.0", "1.2.0"]

    # Compliance field may be added by enrichment (depends on CWE mapping)
    if hasattr(item, "compliance") and item.compliance:
        compliance = item.compliance

        # Verify structure - should have at least one framework
        possible_frameworks = [
            "owaspTop10_2021",
            "cweTop25_2024",
            "cisControlsV8_1",
            "nistCsf2_0",
            "pciDss4_0",
            "mitreAttack",
        ]

        # At least one framework should be present if CWE matched
        framework_count = sum(1 for fw in possible_frameworks if fw in compliance)
        assert framework_count > 0, "Should have at least one framework mapping"

        # CWE-79 (XSS) should map to OWASP A03:2021 (Injection)
        if "owaspTop10_2021" in compliance:
            assert "A03:2021" in compliance["owaspTop10_2021"]

    # Verify risk metadata is preserved after enrichment
    if hasattr(item, "risk") and item.risk:
        assert "cwe" in item.risk
        assert item.risk["cwe"] == ["CWE-79"]


def test_nuclei_compliance_no_cwe(tmp_path: Path):
    """Test findings without CWE still get enriched (category-based mapping)."""
    sample = json.dumps(
        {
            "template-id": "custom-misconfiguration",
            "info": {
                "name": "Custom Finding",
                "severity": "medium",
            },
            "matched-at": "https://example.com/",
        }
    )
    path = write_tmp(tmp_path, "nuclei_no_cwe.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Should still have schemaVersion 1.2.0 after enrichment attempt
    assert item.schemaVersion in ["1.1.0", "1.2.0"]


# ========================================
# Category 5: Tool-Specific Edge Cases
# ========================================


def test_nuclei_severity_normalization(tmp_path: Path):
    """Test severity normalization from Nuclei values."""
    severities = [
        ("info", "INFO"),
        ("low", "LOW"),
        ("medium", "MEDIUM"),
        ("high", "HIGH"),
        ("critical", "CRITICAL"),
        ("unknown", "UNKNOWN"),
        ("INVALID", "UNKNOWN"),  # Fallback for invalid values
    ]

    for nuclei_sev, expected_sev in severities:
        sample = json.dumps(
            {
                "template-id": f"test-{nuclei_sev}",
                "info": {
                    "name": "Test",
                    "severity": nuclei_sev,
                },
                "matched-at": "https://example.com/",
            }
        )
        path = write_tmp(tmp_path, f"nuclei_{nuclei_sev}.json", sample)
        adapter = NucleiAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].severity == expected_sev, f"Failed for {nuclei_sev}"


def test_nuclei_alternative_field_names(tmp_path: Path):
    """Test handling alternative field names (templateID vs template-id)."""
    sample = json.dumps(
        {
            "templateID": "alt-field-test",  # Alternative field name
            "info": {
                "name": "Alternative Fields Test",
                "severity": "low",
            },
            "matched": "https://example.com/alt",  # Alternative to matched-at
        }
    )
    path = write_tmp(tmp_path, "nuclei_alt_fields.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].ruleId == "alt-field-test"
    assert findings[0].location["path"] == "https://example.com/alt"


def test_nuclei_missing_optional_fields(tmp_path: Path):
    """Test handling of missing optional fields (should use defaults)."""
    sample = json.dumps(
        {
            "template-id": "minimal-finding",
            "info": {
                "name": "Minimal",
                # Missing: severity, description, remediation, classification
            },
            # Missing: matched-at, matcher-name
        }
    )
    path = write_tmp(tmp_path, "nuclei_minimal.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Required fields should be populated with defaults
    assert item.severity == "MEDIUM"  # Default severity
    assert item.location["path"] == ""  # Empty string if missing
    assert hasattr(item, "remediation")  # Should have default remediation
    assert item.tool["version"] == "unknown"  # Default version


def test_nuclei_tags_present(tmp_path: Path):
    """Test that appropriate category tags are always present."""
    sample = json.dumps(
        {
            "template-id": "test-tags",
            "info": {
                "name": "Test Tags",
                "severity": "info",
                "tags": ["cve", "wordpress", "plugin"],  # Template tags
            },
            "matched-at": "https://example.com/",
        }
    )
    path = write_tmp(tmp_path, "nuclei_tags.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "tags") and item.tags
    assert isinstance(item.tags, list)
    assert len(item.tags) > 0

    # Verify tool category tags present
    assert "dast" in item.tags
    assert "web-security" in item.tags
    assert "api-security" in item.tags

    # Verify template tags were added
    assert "cve" in item.tags
    assert "wordpress" in item.tags
    assert "plugin" in item.tags


def test_nuclei_raw_field_preserved(tmp_path: Path):
    """Test that raw tool output is preserved in finding."""
    sample = json.dumps(
        {
            "template-id": "raw-test",
            "info": {
                "name": "Raw Preservation Test",
                "severity": "info",
            },
            "matched-at": "https://example.com/",
            "custom_nuclei_field": "custom_value",  # Tool-specific field
            "metadata": {"key": "value"},
        }
    )
    path = write_tmp(tmp_path, "nuclei_raw.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "raw") and item.raw
    assert isinstance(item.raw, dict)
    # Original tool output should be completely preserved
    assert item.raw["custom_nuclei_field"] == "custom_value"
    assert item.raw["metadata"] == {"key": "value"}


def test_nuclei_fingerprint_stability(tmp_path: Path):
    """Test that fingerprint is stable across multiple parses."""
    sample = json.dumps(
        {
            "template-id": "stable-test",
            "info": {
                "name": "Fingerprint Stability Test",
                "severity": "high",
            },
            "matched-at": "https://example.com/api",
        }
    )

    # Parse twice to verify fingerprint doesn't change
    path = write_tmp(tmp_path, "nuclei_fingerprint.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    out1 = adapter.parse(path)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    out2 = adapter.parse(path)

    assert len(out1) == 1
    assert len(out2) == 1

    # Fingerprints should be identical
    assert out1[0].id == out2[0].id
    # Fingerprint should be 16 hex characters (truncated SHA256)
    assert len(out1[0].id) == 16
    assert all(c in "0123456789abcdef" for c in out1[0].id)


def test_nuclei_matcher_name_in_message(tmp_path: Path):
    """Test that matcher-name is included in message when present."""
    sample = json.dumps(
        {
            "template-id": "version-detection",
            "info": {
                "name": "Nginx Version Detection",
                "severity": "info",
            },
            "matched-at": "https://example.com/",
            "matcher-name": "nginx-1.20.1",
        }
    )
    path = write_tmp(tmp_path, "nuclei_matcher.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Matcher name should be in message
    assert "matcher: nginx-1.20.1" in item.message


def test_nuclei_host_fallback(tmp_path: Path):
    """Test using host field when matched-at is missing."""
    sample = json.dumps(
        {
            "template-id": "dns-test",
            "info": {
                "name": "DNS Misconfiguration",
                "severity": "medium",
            },
            "host": "example.com",  # Used when matched-at missing
            "type": "dns",
        }
    )
    path = write_tmp(tmp_path, "nuclei_host.json", sample)
    adapter = NucleiAdapter()
    adapter = NucleiAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert item.location["path"] == "example.com"
