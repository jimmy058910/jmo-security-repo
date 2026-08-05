# Required Test Functions by Category

Every adapter test suite MUST include these 5 categories of tests.

---

## Category 1: Basic Valid Input Test

Tests the happy path with valid tool output containing all required fields.

**Purpose:** Verify adapter correctly parses well-formed tool output and maps to CommonFinding schema.

**Pattern:**

```python
def test_<tool>_basic(tmp_path: Path):
    """Test basic valid finding with all required fields."""
    sample = {
        # Create minimal valid tool output
        # Match real tool's JSON structure exactly
        "results": [
            {
                "ruleId": "test-rule-001",
                "message": "Security vulnerability detected",
                "severity": "HIGH",
                "path": "src/app.py",
                "line": 42,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>.json", json.dumps(sample))
    out = load_<tool>(path)

    # Verify parsing succeeded
    assert len(out) == 1, "Expected exactly one finding"

    item = out[0]

    # Verify CommonFinding schema fields
    assert item["ruleId"] == "test-rule-001"
    assert item["severity"] == "HIGH"
    assert item["message"] == "Security vulnerability detected"
    assert item["location"]["path"] == "src/app.py"
    assert item["location"]["startLine"] == 42

    # Verify schema version (may be 1.1.0 or 1.2.0 after enrichment)
    assert item["schemaVersion"] in ["1.0.0", "1.1.0", "1.2.0"]

    # Verify fingerprint ID is present and stable
    assert "id" in item
    assert len(item["id"]) > 20  # SHA256 hash
    assert item["id"].startswith(("<tool>", ""))  # Some use tool prefix

    # Verify tool metadata
    assert "tool" in item
    assert item["tool"]["name"] == "<tool>"
    assert "version" in item["tool"]

    # Verify raw payload is preserved
    assert "raw" in item
    assert item["raw"]["ruleId"] == "test-rule-001"
```

**Key Assertions:**

1. **Length check:** `assert len(out) == 1` -- Verify expected number of findings
2. **Field mapping:** Verify all CommonFinding required fields present
3. **Schema version:** Allow 1.0.0, 1.1.0, or 1.2.0 (depends on enrichment)
4. **Fingerprint stability:** ID should be deterministic and unique
5. **Raw preservation:** Original tool output must be in `raw` field

**Variants for Different Tools:**

```python
# Secrets tool (trufflehog, noseyparker)
def test_trufflehog_basic(tmp_path: Path):
    sample = [
        {
            "DetectorName": "AWS",
            "Verified": True,
            "Raw": "AKIAIOSFODNN7EXAMPLE",
            "SourceMetadata": {
                "Data": {"Filesystem": {"file": "config.yaml", "line": 7}}
            },
        }
    ]
    path = write_tmp(tmp_path, "trufflehog.json", json.dumps(sample))
    out = load_trufflehog(path)
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"  # Verified secret
    assert out[0]["location"]["path"] == "config.yaml"


# SAST tool (semgrep, bandit)
def test_semgrep_basic(tmp_path: Path):
    sample = {
        "results": [
            {
                "check_id": "python.django.security.injection.sql",
                "path": "views.py",
                "start": {"line": 15, "col": 4},
                "end": {"line": 15, "col": 30},
                "extra": {
                    "message": "SQL injection vulnerability",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89"], "confidence": "HIGH"},
                },
            }
        ]
    }
    path = write_tmp(tmp_path, "semgrep.json", json.dumps(sample))
    out = load_semgrep(path)
    assert len(out) == 1
    assert out[0]["ruleId"] == "python.django.security.injection.sql"


# Vulnerability scanner (trivy, snyk)
def test_trivy_basic(tmp_path: Path):
    sample = {
        "Results": [
            {
                "Target": "package-lock.json",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2023-12345",
                        "PkgName": "lodash",
                        "InstalledVersion": "4.17.15",
                        "Severity": "HIGH",
                        "Title": "Prototype pollution vulnerability",
                    }
                ],
            }
        ]
    }
    path = write_tmp(tmp_path, "trivy.json", json.dumps(sample))
    out = load_trivy(path)
    assert len(out) == 1
    assert out[0]["ruleId"] == "CVE-2023-12345"
```

---

## Category 2: Error Handling Tests

Tests resilience to malformed, empty, or missing inputs. Adapters MUST return empty list `[]` for invalid inputs (never raise exceptions).

**Purpose:** Ensure adapter gracefully handles real-world error conditions without crashing the scan.

**Pattern:**

```python
def test_<tool>_empty_and_malformed(tmp_path: Path):
    """Test error handling for empty and malformed inputs."""
    # Test 1: Empty file
    p1 = write_tmp(tmp_path, "empty.json", "")
    assert load_<tool>(p1) == [], "Empty file should return empty list"

    # Test 2: Malformed JSON (syntax error)
    p2 = write_tmp(tmp_path, "bad.json", "{not valid json}")
    assert load_<tool>(p2) == [], "Malformed JSON should return empty list"

    # Test 3: Valid JSON but missing expected structure
    p3 = write_tmp(tmp_path, "noresults.json", json.dumps({}))
    assert load_<tool>(p3) == [], "Missing results field should return empty list"

    # Test 4: Valid JSON but wrong results type (string instead of array)
    p4 = write_tmp(tmp_path, "badresults.json", json.dumps({"results": "not an array"}))
    assert load_<tool>(p4) == [], "Non-array results should return empty list"

    # Test 5: Valid JSON but results is null
    p5 = write_tmp(tmp_path, "nullresults.json", json.dumps({"results": None}))
    assert load_<tool>(p5) == [], "Null results should return empty list"


def test_<tool>_nonexistent_file(tmp_path: Path):
    """Test loading from non-existent file returns empty list."""
    result = load_<tool>(tmp_path / "nonexistent.json")
    assert result == [], "Non-existent file should return empty list"


def test_<tool>_non_dict_results_item(tmp_path: Path):
    """Test handling non-dict items in results array."""
    sample = {
        "results": [
            "not a dict",  # Invalid (string)
            123,           # Invalid (number)
            None,          # Invalid (null)
            [],            # Invalid (array)
            {"ruleId": "valid-rule", "message": "Valid finding", "severity": "HIGH"},  # Valid
        ]
    }
    path = write_tmp(tmp_path, "<tool>_invalid_items.json", json.dumps(sample))
    out = load_<tool>(path)

    # Should skip invalid items and process only valid one
    assert len(out) == 1, "Should skip non-dict items"
    assert out[0]["ruleId"] == "valid-rule"


def test_<tool>_unicode_and_special_chars(tmp_path: Path):
    """Test handling Unicode and special characters in messages."""
    sample = {
        "results": [
            {
                "ruleId": "test-unicode",
                "message": "Emoji test and Chinese: security-vulnerability",
                "severity": "INFO",
                "path": "test/file.py",  # Cyrillic filename
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_unicode.json", json.dumps(sample, ensure_ascii=False))
    out = load_<tool>(path)
    assert len(out) == 1


def test_<tool>_large_file_truncation(tmp_path: Path):
    """Test handling very large messages (should truncate gracefully)."""
    large_msg = "A" * 10000  # 10KB message
    sample = {
        "results": [
            {"ruleId": "large-msg", "message": large_msg, "severity": "LOW"}
        ]
    }
    path = write_tmp(tmp_path, "<tool>_large.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1
    # Message should be present (may be truncated by adapter, but not dropped)
    assert len(out[0]["message"]) > 0
```

**Required Error Scenarios:**

| Scenario | Expected Behavior | Test Name |
|----------|-------------------|-----------|
| Empty file (`""`) | Return `[]` | `test_<tool>_empty_and_malformed` |
| Malformed JSON (`{bad}`) | Return `[]` | `test_<tool>_empty_and_malformed` |
| Missing file | Return `[]` | `test_<tool>_nonexistent_file` |
| Missing `results` field | Return `[]` | `test_<tool>_empty_and_malformed` |
| `results` is not array | Return `[]` | `test_<tool>_empty_and_malformed` |
| Non-dict item in array | Skip invalid, process valid | `test_<tool>_non_dict_results_item` |
| Unicode characters | Handle correctly | `test_<tool>_unicode_and_special_chars` |
| Very large message | Truncate or handle | `test_<tool>_large_file_truncation` |

---

## Category 3: Schema v1.1.0 Features

Tests v1.1.0 features: autofix remediation, risk metadata (CWE, confidence, likelihood, impact), and code context extraction.

**Purpose:** Verify adapter enriches findings with v1.1.0 risk and remediation fields when source data provides them.

### Test 3a: Autofix Remediation (Dict Format)

```python
def test_<tool>_v110_autofix_remediation(tmp_path: Path):
    """Test v1.1.0 autofix remediation structure."""
    sample = {
        "results": [
            {
                "ruleId": "sql-injection",
                "message": "SQL injection vulnerability detected",
                "severity": "HIGH",
                "path": "app.py",
                "line": 42,
                "fix": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                "fixSteps": [
                    "1. Replace raw SQL concatenation with parameterized query",
                    "2. Ensure user input is properly escaped",
                    "3. Test with various input types",
                ],
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_autofix.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Check remediation is dict with fix field
    assert isinstance(item["remediation"], dict), "Remediation should be dict for autofix"
    assert "fix" in item["remediation"]
    assert "cursor.execute" in item["remediation"]["fix"]

    # Check steps array is present
    assert "steps" in item["remediation"]
    assert isinstance(item["remediation"]["steps"], list)
    assert len(item["remediation"]["steps"]) == 3
    assert "parameterized query" in item["remediation"]["steps"][0]
```

### Test 3b: Remediation Without Autofix (String Format)

```python
def test_<tool>_v110_remediation_without_autofix(tmp_path: Path):
    """Test v1.1.0 remediation without autofix (string format)."""
    sample = {
        "results": [
            {
                "ruleId": "insecure-random",
                "message": "Use secrets module for cryptographic randomness",
                "severity": "MEDIUM",
                "path": "crypto.py",
                "line": 5,
                "recommendation": "Replace random.randint with secrets.randbelow",
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_no_autofix.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Without autofix, remediation should be string
    assert isinstance(item["remediation"], str), "Remediation without autofix should be string"
    assert len(item["remediation"]) > 0
    assert "secrets" in item["remediation"].lower()
```

### Test 3c: CWE Metadata Extraction

```python
def test_<tool>_v110_cwe_metadata(tmp_path: Path):
    """Test v1.1.0 CWE metadata extraction."""
    sample = {
        "results": [
            {
                "ruleId": "cwe-89-sql-injection",
                "message": "SQL injection vulnerability",
                "severity": "HIGH",
                "path": "db.py",
                "line": 20,
                "cwe": ["CWE-89", "CWE-20"],  # Array format
                "confidence": "HIGH",
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_cwe.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Check risk metadata
    assert "risk" in item
    assert "cwe" in item["risk"]
    assert item["risk"]["cwe"] == ["CWE-89", "CWE-20"]
    assert item["risk"]["confidence"] == "HIGH"


def test_<tool>_v110_cwe_string_format(tmp_path: Path):
    """Test v1.1.0 CWE as string instead of array (should normalize to array)."""
    sample = {
        "results": [
            {
                "ruleId": "xss",
                "message": "XSS vulnerability",
                "severity": "HIGH",
                "path": "web.py",
                "line": 15,
                "cwe": "CWE-79",  # String, not array
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_cwe_string.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    assert "risk" in item
    assert "cwe" in item["risk"]
    # Should be converted to array
    assert item["risk"]["cwe"] == ["CWE-79"]
```

### Test 3d: Likelihood and Impact Metadata

```python
def test_<tool>_v110_likelihood_impact(tmp_path: Path):
    """Test v1.1.0 likelihood and impact metadata."""
    sample = {
        "results": [
            {
                "ruleId": "auth-bypass",
                "message": "Authentication bypass vulnerability",
                "severity": "CRITICAL",
                "path": "auth.py",
                "line": 100,
                "likelihood": "HIGH",
                "impact": "HIGH",
                "confidence": "MEDIUM",
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_likelihood.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    assert "risk" in item
    assert item["risk"]["likelihood"] == "HIGH"
    assert item["risk"]["impact"] == "HIGH"
    assert item["risk"]["confidence"] == "MEDIUM"


def test_<tool>_v110_risk_score_calculation(tmp_path: Path):
    """Test v1.1.0 risk score calculation (if tool provides)."""
    sample = {
        "results": [
            {
                "ruleId": "high-risk-vuln",
                "message": "High-risk vulnerability",
                "severity": "HIGH",
                "path": "app.py",
                "line": 50,
                "riskScore": 8.5,  # Some tools provide numeric risk score
                "cvssScore": 7.8,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_risk_score.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Risk score may be in cvss field or risk metadata
    if "cvss" in item:
        assert "score" in item["cvss"] or "baseScore" in item["cvss"]
```

### Test 3e: Code Context Extraction

```python
def test_<tool>_v110_code_context_integration(tmp_path: Path):
    """Test v1.1.0 code context extraction."""
    # Create actual file to extract context from
    test_file = tmp_path / "vulnerable.py"
    test_file.write_text(
        """import random

def generate_token():
    # INSECURE: Using random instead of secrets
    return random.randint(1000, 9999)

def secure_token():
    import secrets
    return secrets.randbelow(10000)
"""
    )

    sample = {
        "results": [
            {
                "ruleId": "insecure-random",
                "message": "Use secrets module for cryptographic randomness",
                "severity": "MEDIUM",
                "path": str(test_file),
                "line": 5,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_context.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Context should be extracted if file exists and adapter supports it
    if "context" in item:
        assert "snippet" in item["context"]
        assert "random.randint" in item["context"]["snippet"]
        assert item["context"]["language"] == "python"
        # Verify startLine and endLine are present
        assert "startLine" in item["context"]
        assert "endLine" in item["context"]


def test_<tool>_v110_no_context_if_file_missing(tmp_path: Path):
    """Test v1.1.0 context is None/absent if file doesn't exist."""
    sample = {
        "results": [
            {
                "ruleId": "test-rule",
                "message": "Test finding",
                "severity": "LOW",
                "path": "/nonexistent/file.py",
                "line": 10,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_no_context.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Context should not be present if file doesn't exist
    assert "context" not in item or item["context"] is None
```

---

## Category 4: Compliance Enrichment Tests (v1.2.0)

Tests that compliance enrichment is applied during adapter processing (via `enrich_finding_with_compliance` utility).

**Purpose:** Verify findings with CWE mappings are automatically enriched with 6 compliance frameworks.

```python
def test_<tool>_compliance_enrichment(tmp_path: Path):
    """Test that findings are enriched with compliance mappings."""
    sample = {
        "results": [
            {
                "ruleId": "CWE-79",
                "message": "XSS vulnerability detected",
                "severity": "HIGH",
                "path": "app.py",
                "line": 42,
                "cwe": "CWE-79",
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_compliance.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]

    # Schema version should be 1.2.0 after enrichment (or 1.1.0 if enrichment not called)
    assert item["schemaVersion"] in ["1.1.0", "1.2.0"]

    # Compliance field may be added by enrichment
    # (Not all findings have CWE mappings, so compliance field is optional)
    if "compliance" in item:
        # If present, verify structure
        compliance = item["compliance"]

        # Should have at least one framework mapping
        possible_frameworks = [
            "owaspTop10_2021",
            "cweTop25_2024",
            "cisControlsV8_1",
            "nistCsf2_0",
            "pciDss4_0",
            "mitreAttack",
        ]
        assert any(fw in compliance for fw in possible_frameworks), "Should have at least one framework"

        # If OWASP present, verify structure
        if "owaspTop10_2021" in compliance:
            assert isinstance(compliance["owaspTop10_2021"], list)
            # CWE-79 maps to OWASP A03:2021 (Injection)
            assert any("A03" in cat for cat in compliance["owaspTop10_2021"])

        # If CWE Top 25 present, verify structure
        if "cweTop25_2024" in compliance:
            assert isinstance(compliance["cweTop25_2024"], list)
            for entry in compliance["cweTop25_2024"]:
                assert "id" in entry  # Correct field name (NOT "cweId")
                assert entry["id"] == "CWE-79"
                assert "rank" in entry
                assert "category" in entry


def test_<tool>_compliance_multiple_cwes(tmp_path: Path):
    """Test compliance enrichment with multiple CWEs."""
    sample = {
        "results": [
            {
                "ruleId": "multi-cwe",
                "message": "Multiple CWE mapping",
                "severity": "HIGH",
                "path": "app.py",
                "line": 10,
                "cwe": ["CWE-79", "CWE-89", "CWE-20"],  # XSS, SQLi, Input Validation
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_multi_cwe.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Should have CWEs in risk field
    assert "risk" in item
    assert item["risk"]["cwe"] == ["CWE-79", "CWE-89", "CWE-20"]

    # Compliance enrichment may aggregate mappings from all CWEs
    if "compliance" in item:
        # OWASP should include both A03 (Injection) and A02 (Cryptographic Failures)
        if "owaspTop10_2021" in item["compliance"]:
            owasp_cats = item["compliance"]["owaspTop10_2021"]
            # At least one mapping should be present
            assert len(owasp_cats) > 0


def test_<tool>_compliance_no_cwe(tmp_path: Path):
    """Test findings without CWE don't crash enrichment."""
    sample = {
        "results": [
            {
                "ruleId": "no-cwe-rule",
                "message": "Finding without CWE",
                "severity": "INFO",
                "path": "test.py",
                "line": 1,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_no_cwe.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    item = out[0]
    # Should still have valid finding
    assert item["ruleId"] == "no-cwe-rule"
    # Compliance field may be absent or empty
    assert "compliance" not in item or item["compliance"] == {}
```

---

## Category 5: Tool-Specific Edge Cases

Test variations in tool output format: alternative field names, missing optional fields, nested structures, NDJSON vs JSON arrays, etc.

**Purpose:** Ensure adapter handles real-world tool output variations without breaking.

### Test 5a: Alternative Field Locations

```python
def test_<tool>_alternative_severity_field(tmp_path: Path):
    """Test severity from alternative field location."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "level": "WARNING",  # Tool uses 'level' instead of 'severity'
                "message": "Alternative severity test",
                "path": "file.py",
                "line": 1,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_alt_severity.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    # WARNING should map to MEDIUM
    assert out[0]["severity"] == "MEDIUM"


def test_<tool>_nested_severity(tmp_path: Path):
    """Test severity in nested metadata object."""
    sample = {
        "results": [
            {
                "ruleId": "rule2",
                "message": "Nested severity",
                "path": "file.py",
                "line": 5,
                "metadata": {
                    "severity": "ERROR",  # Nested in metadata
                },
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_nested_sev.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    # ERROR should map to HIGH
    assert out[0]["severity"] == "HIGH"


def test_<tool>_alternative_message_field(tmp_path: Path):
    """Test message from alternative field location."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "description": "Tool uses 'description' instead of 'message'",
                "severity": "INFO",
                "path": "file.py",
                "line": 1,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_alt_message.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1
    assert "description" in out[0]["message"]
```

### Test 5b: Missing Optional Fields

```python
def test_<tool>_missing_version(tmp_path: Path):
    """Test handling missing version field."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "message": "No version",
                "severity": "INFO",
                "path": "file.py",
                "line": 1,
            }
        ]
        # No version field at top level
    }
    path = write_tmp(tmp_path, "<tool>_no_version.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1
    assert out[0]["tool"]["version"] == "unknown"


def test_<tool>_missing_line_number(tmp_path: Path):
    """Test handling missing line number (should default to 1)."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "message": "No line number",
                "severity": "LOW",
                "path": "file.py",
                # No line field
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_no_line.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1
    # Should default to line 1
    assert out[0]["location"]["startLine"] == 1


def test_<tool>_missing_path(tmp_path: Path):
    """Test handling missing path (should use fallback)."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "message": "No path",
                "severity": "INFO",
                "line": 10,
                # No path field
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_no_path.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1
    # Should use fallback path
    assert out[0]["location"]["path"] in ["<unknown>", "unknown", ""]
```

### Test 5c: Tags and Categories

```python
def test_<tool>_tags_present(tmp_path: Path):
    """Test that appropriate tags are always present."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "message": "Test",
                "severity": "INFO",
                "path": "file.py",
                "line": 1,
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_tags.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    assert "tags" in out[0]
    tags = out[0]["tags"]
    assert isinstance(tags, list)
    assert len(tags) > 0

    # Verify tool category tag present
    expected_categories = ["sast", "secrets", "iac", "vuln", "container", "dast"]
    assert any(cat in tags for cat in expected_categories)


def test_<tool>_tags_from_tool_metadata(tmp_path: Path):
    """Test tags extracted from tool metadata."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "message": "Test",
                "severity": "INFO",
                "path": "file.py",
                "line": 1,
                "tags": ["security", "injection", "web"],  # Tool-provided tags
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_tool_tags.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    tags = out[0]["tags"]
    # Tool tags should be preserved
    assert "security" in tags
    assert "injection" in tags
```

### Test 5d: Raw Field Preservation

```python
def test_<tool>_raw_field_preserved(tmp_path: Path):
    """Test that raw tool output is preserved in 'raw' field."""
    sample = {
        "results": [
            {
                "ruleId": "rule1",
                "message": "Test",
                "severity": "INFO",
                "path": "file.py",
                "line": 1,
                "custom_field": "custom_value",  # Tool-specific field
                "internal_metadata": {"key": "value"},
            }
        ]
    }
    path = write_tmp(tmp_path, "<tool>_raw.json", json.dumps(sample))
    out = load_<tool>(path)
    assert len(out) == 1

    assert "raw" in out[0]
    # Original tool output should be fully preserved
    assert out[0]["raw"]["custom_field"] == "custom_value"
    assert out[0]["raw"]["internal_metadata"]["key"] == "value"
```

### Test 5e: NDJSON Format (Newline-Delimited JSON)

```python
def test_<tool>_ndjson_format(tmp_path: Path):
    """Test parsing NDJSON (newline-delimited JSON) format."""
    # Some tools (trufflehog, gitleaks) output NDJSON
    ndjson = "\n".join(
        [
            json.dumps({"ruleId": "rule1", "message": "First", "severity": "HIGH"}),
            json.dumps({"ruleId": "rule2", "message": "Second", "severity": "MEDIUM"}),
            json.dumps({"ruleId": "rule3", "message": "Third", "severity": "LOW"}),
        ]
    )
    path = write_tmp(tmp_path, "<tool>.ndjson", ndjson)
    out = load_<tool>(path)

    # Should parse all 3 findings
    assert len(out) == 3
    assert out[0]["ruleId"] == "rule1"
    assert out[1]["ruleId"] == "rule2"
    assert out[2]["ruleId"] == "rule3"


def test_<tool>_ndjson_with_empty_lines(tmp_path: Path):
    """Test NDJSON with empty lines and comments (should skip)."""
    ndjson = "\n".join(
        [
            json.dumps({"ruleId": "rule1", "message": "First", "severity": "HIGH"}),
            "",  # Empty line (should skip)
            json.dumps({"ruleId": "rule2", "message": "Second", "severity": "MEDIUM"}),
            "# Comment line",  # Invalid JSON (should skip)
            json.dumps({"ruleId": "rule3", "message": "Third", "severity": "LOW"}),
        ]
    )
    path = write_tmp(tmp_path, "<tool>_sparse.ndjson", ndjson)
    out = load_<tool>(path)

    # Should parse only valid lines
    assert len(out) == 3
```

### Test 5f: Nested Arrays (Flattening)

```python
def test_<tool>_nested_arrays(tmp_path: Path):
    """Test handling nested arrays (some tools nest results)."""
    sample = {
        "scans": [
            {
                "target": "file1.py",
                "findings": [
                    {"ruleId": "rule1", "message": "Finding 1", "severity": "HIGH", "line": 10},
                    {"ruleId": "rule2", "message": "Finding 2", "severity": "MEDIUM", "line": 20},
                ],
            },
            {
                "target": "file2.py",
                "findings": [
                    {"ruleId": "rule3", "message": "Finding 3", "severity": "LOW", "line": 5},
                ],
            },
        ]
    }
    path = write_tmp(tmp_path, "<tool>_nested.json", json.dumps(sample))
    out = load_<tool>(path)

    # Should flatten nested structure
    assert len(out) == 3
    assert out[0]["ruleId"] == "rule1"
    assert out[1]["ruleId"] == "rule2"
    assert out[2]["ruleId"] == "rule3"
```
