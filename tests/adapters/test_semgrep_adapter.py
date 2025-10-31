import json
from pathlib import Path

from scripts.core.adapters.semgrep_adapter import SemgrepAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_semgrep_basic(tmp_path: Path):
    sample = {
        "results": [
            {
                "check_id": "python.lang.correctness.useless-comparison",
                "path": "foo.py",
                "start": {"line": 3},
                "extra": {"message": "useless comparison", "severity": "ERROR"},
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    item = findings[0]
    assert item.ruleId.endswith("useless-comparison")
    assert item.severity == "HIGH"
    assert item.location["path"] == "foo.py"
    assert item.location["startLine"] == 3


def test_semgrep_empty_and_malformed(tmp_path: Path):
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    p1 = write_tmp(tmp_path, "empty.json", "")
    assert adapter.parse(p1) == []
    p2 = write_tmp(tmp_path, "bad.json", "{not json}")
    assert adapter.parse(p2) == []
    p3 = write_tmp(tmp_path, "noresults.json", json.dumps({"results": {}}))
    assert adapter.parse(p3) == []


def test_semgrep_v110_autofix(tmp_path: Path):
    """Test v1.1.0 autofix remediation."""
    sample = {
        "results": [
            {
                "check_id": "python.security.sql-injection",
                "path": "app.py",
                "start": {"line": 10},
                "extra": {
                    "message": "SQL injection vulnerability",
                    "severity": "ERROR",
                    "fix": "Use parameterized query: cursor.execute('SELECT * FROM users WHERE id = ?', (user_id,))",
                },
            }
        ],
        "version": "1.45.0",
    }
    path = write_tmp(tmp_path, "semgrep_autofix.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert item.schemaVersion in ["1.1.0", "1.2.0"]  # Enriched findings get 1.2.0
    assert isinstance(item.remediation, dict)
    assert "fix" in item.remediation
    assert "cursor.execute" in item.remediation["fix"]
    assert "steps" in item.remediation
    assert len(item.remediation["steps"]) > 0


def test_semgrep_v110_remediation_without_autofix(tmp_path: Path):
    """Test v1.1.0 remediation without autofix."""
    sample = {
        "results": [
            {
                "check_id": "python.security.insecure-random",
                "path": "crypto.py",
                "start": {"line": 5},
                "extra": {
                    "message": "Use secrets module instead of random",
                    "severity": "WARNING",
                },
            }
        ],
        "version": "1.45.0",
    }
    path = write_tmp(tmp_path, "semgrep_no_autofix.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert isinstance(item.remediation, str)
    assert "Review and remediate" in item.remediation


def test_semgrep_v110_cwe_metadata(tmp_path: Path):
    """Test v1.1.0 CWE metadata extraction."""
    sample = {
        "results": [
            {
                "check_id": "python.security.cwe-89",
                "path": "db.py",
                "start": {"line": 20},
                "extra": {
                    "message": "SQL injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89", "CWE-20"], "confidence": "HIGH"},
                },
            }
        ],
        "version": "1.45.0",
    }
    path = write_tmp(tmp_path, "semgrep_cwe.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "cwe" in item.risk
    assert item.risk["cwe"] == ["CWE-89", "CWE-20"]
    assert item.risk["confidence"] == "HIGH"


def test_semgrep_v110_cwe_string_format(tmp_path: Path):
    """Test v1.1.0 CWE as string instead of list."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Finding",
                    "severity": "ERROR",
                    "metadata": {"cwe": "CWE-79"},
                },
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_cwe_string.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "cwe" in item.risk
    assert item.risk["cwe"] == ["CWE-79"]  # Converted to list


def test_semgrep_v110_owasp_metadata(tmp_path: Path):
    """Test v1.1.0 OWASP metadata extraction."""
    sample = {
        "results": [
            {
                "check_id": "owasp-rule",
                "path": "web.py",
                "start": {"line": 15},
                "extra": {
                    "message": "XSS vulnerability",
                    "severity": "ERROR",
                    "metadata": {
                        "owasp": ["A03:2021", "A07:2017"],
                        "confidence": "MEDIUM",
                    },
                },
            }
        ],
        "version": "1.45.0",
    }
    path = write_tmp(tmp_path, "semgrep_owasp.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "owasp" in item.risk
    assert item.risk["owasp"] == ["A03:2021", "A07:2017"]
    assert item.risk["confidence"] == "MEDIUM"


def test_semgrep_v110_owasp_string_format(tmp_path: Path):
    """Test v1.1.0 OWASP as string instead of list."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Finding",
                    "severity": "INFO",
                    "metadata": {"owasp": "A01:2021"},
                },
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_owasp_string.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "owasp" in item.risk
    assert item.risk["owasp"] == ["A01:2021"]  # Converted to list


def test_semgrep_v110_likelihood_impact(tmp_path: Path):
    """Test v1.1.0 likelihood and impact metadata."""
    sample = {
        "results": [
            {
                "check_id": "high-risk-rule",
                "path": "auth.py",
                "start": {"line": 42},
                "extra": {
                    "message": "Authentication bypass",
                    "severity": "ERROR",
                    "metadata": {
                        "likelihood": "HIGH",
                        "impact": "HIGH",
                        "confidence": "HIGH",
                    },
                },
            }
        ],
        "version": "1.45.0",
    }
    path = write_tmp(tmp_path, "semgrep_likelihood.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert item.risk["likelihood"] == "HIGH"
    assert item.risk["impact"] == "HIGH"
    assert item.risk["confidence"] == "HIGH"


def test_semgrep_v110_invalid_confidence_values(tmp_path: Path):
    """Test v1.1.0 ignores invalid confidence values."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "extra": {
                    "message": "Finding",
                    "severity": "INFO",
                    "metadata": {"confidence": "INVALID"},
                },
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_invalid_conf.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Risk should not have confidence if invalid
    if hasattr(item, "risk") and item.risk:
        assert "confidence" not in item.risk


def test_semgrep_v110_code_context_integration(tmp_path: Path):
    """Test v1.1.0 code context extraction."""
    # Create a test file to extract context from
    test_file = tmp_path / "vulnerable.py"
    test_file.write_text(
        """import random

def generate_token():
    # INSECURE: Using random instead of secrets
    return random.randint(1000, 9999)
"""
    )

    sample = {
        "results": [
            {
                "check_id": "python.security.insecure-random",
                "path": str(test_file),
                "start": {"line": 5},
                "extra": {"message": "Use secrets module", "severity": "WARNING"},
            }
        ],
        "version": "1.45.0",
    }
    path = write_tmp(tmp_path, "semgrep_context.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "context") and item.context
    assert "snippet" in item.context
    assert "random.randint" in item.context["snippet"]
    assert item.context["language"] == "python"


def test_semgrep_v110_no_context_if_file_missing(tmp_path: Path):
    """Test v1.1.0 context is None if file doesn't exist."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "/nonexistent/file.py",
                "start": {"line": 10},
                "extra": {"message": "Finding", "severity": "INFO"},
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_no_context.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Context should not be present if file doesn't exist
    assert not hasattr(item, "context") or item.context is None


def test_semgrep_v110_combined_metadata(tmp_path: Path):
    """Test v1.1.0 with all metadata fields combined."""
    sample = {
        "results": [
            {
                "check_id": "comprehensive-rule",
                "path": "app.py",
                "start": {"line": 100},
                "extra": {
                    "message": "Critical security issue",
                    "severity": "ERROR",
                    "fix": "Apply this patch: use_safe_function()",
                    "metadata": {
                        "cwe": ["CWE-79", "CWE-89"],
                        "owasp": ["A03:2021"],
                        "confidence": "HIGH",
                        "likelihood": "MEDIUM",
                        "impact": "HIGH",
                    },
                },
            }
        ],
        "version": "1.45.0",
    }
    path = write_tmp(tmp_path, "semgrep_combined.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert item.schemaVersion in ["1.1.0", "1.2.0"]  # Enriched findings get 1.2.0

    # Check remediation with autofix
    assert isinstance(item.remediation, dict)
    assert "fix" in item.remediation
    assert "use_safe_function" in item.remediation["fix"]

    # Check risk metadata
    assert hasattr(item, "risk") and item.risk
    assert item.risk["cwe"] == ["CWE-79", "CWE-89"]
    assert item.risk["owasp"] == ["A03:2021"]
    assert item.risk["confidence"] == "HIGH"
    assert item.risk["likelihood"] == "MEDIUM"
    assert item.risk["impact"] == "HIGH"


def test_semgrep_alternative_severity_field(tmp_path: Path):
    """Test severity from direct 'severity' field instead of extra.severity."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "severity": "WARNING",
                "message": "Direct severity test",
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_direct_sev.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_semgrep_alternative_message_field(tmp_path: Path):
    """Test message from direct 'message' field instead of extra.message."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "message": "Direct message",
                "extra": {"severity": "INFO"},
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_direct_msg.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].message == "Direct message"


def test_semgrep_alternative_location_fields(tmp_path: Path):
    """Test alternative location field structures."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "ruleId": "backup-rule-id",
                "location": {"path": "alt.py", "start": {"line": 99}},
                "extra": {"message": "Alt location", "severity": "INFO"},
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_alt_loc.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert item.location["path"] == "alt.py"
    assert item.location["startLine"] == 99


def test_semgrep_missing_version(tmp_path: Path):
    """Test handling missing version field."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "extra": {"message": "No version", "severity": "INFO"},
            }
        ]
    }
    path = write_tmp(tmp_path, "semgrep_no_version.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].tool["version"] == "unknown"


def test_semgrep_tags_present(tmp_path: Path):
    """Test that SAST tag is always present."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "extra": {"message": "Test", "severity": "INFO"},
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_tags.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert hasattr(findings[0], "tags")
    assert "sast" in findings[0].tags


def test_semgrep_raw_field_preserved(tmp_path: Path):
    """Test that raw tool output is preserved."""
    sample = {
        "results": [
            {
                "check_id": "rule1",
                "path": "file.py",
                "start": {"line": 1},
                "extra": {"message": "Test", "severity": "INFO"},
                "custom_field": "custom_value",
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep_raw.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert hasattr(findings[0], "raw")
    assert findings[0].raw["custom_field"] == "custom_value"


def test_semgrep_nonexistent_file(tmp_path: Path):
    """Test loading from non-existent file."""
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    result = adapter.parse(tmp_path / "nonexistent.json")
    assert result == []


def test_semgrep_non_dict_results_item(tmp_path: Path):
    """Test handling non-dict items in results array."""
    sample = {"results": ["not a dict", 123, None, {"check_id": "valid"}]}
    path = write_tmp(tmp_path, "semgrep_invalid_items.json", json.dumps(sample))
    adapter = SemgrepAdapter()
    adapter = SemgrepAdapter()
    findings = adapter.parse(path)
    # Should skip invalid items and process valid one
    assert len(findings) == 1
    assert findings[0].ruleId == "valid"
