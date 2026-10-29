import json
from pathlib import Path

from scripts.core.adapters.opengrep_adapter import OpengrepAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_opengrep_basic(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    item = findings[0]
    assert item.ruleId.endswith("useless-comparison")
    assert item.severity == "HIGH"
    assert item.location["path"] == "foo.py"
    assert item.location["startLine"] == 3


def test_opengrep_empty_and_malformed(tmp_path: Path):
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    p1 = write_tmp(tmp_path, "empty.json", "")
    assert adapter.parse(p1) == []
    p2 = write_tmp(tmp_path, "bad.json", "{not json}")
    assert adapter.parse(p2) == []
    p3 = write_tmp(tmp_path, "noresults.json", json.dumps({"results": {}}))
    assert adapter.parse(p3) == []


def test_opengrep_v110_autofix(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_autofix.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert item.schemaVersion in ["1.1.0", "1.2.0"]  # Enriched findings get 1.2.0
    assert isinstance(item.remediation, dict)
    assert "fix" in item.remediation
    assert "cursor.execute" in item.remediation["fix"]
    assert "steps" in item.remediation
    # The autofix path emits the full apply/test/commit sequence; a count check
    # alone passes if the adapter drops to a single step or emits placeholders.
    assert item.remediation["steps"] == [
        "Apply the suggested fix above",
        "Test the changes",
        "Commit the fix",
    ]


def test_opengrep_v110_remediation_without_autofix(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_no_autofix.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert isinstance(item.remediation, str)
    assert "Review and remediate" in item.remediation


def test_opengrep_v110_cwe_metadata(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_cwe.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "cwe" in item.risk
    assert item.risk["cwe"] == ["CWE-89", "CWE-20"]
    assert item.risk["confidence"] == "HIGH"


def test_opengrep_v110_cwe_string_format(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_cwe_string.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "cwe" in item.risk
    assert item.risk["cwe"] == ["CWE-79"]  # Converted to list


def test_opengrep_v110_owasp_metadata(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_owasp.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "owasp" in item.risk
    assert item.risk["owasp"] == ["A03:2021", "A07:2017"]
    assert item.risk["confidence"] == "MEDIUM"


def test_opengrep_v110_owasp_string_format(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_owasp_string.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert "owasp" in item.risk
    assert item.risk["owasp"] == ["A01:2021"]  # Converted to list


def test_opengrep_v110_likelihood_impact(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_likelihood.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "risk") and item.risk
    assert item.risk["likelihood"] == "HIGH"
    assert item.risk["impact"] == "HIGH"
    assert item.risk["confidence"] == "HIGH"


def test_opengrep_v110_invalid_confidence_values(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_invalid_conf.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Risk should not have confidence if invalid
    if hasattr(item, "risk") and item.risk:
        assert "confidence" not in item.risk


def test_opengrep_v110_code_context_integration(tmp_path: Path):
    """Test v1.1.0 code context extraction."""
    # Create a test file to extract context from
    test_file = tmp_path / "vulnerable.py"
    test_file.write_text("""import random

def generate_token():
    # INSECURE: Using random instead of secrets
    return random.randint(1000, 9999)
""")

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
    path = write_tmp(tmp_path, "opengrep_context.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert hasattr(item, "context") and item.context
    assert "snippet" in item.context
    assert "random.randint" in item.context["snippet"]
    assert item.context["language"] == "python"


def test_opengrep_v110_no_context_if_file_missing(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_no_context.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    # Context should not be present if file doesn't exist
    assert not hasattr(item, "context") or item.context is None


def test_opengrep_v110_combined_metadata(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_combined.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
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


def test_opengrep_alternative_severity_field(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_direct_sev.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].severity == "MEDIUM"


def test_opengrep_alternative_message_field(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_direct_msg.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].message == "Direct message"


def test_opengrep_alternative_location_fields(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_alt_loc.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1

    item = findings[0]
    assert item.location["path"] == "alt.py"
    assert item.location["startLine"] == 99


def test_opengrep_missing_version(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_no_version.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert findings[0].tool["version"] == "unknown"


def test_opengrep_tags_present(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_tags.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert hasattr(findings[0], "tags")
    assert "sast" in findings[0].tags


def test_opengrep_raw_field_preserved(tmp_path: Path):
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
    path = write_tmp(tmp_path, "opengrep_raw.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    assert hasattr(findings[0], "raw")
    assert findings[0].raw["custom_field"] == "custom_value"


def test_opengrep_nonexistent_file(tmp_path: Path):
    """Test loading from non-existent file."""
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    result = adapter.parse(tmp_path / "nonexistent.json")
    assert result == []


def test_opengrep_non_dict_results_item(tmp_path: Path):
    """Test handling non-dict items in results array."""
    sample = {"results": ["not a dict", 123, None, {"check_id": "valid"}]}
    path = write_tmp(tmp_path, "opengrep_invalid_items.json", json.dumps(sample))
    adapter = OpengrepAdapter()
    adapter = OpengrepAdapter()
    findings = adapter.parse(path)
    # Should skip invalid items and process valid one
    assert len(findings) == 1
    assert findings[0].ruleId == "valid"


# --- the golden document ---------------------------------------------------------

GOLDEN = Path(__file__).parent.parent / "fixtures" / "golden" / "opengrep" / "v1.32.0"
BUNDLE = Path(__file__).parent.parent.parent / "scripts" / "jmo_rules"

# The four findings Review Focus 5 and the fixture guard (B7) name, by the last
# segment of the rule id (the rest is the bundle file's path-namespacing).
FIXTURE_TRIPLES = {
    ("tainted-sql-string", "routes/login.ts", 34),
    ("tainted-sql-string", "routes/search.ts", 23),
    ("hardcoded-jwt-secret", "lib/insecurity.ts", 56),
    ("template-explicit-unescape", "views/promotionVideo.pug", 79),
}


def test_the_golden_document():
    """opengrep v1.32.0's own output over four juice-shop files, read through the
    adapter. 10 findings, not the 4 the fixture guard names: the same four
    triples, plus the other rules that fire on those lines (the `sequelize` pair
    beside each `tainted-sql-string`, and two `hardcoded-hmac-key`), as the
    committed bundle's javascript.yaml, typescript.yaml and generic.yaml give."""
    findings = OpengrepAdapter().parse(GOLDEN / "raw-output.json")

    assert len(findings) == 10
    assert {f.tool["name"] for f in findings} == {"opengrep"}
    assert {f.tool["version"] for f in findings} == {"1.32.0"}
    triples = {
        (f.ruleId.rsplit(".", 1)[-1], f.location["path"], f.location["startLine"])
        for f in findings
    }
    assert triples >= FIXTURE_TRIPLES
    by_rule = {f.ruleId.rsplit(".", 1)[-1]: f for f in findings}
    # Severity is `extra.severity`, ERROR/WARNING mapped to HIGH/MEDIUM.
    assert by_rule["tainted-sql-string"].severity == "HIGH"
    assert by_rule["hardcoded-jwt-secret"].severity == "MEDIUM"
    assert by_rule["template-explicit-unescape"].severity == "MEDIUM"
    # CWE and OWASP come from `extra.metadata`.
    assert by_rule["tainted-sql-string"].risk["cwe"] == [
        "CWE-89: Improper Neutralization of Special Elements used in an SQL Command "
        "('SQL Injection')"
    ]
    assert by_rule["hardcoded-jwt-secret"].risk["cwe"][0].startswith("CWE-798")
    assert by_rule["template-explicit-unescape"].risk["cwe"][0].startswith("CWE-79")
    assert "A03:2021 - Injection" in by_rule["tainted-sql-string"].risk["owasp"]


def test_the_golden_ids_are_the_bundles_own():
    """`--no-rewrite-rule-ids`: a rule's id is its YAML id, so the golden is tied to
    the committed bundle. A rebuild that renames or drops one of these rules
    fails here, where the fixture guard needs the binary and the files."""
    shipped = set()
    for name in ("javascript", "typescript", "generic"):
        for line in (BUNDLE / f"{name}.yaml").read_text(encoding="utf-8").splitlines():
            if line.startswith("- id: "):
                shipped.add(line.removeprefix("- id: ").strip())
    ids = {f.ruleId for f in OpengrepAdapter().parse(GOLDEN / "raw-output.json")}

    assert ids <= shipped, f"not in the bundle: {sorted(ids - shipped)}"


def test_the_golden_holds_no_source_text():
    """The run copies matched source into `extra.lines`, `extra.dataflow_trace`
    and every `extra.metavars[*].abstract_content`; one holds lib/insecurity.ts's
    RSA private key, which the secret hooks refuse. A regenerated golden must be
    stripped the same way."""
    text = (GOLDEN / "raw-output.json").read_text(encoding="utf-8")
    document = json.loads(text)

    assert "PRIVATE KEY" not in text and "BEGIN" not in text
    assert document["results"], "the golden has no results"
    for result in document["results"]:
        assert not {"lines", "dataflow_trace", "metavars"} & set(result["extra"])
        assert not Path(result["path"]).is_absolute()
