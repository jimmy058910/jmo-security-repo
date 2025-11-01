import json
from pathlib import Path

from scripts.core.adapters.gosec_adapter import GosecAdapter


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_gosec_adapter_hardcoded_credentials(tmp_path: Path):
    """Test Gosec adapter with G101 (hardcoded credentials) finding."""
    data = {
        "Issues": [
            {
                "severity": "HIGH",
                "confidence": "LOW",
                "rule_id": "G101",
                "details": "Potential hardcoded credentials",
                "file": "/app/main.go",
                "code": 'password := "mysecretpassword"',
                "line": "42",
            }
        ],
        "Stats": {"files": 1, "lines": 100, "nosec": 0, "found": 1},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "G101"
    assert items[0].severity == "HIGH"
    assert "sast" in items[0].tags
    assert "golang" in items[0].tags
    assert items[0].location["path"] == "/app/main.go"
    assert items[0].location["startLine"] == 42
    assert items[0].context["confidence"] == "LOW"


def test_gosec_adapter_sql_injection(tmp_path: Path):
    """Test Gosec adapter with G201 (SQL injection) finding."""
    data = {
        "Issues": [
            {
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "rule_id": "G201",
                "details": "SQL string formatting",
                "file": "/app/db/query.go",
                "code": 'query := fmt.Sprintf("SELECT * FROM users WHERE id = %s", userId)',
                "line": "15",
            }
        ],
        "Stats": {"files": 1, "lines": 50, "nosec": 0, "found": 1},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "G201"
    assert items[0].severity == "MEDIUM"
    assert items[0].context["confidence"] == "HIGH"


def test_gosec_adapter_weak_crypto(tmp_path: Path):
    """Test Gosec adapter with G401 (weak cryptographic hash) finding."""
    data = {
        "Issues": [
            {
                "severity": "MEDIUM",
                "confidence": "HIGH",
                "rule_id": "G401",
                "details": "Use of weak cryptographic primitive",
                "file": "/app/crypto/hash.go",
                "code": "h := md5.New()",
                "line": "23",
            }
        ],
        "Stats": {"files": 1, "lines": 80, "nosec": 0, "found": 1},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "G401"
    assert items[0].severity == "MEDIUM"
    assert "crypto/hash.go" in items[0].location["path"]


def test_gosec_adapter_line_range(tmp_path: Path):
    """Test Gosec adapter handles line ranges (e.g., '10-15')."""
    data = {
        "Issues": [
            {
                "severity": "LOW",
                "confidence": "MEDIUM",
                "rule_id": "G104",
                "details": "Errors unhandled",
                "file": "/app/handlers/api.go",
                "code": "_, err := io.Copy(dst, src)",
                "line": "10-15",  # Line range format
            }
        ],
        "Stats": {"files": 1, "lines": 200, "nosec": 0, "found": 1},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "G104"
    assert items[0].location["startLine"] == 10  # Should extract first line


def test_gosec_adapter_multiple_findings(tmp_path: Path):
    """Test Gosec adapter with multiple findings across different files."""
    data = {
        "Issues": [
            {
                "severity": "HIGH",
                "confidence": "HIGH",
                "rule_id": "G101",
                "details": "Hardcoded credentials",
                "file": "/app/config.go",
                "code": 'apiKey := "sk-1234567890abcdef"',
                "line": "5",
            },
            {
                "severity": "MEDIUM",
                "confidence": "MEDIUM",
                "rule_id": "G304",
                "details": "Potential file inclusion via variable",
                "file": "/app/fileio.go",
                "code": "ioutil.ReadFile(userInput)",
                "line": "22",
            },
            {
                "severity": "LOW",
                "confidence": "LOW",
                "rule_id": "G107",
                "details": "Potential HTTP request made with variable url",
                "file": "/app/client.go",
                "code": "http.Get(url)",
                "line": "35",
            },
        ],
        "Stats": {"files": 3, "lines": 300, "nosec": 0, "found": 3},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert len(items) == 3
    assert items[0].ruleId == "G101"
    assert items[1].ruleId == "G304"
    assert items[2].ruleId == "G107"
    # Verify severity normalization
    assert items[0].severity == "HIGH"
    assert items[1].severity == "MEDIUM"
    assert items[2].severity == "LOW"


def test_gosec_adapter_empty_file(tmp_path: Path):
    """Test Gosec adapter handles empty JSON file."""
    f = tmp_path / "gosec.json"
    f.write_text("", encoding="utf-8")
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert items == []


def test_gosec_adapter_no_issues(tmp_path: Path):
    """Test Gosec adapter with clean scan (no issues)."""
    data = {
        "Issues": [],
        "Stats": {"files": 10, "lines": 1000, "nosec": 2, "found": 0},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert items == []


def test_gosec_adapter_missing_fields(tmp_path: Path):
    """Test Gosec adapter handles missing optional fields gracefully."""
    data = {
        "Issues": [
            {
                "rule_id": "G102",
                # Missing: severity, confidence, details, code
                "file": "/app/test.go",
                "line": "10",
            }
        ],
        "Stats": {},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "G102"
    # Should use defaults
    assert items[0].severity in ["LOW", "MEDIUM", "HIGH", "INFO"]
    assert items[0].message != ""  # Should have default message


def test_gosec_adapter_compliance_enrichment(tmp_path: Path):
    """Test that Gosec findings are enriched with compliance mappings."""
    data = {
        "Issues": [
            {
                "severity": "HIGH",
                "confidence": "HIGH",
                "rule_id": "G201",
                "details": "SQL injection vulnerability",
                "file": "/app/db.go",
                "code": "db.Query(userInput)",
                "line": "50",
            }
        ],
        "Stats": {"files": 1, "lines": 100, "nosec": 0, "found": 1},
    }
    f = tmp_path / "gosec.json"
    write(f, data)
    adapter = GosecAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    # Compliance field should exist (enriched by compliance_mapper)
    assert hasattr(items[0], "compliance")
    # SQL injection should map to OWASP A03:2021 (Injection)
    # Note: Actual mapping depends on compliance_mapper implementation
