"""Comprehensive tests for Gosec adapter.

Tests cover:
- Basic parsing of Gosec JSON output
- Various rule types (G101-G602)
- Severity and confidence levels
- Line number parsing (single and range)
- Edge cases (empty, malformed, missing fields)
- Schema version and compliance enrichment
- Fingerprint generation
"""

import json
from pathlib import Path


from scripts.core.adapters.gosec_adapter import GosecAdapter


def write(p: Path, obj):
    """Write JSON object to a file."""
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


class TestGosecBasicParsing:
    """Tests for basic Gosec output parsing."""

    def test_hardcoded_credentials_g101(self, tmp_path: Path):
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

    def test_sql_injection_g201(self, tmp_path: Path):
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

    def test_weak_crypto_g401(self, tmp_path: Path):
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

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = GosecAdapter()
        metadata = adapter.metadata
        assert metadata.name == "gosec"
        assert metadata.tool_name == "gosec"
        assert metadata.schema_version == "1.2.0"


class TestGosecLineNumber:
    """Tests for line number parsing."""

    def test_single_line_number(self, tmp_path: Path):
        """Test single line number parsing."""
        data = {
            "Issues": [
                {
                    "severity": "LOW",
                    "rule_id": "G104",
                    "details": "Errors unhandled",
                    "file": "/app/main.go",
                    "line": "50",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].location["startLine"] == 50

    def test_line_range_format(self, tmp_path: Path):
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
                    "line": "10-15",
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
        assert items[0].location["startLine"] == 10

    def test_invalid_line_defaults_to_zero(self, tmp_path: Path):
        """Test invalid line number defaults to 0."""
        data = {
            "Issues": [
                {
                    "severity": "LOW",
                    "rule_id": "G100",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "not-a-number",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].location["startLine"] == 0


class TestGosecSeverity:
    """Tests for severity mapping."""

    def test_high_severity(self, tmp_path: Path):
        """Test HIGH severity mapping."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert items[0].severity == "HIGH"

    def test_medium_severity(self, tmp_path: Path):
        """Test MEDIUM severity mapping."""
        data = {
            "Issues": [
                {
                    "severity": "MEDIUM",
                    "rule_id": "G102",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert items[0].severity == "MEDIUM"

    def test_low_severity(self, tmp_path: Path):
        """Test LOW severity mapping."""
        data = {
            "Issues": [
                {
                    "severity": "LOW",
                    "rule_id": "G103",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert items[0].severity == "LOW"


class TestGosecMultipleFindings:
    """Tests for multiple findings."""

    def test_multiple_findings(self, tmp_path: Path):
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
        assert items[0].severity == "HIGH"
        assert items[1].severity == "MEDIUM"
        assert items[2].severity == "LOW"


class TestGosecEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test Gosec adapter handles empty JSON file."""
        f = tmp_path / "gosec.json"
        f.write_text("", encoding="utf-8")
        adapter = GosecAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test Gosec adapter handles nonexistent file."""
        adapter = GosecAdapter()
        items = adapter.parse(tmp_path / "nonexistent.json")
        assert items == []

    def test_malformed_json(self, tmp_path: Path):
        """Test Gosec adapter handles malformed JSON."""
        f = tmp_path / "gosec.json"
        f.write_text("{not valid json}", encoding="utf-8")
        adapter = GosecAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_no_issues(self, tmp_path: Path):
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

    def test_missing_fields(self, tmp_path: Path):
        """Test Gosec adapter handles missing optional fields gracefully."""
        data = {
            "Issues": [
                {
                    "rule_id": "G102",
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
        assert items[0].severity in ["LOW", "MEDIUM", "HIGH", "INFO"]
        assert items[0].message != ""

    def test_missing_rule_id(self, tmp_path: Path):
        """Test Gosec adapter with missing rule_id."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "file": "/app/test.go",
                    "line": "10",
                    "details": "Test issue",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].ruleId == "GOSEC"

    def test_issues_not_list(self, tmp_path: Path):
        """Test Gosec adapter when Issues is not a list."""
        data = {"Issues": "not a list", "Stats": {}}
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)
        assert items == []

    def test_issue_not_dict(self, tmp_path: Path):
        """Test Gosec adapter skips non-dict issue entries."""
        data = {"Issues": ["not a dict", 123], "Stats": {}}
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)
        assert items == []


class TestGosecCodeSnippet:
    """Tests for code snippet handling."""

    def test_code_snippet_in_context(self, tmp_path: Path):
        """Test code snippet is captured in context."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
                    "code": 'password := "secret123"',
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
        assert items[0].context["code_snippet"] == 'password := "secret123"'

    def test_missing_code_snippet(self, tmp_path: Path):
        """Test missing code snippet is None in context."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
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
        assert items[0].context["code_snippet"] is None


class TestGosecCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_compliance_enrichment(self, tmp_path: Path):
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
        assert hasattr(items[0], "compliance")

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is correct."""
        data = {
            "Issues": [
                {
                    "severity": "LOW",
                    "rule_id": "G100",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].schemaVersion == "1.2.0"

    def test_tool_name(self, tmp_path: Path):
        """Test tool name is correct."""
        data = {
            "Issues": [
                {
                    "severity": "LOW",
                    "rule_id": "G100",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert items[0].tool["name"] == "gosec"

    def test_remediation_message(self, tmp_path: Path):
        """Test remediation message includes confidence."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert "Confidence" in items[0].remediation


class TestGosecFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "rule_id": "G101",
                    "details": "Test 1",
                    "file": "/app/file1.go",
                    "line": "10",
                },
                {
                    "severity": "HIGH",
                    "rule_id": "G101",
                    "details": "Test 2",
                    "file": "/app/file2.go",
                    "line": "10",
                },
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 2
        assert items[0].id != items[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "10",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items1 = adapter.parse(f)
        items2 = adapter.parse(f)

        assert items1[0].id == items2[0].id


class TestGosecUnicode:
    """Tests for Unicode handling."""

    def test_unicode_in_file_path(self, tmp_path: Path):
        """Test Unicode in file path."""
        data = {
            "Issues": [
                {
                    "severity": "LOW",
                    "rule_id": "G100",
                    "details": "Test",
                    "file": "/app/日本語/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert "日本語" in items[0].location["path"]

    def test_unicode_in_details(self, tmp_path: Path):
        """Test Unicode in details."""
        data = {
            "Issues": [
                {
                    "severity": "LOW",
                    "rule_id": "G100",
                    "details": "Détails du problème",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert len(items) == 1
        assert "é" in items[0].message


class TestGosecConfidence:
    """Tests for confidence level handling."""

    def test_high_confidence(self, tmp_path: Path):
        """Test HIGH confidence is captured."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "confidence": "HIGH",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert items[0].context["confidence"] == "HIGH"

    def test_medium_confidence(self, tmp_path: Path):
        """Test MEDIUM confidence is captured."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "confidence": "MEDIUM",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert items[0].context["confidence"] == "MEDIUM"

    def test_low_confidence(self, tmp_path: Path):
        """Test LOW confidence is captured."""
        data = {
            "Issues": [
                {
                    "severity": "HIGH",
                    "confidence": "LOW",
                    "rule_id": "G101",
                    "details": "Test",
                    "file": "/app/main.go",
                    "line": "1",
                }
            ],
            "Stats": {},
        }
        f = tmp_path / "gosec.json"
        write(f, data)
        adapter = GosecAdapter()
        items = adapter.parse(f)

        assert items[0].context["confidence"] == "LOW"
