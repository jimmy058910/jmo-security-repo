"""Comprehensive tests for Bandit adapter.

Tests cover:
- Basic parsing of Bandit JSON output
- Multiple severity levels (LOW, MEDIUM, HIGH)
- Multiple confidence levels
- Alternative field naming conventions (test_id vs testId)
- Edge cases (empty input, malformed JSON, missing fields)
- Array-based input format
- Dict-based input format with results key
"""

import json
from pathlib import Path


from scripts.core.adapters.bandit_adapter import BanditAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temporary file."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestBanditBasicParsing:
    """Tests for basic Bandit output parsing."""

    def test_single_result_parsing(self, tmp_path: Path):
        """Test parsing a single Bandit result."""
        sample = {
            "results": [
                {
                    "filename": "scripts/core/foo.py",
                    "line_number": 12,
                    "issue_text": "Use of assert detected.",
                    "test_id": "B101",
                    "test_name": "assert_used",
                    "issue_severity": "LOW",
                    "issue_confidence": "HIGH",
                }
            ]
        }
        path = write_tmp(tmp_path, "bandit.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        item = findings[0]
        assert item.schemaVersion == "1.2.0"
        assert item.ruleId == "B101"
        assert item.severity == "LOW"
        assert item.location["path"].endswith("scripts/core/foo.py")
        assert item.location["startLine"] == 12
        assert item.tool["name"] == "bandit"
        assert "sast" in item.tags
        assert "python" in item.tags

    def test_multiple_results_parsing(self, tmp_path: Path):
        """Test parsing multiple Bandit results."""
        sample = {
            "results": [
                {
                    "filename": "app.py",
                    "line_number": 10,
                    "issue_text": "Possible SQL injection",
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions",
                    "issue_severity": "HIGH",
                    "issue_confidence": "MEDIUM",
                },
                {
                    "filename": "utils.py",
                    "line_number": 25,
                    "issue_text": "Use of exec detected",
                    "test_id": "B102",
                    "test_name": "exec_used",
                    "issue_severity": "MEDIUM",
                    "issue_confidence": "HIGH",
                },
            ]
        }
        path = write_tmp(tmp_path, "bandit.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        rule_ids = {f.ruleId for f in findings}
        assert rule_ids == {"B608", "B102"}

    def test_metadata_property(self, tmp_path: Path):
        """Test adapter metadata property."""
        adapter = BanditAdapter()
        metadata = adapter.metadata
        assert metadata.name == "bandit"
        assert metadata.tool_name == "bandit"
        assert metadata.schema_version == "1.2.0"
        assert metadata.output_format == "json"


class TestBanditSeverityMapping:
    """Tests for severity level mapping."""

    def test_low_severity(self, tmp_path: Path):
        """Test LOW severity mapping."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "Low severity issue",
                    "test_id": "B000",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "low.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "LOW"

    def test_medium_severity(self, tmp_path: Path):
        """Test MEDIUM severity mapping."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "Medium severity issue",
                    "test_id": "B000",
                    "issue_severity": "MEDIUM",
                }
            ]
        }
        path = write_tmp(tmp_path, "medium.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "MEDIUM"

    def test_high_severity(self, tmp_path: Path):
        """Test HIGH severity mapping."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "High severity issue",
                    "test_id": "B000",
                    "issue_severity": "HIGH",
                }
            ]
        }
        path = write_tmp(tmp_path, "high.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "HIGH"

    def test_missing_severity_defaults_to_medium(self, tmp_path: Path):
        """Test missing severity defaults to MEDIUM."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "Issue without severity",
                    "test_id": "B000",
                }
            ]
        }
        path = write_tmp(tmp_path, "nosev.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert findings[0].severity == "MEDIUM"


class TestBanditAlternativeFieldNames:
    """Tests for alternative field naming conventions."""

    def test_camel_case_test_id(self, tmp_path: Path):
        """Test parsing with camelCase testId field."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 5,
                    "issue_text": "Security issue",
                    "testId": "B103",
                    "issue_severity": "MEDIUM",
                }
            ]
        }
        path = write_tmp(tmp_path, "camel.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "B103"

    def test_kebab_case_test_id(self, tmp_path: Path):
        """Test parsing with kebab-case test-id field."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 5,
                    "issue_text": "Security issue",
                    "test-id": "B104",
                    "issue_severity": "MEDIUM",
                }
            ]
        }
        path = write_tmp(tmp_path, "kebab.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "B104"

    def test_file_name_alternative(self, tmp_path: Path):
        """Test parsing with file_name instead of filename."""
        sample = {
            "results": [
                {
                    "file_name": "alternative.py",
                    "line_number": 10,
                    "issue_text": "Issue with alt field",
                    "test_id": "B105",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "alt.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].location["path"] == "alternative.py"

    def test_line_field_instead_of_line_number(self, tmp_path: Path):
        """Test parsing with line instead of line_number."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line": 42,
                    "issue_text": "Issue with line field",
                    "test_id": "B106",
                    "issue_severity": "MEDIUM",
                }
            ]
        }
        path = write_tmp(tmp_path, "line.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].location["startLine"] == 42

    def test_message_instead_of_issue_text(self, tmp_path: Path):
        """Test parsing with message instead of issue_text."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "message": "Alternative message field",
                    "test_id": "B107",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "msg.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "Alternative message field" in findings[0].message


class TestBanditArrayFormat:
    """Tests for array-based Bandit output format."""

    def test_array_format_parsing(self, tmp_path: Path):
        """Test parsing direct array format (not wrapped in results key)."""
        sample = [
            {
                "filename": "array_format.py",
                "line_number": 5,
                "issue_text": "Direct array result",
                "test_id": "B200",
                "issue_severity": "MEDIUM",
            }
        ]
        path = write_tmp(tmp_path, "array.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].ruleId == "B200"


class TestBanditEdgeCases:
    """Tests for edge cases and error handling."""

    def test_empty_file(self, tmp_path: Path):
        """Test parsing empty file."""
        path = write_tmp(tmp_path, "empty.json", "")
        adapter = BanditAdapter()
        assert adapter.parse(path) == []

    def test_malformed_json(self, tmp_path: Path):
        """Test parsing malformed JSON."""
        path = write_tmp(tmp_path, "bad.json", "{not valid json}")
        adapter = BanditAdapter()
        assert adapter.parse(path) == []

    def test_nonexistent_file(self, tmp_path: Path):
        """Test parsing nonexistent file."""
        adapter = BanditAdapter()
        assert adapter.parse(tmp_path / "nonexistent.json") == []

    def test_empty_results_array(self, tmp_path: Path):
        """Test parsing with empty results array."""
        sample = {"results": []}
        path = write_tmp(tmp_path, "empty_results.json", json.dumps(sample))
        adapter = BanditAdapter()
        assert adapter.parse(path) == []

    def test_result_item_not_dict(self, tmp_path: Path):
        """Test parsing when result item is not a dictionary."""
        sample = {"results": ["string", 123, None]}
        path = write_tmp(tmp_path, "bad_items.json", json.dumps(sample))
        adapter = BanditAdapter()
        assert adapter.parse(path) == []

    def test_missing_filename_defaults_to_empty(self, tmp_path: Path):
        """Test missing filename defaults to empty string."""
        sample = {
            "results": [
                {
                    "line_number": 1,
                    "issue_text": "No filename",
                    "test_id": "B300",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "no_file.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].location["path"] == ""

    def test_missing_line_number_defaults_to_zero(self, tmp_path: Path):
        """Test missing line_number defaults to 0."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "issue_text": "No line number",
                    "test_id": "B301",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "no_line.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert findings[0].location["startLine"] == 0


class TestBanditCompliance:
    """Tests for compliance enrichment and metadata."""

    def test_schema_version(self, tmp_path: Path):
        """Test schema version is set correctly."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "Test",
                    "test_id": "B400",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "schema.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert findings[0].schemaVersion == "1.2.0"

    def test_tool_name(self, tmp_path: Path):
        """Test tool name is set correctly."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "Test",
                    "test_id": "B401",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "tool.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert findings[0].tool["name"] == "bandit"

    def test_remediation_message(self, tmp_path: Path):
        """Test remediation message is present."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "Test issue",
                    "test_id": "B402",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "remediation.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert "Bandit" in findings[0].remediation


class TestBanditFingerprinting:
    """Tests for finding fingerprint generation."""

    def test_unique_fingerprints(self, tmp_path: Path):
        """Test that different findings get unique fingerprints."""
        sample = {
            "results": [
                {
                    "filename": "file1.py",
                    "line_number": 1,
                    "issue_text": "Issue 1",
                    "test_id": "B500",
                    "issue_severity": "LOW",
                },
                {
                    "filename": "file2.py",
                    "line_number": 1,
                    "issue_text": "Issue 2",
                    "test_id": "B500",
                    "issue_severity": "LOW",
                },
            ]
        }
        path = write_tmp(tmp_path, "fingerprint.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 2
        assert findings[0].id != findings[1].id

    def test_consistent_fingerprints(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 10,
                    "issue_text": "Consistent issue",
                    "test_id": "B501",
                    "issue_severity": "MEDIUM",
                }
            ]
        }
        path = write_tmp(tmp_path, "consistent.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings1 = adapter.parse(path)
        findings2 = adapter.parse(path)
        assert findings1[0].id == findings2[0].id


class TestBanditUnicodeHandling:
    """Tests for Unicode and encoding edge cases."""

    def test_unicode_in_filename(self, tmp_path: Path):
        """Test parsing with Unicode in filename."""
        sample = {
            "results": [
                {
                    "filename": "scripts/\u4e2d\u6587/app.py",
                    "line_number": 5,
                    "issue_text": "Unicode filename test",
                    "test_id": "B600",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "unicode.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u4e2d\u6587" in findings[0].location["path"]

    def test_unicode_in_issue_text(self, tmp_path: Path):
        """Test parsing with Unicode in issue text."""
        sample = {
            "results": [
                {
                    "filename": "test.py",
                    "line_number": 1,
                    "issue_text": "Issue with \u00e9\u00e8\u00ea\u00eb characters",
                    "test_id": "B601",
                    "issue_severity": "LOW",
                }
            ]
        }
        path = write_tmp(tmp_path, "unicode_msg.json", json.dumps(sample))
        adapter = BanditAdapter()
        findings = adapter.parse(path)
        assert len(findings) == 1
        assert "\u00e9" in findings[0].message
