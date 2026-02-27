"""Comprehensive tests for BaseAdapter abstract class.

Tests cover:
- Abstract class instantiation (should fail)
- Concrete subclass implementation
- Fingerprint generation (consistency and uniqueness)
- Severity mapping (all levels including aliases)
- File loading with missing/empty files
- JSON loading helper function
- Schema version injection
- Tool metadata injection
"""

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.core.adapters.base_adapter import BaseAdapter, load_json_file


class ConcreteTestAdapter(BaseAdapter):
    """Concrete implementation of BaseAdapter for testing."""

    def _parse_output(self, output_file: Path) -> list[dict[str, Any]]:
        """Parse test JSON format."""
        with open(output_file, encoding="utf-8") as f:
            data = json.load(f)
        return data.get("findings", []) if isinstance(data, dict) else []

    def _extract_finding(self, raw: dict[str, Any]) -> dict[str, Any]:
        """Extract finding from raw format."""
        return {
            "ruleId": raw.get("rule_id", "TEST"),
            "severity": self._map_severity(raw.get("severity", "INFO")),
            "message": raw.get("message", "Test finding"),
            "location": {
                "path": raw.get("file", ""),
                "startLine": raw.get("line", 0),
            },
        }


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temporary file."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


class TestBaseAdapterInstantiation:
    """Tests for BaseAdapter instantiation."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that BaseAdapter cannot be instantiated directly."""
        with pytest.raises(TypeError):
            BaseAdapter("test", "1.0.0")  # type: ignore

    def test_concrete_subclass_instantiation(self):
        """Test that concrete subclass can be instantiated."""
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        assert adapter.tool_name == "test-tool"
        assert adapter.tool_version == "1.0.0"

    def test_default_version(self):
        """Test default version is 'unknown'."""
        adapter = ConcreteTestAdapter("test-tool")
        assert adapter.tool_version == "unknown"


class TestBaseAdapterFingerprint:
    """Tests for fingerprint generation."""

    def test_fingerprint_consistency(self, tmp_path: Path):
        """Test that same input produces same fingerprint."""
        sample = {
            "findings": [
                {
                    "rule_id": "TEST-001",
                    "severity": "HIGH",
                    "file": "test.py",
                    "line": 10,
                }
            ]
        }
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings1 = adapter.load(path)
        findings2 = adapter.load(path)
        assert findings1[0]["id"] == findings2[0]["id"]

    def test_fingerprint_uniqueness_by_file(self, tmp_path: Path):
        """Test different files produce different fingerprints."""
        sample = {
            "findings": [
                {
                    "rule_id": "TEST-001",
                    "severity": "HIGH",
                    "file": "file1.py",
                    "line": 10,
                },
                {
                    "rule_id": "TEST-001",
                    "severity": "HIGH",
                    "file": "file2.py",
                    "line": 10,
                },
            ]
        }
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert findings[0]["id"] != findings[1]["id"]

    def test_fingerprint_uniqueness_by_line(self, tmp_path: Path):
        """Test different lines produce different fingerprints."""
        sample = {
            "findings": [
                {
                    "rule_id": "TEST-001",
                    "severity": "HIGH",
                    "file": "test.py",
                    "line": 10,
                },
                {
                    "rule_id": "TEST-001",
                    "severity": "HIGH",
                    "file": "test.py",
                    "line": 20,
                },
            ]
        }
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert findings[0]["id"] != findings[1]["id"]

    def test_fingerprint_uniqueness_by_rule(self, tmp_path: Path):
        """Test different rules produce different fingerprints."""
        sample = {
            "findings": [
                {
                    "rule_id": "TEST-001",
                    "severity": "HIGH",
                    "file": "test.py",
                    "line": 10,
                },
                {
                    "rule_id": "TEST-002",
                    "severity": "HIGH",
                    "file": "test.py",
                    "line": 10,
                },
            ]
        }
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert findings[0]["id"] != findings[1]["id"]

    def test_fingerprint_length(self, tmp_path: Path):
        """Test fingerprint has expected length (16 hex chars)."""
        sample = {"findings": [{"rule_id": "TEST", "file": "test.py", "line": 1}]}
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert len(findings[0]["id"]) == 16
        # Should be valid hex
        int(findings[0]["id"], 16)


class TestBaseAdapterSeverityMapping:
    """Tests for severity level mapping."""

    def test_map_critical(self):
        """Test CRITICAL severity mapping."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("CRITICAL") == "CRITICAL"
        assert adapter._map_severity("critical") == "CRITICAL"
        assert adapter._map_severity("Critical") == "CRITICAL"

    def test_map_high(self):
        """Test HIGH severity mapping."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("HIGH") == "HIGH"
        assert adapter._map_severity("high") == "HIGH"

    def test_map_medium(self):
        """Test MEDIUM severity mapping."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("MEDIUM") == "MEDIUM"
        assert adapter._map_severity("medium") == "MEDIUM"

    def test_map_low(self):
        """Test LOW severity mapping."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("LOW") == "LOW"
        assert adapter._map_severity("low") == "LOW"

    def test_map_info(self):
        """Test INFO severity mapping."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("INFO") == "INFO"
        assert adapter._map_severity("info") == "INFO"

    def test_map_error_alias(self):
        """Test ERROR maps to HIGH."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("ERROR") == "HIGH"
        assert adapter._map_severity("error") == "HIGH"

    def test_map_warning_alias(self):
        """Test WARNING/WARN maps to MEDIUM."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("WARNING") == "MEDIUM"
        assert adapter._map_severity("WARN") == "MEDIUM"
        assert adapter._map_severity("warn") == "MEDIUM"

    def test_map_note_alias(self):
        """Test NOTE maps to LOW."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("NOTE") == "LOW"
        assert adapter._map_severity("note") == "LOW"

    def test_map_informational_alias(self):
        """Test INFORMATIONAL/INFORMATION maps to INFO."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("INFORMATIONAL") == "INFO"
        assert adapter._map_severity("INFORMATION") == "INFO"

    def test_map_unknown_defaults_to_info(self):
        """Test unknown severity defaults to INFO."""
        adapter = ConcreteTestAdapter("test", "1.0")
        assert adapter._map_severity("UNKNOWN") == "INFO"
        assert adapter._map_severity("") == "INFO"
        assert adapter._map_severity("random") == "INFO"


class TestBaseAdapterLoad:
    """Tests for the load method."""

    def test_load_nonexistent_file(self, tmp_path: Path):
        """Test loading nonexistent file returns empty list."""
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        result = adapter.load(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_injects_schema_version(self, tmp_path: Path):
        """Test that load injects schemaVersion."""
        sample = {"findings": [{"rule_id": "TEST", "file": "test.py", "line": 1}]}
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert findings[0]["schemaVersion"] == "1.2.0"

    def test_load_injects_tool_metadata(self, tmp_path: Path):
        """Test that load injects tool name and version."""
        sample = {"findings": [{"rule_id": "TEST", "file": "test.py", "line": 1}]}
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("my-tool", "2.5.0")
        findings = adapter.load(path)
        assert findings[0]["tool"]["name"] == "my-tool"
        assert findings[0]["tool"]["version"] == "2.5.0"

    def test_load_injects_id(self, tmp_path: Path):
        """Test that load injects fingerprint id."""
        sample = {"findings": [{"rule_id": "TEST", "file": "test.py", "line": 1}]}
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert "id" in findings[0]
        assert len(findings[0]["id"]) == 16

    def test_load_preserves_raw(self, tmp_path: Path):
        """Test that load preserves raw finding."""
        sample = {
            "findings": [
                {
                    "rule_id": "TEST",
                    "file": "test.py",
                    "line": 1,
                    "extra_field": "value",
                }
            ]
        }
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert "raw" in findings[0]
        assert findings[0]["raw"]["extra_field"] == "value"

    def test_load_multiple_findings(self, tmp_path: Path):
        """Test loading multiple findings."""
        sample = {
            "findings": [
                {"rule_id": "TEST-1", "file": "a.py", "line": 1},
                {"rule_id": "TEST-2", "file": "b.py", "line": 2},
                {"rule_id": "TEST-3", "file": "c.py", "line": 3},
            ]
        }
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert len(findings) == 3

    def test_load_empty_findings(self, tmp_path: Path):
        """Test loading empty findings list."""
        sample = {"findings": []}
        path = write_tmp(tmp_path, "test.json", json.dumps(sample))
        adapter = ConcreteTestAdapter("test-tool", "1.0.0")
        findings = adapter.load(path)
        assert findings == []


class TestLoadJsonFile:
    """Tests for the load_json_file helper function."""

    def test_load_valid_json(self, tmp_path: Path):
        """Test loading valid JSON file."""
        sample = {"key": "value", "number": 42}
        path = write_tmp(tmp_path, "valid.json", json.dumps(sample))
        result = load_json_file(path)
        assert result == sample

    def test_load_nonexistent_file_raises(self, tmp_path: Path):
        """Test loading nonexistent file raises FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            load_json_file(tmp_path / "nonexistent.json")

    def test_load_invalid_json_raises(self, tmp_path: Path):
        """Test loading invalid JSON raises JSONDecodeError."""
        path = write_tmp(tmp_path, "invalid.json", "{not valid json}")
        with pytest.raises(json.JSONDecodeError):
            load_json_file(path)

    def test_load_unicode_content(self, tmp_path: Path):
        """Test loading JSON with Unicode content."""
        sample = {"message": "日本語テスト", "emoji": "🔒"}
        path = write_tmp(tmp_path, "unicode.json", json.dumps(sample))
        result = load_json_file(path)
        assert result["message"] == "日本語テスト"
        assert result["emoji"] == "🔒"

    def test_load_nested_structure(self, tmp_path: Path):
        """Test loading deeply nested JSON structure."""
        sample = {"level1": {"level2": {"level3": {"level4": {"value": "deep"}}}}}
        path = write_tmp(tmp_path, "nested.json", json.dumps(sample))
        result = load_json_file(path)
        assert result["level1"]["level2"]["level3"]["level4"]["value"] == "deep"
