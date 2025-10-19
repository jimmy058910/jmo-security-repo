"""
Tests for BaseAdapter

Tests the abstract base class for tool adapters.
"""

import pytest
from pathlib import Path
import json

import sys

sys.path.insert(0, str(Path(__file__).parent.parent.parent / "scripts"))

from scripts.core.adapters.base_adapter import (
    BaseAdapter,
    CURRENT_SCHEMA_VERSION,
    load_json_file,
)


# Concrete implementation for testing
class TestToolAdapter(BaseAdapter):
    """Minimal adapter implementation for testing"""

    def _parse_output(self, output_file: Path):
        data = load_json_file(output_file)
        return data.get("findings", [])

    def _extract_finding(self, raw):
        return {
            "ruleId": raw["rule"],
            "severity": self._map_severity(raw["severity"]),
            "message": raw["msg"],
            "location": {
                "path": raw["file"],
                "startLine": raw["line"],
                "endLine": raw["line"],
            },
        }


class TestBaseAdapter:
    """Test BaseAdapter functionality"""

    def test_adapter_initialization(self):
        """Test adapter can be initialized with tool metadata"""
        adapter = TestToolAdapter("testtool", "1.0.0")
        assert adapter.tool_name == "testtool"
        assert adapter.tool_version == "1.0.0"

    def test_load_nonexistent_file(self, tmp_path):
        """Test loading nonexistent file returns empty list"""
        adapter = TestToolAdapter("testtool", "1.0.0")
        result = adapter.load(tmp_path / "nonexistent.json")
        assert result == []

    def test_load_with_findings(self, tmp_path):
        """Test loading file with findings"""
        # Create test JSON file
        test_file = tmp_path / "output.json"
        test_data = {
            "findings": [
                {
                    "rule": "SQL_INJECTION",
                    "severity": "HIGH",
                    "msg": "SQL injection detected",
                    "file": "app.py",
                    "line": 42,
                }
            ]
        }
        test_file.write_text(json.dumps(test_data))

        # Load findings
        adapter = TestToolAdapter("testtool", "1.0.0")
        findings = adapter.load(test_file)

        assert len(findings) == 1
        finding = findings[0]

        # Check required fields are present
        assert "id" in finding
        assert "schemaVersion" in finding
        assert "tool" in finding
        assert "ruleId" in finding
        assert "severity" in finding
        assert "message" in finding
        assert "location" in finding

        # Check values
        assert finding["schemaVersion"] == CURRENT_SCHEMA_VERSION
        assert finding["tool"]["name"] == "testtool"
        assert finding["tool"]["version"] == "1.0.0"
        assert finding["ruleId"] == "SQL_INJECTION"
        assert finding["severity"] == "HIGH"
        assert finding["message"] == "SQL injection detected"
        assert finding["location"]["path"] == "app.py"
        assert finding["location"]["startLine"] == 42

    def test_generate_fingerprint_stable(self, tmp_path):
        """Test fingerprint generation is stable for same finding"""
        test_file = tmp_path / "output.json"
        test_data = {
            "findings": [
                {
                    "rule": "XSS",
                    "severity": "HIGH",
                    "msg": "Cross-site scripting vulnerability",
                    "file": "index.html",
                    "line": 10,
                }
            ]
        }
        test_file.write_text(json.dumps(test_data))

        adapter = TestToolAdapter("testtool", "1.0.0")

        # Load twice
        findings1 = adapter.load(test_file)
        findings2 = adapter.load(test_file)

        # Fingerprints should be identical
        assert findings1[0]["id"] == findings2[0]["id"]

    def test_generate_fingerprint_unique(self, tmp_path):
        """Test different findings get different fingerprints"""
        test_file = tmp_path / "output.json"
        test_data = {
            "findings": [
                {
                    "rule": "XSS",
                    "severity": "HIGH",
                    "msg": "XSS found",
                    "file": "a.html",
                    "line": 10,
                },
                {
                    "rule": "SQLI",
                    "severity": "HIGH",
                    "msg": "SQL injection",
                    "file": "b.py",
                    "line": 20,
                },
            ]
        }
        test_file.write_text(json.dumps(test_data))

        adapter = TestToolAdapter("testtool", "1.0.0")
        findings = adapter.load(test_file)

        assert len(findings) == 2
        assert findings[0]["id"] != findings[1]["id"]

    def test_map_severity_direct_match(self):
        """Test severity mapping with direct matches"""
        adapter = TestToolAdapter("testtool", "1.0.0")

        assert adapter._map_severity("CRITICAL") == "CRITICAL"
        assert adapter._map_severity("HIGH") == "HIGH"
        assert adapter._map_severity("MEDIUM") == "MEDIUM"
        assert adapter._map_severity("LOW") == "LOW"
        assert adapter._map_severity("INFO") == "INFO"

    def test_map_severity_aliases(self):
        """Test severity mapping with common aliases"""
        adapter = TestToolAdapter("testtool", "1.0.0")

        assert adapter._map_severity("ERROR") == "HIGH"
        assert adapter._map_severity("WARNING") == "MEDIUM"
        assert adapter._map_severity("WARN") == "MEDIUM"
        assert adapter._map_severity("NOTE") == "LOW"
        assert adapter._map_severity("INFORMATIONAL") == "INFO"

    def test_map_severity_case_insensitive(self):
        """Test severity mapping is case-insensitive"""
        adapter = TestToolAdapter("testtool", "1.0.0")

        assert adapter._map_severity("critical") == "CRITICAL"
        assert adapter._map_severity("High") == "HIGH"
        assert adapter._map_severity("medium") == "MEDIUM"

    def test_map_severity_unknown(self):
        """Test unknown severity defaults to INFO"""
        adapter = TestToolAdapter("testtool", "1.0.0")

        assert adapter._map_severity("UNKNOWN") == "INFO"
        assert adapter._map_severity("CUSTOM_LEVEL") == "INFO"

    def test_raw_finding_included(self, tmp_path):
        """Test raw finding is included in output"""
        test_file = tmp_path / "output.json"
        test_data = {
            "findings": [
                {
                    "rule": "TEST",
                    "severity": "LOW",
                    "msg": "Test message",
                    "file": "test.py",
                    "line": 1,
                    "custom_field": "custom_value",
                }
            ]
        }
        test_file.write_text(json.dumps(test_data))

        adapter = TestToolAdapter("testtool", "1.0.0")
        findings = adapter.load(test_file)

        assert len(findings) == 1
        assert "raw" in findings[0]
        assert findings[0]["raw"]["custom_field"] == "custom_value"

    def test_load_json_file_helper(self, tmp_path):
        """Test load_json_file helper function"""
        test_file = tmp_path / "test.json"
        test_data = {"key": "value"}
        test_file.write_text(json.dumps(test_data))

        result = load_json_file(test_file)
        assert result == test_data

    def test_load_json_file_nonexistent(self, tmp_path):
        """Test load_json_file raises FileNotFoundError for missing file"""
        with pytest.raises(FileNotFoundError):
            load_json_file(tmp_path / "nonexistent.json")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
