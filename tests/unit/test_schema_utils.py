#!/usr/bin/env python3
"""
Comprehensive unit tests for scripts/core/schema_utils.py

Tests cover:
1. load_schema() - schema loading and error handling
2. validate_findings() - validation with/without jsonschema library

Target: ≥85% code coverage
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from scripts.core.schema_utils import load_schema, validate_findings


# ============================================================================
# load_schema() Tests
# ============================================================================


class TestLoadSchema:
    """Test suite for load_schema() function."""

    def test_load_schema_success(self):
        """Test successfully loading the CommonFinding schema."""
        schema = load_schema()

        # Verify schema structure
        assert isinstance(schema, dict)
        assert "$schema" in schema
        assert "title" in schema
        assert schema["title"] == "CommonFinding"
        assert "type" in schema
        assert schema["type"] == "object"

    def test_load_schema_has_required_fields(self):
        """Test that loaded schema includes required field definitions."""
        schema = load_schema()

        # Verify required fields are defined
        assert "required" in schema
        required_fields = schema["required"]
        assert "schemaVersion" in required_fields
        assert "id" in required_fields
        assert "ruleId" in required_fields
        assert "severity" in required_fields
        assert "tool" in required_fields
        assert "location" in required_fields
        assert "message" in required_fields

    def test_load_schema_has_properties(self):
        """Test that loaded schema defines properties for all required fields."""
        schema = load_schema()

        # Verify properties are defined
        assert "properties" in schema
        properties = schema["properties"]
        assert "schemaVersion" in properties
        assert "id" in properties
        assert "ruleId" in properties
        assert "severity" in properties
        assert "tool" in properties
        assert "location" in properties
        assert "message" in properties

    def test_load_schema_severity_enum(self):
        """Test that severity field has correct enum values."""
        schema = load_schema()

        severity_prop = schema["properties"]["severity"]
        assert "enum" in severity_prop
        severities = severity_prop["enum"]
        assert "CRITICAL" in severities
        assert "HIGH" in severities
        assert "MEDIUM" in severities
        assert "LOW" in severities
        assert "INFO" in severities

    def test_load_schema_schema_version_enum(self):
        """Test that schemaVersion field has correct enum values."""
        schema = load_schema()

        schema_version_prop = schema["properties"]["schemaVersion"]
        assert "enum" in schema_version_prop
        versions = schema_version_prop["enum"]
        assert "1.0.0" in versions
        assert "1.1.0" in versions
        assert "1.2.0" in versions

    def test_load_schema_file_not_found(self, monkeypatch):
        """Test FileNotFoundError when schema file doesn't exist."""

        # Mock Path to raise FileNotFoundError
        def mock_read_text(*args, **kwargs):
            raise FileNotFoundError("Schema file not found")

        with patch("pathlib.Path.read_text", side_effect=mock_read_text):
            with pytest.raises(FileNotFoundError):
                load_schema()

    def test_load_schema_invalid_json(self, monkeypatch):
        """Test JSONDecodeError when schema file has invalid JSON."""
        # Mock Path.read_text to return invalid JSON
        with patch("pathlib.Path.read_text", return_value="{ invalid json }"):
            with pytest.raises(json.JSONDecodeError):
                load_schema()

    def test_load_schema_empty_file(self, monkeypatch):
        """Test JSONDecodeError when schema file is empty."""
        with patch("pathlib.Path.read_text", return_value=""):
            with pytest.raises(json.JSONDecodeError):
                load_schema()

    def test_load_schema_returns_new_dict_each_time(self):
        """Test that load_schema() returns a new dict each time (not cached)."""
        schema1 = load_schema()
        schema2 = load_schema()

        # Should be equal but not the same object
        assert schema1 == schema2
        assert schema1 is not schema2


# ============================================================================
# validate_findings() Tests
# ============================================================================


class TestValidateFindings:
    """Test suite for validate_findings() function."""

    def test_validate_findings_without_jsonschema(self, monkeypatch):
        """Test that validation returns True when jsonschema not installed."""
        # Mock jsonschema as None (not installed)
        import scripts.core.schema_utils as schema_utils_module

        original_jsonschema = schema_utils_module.jsonschema
        try:
            schema_utils_module.jsonschema = None

            # Should return True when jsonschema not installed
            findings = [
                {
                    "schemaVersion": "1.2.0",
                    "id": "abc123",
                    "ruleId": "G101",
                    "severity": "HIGH",
                    "tool": {"name": "test", "version": "1.0"},
                    "location": {"path": "test.py"},
                    "message": "Test finding",
                }
            ]
            assert validate_findings(findings) is True
        finally:
            schema_utils_module.jsonschema = original_jsonschema

    def test_validate_findings_empty_list(self):
        """Test validation with empty findings list."""
        assert validate_findings([]) is True

    def test_validate_findings_valid_finding(self):
        """Test validation with a valid finding."""
        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "fingerprint-abc123",
                "ruleId": "CWE-79",
                "severity": "HIGH",
                "tool": {"name": "semgrep", "version": "1.50.0"},
                "location": {"path": "app/views.py", "startLine": 42, "endLine": 45},
                "message": "Potential XSS vulnerability",
            }
        ]

        assert validate_findings(findings) is True

    def test_validate_findings_multiple_valid_findings(self):
        """Test validation with multiple valid findings."""
        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "fp-001",
                "ruleId": "G101",
                "severity": "CRITICAL",
                "tool": {"name": "trufflehog", "version": "3.63.0"},
                "location": {"path": "config.py"},
                "message": "Hardcoded API key detected",
            },
            {
                "schemaVersion": "1.2.0",
                "id": "fp-002",
                "ruleId": "CVE-2024-1234",
                "severity": "MEDIUM",
                "tool": {"name": "trivy", "version": "0.50.0"},
                "location": {"path": "requirements.txt"},
                "message": "Known vulnerability in dependency",
            },
        ]

        assert validate_findings(findings) is True

    def test_validate_findings_with_optional_fields(self):
        """Test validation with finding containing optional fields."""
        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "fp-003",
                "ruleId": "CWE-89",
                "severity": "HIGH",
                "tool": {"name": "bandit", "version": "1.7.5"},
                "location": {"path": "db/queries.py", "startLine": 100, "endLine": 105},
                "message": "SQL injection vulnerability",
                "title": "SQL Injection in User Query",
                "description": "User input is directly concatenated into SQL query",
                "cvss": 7.5,
                "remediation": "Use parameterized queries",
                "references": ["https://owasp.org/www-community/attacks/SQL_Injection"],
                "tags": ["sql", "injection", "database"],
            }
        ]

        assert validate_findings(findings) is True

    def test_validate_findings_missing_required_field_id(self):
        """Test ValidationError when required field 'id' is missing."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                # Missing 'id' field
                "ruleId": "G101",
                "severity": "HIGH",
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_missing_required_field_severity(self):
        """Test ValidationError when required field 'severity' is missing."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "abc123",
                "ruleId": "G101",
                # Missing 'severity' field
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_missing_required_field_tool(self):
        """Test ValidationError when required field 'tool' is missing."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "abc123",
                "ruleId": "G101",
                "severity": "HIGH",
                # Missing 'tool' field
                "location": {"path": "test.py"},
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_invalid_severity_value(self):
        """Test ValidationError when severity has invalid enum value."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "abc123",
                "ruleId": "G101",
                "severity": "SUPER_CRITICAL",  # Invalid enum value
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_invalid_schema_version(self):
        """Test ValidationError when schemaVersion has invalid enum value."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "2.0.0",  # Invalid enum value
                "id": "abc123",
                "ruleId": "G101",
                "severity": "HIGH",
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_invalid_tool_structure(self):
        """Test ValidationError when tool object is missing required fields."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "abc123",
                "ruleId": "G101",
                "severity": "HIGH",
                "tool": {"name": "test"},  # Missing 'version' field
                "location": {"path": "test.py"},
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_invalid_location_structure(self):
        """Test ValidationError when location object is missing required fields."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "abc123",
                "ruleId": "G101",
                "severity": "HIGH",
                "tool": {"name": "test", "version": "1.0"},
                "location": {},  # Missing 'path' field
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_wrong_type_severity(self):
        """Test ValidationError when severity is wrong type (number instead of string)."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "abc123",
                "ruleId": "G101",
                "severity": 3,  # Should be string, not number
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Test finding",
            }
        ]

        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_draft_07_fallback(self):
        """Test that validation falls back to draft-07 schema if initial validation fails."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": "fp-fallback",
                "ruleId": "TEST-001",
                "severity": "LOW",
                "tool": {"name": "test-tool", "version": "1.0.0"},
                "location": {"path": "test.py"},
                "message": "Test finding for fallback",
            }
        ]

        # Mock the first validation to raise an exception to trigger fallback
        original_validate = jsonschema.validate

        call_count = [0]

        def mock_validate(instance, schema, **kwargs):
            call_count[0] += 1
            # First call (sample validation) should fail to trigger fallback
            if call_count[0] == 1:
                raise jsonschema.ValidationError("Forcing fallback to draft-07")
            # Subsequent calls should use draft-07 schema
            assert schema.get("$schema") == "http://json-schema.org/draft-07/schema#"
            # Actually validate with the modified schema
            return original_validate(instance, schema, **kwargs)

        with patch("jsonschema.validate", side_effect=mock_validate):
            # Should succeed with draft-07 fallback
            assert validate_findings(findings) is True

    def test_validate_findings_validates_each_finding_individually(self):
        """Test that validation checks each finding in the list."""
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed")

        findings = [
            # First finding is valid
            {
                "schemaVersion": "1.2.0",
                "id": "fp-001",
                "ruleId": "G101",
                "severity": "HIGH",
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "First finding",
            },
            # Second finding is invalid (missing 'id')
            {
                "schemaVersion": "1.2.0",
                "ruleId": "G102",
                "severity": "MEDIUM",
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test2.py"},
                "message": "Second finding",
            },
        ]

        # Should raise ValidationError on the second finding
        with pytest.raises(jsonschema.ValidationError):
            validate_findings(findings)

    def test_validate_findings_with_all_schema_versions(self):
        """Test validation with all valid schemaVersion values."""
        findings = [
            {
                "schemaVersion": "1.0.0",
                "id": "fp-v1-0",
                "ruleId": "TEST-001",
                "severity": "INFO",
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Schema v1.0.0 finding",
            },
            {
                "schemaVersion": "1.1.0",
                "id": "fp-v1-1",
                "ruleId": "TEST-002",
                "severity": "LOW",
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Schema v1.1.0 finding",
            },
            {
                "schemaVersion": "1.2.0",
                "id": "fp-v1-2",
                "ruleId": "TEST-003",
                "severity": "MEDIUM",
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": "Schema v1.2.0 finding",
            },
        ]

        assert validate_findings(findings) is True

    def test_validate_findings_with_all_severities(self):
        """Test validation with all valid severity values."""
        findings = [
            {
                "schemaVersion": "1.2.0",
                "id": f"fp-{severity.lower()}",
                "ruleId": f"TEST-{severity}",
                "severity": severity,
                "tool": {"name": "test", "version": "1.0"},
                "location": {"path": "test.py"},
                "message": f"{severity} severity finding",
            }
            for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        ]

        assert validate_findings(findings) is True
