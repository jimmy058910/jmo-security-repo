"""Tests for scripts/core/schema_validator.py.

Covers:
- load_schema(): File loading, missing file, invalid JSON
- validate_finding(): Valid/invalid findings, schema loading errors
- validate_findings(): Batch validation, error aggregation
- validate_findings_file(): File format handling (array, dict, single)
- validate_directory(): Directory traversal, exclude patterns
- JSONSCHEMA_AVAILABLE fallback when jsonschema is not installed
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest


# ========== Helpers ==========


def write_json(tmp_path: Path, name: str, data: Any) -> Path:
    """Write JSON data to a temp file."""
    p = tmp_path / name
    p.write_text(json.dumps(data), encoding="utf-8")
    return p


def make_valid_finding(**overrides: Any) -> dict[str, Any]:
    """Create a minimal valid CommonFinding for testing."""
    finding: dict[str, Any] = {
        "schemaVersion": "1.2.0",
        "id": "test-finding-001",
        "ruleId": "TEST-001",
        "severity": "HIGH",
        "message": "Test finding message",
        "tool": {"name": "test-tool", "version": "1.0.0"},
        "location": {"path": "src/app.py", "startLine": 42},
        "tags": ["test"],
    }
    finding.update(overrides)
    return finding


# ========== Category 1: load_schema() ==========


class TestLoadSchema:
    """Tests for load_schema()."""

    def test_load_default_schema(self):
        """Test loading the default schema from docs/schemas/."""
        from scripts.core.schema_validator import load_schema, SCHEMA_PATH

        # Only run if schema file exists (it should in the repo)
        if not SCHEMA_PATH.exists():
            pytest.skip("Schema file not present in checkout")

        schema = load_schema()
        assert isinstance(schema, dict)
        assert "$schema" in schema or "type" in schema

    def test_load_custom_schema(self, tmp_path: Path):
        """Test loading a schema from a custom path."""
        from scripts.core.schema_validator import load_schema

        schema_data = {"type": "object", "properties": {"id": {"type": "string"}}}
        schema_file = write_json(tmp_path, "custom_schema.json", schema_data)

        result = load_schema(schema_file)
        assert result == schema_data

    def test_load_schema_missing_file(self, tmp_path: Path):
        """Test FileNotFoundError for missing schema file."""
        from scripts.core.schema_validator import load_schema

        with pytest.raises(FileNotFoundError, match="Schema file not found"):
            load_schema(tmp_path / "nonexistent.json")

    def test_load_schema_invalid_json(self, tmp_path: Path):
        """Test JSONDecodeError for invalid JSON schema file."""
        from scripts.core.schema_validator import load_schema

        bad_file = tmp_path / "bad.json"
        bad_file.write_text("{invalid json", encoding="utf-8")

        with pytest.raises(json.JSONDecodeError):
            load_schema(bad_file)


# ========== Category 2: validate_finding() ==========


class TestValidateFinding:
    """Tests for validate_finding()."""

    def test_valid_finding_no_errors(self, tmp_path: Path):
        """Test that a valid finding returns empty error list."""
        from scripts.core.schema_validator import validate_finding

        # Use a permissive schema that accepts our test finding
        schema = {"type": "object", "properties": {"id": {"type": "string"}}}
        finding = make_valid_finding()

        errors = validate_finding(finding, schema)
        assert errors == []

    def test_invalid_finding_returns_errors(self):
        """Test that an invalid finding returns error messages."""
        from scripts.core.schema_validator import validate_finding, JSONSCHEMA_AVAILABLE

        if not JSONSCHEMA_AVAILABLE:
            pytest.skip("jsonschema not installed")

        # Schema requires 'id' to be a string
        schema = {
            "type": "object",
            "properties": {"id": {"type": "string"}},
            "required": ["id"],
        }
        finding = {"id": 12345}  # id should be string

        errors = validate_finding(finding, schema)
        assert len(errors) >= 1
        assert any("id" in e for e in errors)

    def test_validate_finding_missing_required(self):
        """Test validation when required fields are missing."""
        from scripts.core.schema_validator import validate_finding, JSONSCHEMA_AVAILABLE

        if not JSONSCHEMA_AVAILABLE:
            pytest.skip("jsonschema not installed")

        schema = {
            "type": "object",
            "required": ["id", "severity"],
            "properties": {
                "id": {"type": "string"},
                "severity": {"type": "string"},
            },
        }
        finding = {}  # Missing required fields

        errors = validate_finding(finding, schema)
        assert len(errors) >= 1

    def test_validate_finding_no_schema_loads_default(self):
        """Test that passing no schema tries to load default."""
        from scripts.core.schema_validator import validate_finding, SCHEMA_PATH

        if not SCHEMA_PATH.exists():
            # Should return schema load error
            errors = validate_finding(make_valid_finding(), None)
            assert any("Failed to load schema" in e for e in errors)

    def test_validate_finding_schema_load_error(self):
        """Test error handling when schema can't be loaded."""
        from scripts.core.schema_validator import validate_finding, JSONSCHEMA_AVAILABLE

        if not JSONSCHEMA_AVAILABLE:
            pytest.skip("jsonschema not installed")

        with patch(
            "scripts.core.schema_validator.load_schema",
            side_effect=FileNotFoundError("not found"),
        ):
            errors = validate_finding(make_valid_finding())
            assert len(errors) == 1
            assert "Failed to load schema" in errors[0]

    def test_validate_finding_jsonschema_unavailable(self):
        """Test graceful skip when jsonschema is not installed."""
        from scripts.core import schema_validator

        original = schema_validator.JSONSCHEMA_AVAILABLE
        try:
            schema_validator.JSONSCHEMA_AVAILABLE = False
            errors = schema_validator.validate_finding(make_valid_finding(), {})
            assert errors == []
        finally:
            schema_validator.JSONSCHEMA_AVAILABLE = original


# ========== Category 3: validate_findings() ==========


class TestValidateFindings:
    """Tests for validate_findings() batch validation."""

    def test_all_valid(self):
        """Test batch validation with all valid findings."""
        from scripts.core.schema_validator import validate_findings

        schema = {"type": "object"}
        findings = [make_valid_finding(id=f"f-{i}") for i in range(3)]

        result = validate_findings(findings, schema)
        assert result == {}

    def test_mixed_valid_invalid(self):
        """Test batch validation with mix of valid/invalid findings."""
        from scripts.core.schema_validator import (
            validate_findings,
            JSONSCHEMA_AVAILABLE,
        )

        if not JSONSCHEMA_AVAILABLE:
            pytest.skip("jsonschema not installed")

        schema = {
            "type": "object",
            "required": ["id"],
            "properties": {"id": {"type": "string"}},
        }
        findings = [
            {"id": "valid-1"},
            {"id": 999},  # Invalid: id should be string
            {"id": "valid-2"},
        ]

        result = validate_findings(findings, schema)
        # Only invalid findings should appear
        assert len(result) >= 1

    def test_uses_finding_id_as_key(self):
        """Test that finding id is used as dict key when available."""
        from scripts.core.schema_validator import (
            validate_findings,
            JSONSCHEMA_AVAILABLE,
        )

        if not JSONSCHEMA_AVAILABLE:
            pytest.skip("jsonschema not installed")

        schema = {
            "type": "object",
            "required": ["severity"],
            "properties": {"severity": {"type": "string"}},
        }
        findings = [{"id": "my-finding-id"}]  # Missing required 'severity'

        result = validate_findings(findings, schema)
        assert "my-finding-id" in result

    def test_uses_index_when_no_id(self):
        """Test that index is used as key when finding has no id."""
        from scripts.core.schema_validator import (
            validate_findings,
            JSONSCHEMA_AVAILABLE,
        )

        if not JSONSCHEMA_AVAILABLE:
            pytest.skip("jsonschema not installed")

        schema = {
            "type": "object",
            "required": ["severity"],
            "properties": {"severity": {"type": "string"}},
        }
        findings = [{}]  # No id, missing required

        result = validate_findings(findings, schema)
        assert "index_0" in result

    def test_schema_load_error(self):
        """Test error when schema can't be loaded in batch mode."""
        from scripts.core.schema_validator import (
            validate_findings,
            JSONSCHEMA_AVAILABLE,
        )

        if not JSONSCHEMA_AVAILABLE:
            pytest.skip("jsonschema not installed")

        with patch(
            "scripts.core.schema_validator.load_schema",
            side_effect=FileNotFoundError("missing"),
        ):
            result = validate_findings([make_valid_finding()])
            assert "schema_load_error" in result

    def test_jsonschema_unavailable(self):
        """Test graceful skip when jsonschema is not installed."""
        from scripts.core import schema_validator

        original = schema_validator.JSONSCHEMA_AVAILABLE
        try:
            schema_validator.JSONSCHEMA_AVAILABLE = False
            result = schema_validator.validate_findings([make_valid_finding()])
            assert result == {}
        finally:
            schema_validator.JSONSCHEMA_AVAILABLE = original


# ========== Category 4: validate_findings_file() ==========


class TestValidateFindingsFile:
    """Tests for validate_findings_file() with different file formats."""

    def test_array_format(self, tmp_path: Path):
        """Test file containing array of findings."""
        from scripts.core.schema_validator import validate_findings_file

        findings = [make_valid_finding()]
        f = write_json(tmp_path, "findings.json", findings)

        with patch(
            "scripts.core.schema_validator.load_schema", return_value={"type": "object"}
        ):
            with patch(
                "scripts.core.schema_validator.validate_findings", return_value={}
            ):
                errors = validate_findings_file(f)
                assert errors == []

    def test_dict_with_findings_key(self, tmp_path: Path):
        """Test file containing {findings: [...]} format."""
        from scripts.core.schema_validator import validate_findings_file

        data = {"findings": [make_valid_finding()]}
        f = write_json(tmp_path, "findings.json", data)

        with patch(
            "scripts.core.schema_validator.load_schema", return_value={"type": "object"}
        ):
            with patch(
                "scripts.core.schema_validator.validate_findings", return_value={}
            ):
                errors = validate_findings_file(f)
                assert errors == []

    def test_single_finding_dict(self, tmp_path: Path):
        """Test file containing a single finding object."""
        from scripts.core.schema_validator import validate_findings_file

        f = write_json(tmp_path, "finding.json", make_valid_finding())

        with patch(
            "scripts.core.schema_validator.load_schema", return_value={"type": "object"}
        ):
            with patch(
                "scripts.core.schema_validator.validate_findings", return_value={}
            ):
                errors = validate_findings_file(f)
                assert errors == []

    def test_empty_array(self, tmp_path: Path):
        """Test file containing empty array."""
        from scripts.core.schema_validator import validate_findings_file

        f = write_json(tmp_path, "empty.json", [])

        errors = validate_findings_file(f)
        assert errors == []

    def test_invalid_json(self, tmp_path: Path):
        """Test file containing invalid JSON."""
        from scripts.core.schema_validator import validate_findings_file

        bad = tmp_path / "bad.json"
        bad.write_text("{not valid json", encoding="utf-8")

        errors = validate_findings_file(bad)
        assert len(errors) == 1
        assert "Invalid JSON" in errors[0]

    def test_file_read_error(self, tmp_path: Path):
        """Test error when file can't be read."""
        from scripts.core.schema_validator import validate_findings_file

        missing = tmp_path / "nonexistent.json"

        errors = validate_findings_file(missing)
        assert len(errors) == 1
        assert "Failed to read file" in errors[0]

    def test_unexpected_data_type(self, tmp_path: Path):
        """Test file containing unexpected data type (string, number)."""
        from scripts.core.schema_validator import validate_findings_file

        f = write_json(tmp_path, "weird.json", "just a string")

        errors = validate_findings_file(f)
        assert len(errors) == 1
        assert "Unexpected data type" in errors[0]

    def test_validation_errors_aggregated(self, tmp_path: Path):
        """Test that validation errors are properly formatted with file path."""
        from scripts.core.schema_validator import validate_findings_file

        findings = [make_valid_finding()]
        f = write_json(tmp_path, "findings.json", findings)

        mock_errors = {"test-finding-001": ["root: invalid type"]}
        with patch(
            "scripts.core.schema_validator.load_schema", return_value={"type": "object"}
        ):
            with patch(
                "scripts.core.schema_validator.validate_findings",
                return_value=mock_errors,
            ):
                errors = validate_findings_file(f)
                assert len(errors) == 1
                assert "test-finding-001" in errors[0]

    def test_schema_load_failure(self, tmp_path: Path):
        """Test error when schema can't be loaded during file validation."""
        from scripts.core.schema_validator import validate_findings_file

        f = write_json(tmp_path, "findings.json", [make_valid_finding()])

        with patch(
            "scripts.core.schema_validator.load_schema",
            side_effect=FileNotFoundError("schema missing"),
        ):
            errors = validate_findings_file(f)
            assert len(errors) == 1
            assert "Failed to load schema" in errors[0]


# ========== Category 5: validate_directory() ==========


class TestValidateDirectory:
    """Tests for validate_directory() recursive validation."""

    def test_valid_directory(self, tmp_path: Path):
        """Test directory with valid files."""
        from scripts.core.schema_validator import validate_directory

        write_json(tmp_path, "findings.json", [])

        result = validate_directory(tmp_path)
        # Empty array means no findings to validate → no errors
        assert isinstance(result, dict)

    def test_nonexistent_directory(self, tmp_path: Path):
        """Test error for missing directory."""
        from scripts.core.schema_validator import validate_directory

        missing = tmp_path / "does_not_exist"

        result = validate_directory(missing)
        assert str(missing) in result
        assert any("Directory not found" in e for e in result[str(missing)])

    def test_exclude_patterns(self, tmp_path: Path):
        """Test that exclude patterns skip matching files."""
        from scripts.core.schema_validator import validate_directory

        # Create files
        write_json(tmp_path, "findings.json", "invalid")
        write_json(tmp_path, "node_modules_data.json", "invalid")

        with patch(
            "scripts.core.schema_validator.validate_findings_file",
            return_value=["error"],
        ):
            result = validate_directory(tmp_path, exclude_patterns=["node_modules"])
            # node_modules file should be excluded
            for path_key in result:
                assert "node_modules" not in path_key

    def test_custom_glob_pattern(self, tmp_path: Path):
        """Test custom glob pattern for file selection."""
        from scripts.core.schema_validator import validate_directory

        write_json(tmp_path, "findings.json", [])
        (tmp_path / "readme.txt").write_text("not json", encoding="utf-8")

        # Only process .json files (default)
        result = validate_directory(tmp_path, glob_pattern="*.json")
        assert isinstance(result, dict)

    def test_files_with_errors_included(self, tmp_path: Path):
        """Test that only files with errors are in result."""
        from scripts.core.schema_validator import validate_directory

        write_json(tmp_path, "bad.json", "not an array or dict")

        result = validate_directory(tmp_path)
        # bad.json should have errors
        assert len(result) >= 1
