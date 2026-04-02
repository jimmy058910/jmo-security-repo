#!/usr/bin/env python3
"""
Tests for CommonFinding JSON schema compliance.

These tests ensure that:
1. All fixture/sample JSON files comply with the CommonFinding schema
2. The schema validator correctly identifies valid and invalid findings
3. Adapter outputs produce schema-compliant findings
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.core.schema_validator import (
    JSONSCHEMA_AVAILABLE,
    SCHEMA_PATH,
    load_schema,
    validate_finding,
    validate_findings,
    validate_findings_file,
    validate_directory,
)

# Skip all tests if jsonschema is not installed
pytestmark = pytest.mark.skipif(
    not JSONSCHEMA_AVAILABLE,
    reason="jsonschema library not installed",
)


@pytest.fixture
def schema() -> dict[str, Any]:
    """Load the CommonFinding schema."""
    return load_schema()


@pytest.fixture
def valid_finding() -> dict[str, Any]:
    """Return a minimal valid CommonFinding."""
    return {
        "schemaVersion": "1.2.0",
        "id": "test-fingerprint-001",
        "ruleId": "TEST-001",
        "severity": "HIGH",
        "tool": {"name": "test-tool", "version": "1.0.0"},
        "location": {"path": "src/test.py"},
        "message": "Test finding message",
    }


class TestSchemaLoading:
    """Tests for schema loading functionality."""

    def test_schema_file_exists(self) -> None:
        """Verify schema file exists at expected location."""
        assert SCHEMA_PATH.exists(), f"Schema file not found at {SCHEMA_PATH}"

    def test_schema_loads_successfully(self, schema: dict[str, Any]) -> None:
        """Verify schema can be loaded and parsed."""
        assert schema is not None
        assert "properties" in schema
        assert "required" in schema

    def test_schema_has_required_fields(self, schema: dict[str, Any]) -> None:
        """Verify schema defines required fields."""
        required = schema.get("required", [])
        expected_required = [
            "schemaVersion",
            "id",
            "ruleId",
            "severity",
            "tool",
            "location",
            "message",
        ]
        for field in expected_required:
            assert field in required, f"Missing required field: {field}"


class TestValidateFinding:
    """Tests for single finding validation."""

    def test_valid_finding_passes(self, valid_finding: dict[str, Any]) -> None:
        """Valid finding should produce no errors."""
        errors = validate_finding(valid_finding)
        assert errors == [], f"Valid finding should pass: {errors}"

    def test_missing_required_field_fails(self, valid_finding: dict[str, Any]) -> None:
        """Missing required field should produce error."""
        del valid_finding["message"]
        errors = validate_finding(valid_finding)
        assert len(errors) > 0
        assert any("message" in err for err in errors)

    def test_invalid_severity_fails(self, valid_finding: dict[str, Any]) -> None:
        """Invalid severity value should produce error."""
        valid_finding["severity"] = "INVALID"
        errors = validate_finding(valid_finding)
        assert len(errors) > 0
        assert any("severity" in err.lower() or "INVALID" in err for err in errors)

    def test_valid_severity_values(self, valid_finding: dict[str, Any]) -> None:
        """All valid severity values should pass."""
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            valid_finding["severity"] = severity
            errors = validate_finding(valid_finding)
            assert errors == [], f"Severity {severity} should be valid: {errors}"

    def test_invalid_schema_version_fails(self, valid_finding: dict[str, Any]) -> None:
        """Invalid schemaVersion should produce error."""
        valid_finding["schemaVersion"] = "99.99.99"
        errors = validate_finding(valid_finding)
        assert len(errors) > 0

    def test_missing_tool_name_fails(self, valid_finding: dict[str, Any]) -> None:
        """Tool object without name should fail."""
        del valid_finding["tool"]["name"]
        errors = validate_finding(valid_finding)
        assert len(errors) > 0

    def test_missing_location_path_fails(self, valid_finding: dict[str, Any]) -> None:
        """Location without path should fail."""
        del valid_finding["location"]["path"]
        errors = validate_finding(valid_finding)
        assert len(errors) > 0

    def test_additional_fields_allowed(self, valid_finding: dict[str, Any]) -> None:
        """Additional fields should be allowed (additionalProperties: true)."""
        valid_finding["customField"] = "custom value"
        errors = validate_finding(valid_finding)
        assert errors == [], f"Additional fields should be allowed: {errors}"


class TestValidateFindings:
    """Tests for batch finding validation."""

    def test_empty_list_passes(self) -> None:
        """Empty findings list should not produce errors."""
        errors = validate_findings([])
        assert errors == {}

    def test_all_valid_findings_pass(self, valid_finding: dict[str, Any]) -> None:
        """All valid findings should pass."""
        findings = [
            valid_finding,
            {**valid_finding, "id": "test-002", "severity": "CRITICAL"},
            {**valid_finding, "id": "test-003", "severity": "LOW"},
        ]
        errors = validate_findings(findings)
        assert errors == {}

    def test_one_invalid_finding_reported(self, valid_finding: dict[str, Any]) -> None:
        """Invalid finding among valid ones should be reported."""
        invalid = {**valid_finding, "id": "invalid-finding"}
        del invalid["message"]

        findings = [valid_finding, invalid]
        errors = validate_findings(findings)
        assert "invalid-finding" in errors
        assert valid_finding["id"] not in errors


class TestValidateFindingsFile:
    """Tests for file-based validation."""

    def test_valid_array_file(
        self, tmp_path: Path, valid_finding: dict[str, Any]
    ) -> None:
        """JSON array of findings should validate."""
        file_path = tmp_path / "findings.json"
        file_path.write_text(json.dumps([valid_finding]), encoding="utf-8")

        errors = validate_findings_file(file_path)
        assert errors == []

    def test_valid_object_with_findings_key(
        self, tmp_path: Path, valid_finding: dict[str, Any]
    ) -> None:
        """Object with 'findings' key should validate."""
        file_path = tmp_path / "report.json"
        file_path.write_text(
            json.dumps({"findings": [valid_finding]}), encoding="utf-8"
        )

        errors = validate_findings_file(file_path)
        assert errors == []

    def test_single_finding_object(
        self, tmp_path: Path, valid_finding: dict[str, Any]
    ) -> None:
        """Single finding object should validate."""
        file_path = tmp_path / "single.json"
        file_path.write_text(json.dumps(valid_finding), encoding="utf-8")

        errors = validate_findings_file(file_path)
        assert errors == []

    def test_invalid_json_reports_error(self, tmp_path: Path) -> None:
        """Invalid JSON should report error."""
        file_path = tmp_path / "bad.json"
        file_path.write_text("{invalid json", encoding="utf-8")

        errors = validate_findings_file(file_path)
        assert len(errors) > 0
        assert any("Invalid JSON" in err for err in errors)

    def test_nonexistent_file_reports_error(self, tmp_path: Path) -> None:
        """Non-existent file should report error."""
        file_path = tmp_path / "nonexistent.json"

        errors = validate_findings_file(file_path)
        assert len(errors) > 0
        assert any("Failed to read" in err for err in errors)

    def test_empty_array_passes(self, tmp_path: Path) -> None:
        """Empty array should pass (no findings to validate)."""
        file_path = tmp_path / "empty.json"
        file_path.write_text("[]", encoding="utf-8")

        errors = validate_findings_file(file_path)
        assert errors == []


class TestValidateDirectory:
    """Tests for directory-based validation."""

    def test_valid_directory(
        self, tmp_path: Path, valid_finding: dict[str, Any]
    ) -> None:
        """Directory with valid files should pass."""
        (tmp_path / "findings1.json").write_text(
            json.dumps([valid_finding]), encoding="utf-8"
        )
        (tmp_path / "findings2.json").write_text(
            json.dumps([valid_finding]), encoding="utf-8"
        )

        errors = validate_directory(tmp_path)
        assert errors == {}

    def test_mixed_valid_invalid_files(
        self, tmp_path: Path, valid_finding: dict[str, Any]
    ) -> None:
        """Directory with mixed files should report only invalid ones."""
        (tmp_path / "valid.json").write_text(
            json.dumps([valid_finding]), encoding="utf-8"
        )

        invalid_finding = {**valid_finding}
        del invalid_finding["schemaVersion"]
        (tmp_path / "invalid.json").write_text(
            json.dumps([invalid_finding]), encoding="utf-8"
        )

        errors = validate_directory(tmp_path)
        assert len(errors) == 1
        assert "invalid.json" in list(errors.keys())[0]

    def test_exclude_patterns(
        self, tmp_path: Path, valid_finding: dict[str, Any]
    ) -> None:
        """Excluded patterns should be skipped."""
        (tmp_path / "valid.json").write_text(
            json.dumps([valid_finding]), encoding="utf-8"
        )
        (tmp_path / "package.json").write_text('{"name": "test"}', encoding="utf-8")

        errors = validate_directory(tmp_path, exclude_patterns=["package.json"])
        # package.json would fail validation but should be excluded
        assert "package.json" not in str(errors)

    def test_nonexistent_directory(self) -> None:
        """Non-existent directory should report error."""
        errors = validate_directory(Path("/nonexistent/path"))
        assert len(errors) > 0


class TestFixtureCompliance:
    """Tests for actual fixture file compliance."""

    @pytest.fixture
    def project_root(self) -> Path:
        """Get project root directory."""
        return Path(__file__).parent.parent.parent

    def test_sample_findings_file(self, project_root: Path) -> None:
        """tests/fixtures/findings/sample-findings.json should be schema-compliant."""
        fixture_path = (
            project_root / "tests" / "fixtures" / "findings" / "sample-findings.json"
        )
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        errors = validate_findings_file(fixture_path)
        assert (
            errors == []
        ), "sample-findings.json has schema violations:\n" + "\n".join(errors)

    def test_mcp_fixtures_findings(self, project_root: Path) -> None:
        """tests/jmo_mcp/fixtures/findings.json should be schema-compliant."""
        fixture_path = project_root / "tests" / "jmo_mcp" / "fixtures" / "findings.json"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        errors = validate_findings_file(fixture_path)
        assert errors == [], "MCP findings.json has schema violations:\n" + "\n".join(
            errors
        )

    def test_cross_tool_findings_file(self, project_root: Path) -> None:
        """tests/fixtures/cross_tool_findings.json findings should be schema-compliant.

        Note: This file has a special structure with nested findings.
        """
        fixture_path = project_root / "tests" / "fixtures" / "cross_tool_findings.json"
        if not fixture_path.exists():
            pytest.skip(f"Fixture not found: {fixture_path}")

        # Load and extract all findings from the special structure
        content = json.loads(fixture_path.read_text(encoding="utf-8"))
        all_findings: list[dict[str, Any]] = []

        # Extract findings from known_duplicates clusters
        for cluster in content.get("known_duplicates", []):
            all_findings.extend(cluster.get("findings", []))

        # Extract findings from known_non_duplicates
        for group in content.get("known_non_duplicates", []):
            all_findings.extend(group.get("findings", []))

        # Validate all extracted findings
        errors = validate_findings(all_findings)
        if errors:
            error_messages = []
            for finding_id, errs in errors.items():
                error_messages.append(f"  {finding_id}: {errs}")
            pytest.fail(
                f"cross_tool_findings.json has {len(errors)} findings with schema violations:\n"
                + "\n".join(error_messages)
            )


class TestAdapterOutputCompliance:
    """Tests ensuring adapter-generated findings are schema-compliant.

    These tests create mock adapter outputs and validate they conform to schema.
    """

    def test_minimal_adapter_output(self) -> None:
        """Adapter should produce minimum required fields."""
        # Simulates what an adapter should produce
        adapter_output = {
            "schemaVersion": "1.2.0",
            "id": "abc123def456",
            "ruleId": "test-rule-001",
            "severity": "MEDIUM",
            "tool": {"name": "test-adapter", "version": "1.0.0"},
            "location": {"path": "src/example.py", "startLine": 10},
            "message": "Test finding from adapter",
        }

        errors = validate_finding(adapter_output)
        assert errors == [], f"Minimal adapter output should be valid: {errors}"

    def test_full_adapter_output(self) -> None:
        """Adapter with all optional fields should be valid."""
        adapter_output = {
            "schemaVersion": "1.2.0",
            "id": "full-finding-001",
            "ruleId": "FULL-001",
            "title": "Full Finding Example",
            "message": "Complete finding with all fields",
            "description": "Detailed description of the finding",
            "severity": "HIGH",
            "cvss": 7.5,
            "tool": {"name": "full-adapter", "version": "2.0.0"},
            "location": {
                "path": "src/vulnerable.py",
                "startLine": 42,
                "endLine": 45,
            },
            "remediation": {
                "summary": "Fix the vulnerability",
                "fix": "Use safe_function() instead",
                "steps": ["Step 1", "Step 2"],
                "references": ["https://example.com/fix"],
            },
            "references": ["https://cve.org/CVE-2024-0001"],
            "tags": ["security", "injection"],
            "context": {
                "snippet": "vulnerable_code(user_input)",
                "startLine": 40,
                "endLine": 44,
                "language": "python",
            },
            "risk": {
                "cwe": ["CWE-89"],
                "owasp": ["A03:2021"],
                "confidence": "HIGH",
                "likelihood": "MEDIUM",
                "impact": "HIGH",
            },
            "compliance": {
                "owaspTop10_2021": ["A03:2021"],
                "cweTop25_2024": [{"id": "CWE-89", "rank": 3, "category": "Injection"}],
            },
            "raw": {"original_tool_data": "preserved"},
        }

        errors = validate_finding(adapter_output)
        assert errors == [], f"Full adapter output should be valid: {errors}"
