"""
Tests for {tool} adapter (v3.0.0 plugin architecture).

Test Fixtures (from memory):
{list_of_reused_fixtures}
"""

import json
import pytest
from pathlib import Path

# REQUIRED: Import adapter class (not function)
from scripts.core.adapters.{tool}_adapter import {Tool}Adapter
from scripts.core.plugin_api import Finding


@pytest.fixture
def {tool}_output_high_severity(tmp_path):
    """
    High severity vulnerabilities (fixture reused from memory).

    Scenario: 2 HIGH vulnerabilities in lodash dependency
    Source: .jmo/memory/adapters/{tool}.json::test_fixtures[0]
    """
    data = {
        "results": [
            {
                "vulnerabilities": [
                    {
                        "id": "SNYK-JS-LODASH-590103",
                        "severity": "high",
                        "title": "Prototype Pollution",
                        "file": "package.json",
                        "line": 10,
                        "cvssScore": 7.5,
                        "cwe": ["CWE-1321"]
                    },
                    {
                        "id": "SNYK-JS-LODASH-590104",
                        "severity": "high",
                        "title": "Command Injection",
                        "file": "package.json",
                        "line": 10,
                        "cvssScore": 7.3,
                        "cwe": ["CWE-78"]
                    }
                ]
            }
        ]
    }
    output_file = tmp_path / "{tool}.json"
    output_file.write_text(json.dumps(data))
    return output_file


@pytest.fixture
def {tool}_output_clean(tmp_path):
    """Clean scan (no vulnerabilities)."""
    data = {"results": [{"vulnerabilities": []}]}
    output_file = tmp_path / "{tool}.json"
    output_file.write_text(json.dumps(data))
    return output_file


@pytest.fixture
def {tool}_output_malformed(tmp_path):
    """
    Malformed JSON (missing --json flag).

    Common Pitfall: Learned from memory
    """
    output_file = tmp_path / "{tool}.json"
    output_file.write_text("ERROR: Missing --json flag\n")
    return output_file


def test_{tool}_adapter_high_severity({tool}_output_high_severity):
    """Test {Tool}Adapter with high severity findings."""
    # Instantiate adapter (v3.0.0 pattern)
    adapter = {Tool}Adapter()

    # Call parse() method (not load_{tool}() function!)
    findings = adapter.parse({tool}_output_high_severity)

    # Verify findings are Finding objects (not dicts)
    assert len(findings) == 2
    assert all(isinstance(f, Finding) for f in findings)

    # Verify first finding
    assert findings[0].severity == "HIGH"
    assert findings[0].ruleId == "SNYK-JS-LODASH-590103"
    assert "Prototype Pollution" in findings[0].message

    # Verify fingerprint ID exists
    assert findings[0].id is not None
    assert len(findings[0].id) == 64  # SHA256 hex digest

    # Verify tool metadata
    assert findings[0].tool["name"] == "{tool}"

    # Note: Compliance enrichment is tested separately in normalize_and_report
    # tests since it's now applied centrally (Scenario 8 optimization)


def test_{tool}_adapter_clean({tool}_output_clean):
    """Test clean scan with no vulnerabilities."""
    adapter = {Tool}Adapter()
    findings = adapter.parse({tool}_output_clean)
    assert len(findings) == 0


def test_{tool}_adapter_malformed({tool}_output_malformed):
    """Test graceful handling of malformed output (common pitfall)."""
    adapter = {Tool}Adapter()
    findings = adapter.parse({tool}_output_malformed)
    assert len(findings) == 0  # Should return empty list, not crash


def test_{tool}_adapter_missing_file(tmp_path):
    """Test handling of missing output file."""
    missing_file = tmp_path / "nonexistent.json"
    adapter = {Tool}Adapter()
    findings = adapter.parse(missing_file)
    assert len(findings) == 0


def test_{tool}_severity_mapping():
    """Test severity mapping from {tool} to CommonFinding."""
    adapter = {Tool}Adapter()

    assert adapter._map_severity("critical") == "CRITICAL"
    assert adapter._map_severity("high") == "HIGH"
    assert adapter._map_severity("medium") == "MEDIUM"
    assert adapter._map_severity("low") == "LOW"
    assert adapter._map_severity("info") == "INFO"
    assert adapter._map_severity("unknown") == "INFO"  # Default


def test_{tool}_plugin_metadata():
    """Test plugin metadata is correctly set (v3.0.0)."""
    adapter = {Tool}Adapter()
    metadata = adapter.metadata

    assert metadata.name == "{tool}"
    assert metadata.tool_name == "{tool}"
    assert metadata.schema_version == "1.2.0"
    assert "0" in metadata.exit_codes
    assert "1" in metadata.exit_codes


def test_{tool}_finding_objects_not_dicts({tool}_output_high_severity):
    """Verify parse() returns Finding objects, not dicts (v3.0.0 requirement)."""
    adapter = {Tool}Adapter()
    findings = adapter.parse({tool}_output_high_severity)

    # CRITICAL: Findings must be Finding objects, not dicts
    for finding in findings:
        assert isinstance(finding, Finding)
        assert hasattr(finding, "schemaVersion")
        assert hasattr(finding, "id")
        assert hasattr(finding, "ruleId")
        assert hasattr(finding, "severity")
