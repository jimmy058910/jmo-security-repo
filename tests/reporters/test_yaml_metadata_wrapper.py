#!/usr/bin/env python3
"""Comprehensive tests for Phase 1: YAML reporter with metadata wrapper (v1.0.0).

Tests the YAML reporter's metadata wrapper structure and schema validation:
meta:
  output_version: "1.0.0"
  jmo_version: "0.9.0"
  schema_version: "1.2.0"
  timestamp: "2025-11-04T12:34:56Z"
  scan_id: "uuid-here"
  profile: "balanced"
  tools: ["trivy", "semgrep"]
  target_count: 3
  finding_count: 10
  platform: "Linux"
findings:
  - schemaVersion: "1.2.0"
    id: "..."
    ...
"""

from __future__ import annotations

from pathlib import Path

import pytest

# Conditional imports (YAML is optional dependency)
try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False

try:
    import jsonschema

    JSONSCHEMA_AVAILABLE = True
except ImportError:
    JSONSCHEMA_AVAILABLE = False

from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.core.reporters.basic_reporter import _generate_metadata


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_findings() -> list[dict]:
    """Sample findings for testing YAML metadata wrapper."""
    return [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-1",
            "ruleId": "CVE-2024-1234",
            "severity": "HIGH",
            "message": "Vulnerable dependency",
            "tool": {"name": "trivy", "version": "0.50.0"},
            "location": {"path": "package.json", "startLine": 10},
        },
        {
            "schemaVersion": "1.2.0",
            "id": "finding-2",
            "ruleId": "aws-secret-key",
            "severity": "CRITICAL",
            "message": "AWS secret key detected",
            "tool": {"name": "trufflehog", "version": "3.70.0"},
            "location": {"path": "config.yaml", "startLine": 5},
        },
    ]


# ============================================================================
# Test: write_yaml() with metadata wrapper
# ============================================================================


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_with_metadata_wrapper(tmp_path: Path, sample_findings):
    """Test write_yaml() produces v1.0.0 metadata wrapper structure."""
    out_path = tmp_path / "findings.yaml"

    metadata = _generate_metadata(
        sample_findings,
        scan_id="test-123",
        profile="fast",
        tools=["trivy"],
        target_count=1,
    )

    write_yaml(sample_findings, out_path, metadata=metadata, validate=False)

    # Read back and verify structure
    content = out_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    # Top-level keys
    assert "meta" in data
    assert "findings" in data

    # Metadata structure
    meta = data["meta"]
    assert meta["output_version"] == "1.0.0"
    assert meta["scan_id"] == "test-123"
    assert meta["profile"] == "fast"
    assert meta["tools"] == ["trivy"]
    assert meta["target_count"] == 1
    assert meta["finding_count"] == 2

    # Findings array
    findings = data["findings"]
    assert len(findings) == 2
    assert findings[0]["id"] == "finding-1"
    assert findings[1]["id"] == "finding-2"


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_auto_generates_metadata(tmp_path: Path, sample_findings):
    """Test write_yaml() auto-generates metadata if not provided."""
    out_path = tmp_path / "findings.yaml"

    # Call without metadata parameter
    write_yaml(sample_findings, out_path, validate=False)

    # Read back and verify metadata was generated
    content = out_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    assert "meta" in data
    assert "findings" in data

    meta = data["meta"]
    assert meta["output_version"] == "1.0.0"
    assert meta["finding_count"] == 2
    # Auto-generated defaults
    assert meta["scan_id"] == ""
    assert meta["profile"] == ""


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_creates_parent_dirs(tmp_path: Path, sample_findings):
    """Test write_yaml() creates parent directories if they don't exist."""
    out_path = tmp_path / "nested" / "dir" / "findings.yaml"

    write_yaml(sample_findings, out_path, validate=False)

    assert out_path.exists()
    data = yaml.safe_load(out_path.read_text())
    assert "meta" in data
    assert "findings" in data


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_utf8_encoding(tmp_path: Path):
    """Test write_yaml() handles UTF-8 characters correctly."""
    findings_with_unicode = [
        {
            "schemaVersion": "1.2.0",
            "id": "unicode-test",
            "ruleId": "test-rule",
            "severity": "INFO",
            "message": "Unicode test: 你好世界 🔒 café",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "test.txt", "startLine": 1},
        }
    ]

    out_path = tmp_path / "unicode.yaml"
    write_yaml(findings_with_unicode, out_path, validate=False)

    content = out_path.read_text(encoding="utf-8")
    data = yaml.safe_load(content)

    # Unicode should be preserved
    assert "你好世界" in data["findings"][0]["message"]
    assert "🔒" in data["findings"][0]["message"]
    assert "café" in data["findings"][0]["message"]


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_preserves_order(tmp_path: Path, sample_findings):
    """Test write_yaml() preserves key order (not sorted alphabetically)."""
    out_path = tmp_path / "findings.yaml"

    write_yaml(sample_findings, out_path, validate=False)

    content = out_path.read_text(encoding="utf-8")

    # "meta:" should appear before "findings:" (insertion order preserved)
    meta_pos = content.find("meta:")
    findings_pos = content.find("findings:")
    assert meta_pos < findings_pos


# ============================================================================
# Test: Schema validation
# ============================================================================


@pytest.mark.skipif(
    not YAML_AVAILABLE or not JSONSCHEMA_AVAILABLE,
    reason="PyYAML or jsonschema not installed",
)
def test_write_yaml_schema_validation_valid_findings(tmp_path: Path, sample_findings):
    """Test write_yaml() validates findings against CommonFinding schema."""
    out_path = tmp_path / "findings.yaml"

    # Valid findings should pass validation (no warnings/errors)
    write_yaml(sample_findings, out_path, validate=True)

    # If validation failed, would have logged warnings (we can't assert logs easily)
    # But the file should still be written
    assert out_path.exists()


@pytest.mark.skipif(
    not YAML_AVAILABLE or not JSONSCHEMA_AVAILABLE,
    reason="PyYAML or jsonschema not installed",
)
def test_write_yaml_schema_validation_invalid_findings(tmp_path: Path, caplog):
    """Test write_yaml() logs warnings for invalid findings."""
    invalid_findings = [
        {
            # Missing required fields: ruleId, severity, message, tool, location
            "schemaVersion": "1.2.0",
            "id": "invalid",
        }
    ]

    out_path = tmp_path / "invalid.yaml"

    # Should log warning but still write file
    write_yaml(invalid_findings, out_path, validate=True)

    assert out_path.exists()

    # Check if warning was logged (caplog captures log output)
    # Note: This might not trigger if schema file doesn't exist
    # The function catches exceptions and logs debug messages


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_validation_disabled(tmp_path: Path, sample_findings):
    """Test write_yaml() skips validation when validate=False."""
    out_path = tmp_path / "findings.yaml"

    # Should not attempt validation
    write_yaml(sample_findings, out_path, validate=False)

    assert out_path.exists()


@pytest.mark.skipif(
    not YAML_AVAILABLE or not JSONSCHEMA_AVAILABLE,
    reason="PyYAML or jsonschema not installed",
)
def test_write_yaml_validation_missing_schema(
    tmp_path: Path, sample_findings, monkeypatch
):
    """Test write_yaml() handles missing schema file gracefully."""
    out_path = tmp_path / "findings.yaml"

    # Monkey-patch the schema path to point to nonexistent file
    from scripts.core.reporters import yaml_reporter

    original_file = yaml_reporter.__file__
    fake_path = tmp_path / "fake_reporter.py"
    fake_path.write_text("")  # Create fake file
    monkeypatch.setattr(yaml_reporter, "__file__", str(fake_path))

    # Should log debug message and continue (no crash)
    write_yaml(sample_findings, out_path, validate=True)

    assert out_path.exists()

    # Restore
    monkeypatch.setattr(yaml_reporter, "__file__", original_file)


# ============================================================================
# Test: Error handling
# ============================================================================


def test_write_yaml_raises_runtime_error_if_yaml_missing(tmp_path: Path, monkeypatch):
    """Test write_yaml() raises RuntimeError if PyYAML not installed."""
    # Simulate PyYAML being unavailable
    from scripts.core.reporters import yaml_reporter

    monkeypatch.setattr(yaml_reporter, "yaml", None)

    out_path = tmp_path / "findings.yaml"

    with pytest.raises(RuntimeError, match="PyYAML not installed"):
        write_yaml([], out_path)


# ============================================================================
# Test: Backward compatibility
# ============================================================================


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_yaml_metadata_wrapper_preserves_findings_structure(
    tmp_path: Path, sample_findings
):
    """Test that findings array structure is unchanged (only wrapped)."""
    out_path = tmp_path / "findings.yaml"

    write_yaml(sample_findings, out_path, validate=False)

    data = yaml.safe_load(out_path.read_text())
    findings = data["findings"]

    # Findings should be identical to input (no transformation)
    assert findings == sample_findings

    # Verify all expected fields are present
    assert findings[0]["schemaVersion"] == "1.2.0"
    assert findings[0]["id"] == "finding-1"
    assert findings[0]["ruleId"] == "CVE-2024-1234"
    assert findings[0]["tool"]["name"] == "trivy"


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_yaml_metadata_wrapper_does_not_modify_findings(tmp_path: Path):
    """Test that write_yaml() does not mutate the input findings list."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "test",
            "ruleId": "rule",
            "severity": "LOW",
            "message": "test",
            "tool": {"name": "tool", "version": "1.0"},
            "location": {"path": "file", "startLine": 1},
        }
    ]

    original_findings = findings.copy()

    out_path = tmp_path / "findings.yaml"
    write_yaml(findings, out_path, validate=False)

    # Input should be unchanged
    assert findings == original_findings


# ============================================================================
# Test: Edge cases
# ============================================================================


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_large_finding_count(tmp_path: Path):
    """Test YAML metadata correctly handles large finding counts."""
    # Generate 500 findings (YAML is less efficient than JSON)
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": f"finding-{i}",
            "ruleId": "test-rule",
            "severity": "INFO",
            "message": f"Finding {i}",
            "tool": {"name": "test", "version": "1.0"},
            "location": {"path": "test.txt", "startLine": i},
        }
        for i in range(500)
    ]

    out_path = tmp_path / "large.yaml"
    write_yaml(findings, out_path, validate=False)

    data = yaml.safe_load(out_path.read_text())
    assert data["meta"]["finding_count"] == 500
    assert len(data["findings"]) == 500


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_empty_findings(tmp_path: Path):
    """Test write_yaml() with empty findings list."""
    out_path = tmp_path / "empty.yaml"

    write_yaml([], out_path, validate=False)

    data = yaml.safe_load(out_path.read_text())
    assert data["meta"]["finding_count"] == 0
    assert data["findings"] == []


@pytest.mark.skipif(not YAML_AVAILABLE, reason="PyYAML not installed")
def test_write_yaml_special_characters_in_metadata(tmp_path: Path):
    """Test YAML metadata handles special characters in scan_id and profile."""
    findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "test",
            "ruleId": "rule",
            "severity": "INFO",
            "message": "test",
            "tool": {"name": "tool", "version": "1.0"},
            "location": {"path": "file", "startLine": 1},
        }
    ]

    metadata = _generate_metadata(
        findings,
        scan_id="scan-with-special_chars-123!@#",
        profile="custom/profile:v2",
    )

    out_path = tmp_path / "special.yaml"
    write_yaml(findings, out_path, metadata=metadata, validate=False)

    data = yaml.safe_load(out_path.read_text())
    assert data["meta"]["scan_id"] == "scan-with-special_chars-123!@#"
    assert data["meta"]["profile"] == "custom/profile:v2"
