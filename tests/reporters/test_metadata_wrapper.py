#!/usr/bin/env python3
"""Comprehensive tests for Phase 1: Metadata wrapper and versioning (v1.0.0).

Tests the new metadata wrapper structure for JSON/YAML outputs:
{
  "meta": {
    "output_version": "1.0.0",
    "jmo_version": "0.9.0",
    "schema_version": "1.2.0",
    "timestamp": "2025-11-04T12:34:56Z",
    "scan_id": "uuid-here",
    "profile": "balanced",
    "tools": ["trivy", "semgrep"],
    "target_count": 3,
    "finding_count": 10,
    "platform": "Linux"
  },
  "findings": [...]
}
"""

from __future__ import annotations

import json
from pathlib import Path
from datetime import datetime

import pytest

from scripts.core.reporters.basic_reporter import (
    write_json,
    _get_jmo_version,
    _generate_metadata,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def sample_findings() -> list[dict]:
    """Sample findings for testing metadata wrapper."""
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
# Test: _get_jmo_version()
# ============================================================================


def test_get_jmo_version_success():
    """Test that _get_jmo_version() reads version from pyproject.toml."""
    version = _get_jmo_version()

    # Should return a valid semantic version string
    assert isinstance(version, str)
    assert len(version) > 0

    # Should match semantic versioning pattern (x.y.z)
    parts = version.split(".")
    assert len(parts) >= 2  # At least major.minor
    assert parts[0].isdigit()  # Major version is digit
    assert parts[1].isdigit()  # Minor version is digit


def test_get_jmo_version_fallback(tmp_path: Path, monkeypatch):
    """Test that _get_jmo_version() falls back to 1.0.0 if pyproject.toml missing."""
    # Create a fake pyproject.toml path that doesn't exist
    fake_path = tmp_path / "nonexistent" / "pyproject.toml"

    # Monkey-patch Path to return our fake path
    from scripts.core.reporters import basic_reporter

    original_file = basic_reporter.__file__
    monkeypatch.setattr(basic_reporter, "__file__", str(fake_path))

    # Should fall back to default version
    version = _get_jmo_version()
    assert version == "1.0.0"

    # Restore
    monkeypatch.setattr(basic_reporter, "__file__", original_file)


# ============================================================================
# Test: _generate_metadata()
# ============================================================================


def test_generate_metadata_minimal(sample_findings):
    """Test _generate_metadata() with minimal parameters (just findings)."""
    metadata = _generate_metadata(sample_findings)

    # Required fields
    assert metadata["output_version"] == "1.0.0"
    assert metadata["schema_version"] == "1.2.0"
    assert "jmo_version" in metadata
    assert "timestamp" in metadata
    assert "platform" in metadata

    # Auto-computed fields
    assert metadata["finding_count"] == 2

    # Optional fields (defaults)
    assert metadata["scan_id"] == ""
    assert metadata["profile"] == ""
    assert metadata["tools"] == []
    assert metadata["target_count"] == 0


def test_generate_metadata_full_parameters(sample_findings):
    """Test _generate_metadata() with all parameters provided."""
    metadata = _generate_metadata(
        sample_findings,
        scan_id="test-scan-123",
        profile="balanced",
        tools=["trivy", "trufflehog", "semgrep"],
        target_count=5,
    )

    # Verify all provided parameters are used
    assert metadata["scan_id"] == "test-scan-123"
    assert metadata["profile"] == "balanced"
    assert metadata["tools"] == ["trivy", "trufflehog", "semgrep"]
    assert metadata["target_count"] == 5
    assert metadata["finding_count"] == 2


def test_generate_metadata_timestamp_format(sample_findings):
    """Test that timestamp is in ISO 8601 UTC format."""
    metadata = _generate_metadata(sample_findings)

    timestamp = metadata["timestamp"]

    # Should end with 'Z' (UTC indicator)
    assert timestamp.endswith("Z")

    # Should be parseable as ISO 8601
    parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    assert parsed.tzinfo is not None  # Has timezone info


def test_generate_metadata_empty_findings():
    """Test _generate_metadata() with empty findings list."""
    metadata = _generate_metadata([])

    assert metadata["finding_count"] == 0
    assert "output_version" in metadata
    assert "timestamp" in metadata


def test_generate_metadata_platform():
    """Test that platform is captured correctly."""
    metadata = _generate_metadata([])

    platform = metadata["platform"]

    # Should be one of the common platform names
    assert platform in ["Linux", "Windows", "Darwin", "Java"]


# ============================================================================
# Test: write_json() with metadata wrapper
# ============================================================================


def test_write_json_with_metadata_wrapper(tmp_path: Path, sample_findings):
    """Test write_json() produces v1.0.0 metadata wrapper structure."""
    out_path = tmp_path / "findings.json"

    metadata = _generate_metadata(
        sample_findings,
        scan_id="test-123",
        profile="fast",
        tools=["trivy"],
        target_count=1,
    )

    write_json(sample_findings, out_path, metadata=metadata)

    # Read back and verify structure
    content = out_path.read_text(encoding="utf-8")
    data = json.loads(content)

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


def test_write_json_auto_generates_metadata(tmp_path: Path, sample_findings):
    """Test write_json() auto-generates metadata if not provided."""
    out_path = tmp_path / "findings.json"

    # Call without metadata parameter
    write_json(sample_findings, out_path)

    # Read back and verify metadata was generated
    content = out_path.read_text(encoding="utf-8")
    data = json.loads(content)

    assert "meta" in data
    assert "findings" in data

    meta = data["meta"]
    assert meta["output_version"] == "1.0.0"
    assert meta["finding_count"] == 2
    # Auto-generated defaults
    assert meta["scan_id"] == ""
    assert meta["profile"] == ""


def test_write_json_creates_parent_dirs(tmp_path: Path, sample_findings):
    """Test write_json() creates parent directories if they don't exist."""
    out_path = tmp_path / "nested" / "dir" / "findings.json"

    write_json(sample_findings, out_path)

    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert "meta" in data
    assert "findings" in data


def test_write_json_utf8_encoding(tmp_path: Path):
    """Test write_json() handles UTF-8 characters correctly."""
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

    out_path = tmp_path / "unicode.json"
    write_json(findings_with_unicode, out_path)

    content = out_path.read_text(encoding="utf-8")
    data = json.loads(content)

    # Unicode should be preserved
    assert "你好世界" in data["findings"][0]["message"]
    assert "🔒" in data["findings"][0]["message"]
    assert "café" in data["findings"][0]["message"]


def test_write_json_trailing_newline(tmp_path: Path, sample_findings):
    """Test write_json() adds trailing newline (POSIX compliance)."""
    out_path = tmp_path / "findings.json"

    write_json(sample_findings, out_path)

    content = out_path.read_text(encoding="utf-8")
    assert content.endswith("\n")


def test_write_json_pretty_printed(tmp_path: Path, sample_findings):
    """Test write_json() produces pretty-printed (indented) JSON."""
    out_path = tmp_path / "findings.json"

    write_json(sample_findings, out_path)

    content = out_path.read_text(encoding="utf-8")

    # Should have indentation (2 spaces)
    assert '  "meta":' in content or '  "meta": {' in content
    # Should have newlines (not minified)
    assert content.count("\n") > 5


# ============================================================================
# Test: Backward compatibility checks
# ============================================================================


def test_metadata_wrapper_preserves_findings_structure(tmp_path: Path, sample_findings):
    """Test that findings array structure is unchanged (only wrapped)."""
    out_path = tmp_path / "findings.json"

    write_json(sample_findings, out_path)

    data = json.loads(out_path.read_text())
    findings = data["findings"]

    # Findings should be identical to input (no transformation)
    assert findings == sample_findings

    # Verify all expected fields are present
    assert findings[0]["schemaVersion"] == "1.2.0"
    assert findings[0]["id"] == "finding-1"
    assert findings[0]["ruleId"] == "CVE-2024-1234"
    assert findings[0]["tool"]["name"] == "trivy"


def test_metadata_wrapper_does_not_modify_findings(tmp_path: Path):
    """Test that write_json() does not mutate the input findings list."""
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

    out_path = tmp_path / "findings.json"
    write_json(findings, out_path)

    # Input should be unchanged
    assert findings == original_findings


# ============================================================================
# Test: Edge cases
# ============================================================================


def test_write_json_large_finding_count(tmp_path: Path):
    """Test metadata correctly handles large finding counts."""
    # Generate 1000 findings
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
        for i in range(1000)
    ]

    out_path = tmp_path / "large.json"
    write_json(findings, out_path)

    data = json.loads(out_path.read_text())
    assert data["meta"]["finding_count"] == 1000
    assert len(data["findings"]) == 1000


def test_write_json_special_characters_in_metadata(tmp_path: Path):
    """Test metadata handles special characters in scan_id and profile."""
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

    out_path = tmp_path / "special.json"
    write_json(findings, out_path, metadata=metadata)

    data = json.loads(out_path.read_text())
    assert data["meta"]["scan_id"] == "scan-with-special_chars-123!@#"
    assert data["meta"]["profile"] == "custom/profile:v2"


def test_write_json_empty_tools_list(tmp_path: Path):
    """Test metadata handles empty tools list correctly."""
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

    metadata = _generate_metadata(findings, tools=[])

    out_path = tmp_path / "empty_tools.json"
    write_json(findings, out_path, metadata=metadata)

    data = json.loads(out_path.read_text())
    assert data["meta"]["tools"] == []
