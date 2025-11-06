"""Tests for SARIF diff reporter."""

import json
from pathlib import Path

import pytest

from scripts.core.diff_engine import DiffResult, DiffSource, ModifiedFinding
from scripts.core.reporters.diff_sarif_reporter import (
    write_sarif_diff,
    _map_severity_to_sarif,
    _convert_location_to_sarif,
)


@pytest.fixture
def sample_diff_result():
    """Create sample DiffResult for testing."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline-results/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=150,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current-results/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=142,
    )

    new_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "abc123",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
        }
    ]

    resolved_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "old123",
            "severity": "MEDIUM",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/views.py", "startLine": 120},
            "message": "XSS vulnerability",
        }
    ]

    modified_findings = [
        ModifiedFinding(
            fingerprint="mod456",
            changes={"severity": ["MEDIUM", "HIGH"]},
            baseline={
                "severity": "MEDIUM",
                "ruleId": "G101",
                "message": "Hardcoded password",
                "location": {"path": "src/config.py", "startLine": 15},
            },
            current={
                "severity": "HIGH",
                "ruleId": "G101",
                "message": "Hardcoded password",
                "location": {"path": "src/config.py", "startLine": 15},
            },
            risk_delta="worsened",
        )
    ]

    statistics = {
        "total_new": 1,
        "total_resolved": 1,
        "total_unchanged": 139,
        "total_modified": 1,
        "net_change": 0,
        "trend": "stable",
        "new_by_severity": {"HIGH": 1},
        "resolved_by_severity": {"MEDIUM": 1},
        "modifications_by_type": {"severity": 1},
    }

    return DiffResult(
        new=new_findings,
        resolved=resolved_findings,
        unchanged=[],
        modified=modified_findings,
        baseline_source=baseline_source,
        current_source=current_source,
        statistics=statistics,
    )


def test_sarif_schema_compliance(tmp_path, sample_diff_result):
    """Test SARIF output complies with schema."""
    out_path = tmp_path / "diff.sarif"
    write_sarif_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        sarif = json.load(f)

    # Check top-level structure
    assert "$schema" in sarif
    assert sarif["version"] == "2.1.0"
    assert "runs" in sarif
    assert len(sarif["runs"]) == 1


def test_sarif_tool_metadata(tmp_path, sample_diff_result):
    """Test tool metadata in SARIF output."""
    out_path = tmp_path / "diff.sarif"
    write_sarif_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        sarif = json.load(f)

    tool = sarif["runs"][0]["tool"]["driver"]
    assert tool["name"] == "JMo Security Diff"
    assert tool["version"] == "1.0.0"
    assert tool["informationUri"] == "https://jmotools.com"


def test_sarif_diff_metadata(tmp_path, sample_diff_result):
    """Test diff metadata in properties."""
    out_path = tmp_path / "diff.sarif"
    write_sarif_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        sarif = json.load(f)

    props = sarif["runs"][0]["properties"]
    assert "baseline" in props
    assert "current" in props
    assert "statistics" in props

    assert props["baseline"]["path"] == "baseline-results/"
    assert props["current"]["path"] == "current-results/"
    assert props["statistics"]["total_new"] == 1


def test_sarif_new_findings(tmp_path, sample_diff_result):
    """Test new findings representation."""
    out_path = tmp_path / "diff.sarif"
    write_sarif_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        sarif = json.load(f)

    results = sarif["runs"][0]["results"]
    new_results = [r for r in results if r.get("baselineState") == "new"]

    assert len(new_results) == 1
    result = new_results[0]

    assert result["ruleId"] == "G101"
    assert result["level"] == "error"  # HIGH -> error
    assert "NEW in current scan" in result["message"]["text"]
    assert result["properties"]["diff_category"] == "new"


def test_sarif_resolved_findings(tmp_path, sample_diff_result):
    """Test resolved findings representation."""
    out_path = tmp_path / "diff.sarif"
    write_sarif_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        sarif = json.load(f)

    results = sarif["runs"][0]["results"]
    resolved_results = [r for r in results if r.get("baselineState") == "absent"]

    assert len(resolved_results) == 1
    result = resolved_results[0]

    assert result["ruleId"] == "CWE-79"
    assert result["level"] == "warning"  # MEDIUM -> warning
    assert "RESOLVED since baseline" in result["message"]["text"]
    assert "suppressions" in result
    assert result["suppressions"][0]["status"] == "accepted"
    assert result["properties"]["diff_category"] == "resolved"


def test_sarif_modified_findings(tmp_path, sample_diff_result):
    """Test modified findings representation."""
    out_path = tmp_path / "diff.sarif"
    write_sarif_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        sarif = json.load(f)

    results = sarif["runs"][0]["results"]
    modified_results = [r for r in results if r.get("baselineState") == "updated"]

    assert len(modified_results) == 1
    result = modified_results[0]

    assert result["ruleId"] == "G101"
    assert result["level"] == "error"  # HIGH (current) -> error
    assert "MODIFIED" in result["message"]["text"]
    assert result["properties"]["diff_category"] == "modified"
    assert "changes" in result["properties"]
    assert result["properties"]["changes"]["severity"] == ["MEDIUM", "HIGH"]


def test_sarif_severity_mapping():
    """Test severity to SARIF level mapping."""
    assert _map_severity_to_sarif("CRITICAL") == "error"
    assert _map_severity_to_sarif("HIGH") == "error"
    assert _map_severity_to_sarif("MEDIUM") == "warning"
    assert _map_severity_to_sarif("LOW") == "note"
    assert _map_severity_to_sarif("INFO") == "note"
    assert _map_severity_to_sarif(None) == "note"


def test_sarif_location_conversion():
    """Test location conversion to SARIF format."""
    location = {
        "path": "src/test.py",
        "startLine": 42,
        "endLine": 45,
        "startColumn": 10,
        "endColumn": 20,
    }

    sarif_loc = _convert_location_to_sarif(location)

    assert sarif_loc["physicalLocation"]["artifactLocation"]["uri"] == "src/test.py"
    assert sarif_loc["physicalLocation"]["region"]["startLine"] == 42
    assert sarif_loc["physicalLocation"]["region"]["endLine"] == 45
    assert sarif_loc["physicalLocation"]["region"]["startColumn"] == 10
    assert sarif_loc["physicalLocation"]["region"]["endColumn"] == 20


def test_sarif_location_minimal():
    """Test location conversion with minimal data."""
    location = {"path": "src/test.py", "startLine": 10}

    sarif_loc = _convert_location_to_sarif(location)

    assert sarif_loc["physicalLocation"]["artifactLocation"]["uri"] == "src/test.py"
    assert sarif_loc["physicalLocation"]["region"]["startLine"] == 10
    assert "endLine" not in sarif_loc["physicalLocation"]["region"]


def test_sarif_empty_location():
    """Test location conversion with no location data."""
    sarif_loc = _convert_location_to_sarif({})

    assert sarif_loc["physicalLocation"]["artifactLocation"]["uri"] == "unknown"
    assert sarif_loc["physicalLocation"]["region"]["startLine"] == 1


def test_sarif_valid_json(tmp_path, sample_diff_result):
    """Test output is valid JSON."""
    out_path = tmp_path / "diff.sarif"
    write_sarif_diff(sample_diff_result, out_path)

    # Should parse without errors
    with open(out_path) as f:
        data = json.load(f)

    assert isinstance(data, dict)


def test_sarif_unicode_handling(tmp_path):
    """Test SARIF handles Unicode correctly."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=1,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=1,
    )

    new_findings = [
        {
            "id": "unicode123",
            "severity": "HIGH",
            "ruleId": "CWE-79",
            "message": "XSS: 你好 🚨 مرحبا",
            "location": {"path": "test/файл.py", "startLine": 10},
        }
    ]

    diff = DiffResult(
        new=new_findings,
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 1,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 1,
            "trend": "worsening",
            "new_by_severity": {"HIGH": 1},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    out_path = tmp_path / "unicode-diff.sarif"
    write_sarif_diff(diff, out_path)

    with open(out_path, encoding="utf-8") as f:
        sarif = json.load(f)

    result = sarif["runs"][0]["results"][0]
    assert "你好" in result["message"]["text"]
    assert "🚨" in result["message"]["text"]
    assert "файл.py" in result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]


def test_sarif_creates_parent_directory(tmp_path, sample_diff_result):
    """Test parent directories are created."""
    out_path = tmp_path / "nested" / "dir" / "diff.sarif"

    write_sarif_diff(sample_diff_result, out_path)

    assert out_path.exists()
    assert out_path.parent.exists()


def test_sarif_empty_diff(tmp_path):
    """Test SARIF output for empty diff."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="fast",
        total_findings=0,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="fast",
        total_findings=0,
    )

    diff = DiffResult(
        new=[],
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 0,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 0,
            "trend": "stable",
            "new_by_severity": {},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    out_path = tmp_path / "empty-diff.sarif"
    write_sarif_diff(diff, out_path)

    with open(out_path) as f:
        sarif = json.load(f)

    assert len(sarif["runs"][0]["results"]) == 0
    assert sarif["runs"][0]["properties"]["statistics"]["total_new"] == 0
