"""Tests for JSON diff reporter."""

import json
from pathlib import Path

import pytest

from scripts.core.diff_engine import DiffResult, DiffSource, ModifiedFinding
from scripts.core.reporters.diff_json_reporter import write_json_diff


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
            "id": "abc123def456",
            "severity": "HIGH",
            "ruleId": "G101",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/auth.py", "startLine": 42},
            "message": "Hardcoded secret detected",
        },
        {
            "schemaVersion": "1.2.0",
            "id": "xyz789abc123",
            "severity": "CRITICAL",
            "ruleId": "CWE-89",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "location": {"path": "src/db.py", "startLine": 89},
            "message": "SQL injection vulnerability",
        },
    ]

    resolved_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "old123def456",
            "severity": "MEDIUM",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/views.py", "startLine": 120},
            "message": "XSS vulnerability",
        }
    ]

    unchanged_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "unchanged123",
            "severity": "LOW",
            "ruleId": "CWE-200",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "location": {"path": "src/info.py", "startLine": 15},
            "message": "Information disclosure",
        }
    ]

    modified_findings = [
        ModifiedFinding(
            fingerprint="def456abc123",
            changes={"severity": ["MEDIUM", "HIGH"], "priority": [45.2, 78.9]},
            baseline={
                "schemaVersion": "1.2.0",
                "id": "def456abc123",
                "severity": "MEDIUM",
                "ruleId": "G101",
                "message": "Hardcoded password",
            },
            current={
                "schemaVersion": "1.2.0",
                "id": "def456abc123",
                "severity": "HIGH",
                "ruleId": "G101",
                "message": "Hardcoded password",
            },
            risk_delta="worsened",
        )
    ]

    statistics = {
        "total_new": 2,
        "total_resolved": 1,
        "total_unchanged": 1,
        "total_modified": 1,
        "net_change": 1,
        "trend": "worsening",
        "new_by_severity": {"CRITICAL": 1, "HIGH": 1},
        "resolved_by_severity": {"MEDIUM": 1},
        "modifications_by_type": {"severity": 1, "priority": 1},
    }

    return DiffResult(
        new=new_findings,
        resolved=resolved_findings,
        unchanged=unchanged_findings,
        modified=modified_findings,
        baseline_source=baseline_source,
        current_source=current_source,
        statistics=statistics,
    )


def test_json_schema_structure(tmp_path, sample_diff_result):
    """Test that JSON output has required top-level structure."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    assert out_path.exists()

    with open(out_path) as f:
        data = json.load(f)

    # Check top-level keys
    assert "meta" in data
    assert "statistics" in data
    assert "new_findings" in data
    assert "resolved_findings" in data
    assert "modified_findings" in data


def test_json_metadata_wrapper(tmp_path, sample_diff_result):
    """Test v1.0.0 metadata wrapper structure."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        data = json.load(f)

    meta = data["meta"]

    # Check metadata fields
    assert meta["diff_version"] == "1.0.0"
    assert "jmo_version" in meta
    assert "timestamp" in meta
    assert "baseline" in meta
    assert "current" in meta

    # Check timestamp is ISO 8601
    assert "T" in meta["timestamp"]
    assert "Z" in meta["timestamp"] or "+" in meta["timestamp"]

    # Check baseline metadata
    baseline = meta["baseline"]
    assert baseline["source_type"] == "directory"
    assert baseline["path"] == "baseline-results/"
    assert baseline["timestamp"] == "2025-11-04T10:00:00Z"
    assert baseline["profile"] == "balanced"
    assert baseline["total_findings"] == 150

    # Check current metadata
    current = meta["current"]
    assert current["source_type"] == "directory"
    assert current["path"] == "current-results/"
    assert current["timestamp"] == "2025-11-05T10:00:00Z"
    assert current["profile"] == "balanced"
    assert current["total_findings"] == 142


def test_json_statistics_section(tmp_path, sample_diff_result):
    """Test statistics section completeness."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        data = json.load(f)

    stats = data["statistics"]

    # Check all required fields
    assert stats["total_new"] == 2
    assert stats["total_resolved"] == 1
    assert stats["total_unchanged"] == 1
    assert stats["total_modified"] == 1
    assert stats["net_change"] == 1
    assert stats["trend"] == "worsening"
    assert "new_by_severity" in stats
    assert "resolved_by_severity" in stats
    assert "modifications_by_type" in stats


def test_json_new_findings(tmp_path, sample_diff_result):
    """Test new findings section."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        data = json.load(f)

    new = data["new_findings"]

    assert len(new) == 2
    assert new[0]["id"] == "abc123def456"
    assert new[0]["severity"] == "HIGH"
    assert new[0]["ruleId"] == "G101"
    assert new[1]["id"] == "xyz789abc123"
    assert new[1]["severity"] == "CRITICAL"


def test_json_resolved_findings(tmp_path, sample_diff_result):
    """Test resolved findings section."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        data = json.load(f)

    resolved = data["resolved_findings"]

    assert len(resolved) == 1
    assert resolved[0]["id"] == "old123def456"
    assert resolved[0]["severity"] == "MEDIUM"


def test_json_modified_findings(tmp_path, sample_diff_result):
    """Test modified findings section."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    with open(out_path) as f:
        data = json.load(f)

    modified = data["modified_findings"]

    assert len(modified) == 1

    mod = modified[0]
    assert mod["fingerprint"] == "def456abc123"
    assert "changes" in mod
    assert mod["changes"]["severity"] == ["MEDIUM", "HIGH"]
    assert mod["changes"]["priority"] == [45.2, 78.9]
    assert mod["risk_delta"] == "worsened"
    assert "baseline" in mod
    assert "current" in mod


def test_json_valid_format(tmp_path, sample_diff_result):
    """Test that output is valid JSON."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    # Should parse without errors
    with open(out_path) as f:
        data = json.load(f)

    assert isinstance(data, dict)


def test_json_round_trip(tmp_path, sample_diff_result):
    """Test that JSON can be round-tripped."""
    out_path = tmp_path / "diff.json"
    write_json_diff(sample_diff_result, out_path)

    # Read back
    with open(out_path) as f:
        data = json.load(f)

    # Verify all data intact
    assert data["statistics"]["total_new"] == 2
    assert data["statistics"]["total_resolved"] == 1
    assert len(data["new_findings"]) == 2
    assert len(data["resolved_findings"]) == 1
    assert len(data["modified_findings"]) == 1


def test_json_empty_diff(tmp_path):
    """Test JSON output for empty diff result."""
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

    out_path = tmp_path / "empty-diff.json"
    write_json_diff(diff, out_path)

    with open(out_path) as f:
        data = json.load(f)

    assert data["statistics"]["total_new"] == 0
    assert data["statistics"]["total_resolved"] == 0
    assert len(data["new_findings"]) == 0
    assert len(data["resolved_findings"]) == 0
    assert len(data["modified_findings"]) == 0


def test_json_unicode_handling(tmp_path):
    """Test JSON handles Unicode characters correctly."""
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

    # Finding with Unicode characters
    new_findings = [
        {
            "schemaVersion": "1.2.0",
            "id": "unicode123",
            "severity": "HIGH",
            "ruleId": "CWE-79",
            "message": "XSS vulnerability: 你好 🚨 مرحبا",
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

    out_path = tmp_path / "unicode-diff.json"
    write_json_diff(diff, out_path)

    with open(out_path, encoding="utf-8") as f:
        data = json.load(f)

    # Verify Unicode preserved
    assert "你好" in data["new_findings"][0]["message"]
    assert "🚨" in data["new_findings"][0]["message"]
    assert "مرحبا" in data["new_findings"][0]["message"]
    assert "файл.py" in data["new_findings"][0]["location"]["path"]


def test_json_creates_parent_directory(tmp_path):
    """Test that parent directories are created if they don't exist."""
    out_path = tmp_path / "nested" / "dir" / "diff.json"

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

    # Should create parent directories
    write_json_diff(diff, out_path)

    assert out_path.exists()
    assert out_path.parent.exists()
