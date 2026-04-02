"""Tests for Hadolint adapter."""

import json
from pathlib import Path

from scripts.core.adapters.hadolint_adapter import HadolintAdapter


def write(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a file and return the path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_hadolint_single_finding(tmp_path: Path):
    """Test Hadolint adapter parses single finding."""
    sample = [
        {
            "code": "DL3008",
            "file": "Dockerfile",
            "line": 12,
            "level": "warning",
            "message": "Pin versions in apt get install",
        }
    ]
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].ruleId == "DL3008"
    assert findings[0].severity == "MEDIUM"  # warning -> MEDIUM
    assert findings[0].location["path"] == "Dockerfile"
    assert findings[0].location["startLine"] == 12
    assert "dockerfile" in findings[0].tags
    assert "lint" in findings[0].tags


def test_hadolint_multiple_findings(tmp_path: Path):
    """Test Hadolint adapter handles multiple findings."""
    sample = [
        {
            "code": "DL3008",
            "file": "Dockerfile",
            "line": 5,
            "level": "warning",
            "message": "Pin versions in apt get install",
        },
        {
            "code": "DL3009",
            "file": "Dockerfile",
            "line": 10,
            "level": "info",
            "message": "Delete apt cache",
        },
        {
            "code": "DL3003",
            "file": "Dockerfile",
            "line": 15,
            "level": "error",
            "message": "Use WORKDIR to switch to a directory",
        },
    ]
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3
    codes = {f.ruleId for f in findings}
    assert codes == {"DL3008", "DL3009", "DL3003"}


def test_hadolint_severity_mapping(tmp_path: Path):
    """Test Hadolint adapter maps severity levels correctly."""
    sample = [
        {
            "code": "DL1",
            "file": "Dockerfile",
            "line": 1,
            "level": "error",
            "message": "Error",
        },
        {
            "code": "DL2",
            "file": "Dockerfile",
            "line": 2,
            "level": "warning",
            "message": "Warning",
        },
        {
            "code": "DL3",
            "file": "Dockerfile",
            "line": 3,
            "level": "info",
            "message": "Info",
        },
        {
            "code": "DL4",
            "file": "Dockerfile",
            "line": 4,
            "level": "style",
            "message": "Style",
        },
    ]
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 4
    # Verify severity normalization
    severity_map = {f.ruleId: f.severity for f in findings}
    assert severity_map["DL1"] == "HIGH"  # error -> HIGH
    assert severity_map["DL2"] == "MEDIUM"  # warning -> MEDIUM
    assert severity_map["DL3"] == "INFO"  # info -> INFO


def test_hadolint_empty_results(tmp_path: Path):
    """Test Hadolint adapter handles empty array."""
    sample = []
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert findings == []


def test_hadolint_empty_bad_input(tmp_path: Path):
    """Test Hadolint adapter handles empty/bad input."""
    adapter = HadolintAdapter()

    p1 = write(tmp_path, "empty.json", "")
    assert adapter.parse(p1) == []

    p2 = write(tmp_path, "bad.json", "{not json}")
    assert adapter.parse(p2) == []


def test_hadolint_missing_file(tmp_path: Path):
    """Test Hadolint adapter handles missing file."""
    adapter = HadolintAdapter()
    missing = tmp_path / "nonexistent.json"
    assert adapter.parse(missing) == []


def test_hadolint_not_array(tmp_path: Path):
    """Test Hadolint adapter handles non-array input."""
    sample = {"code": "DL3008", "message": "test"}  # Should be array
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert findings == []


def test_hadolint_multiple_dockerfiles(tmp_path: Path):
    """Test Hadolint adapter handles findings from multiple Dockerfiles."""
    sample = [
        {
            "code": "DL3008",
            "file": "Dockerfile",
            "line": 5,
            "level": "warning",
            "message": "Test",
        },
        {
            "code": "DL3009",
            "file": "docker/Dockerfile.dev",
            "line": 10,
            "level": "info",
            "message": "Test",
        },
        {
            "code": "DL3010",
            "file": "docker/Dockerfile.prod",
            "line": 15,
            "level": "error",
            "message": "Test",
        },
    ]
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3
    paths = {f.location["path"] for f in findings}
    assert paths == {"Dockerfile", "docker/Dockerfile.dev", "docker/Dockerfile.prod"}


def test_hadolint_missing_fields(tmp_path: Path):
    """Test Hadolint adapter handles missing fields with defaults."""
    sample = [
        {
            "code": "DL3008",
            # missing file, line, level
            "message": "Test message",
        }
    ]
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].ruleId == "DL3008"
    assert findings[0].location["path"] == "Dockerfile"  # default
    assert findings[0].location["startLine"] == 0  # default
    assert findings[0].severity == "MEDIUM"  # default


def test_hadolint_compliance_enrichment(tmp_path: Path):
    """Test Hadolint findings are enriched with compliance mappings."""
    sample = [
        {
            "code": "DL3008",
            "file": "Dockerfile",
            "line": 12,
            "level": "warning",
            "message": "Pin versions",
        }
    ]
    p = write(tmp_path, "hadolint.json", json.dumps(sample))

    adapter = HadolintAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].schemaVersion == "1.2.0"


def test_hadolint_metadata(tmp_path: Path):
    """Test Hadolint adapter metadata."""
    adapter = HadolintAdapter()
    metadata = adapter.metadata

    assert metadata.name == "hadolint"
    assert metadata.tool_name == "hadolint"
    assert metadata.schema_version == "1.2.0"
    assert metadata.output_format == "json"
