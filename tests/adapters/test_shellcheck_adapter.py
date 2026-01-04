"""Tests for ShellCheck adapter."""

import json
from pathlib import Path

from scripts.core.adapters.shellcheck_adapter import (
    ShellCheckAdapter,
    _map_shellcheck_level,
)


def write(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a file and return the path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_shellcheck_single_finding(tmp_path: Path):
    """Test ShellCheck adapter parses single finding."""
    sample = [
        {
            "file": "script.sh",
            "line": 10,
            "endLine": 10,
            "column": 5,
            "endColumn": 15,
            "level": "warning",
            "code": 2086,
            "message": "Double quote to prevent globbing and word splitting.",
        }
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].ruleId == "SC2086"
    assert findings[0].severity == "MEDIUM"  # warning -> MEDIUM
    assert findings[0].location["path"] == "script.sh"
    assert findings[0].location["startLine"] == 10
    assert findings[0].location["endLine"] == 10
    assert findings[0].location["startColumn"] == 5
    assert findings[0].location["endColumn"] == 15
    assert "shell" in findings[0].tags
    assert "shellcheck" in findings[0].tags


def test_shellcheck_multiple_findings(tmp_path: Path):
    """Test ShellCheck adapter handles multiple findings."""
    sample = [
        {
            "file": "script.sh",
            "line": 5,
            "column": 1,
            "level": "warning",
            "code": 2086,
            "message": "Double quote to prevent globbing",
        },
        {
            "file": "script.sh",
            "line": 10,
            "column": 3,
            "level": "info",
            "code": 2034,
            "message": "Variable appears unused",
        },
        {
            "file": "deploy.sh",
            "line": 15,
            "column": 1,
            "level": "error",
            "code": 1091,
            "message": "Not following: file not found",
        },
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3
    codes = {f.ruleId for f in findings}
    assert codes == {"SC2086", "SC2034", "SC1091"}


def test_shellcheck_severity_mapping(tmp_path: Path):
    """Test ShellCheck adapter maps severity levels correctly."""
    sample = [
        {
            "file": "script.sh",
            "line": 1,
            "level": "error",
            "code": 1000,
            "message": "Error",
        },
        {
            "file": "script.sh",
            "line": 2,
            "level": "warning",
            "code": 2000,
            "message": "Warning",
        },
        {
            "file": "script.sh",
            "line": 3,
            "level": "info",
            "code": 2001,
            "message": "Info",
        },
        {
            "file": "script.sh",
            "line": 4,
            "level": "style",
            "code": 2002,
            "message": "Style",
        },
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 4
    severity_map = {f.ruleId: f.severity for f in findings}
    assert severity_map["SC1000"] == "HIGH"  # error -> HIGH
    assert severity_map["SC2000"] == "MEDIUM"  # warning -> MEDIUM
    assert severity_map["SC2001"] == "LOW"  # info -> LOW
    assert severity_map["SC2002"] == "INFO"  # style -> INFO


def test_shellcheck_level_mapping_function():
    """Test the level mapping function directly."""
    assert _map_shellcheck_level("error") == "HIGH"
    assert _map_shellcheck_level("ERROR") == "HIGH"
    assert _map_shellcheck_level("warning") == "MEDIUM"
    assert _map_shellcheck_level("WARNING") == "MEDIUM"
    assert _map_shellcheck_level("info") == "LOW"
    assert _map_shellcheck_level("INFO") == "LOW"
    assert _map_shellcheck_level("style") == "INFO"
    assert _map_shellcheck_level("STYLE") == "INFO"
    assert _map_shellcheck_level("unknown") == "MEDIUM"  # fallback


def test_shellcheck_empty_results(tmp_path: Path):
    """Test ShellCheck adapter handles empty array."""
    sample = []
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert findings == []


def test_shellcheck_empty_bad_input(tmp_path: Path):
    """Test ShellCheck adapter handles empty/bad input."""
    adapter = ShellCheckAdapter()

    p1 = write(tmp_path, "empty.json", "")
    assert adapter.parse(p1) == []

    p2 = write(tmp_path, "bad.json", "{not json}")
    assert adapter.parse(p2) == []


def test_shellcheck_missing_file(tmp_path: Path):
    """Test ShellCheck adapter handles missing file."""
    adapter = ShellCheckAdapter()
    missing = tmp_path / "nonexistent.json"
    assert adapter.parse(missing) == []


def test_shellcheck_not_array(tmp_path: Path):
    """Test ShellCheck adapter handles non-array input."""
    sample = {"code": 2086, "message": "test"}  # Should be array
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert findings == []


def test_shellcheck_multiple_files(tmp_path: Path):
    """Test ShellCheck adapter handles findings from multiple scripts."""
    sample = [
        {
            "file": "script.sh",
            "line": 5,
            "level": "warning",
            "code": 2086,
            "message": "Test",
        },
        {
            "file": "scripts/deploy.sh",
            "line": 10,
            "level": "info",
            "code": 2034,
            "message": "Test",
        },
        {
            "file": "bin/setup.bash",
            "line": 15,
            "level": "error",
            "code": 1091,
            "message": "Test",
        },
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3
    paths = {f.location["path"] for f in findings}
    assert paths == {"script.sh", "scripts/deploy.sh", "bin/setup.bash"}


def test_shellcheck_missing_fields(tmp_path: Path):
    """Test ShellCheck adapter handles missing fields with defaults."""
    sample = [
        {
            "code": 2086,
            # missing file, line, column, level
            "message": "Test message",
        }
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].ruleId == "SC2086"
    assert findings[0].location["path"] == "unknown.sh"  # default
    assert findings[0].location["startLine"] == 0  # default
    assert findings[0].severity == "MEDIUM"  # default (warning fallback)


def test_shellcheck_rule_category_tags(tmp_path: Path):
    """Test ShellCheck adapter adds category tags based on rule code."""
    sample = [
        {
            "file": "script.sh",
            "line": 1,
            "level": "error",
            "code": 1091,  # SC1xxx - syntax
            "message": "Syntax error",
        },
        {
            "file": "script.sh",
            "line": 2,
            "level": "warning",
            "code": 2086,  # SC2xxx - warning
            "message": "Warning",
        },
        {
            "file": "script.sh",
            "line": 3,
            "level": "info",
            "code": 3045,  # SC3xxx - portability
            "message": "Portability issue",
        },
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3

    # Find findings by code
    sc1 = next(f for f in findings if f.ruleId == "SC1091")
    sc2 = next(f for f in findings if f.ruleId == "SC2086")
    sc3 = next(f for f in findings if f.ruleId == "SC3045")

    assert "syntax" in sc1.tags
    assert "warning" in sc2.tags
    assert "portability" in sc3.tags


def test_shellcheck_references(tmp_path: Path):
    """Test ShellCheck adapter includes wiki references."""
    sample = [
        {
            "file": "script.sh",
            "line": 10,
            "level": "warning",
            "code": 2086,
            "message": "Test",
        }
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].references is not None
    assert "https://www.shellcheck.net/wiki/SC2086" in findings[0].references


def test_shellcheck_schema_version(tmp_path: Path):
    """Test ShellCheck findings have correct schema version."""
    sample = [
        {
            "file": "script.sh",
            "line": 12,
            "level": "warning",
            "code": 2086,
            "message": "Test",
        }
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].schemaVersion == "1.2.0"


def test_shellcheck_metadata(tmp_path: Path):
    """Test ShellCheck adapter metadata."""
    adapter = ShellCheckAdapter()
    metadata = adapter.metadata

    assert metadata.name == "shellcheck"
    assert metadata.tool_name == "shellcheck"
    assert metadata.schema_version == "1.2.0"
    assert metadata.output_format == "json"
    assert metadata.exit_codes == {0: "clean", 1: "findings"}


def test_shellcheck_context_preserved(tmp_path: Path):
    """Test ShellCheck adapter preserves context information."""
    sample = [
        {
            "file": "script.sh",
            "line": 10,
            "level": "warning",
            "code": 2086,
            "message": "Test",
        }
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].context is not None
    assert findings[0].context["level"] == "warning"
    assert findings[0].context["code"] == 2086


def test_shellcheck_raw_preserved(tmp_path: Path):
    """Test ShellCheck adapter preserves raw data."""
    sample = [
        {
            "file": "script.sh",
            "line": 10,
            "endLine": 10,
            "column": 5,
            "endColumn": 15,
            "level": "warning",
            "code": 2086,
            "message": "Test message",
        }
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].raw is not None
    assert findings[0].raw["code"] == 2086
    assert findings[0].raw["file"] == "script.sh"


def test_shellcheck_fingerprint_uniqueness(tmp_path: Path):
    """Test ShellCheck adapter generates unique fingerprints."""
    sample = [
        {
            "file": "script.sh",
            "line": 10,
            "level": "warning",
            "code": 2086,
            "message": "Message 1",
        },
        {
            "file": "script.sh",
            "line": 20,
            "level": "warning",
            "code": 2086,
            "message": "Message 2",
        },
        {
            "file": "other.sh",
            "line": 10,
            "level": "warning",
            "code": 2086,
            "message": "Message 1",
        },
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3
    fingerprints = {f.id for f in findings}
    assert len(fingerprints) == 3  # All unique


def test_shellcheck_non_dict_items_skipped(tmp_path: Path):
    """Test ShellCheck adapter skips non-dict items in array."""
    sample = [
        {
            "file": "script.sh",
            "line": 10,
            "level": "warning",
            "code": 2086,
            "message": "Valid",
        },
        "not a dict",
        123,
        None,
        {
            "file": "script.sh",
            "line": 20,
            "level": "error",
            "code": 1091,
            "message": "Also valid",
        },
    ]
    p = write(tmp_path, "shellcheck.json", json.dumps(sample))

    adapter = ShellCheckAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 2
    codes = {f.ruleId for f in findings}
    assert codes == {"SC2086", "SC1091"}
