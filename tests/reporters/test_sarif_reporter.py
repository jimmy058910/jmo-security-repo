from pathlib import Path
from scripts.core.reporters.sarif_reporter import to_sarif, write_sarif

SAMPLE = [
    {
        "schemaVersion": "1.0.0",
        "id": "abc",
        "ruleId": "aws-key",
        "message": "Potential AWS key",
        "severity": "HIGH",
        "tool": {"name": "gitleaks", "version": "x"},
        "location": {"path": "a.txt", "startLine": 1},
    }
]


def test_to_sarif_basic():
    sarif = to_sarif(SAMPLE)
    assert sarif.get("version") == "2.1.0"
    assert sarif.get("runs")
    assert sarif["runs"][0]["results"][0]["ruleId"] == "aws-key"


def test_write_sarif(tmp_path: Path):
    out = tmp_path / "f.sarif"
    write_sarif(SAMPLE, out)
    s = out.read_text(encoding="utf-8")
    assert '"version": "2.1.0"' in s


def test_write_sarif_with_file_error(tmp_path: Path):
    """Test SARIF writer handles file write errors gracefully."""
    import pytest

    findings = [
        {
            "tool": {"name": "test"},
            "ruleId": "TEST-001",
            "severity": "HIGH",
            "location": {"path": "test.py"},
            "message": "test",
        }
    ]

    # Try to write to read-only directory
    ro_dir = tmp_path / "readonly"
    ro_dir.mkdir()
    ro_dir.chmod(0o444)  # Read-only

    output_path = ro_dir / "findings.sarif"

    with pytest.raises(PermissionError):
        write_sarif(findings, output_path)


def test_write_sarif_malformed_findings(tmp_path: Path):
    """Test SARIF writer handles malformed findings gracefully."""
    # Findings missing required fields
    findings = [{"invalid": "structure"}]

    output_path = tmp_path / "findings.sarif"
    write_sarif(findings, output_path)

    # Should write valid SARIF structure even with malformed input
    assert output_path.exists()
    content = output_path.read_text()
    assert '"version": "2.1.0"' in content
