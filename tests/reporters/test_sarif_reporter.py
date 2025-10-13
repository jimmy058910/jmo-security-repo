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
