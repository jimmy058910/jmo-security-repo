from pathlib import Path

from scripts.core.reporters.basic_reporter import to_markdown_summary, write_json


def test_markdown_summary_counts(tmp_path: Path):
    sample = [
        {"severity": "HIGH", "ruleId": "aws-key"},
        {"severity": "LOW", "ruleId": "dummy"},
        {"severity": "HIGH", "ruleId": "aws-key"},
        {"severity": "INFO", "ruleId": "meta"},
    ]
    md = to_markdown_summary(sample)
    assert "Total findings: 4" in md
    assert "- HIGH: 2" in md
    assert "- LOW: 1" in md
    assert "- INFO: 1" in md
    assert "Top Rules" in md


def test_write_json_roundtrip(tmp_path: Path):
    sample = [
        {
            "schemaVersion": "1.0.0",
            "severity": "HIGH",
            "ruleId": "x",
            "id": "1",
            "tool": {"name": "t", "version": "v"},
            "location": {"path": "a", "startLine": 1},
            "message": "m",
        }
    ]
    out = tmp_path / "out.json"
    write_json(sample, out)
    s = out.read_text(encoding="utf-8")
    assert "\n" in s and "schemaVersion" in s
