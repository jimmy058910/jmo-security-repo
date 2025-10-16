from pathlib import Path

import pytest

from scripts.core.reporters.yaml_reporter import write_yaml
from scripts.core.reporters.html_reporter import write_html


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


def test_write_yaml(tmp_path: Path):
    try:
        out = tmp_path / "f.yaml"
        write_yaml(SAMPLE, out)
        s = out.read_text(encoding="utf-8")
        assert "aws-key" in s and "schemaVersion" in s
    except RuntimeError:
        pytest.skip("PyYAML not installed")


def test_write_html(tmp_path: Path):
    out = tmp_path / "f.html"
    write_html(SAMPLE, out)
    s = out.read_text(encoding="utf-8")
    assert "<!DOCTYPE html>" in s
    assert (
        "Security Dashboard" in s or "Security Summary" in s
    )  # v2 renamed to Dashboard
    assert "aws-key" in s or "AWS" in s
