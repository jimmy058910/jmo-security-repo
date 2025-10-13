from pathlib import Path

import pytest

from scripts.core.reporters.yaml_reporter import write_yaml


def test_yaml_reporter_writes_empty_list(tmp_path: Path):
    out = tmp_path / "empty.yaml"
    write_yaml([], out)
    text = out.read_text(encoding="utf-8")
    # PyYAML emits [] for empty list
    assert text.strip() in ("[]", "[]\n")


def test_yaml_reporter_preserves_fields(tmp_path: Path):
    sample = [
        {
            "schemaVersion": "1.0.0",
            "id": "abc",
            "ruleId": "R1",
            "message": "m",
            "title": "t",
            "severity": "LOW",
            "tool": {"name": "x", "version": "1"},
            "location": {"path": "a.txt", "startLine": 1},
            "context": {"foo": "bar"},
            "tags": ["one", "two"],
        }
    ]
    out = tmp_path / "out.yaml"
    write_yaml(sample, out)
    s = out.read_text(encoding="utf-8")
    # Ensure key fields are present
    for key in ("schemaVersion", "ruleId", "severity", "location", "message"):
        assert key in s


def test_yaml_reporter_raises_without_pyyaml(monkeypatch, tmp_path: Path):
    import scripts.core.reporters.yaml_reporter as ymod

    monkeypatch.setattr(ymod, "yaml", None, raising=False)
    with pytest.raises(RuntimeError):
        ymod.write_yaml([], tmp_path / "x.yaml")
