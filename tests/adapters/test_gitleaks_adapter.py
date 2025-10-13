import json
from pathlib import Path

from scripts.core.adapters.gitleaks_adapter import load_gitleaks


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_gitleaks_array_normalization(tmp_path: Path):
    sample = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "src/app.py",
            "StartLine": 42,
            "Severity": "high",
            "Rule": "Generic API Key",
        }
    ]
    path = write_tmp(tmp_path, "gitleaks.json", json.dumps(sample))
    out = load_gitleaks(path)
    assert len(out) == 1
    item = out[0]
    assert item["schemaVersion"] == "1.0.0"
    assert item["ruleId"] == "generic-api-key"
    assert item["severity"] == "HIGH"
    assert item["location"]["path"] == "src/app.py"
    assert item["location"]["startLine"] == 42
    assert item["tool"]["name"] == "gitleaks"


def test_gitleaks_object_with_findings(tmp_path: Path):
    sample = {"findings": [{"RuleID": "gh-token", "File": "main.go", "Line": 10}]}
    path = write_tmp(tmp_path, "gitleaks.json", json.dumps(sample))
    out = load_gitleaks(path)
    assert len(out) == 1
    assert out[0]["ruleId"] == "gh-token"


def test_gitleaks_empty_and_malformed(tmp_path: Path):
    path1 = write_tmp(tmp_path, "empty.json", "")
    assert load_gitleaks(path1) == []
    path2 = write_tmp(tmp_path, "bad.json", "{not json}")
    assert load_gitleaks(path2) == []
