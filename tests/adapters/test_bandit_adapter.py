import json
from pathlib import Path

from scripts.core.adapters.bandit_adapter import load_bandit


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_bandit_normalization_results_array(tmp_path: Path):
    sample = {
        "results": [
            {
                "filename": "scripts/core/foo.py",
                "line_number": 12,
                "issue_text": "Use of assert detected. The enclosed code will be removed when compiling to optimised byte code.",
                "test_id": "B101",
                "test_name": "assert_used",
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
            }
        ]
    }
    path = write_tmp(tmp_path, "bandit.json", json.dumps(sample))
    out = load_bandit(path)
    assert len(out) == 1
    item = out[0]
    assert item["schemaVersion"] == "1.0.0"
    assert item["ruleId"] == "B101"
    assert item["severity"] in {"LOW", "MEDIUM", "HIGH", "CRITICAL", "INFO"}
    assert item["location"]["path"].endswith("scripts/core/foo.py")
    assert item["location"]["startLine"] == 12
    assert item["tool"]["name"] == "bandit"


def test_bandit_empty_and_malformed(tmp_path: Path):
    p1 = write_tmp(tmp_path, "empty.json", "")
    assert load_bandit(p1) == []
    p2 = write_tmp(tmp_path, "bad.json", "{not json}")
    assert load_bandit(p2) == []
