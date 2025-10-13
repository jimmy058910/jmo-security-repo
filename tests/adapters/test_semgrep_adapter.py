import json
from pathlib import Path

from scripts.core.adapters.semgrep_adapter import load_semgrep


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_semgrep_basic(tmp_path: Path):
    sample = {
        "results": [
            {
                "check_id": "python.lang.correctness.useless-comparison",
                "path": "foo.py",
                "start": {"line": 3},
                "extra": {"message": "useless comparison", "severity": "ERROR"},
            }
        ],
        "version": "1.0.0",
    }
    path = write_tmp(tmp_path, "semgrep.json", json.dumps(sample))
    out = load_semgrep(path)
    assert len(out) == 1
    item = out[0]
    assert item["ruleId"].endswith("useless-comparison")
    assert item["severity"] == "HIGH"
    assert item["location"]["path"] == "foo.py"
    assert item["location"]["startLine"] == 3


def test_semgrep_empty_and_malformed(tmp_path: Path):
    p1 = write_tmp(tmp_path, "empty.json", "")
    assert load_semgrep(p1) == []
    p2 = write_tmp(tmp_path, "bad.json", "{not json}")
    assert load_semgrep(p2) == []
    p3 = write_tmp(tmp_path, "noresults.json", json.dumps({"results": {}}))
    assert load_semgrep(p3) == []
