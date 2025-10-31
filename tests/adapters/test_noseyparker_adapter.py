import json
from pathlib import Path

from scripts.core.adapters.noseyparker_adapter import NoseyParkerAdapter


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_noseyparker_basic(tmp_path: Path):
    sample = {
        "version": "0.16.0",
        "matches": [
            {
                "signature": "AWS",
                "path": "a/b.txt",
                "line_number": 5,
                "match": "AKIA...",
            }
        ],
    }
    path = write_tmp(tmp_path, "np.json", json.dumps(sample))
    adapter = NoseyParkerAdapter()
    adapter = NoseyParkerAdapter()
    findings = adapter.parse(path)
    assert len(findings) == 1
    item = findings[0]
    assert item.ruleId == "AWS"
    assert item.location["path"] == "a/b.txt"
    assert item.location["startLine"] == 5


def test_noseyparker_empty_and_malformed(tmp_path: Path):
    p1 = write_tmp(tmp_path, "empty.json", "")
    adapter = NoseyParkerAdapter()
    adapter = NoseyParkerAdapter()
    assert adapter.parse(p1) == []
    p2 = write_tmp(tmp_path, "bad.json", "{not json}")
    adapter = NoseyParkerAdapter()
    adapter = NoseyParkerAdapter()
    assert adapter.parse(p2) == []
    p3 = write_tmp(tmp_path, "nomatches.json", json.dumps({"matches": {}}))
    adapter = NoseyParkerAdapter()
    adapter = NoseyParkerAdapter()
    assert adapter.parse(p3) == []
