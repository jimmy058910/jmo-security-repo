import json
from pathlib import Path

from scripts.core.adapters.trufflehog_adapter import load_trufflehog


def write_tmp(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_trufflehog_array(tmp_path: Path):
    sample = [
        {
            "DetectorName": "AWS",
            "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "config/aws.yaml"}}},
            "StartLine": 7,
        }
    ]
    path = write_tmp(tmp_path, "th.json", json.dumps(sample))
    out = load_trufflehog(path)
    assert len(out) == 1
    item = out[0]
    assert item["severity"] == "HIGH"
    assert item["location"]["path"] == "config/aws.yaml"
    assert item["location"]["startLine"] == 7


def test_trufflehog_ndjson_and_nested(tmp_path: Path):
    ndjson = "\n".join([
        json.dumps({
            "DetectorName": "Slack", "Verified": True,
            "SourceMetadata": {"Data": {"Filesystem": {"file": "webhooks.js"}}}
        }),
        json.dumps([[{"DetectorName": "Nested", "Verified": False}]])
    ])
    path = write_tmp(tmp_path, "th.ndjson", ndjson)
    out = load_trufflehog(path)
    # Should parse 2 findings
    assert len(out) == 2
    assert any(it["ruleId"] == "Slack" for it in out)
    assert any(it["ruleId"] == "Nested" for it in out)


def test_trufflehog_single_object_and_empty(tmp_path: Path):
    single = {"DetectorName": "JWT", "Verified": True, "Line": 12}
    p1 = write_tmp(tmp_path, "single.json", json.dumps(single))
    assert len(load_trufflehog(p1)) == 1
    empty = write_tmp(tmp_path, "empty.json", "")
    assert load_trufflehog(empty) == []
