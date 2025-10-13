import json
from pathlib import Path

from scripts.core.adapters.osv_adapter import load_osv


def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_osv_basic(tmp_path: Path):
    sample = {
        "version": "0.0",
        "results": [
            {
                "source": {"path": "requirements.txt"},
                "packages": [{"name": "flask"}],
                "vulnerabilities": [
                    {"id": "OSV-1", "summary": "test vuln", "severity": [{"score": "7.5"}]}
                ],
            }
        ],
    }
    p = write(tmp_path, "osv.json", json.dumps(sample))
    out = load_osv(p)
    assert len(out) == 1
    assert out[0]["severity"] == "HIGH"
    assert out[0]["location"]["path"] == "requirements.txt"


def test_osv_empty_bad(tmp_path: Path):
    p1 = write(tmp_path, "empty.json", "")
    assert load_osv(p1) == []
    p2 = write(tmp_path, "bad.json", "{not json}")
    assert load_osv(p2) == []


def test_osv_missing_fields_and_cvss(tmp_path: Path):
    # No vulnerabilities array
    p1 = write(tmp_path, "osv1.json", json.dumps({"results": [{}]}))
    assert load_osv(p1) == []

    # Vulnerability with non-float severity score should be ignored gracefully
    sample = {
        "version": "0.0",
        "results": [
            {
                "source": {"path": "go.mod"},
                "packages": [{"name": "gin"}],
                "vulnerabilities": [
                    {"id": "OSV-2", "summary": "v", "severity": [{"score": "not-a-number"}]}
                ],
            }
        ],
    }
    p2 = write(tmp_path, "osv2.json", json.dumps(sample))
    out = load_osv(p2)
    assert out and out[0]["severity"] in {"MEDIUM", "LOW", "INFO"}
