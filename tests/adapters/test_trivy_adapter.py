import json
from pathlib import Path

from scripts.core.adapters.trivy_adapter import load_trivy


def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_trivy_vuln_and_secret(tmp_path: Path):
    sample = {
        "Version": "0",
        "Results": [
            {
                "Target": "app/Dockerfile",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-123",
                        "Title": "Something",
                        "Severity": "CRITICAL",
                    }
                ],
                "Secrets": [
                    {
                        "Title": "Hardcoded token",
                        "Severity": "HIGH",
                        "Target": "app/.env",
                    }
                ],
            }
        ],
    }
    p = write(tmp_path, "trivy.json", json.dumps(sample))
    out = load_trivy(p)
    assert any(f["ruleId"] == "CVE-123" and f["severity"] == "CRITICAL" for f in out)
    assert any(f["ruleId"] == "secret" or f["title"] == "Hardcoded token" for f in out)


def test_trivy_empty_bad(tmp_path: Path):
    p1 = write(tmp_path, "empty.json", "")
    assert load_trivy(p1) == []
    p2 = write(tmp_path, "bad.json", "{not json}")
    assert load_trivy(p2) == []
