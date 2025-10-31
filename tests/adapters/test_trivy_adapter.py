import json
from pathlib import Path

from scripts.core.adapters.trivy_adapter import TrivyAdapter


def write(tmp_path: Path, name: str, content: str) -> Path:
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_trivy_vuln_and_secret(tmp_path: Path):
    """Test Trivy adapter parses vulnerabilities and secrets."""
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

    adapter = TrivyAdapter()
    adapter = TrivyAdapter()
    findings = adapter.parse(p)

    # Check findings are Finding objects
    assert len(findings) == 2
    assert any(f.ruleId == "CVE-123" and f.severity == "CRITICAL" for f in findings)
    assert any(
        f.ruleId == "Hardcoded token" or f.title == "Hardcoded token" for f in findings
    )


def test_trivy_empty_bad(tmp_path: Path):
    """Test Trivy adapter handles empty/bad input."""
    adapter = TrivyAdapter()
    adapter = TrivyAdapter()

    p1 = write(tmp_path, "empty.json", "")
    assert adapter.parse(p1) == []

    p2 = write(tmp_path, "bad.json", "{not json}")
    assert adapter.parse(p2) == []
