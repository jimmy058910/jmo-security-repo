import json
from pathlib import Path

from scripts.core.normalize_and_report import gather_results


def write(p: Path, s: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")


def test_trivy_enriched_with_syft(tmp_path: Path):
    root = tmp_path / "results"
    repo = root / "individual-repos" / "r1"

    # Minimal Syft SBOM with a package loc and name
    syft_json = {
        "artifacts": [
            {
                "id": "pkg:1",
                "name": "requests",
                "version": "2.32.0",
                "locations": [{"path": "requirements.txt"}],
            }
        ]
    }
    write(repo / "syft.json", json.dumps(syft_json))

    # Trivy finding that references the same path and package name
    trivy_json = {
        "Results": [
            {
                "Target": "requirements.txt",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-1234",
                        "Title": "Vuln in requests",
                        "Severity": "HIGH",
                        "PkgName": "requests",
                        "PkgPath": "requirements.txt",
                        "StartLine": 1,
                    }
                ],
            }
        ]
    }
    write(repo / "trivy.json", json.dumps(trivy_json))

    findings = gather_results(root)
    # Find the trivy finding and check enrichment
    enriched = [f for f in findings if (f.get("tool") or {}).get("name") == "trivy"]
    assert enriched, "expected trivy finding"
    f = enriched[0]
    ctx = (f.get("context") or {}).get("sbom")
    assert ctx and ctx.get("name") == "requests"
    assert any(t.startswith("pkg:requests@") for t in f.get("tags", []))
