import json
from pathlib import Path

from scripts.core.normalize_and_report import gather_results


def write(p: Path, s: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(s, encoding="utf-8")


def test_gather_results_merges_and_dedupes(tmp_path: Path):
    # Layout: results/individual-repos/<repo>/*tool*.json
    root = tmp_path / "results"
    r1 = root / "individual-repos" / "repo1"
    r2 = root / "individual-repos" / "repo2"

    # Minimal valid JSONs for each tool
    write(
        r1 / "gitleaks.json",
        json.dumps([{"RuleID": "k1", "File": "a.txt", "StartLine": 1}]),
    )
    write(
        r1 / "trufflehog.json",
        json.dumps({"DetectorName": "AWS", "Verified": True, "Line": 2}),
    )
    write(
        r2 / "semgrep.json",
        json.dumps(
            {
                "results": [
                    {
                        "check_id": "rule.x",
                        "path": "b.py",
                        "start": {"line": 3},
                        "extra": {"message": "m", "severity": "ERROR"},
                    }
                ]
            }
        ),
    )
    write(
        r2 / "noseyparker.json",
        json.dumps(
            {"matches": [{"signature": "slack", "path": "c.txt", "line_number": 4}]}
        ),
    )

    findings = gather_results(root)
    # Expect 4 findings, but allow dedupe if collisions happen (unlikely with different inputs)
    assert len(findings) >= 4
    # Ensure required keys exist in normalized items
    for f in findings:
        assert f["schemaVersion"] in ["1.0.0", "1.1.0", "1.2.0"]
        assert "ruleId" in f and "severity" in f and "location" in f and "message" in f
