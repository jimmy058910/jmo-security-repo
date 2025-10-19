import json
from pathlib import Path

from scripts.core.adapters.syft_adapter import load_syft
from scripts.core.adapters.hadolint_adapter import load_hadolint
from scripts.core.adapters.checkov_adapter import load_checkov


def write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_syft_adapter_packages_and_vulns(tmp_path: Path):
    data = {
        "artifacts": [
            {
                "id": "pkg1",
                "name": "flask",
                "version": "2.3.0",
                "locations": [{"path": "requirements.txt"}],
            }
        ],
        "vulnerabilities": [
            {
                "id": "CVE-2024-0001",
                "severity": "HIGH",
                "description": "test",
                "artifactIds": ["pkg1"],
            }
        ],
    }
    f = tmp_path / "syft.json"
    write(f, data)
    items = load_syft(f)
    assert any(i.get("ruleId") == "SBOM.PACKAGE" for i in items)
    assert any(
        i.get("ruleId") == "CVE-2024-0001" and i.get("severity") == "HIGH"
        for i in items
    )


def test_hadolint_adapter(tmp_path: Path):
    data = [
        {
            "code": "DL3008",
            "file": "Dockerfile",
            "line": 12,
            "level": "error",
            "message": "Use apk add --no-cache",
        }
    ]
    f = tmp_path / "hadolint.json"
    write(f, data)
    items = load_hadolint(f)
    assert items and items[0]["ruleId"] == "DL3008"


def test_checkov_adapter(tmp_path: Path):
    data = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "file_path": "main.tf",
                    "file_line_range": [10, 12],
                    "severity": "HIGH",
                }
            ]
        }
    }
    f = tmp_path / "checkov.json"
    write(f, data)
    items = load_checkov(f)
    assert (
        items and items[0]["ruleId"] == "CKV_AWS_1" and items[0]["severity"] == "HIGH"
    )


# tfsec removed in v0.6.0+ (replaced by trivy IaC scanning)
