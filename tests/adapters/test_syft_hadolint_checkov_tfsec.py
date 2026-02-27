import json
from pathlib import Path

from scripts.core.adapters.syft_adapter import SyftAdapter
from scripts.core.adapters.hadolint_adapter import HadolintAdapter
from scripts.core.adapters.checkov_adapter import CheckovAdapter


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
    adapter = SyftAdapter()
    adapter = SyftAdapter()
    items = adapter.parse(f)
    assert any(i.ruleId == "SBOM.PACKAGE" for i in items)
    assert any(i.ruleId == "CVE-2024-0001" and i.severity == "HIGH" for i in items)


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
    adapter = HadolintAdapter()
    adapter = HadolintAdapter()
    items = adapter.parse(f)
    assert items and items[0].ruleId == "DL3008"


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
    adapter = CheckovAdapter()
    adapter = CheckovAdapter()
    items = adapter.parse(f)
    assert items and items[0].ruleId == "CKV_AWS_1" and items[0].severity == "HIGH"


def test_checkov_adapter_github_actions_cicd(tmp_path: Path):
    """Test Checkov CI/CD scanning for GitHub Actions (v2.0.0).

    Verifies that CI/CD findings are tagged with 'cicd-security'.
    """
    data = {
        "check_type": "github_actions",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV2_GHA_1",
                    "check_name": "Ensure top-level permissions are not set to write-all",
                    "file_path": "/.github/workflows/test.yml",
                    "file_line_range": [6, 7],
                    "severity": "HIGH",
                    "guideline": "Set minimal required permissions for GitHub Actions workflow",
                }
            ]
        },
        "checkov_version": "3.2.477",
    }
    f = tmp_path / "checkov.json"
    write(f, data)
    adapter = CheckovAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CKV2_GHA_1"
    assert items[0].severity == "HIGH"
    assert "cicd-security" in items[0].tags
    assert "policy" in items[0].tags
    assert items[0].location["path"] == "/.github/workflows/test.yml"


def test_checkov_adapter_gitlab_ci_cicd(tmp_path: Path):
    """Test Checkov CI/CD scanning for GitLab CI (v2.0.0)."""
    data = {
        "check_type": "gitlab_ci",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_GITLABCI_1",
                    "check_name": "Ensure pipeline contains no hardcoded secrets",
                    "file_path": "/.gitlab-ci.yml",
                    "file_line_range": [10, 15],
                    "severity": "CRITICAL",
                }
            ]
        },
    }
    f = tmp_path / "checkov.json"
    write(f, data)
    adapter = CheckovAdapter()
    items = adapter.parse(f)

    assert len(items) == 1
    assert items[0].ruleId == "CKV_GITLABCI_1"
    assert items[0].severity == "CRITICAL"
    assert "cicd-security" in items[0].tags
    assert "iac" not in items[0].tags  # Should NOT have 'iac' tag


def test_checkov_adapter_iac_vs_cicd_tags(tmp_path: Path):
    """Test that IaC findings get 'iac' tag, CI/CD findings get 'cicd-security' tag."""
    # IaC scan (no check_type or non-CI/CD check_type)
    iac_data = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "file_path": "main.tf",
                    "file_line_range": [10, 12],
                }
            ]
        },
    }
    iac_file = tmp_path / "iac_checkov.json"
    write(iac_file, iac_data)

    # CI/CD scan
    cicd_data = {
        "check_type": "github_actions",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV2_GHA_1",
                    "file_path": ".github/workflows/ci.yml",
                    "file_line_range": [5, 6],
                }
            ]
        },
    }
    cicd_file = tmp_path / "cicd_checkov.json"
    write(cicd_file, cicd_data)

    adapter = CheckovAdapter()

    # Parse IaC findings
    iac_items = adapter.parse(iac_file)
    assert len(iac_items) == 1
    assert "iac" in iac_items[0].tags
    assert "cicd-security" not in iac_items[0].tags

    # Parse CI/CD findings
    cicd_items = adapter.parse(cicd_file)
    assert len(cicd_items) == 1
    assert "cicd-security" in cicd_items[0].tags
    assert "iac" not in cicd_items[0].tags


# tfsec removed in v0.6.0+ (replaced by trivy IaC scanning)
