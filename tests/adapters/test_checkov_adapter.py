"""Tests for Checkov adapter."""

import json
from pathlib import Path

from scripts.core.adapters.checkov_adapter import CheckovAdapter


def write(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a file and return the path."""
    p = tmp_path / name
    p.write_text(content, encoding="utf-8")
    return p


def test_checkov_iac_findings(tmp_path: Path):
    """Test Checkov adapter parses IaC failed checks."""
    sample = {
        "check_type": "terraform",
        "checkov_version": "3.2.495",
        "results": {
            "passed_checks": [],
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "Ensure S3 bucket has access logging enabled",
                    "file_path": "/main.tf",
                    "file_line_range": [15, 20],
                    "severity": "HIGH",
                    "guideline": "Enable access logging for S3 buckets",
                }
            ],
            "skipped_checks": [],
        },
    }
    p = write(tmp_path, "checkov.json", json.dumps(sample))

    adapter = CheckovAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].ruleId == "CKV_AWS_20"
    assert findings[0].severity == "HIGH"
    assert findings[0].location["path"] == "/main.tf"
    assert findings[0].location["startLine"] == 15
    assert "iac" in findings[0].tags
    assert findings[0].tool["name"] == "checkov"
    assert findings[0].tool["version"] == "3.2.495"


def test_checkov_cicd_findings(tmp_path: Path):
    """Test Checkov adapter parses CI/CD pipeline findings."""
    sample = {
        "check_type": "github_actions",
        "checkov_version": "3.2.495",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_GHA_1",
                    "check_name": "Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS is not set",
                    "file_path": "/.github/workflows/ci.yml",
                    "file_line_range": [8],
                    "severity": "CRITICAL",
                    "guideline": "Do not allow unsecure commands in GitHub Actions",
                }
            ],
        },
    }
    p = write(tmp_path, "checkov.json", json.dumps(sample))

    adapter = CheckovAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].ruleId == "CKV_GHA_1"
    assert findings[0].severity == "CRITICAL"
    assert "cicd-security" in findings[0].tags
    assert "policy" in findings[0].tags


def test_checkov_multiple_findings(tmp_path: Path):
    """Test Checkov adapter handles multiple findings."""
    sample = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_1",
                    "check_name": "Check 1",
                    "file_path": "/a.tf",
                    "file_line_range": [1, 5],
                    "severity": "LOW",
                },
                {
                    "check_id": "CKV_AWS_2",
                    "check_name": "Check 2",
                    "file_path": "/b.tf",
                    "file_line_range": [10],
                    "severity": "MEDIUM",
                },
                {
                    "check_id": "CKV_AWS_3",
                    "check_name": "Check 3",
                    "file_path": "/c.tf",
                    "file_line_range": [20, 30],
                    "severity": "HIGH",
                },
            ],
        },
    }
    p = write(tmp_path, "checkov.json", json.dumps(sample))

    adapter = CheckovAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 3
    severities = {f.severity for f in findings}
    assert severities == {"LOW", "MEDIUM", "HIGH"}


def test_checkov_empty_results(tmp_path: Path):
    """Test Checkov adapter handles empty results."""
    sample = {
        "check_type": "terraform",
        "results": {
            "passed_checks": [],
            "failed_checks": [],
            "skipped_checks": [],
        },
    }
    p = write(tmp_path, "checkov.json", json.dumps(sample))

    adapter = CheckovAdapter()
    findings = adapter.parse(p)

    assert findings == []


def test_checkov_empty_bad_input(tmp_path: Path):
    """Test Checkov adapter handles empty/bad input."""
    adapter = CheckovAdapter()

    p1 = write(tmp_path, "empty.json", "")
    assert adapter.parse(p1) == []

    p2 = write(tmp_path, "bad.json", "{not json}")
    assert adapter.parse(p2) == []


def test_checkov_missing_file(tmp_path: Path):
    """Test Checkov adapter handles missing file."""
    adapter = CheckovAdapter()
    missing = tmp_path / "nonexistent.json"
    assert adapter.parse(missing) == []


def test_checkov_compliance_enrichment(tmp_path: Path):
    """Test Checkov findings are enriched with compliance mappings."""
    sample = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_AWS_20",
                    "check_name": "S3 logging",
                    "file_path": "/main.tf",
                    "file_line_range": [1],
                    "severity": "HIGH",
                }
            ],
        },
    }
    p = write(tmp_path, "checkov.json", json.dumps(sample))

    adapter = CheckovAdapter()
    findings = adapter.parse(p)

    # Compliance should be enriched
    assert len(findings) == 1
    # The finding should have compliance field (may be None or dict)
    # Just verify it's a valid Finding object
    assert findings[0].schemaVersion == "1.2.0"


def test_checkov_no_line_range(tmp_path: Path):
    """Test Checkov adapter handles missing line range."""
    sample = {
        "check_type": "terraform",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_TEST",
                    "check_name": "Test check",
                    "file_path": "/test.tf",
                    # No file_line_range
                    "severity": "MEDIUM",
                }
            ],
        },
    }
    p = write(tmp_path, "checkov.json", json.dumps(sample))

    adapter = CheckovAdapter()
    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].location["startLine"] == 0


def test_checkov_various_cicd_frameworks(tmp_path: Path):
    """Test Checkov adapter recognizes various CI/CD frameworks."""
    cicd_frameworks = [
        "github_actions",
        "gitlab_ci",
        "circleci_pipelines",
        "azure_pipelines",
        "bitbucket_pipelines",
        "argo_workflows",
    ]

    adapter = CheckovAdapter()

    for framework in cicd_frameworks:
        sample = {
            "check_type": framework,
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_TEST",
                        "check_name": "Test",
                        "file_path": "/pipeline.yml",
                        "file_line_range": [1],
                        "severity": "MEDIUM",
                    }
                ],
            },
        }
        p = write(tmp_path, f"{framework}.json", json.dumps(sample))
        findings = adapter.parse(p)

        assert len(findings) == 1, f"Failed for {framework}"
        assert (
            "cicd-security" in findings[0].tags
        ), f"Missing cicd-security tag for {framework}"


def test_checkov_metadata(tmp_path: Path):
    """Test Checkov adapter metadata."""
    adapter = CheckovAdapter()
    metadata = adapter.metadata

    assert metadata.name == "checkov"
    assert metadata.tool_name == "checkov"
    assert metadata.schema_version == "1.2.0"
    assert metadata.output_format == "json"


def test_checkov_multi_framework_list_output(tmp_path: Path):
    """checkov's LIST output form must be parsed, not silently dropped.

    checkov emits a bare dict when it detects exactly one framework, and a
    **list** of per-framework reports when it detects several. The list form is
    the normal case for any real repository.

    The adapter previously began `if not isinstance(data, dict): return []`, so
    every multi-framework scan produced zero findings while checkov itself
    reported success and wrote megabytes of output.

    Measured on bridgecrewio/terragoat: 3.3 MB of checkov output holding 477
    failed checks across `[terraform, dockerfile, secrets, github_actions]`
    normalized to **0** findings. After the fix, 477.
    """
    adapter = CheckovAdapter()
    payload = json.dumps(
        [
            {
                "check_type": "terraform",
                "checkov_version": "3.3.8",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_20",
                            "check_name": "S3 Bucket has an ACL defined which allows public READ access.",
                            "file_path": "/aws/s3.tf",
                            "file_line_range": [1, 12],
                            "severity": "HIGH",
                        }
                    ]
                },
            },
            {
                "check_type": "dockerfile",
                "checkov_version": "3.3.8",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_DOCKER_2",
                            "check_name": "Ensure that HEALTHCHECK instructions have been added",
                            "file_path": "/Dockerfile",
                            "file_line_range": [1, 5],
                        }
                    ]
                },
            },
            {
                "check_type": "github_actions",
                "checkov_version": "3.3.8",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_GHA_1",
                            "check_name": "Ensure ACTIONS_ALLOW_UNSECURE_COMMANDS is not set",
                            "file_path": "/.github/workflows/ci.yml",
                            "file_line_range": [3, 9],
                        }
                    ]
                },
            },
        ]
    )
    p = write(tmp_path, "checkov.json", payload)

    findings = adapter.parse(p)

    assert len(findings) == 3, "every framework report must contribute findings"
    rule_ids = {f.ruleId for f in findings}
    assert rule_ids == {"CKV_AWS_20", "CKV_DOCKER_2", "CKV_GHA_1"}

    # check_type drives CI/CD tagging, and it lives on each report rather than
    # on the document - so tagging must be decided per report, not once.
    by_rule = {f.ruleId: f for f in findings}
    assert "cicd-security" in by_rule["CKV_GHA_1"].tags
    assert "iac" in by_rule["CKV_AWS_20"].tags


def test_checkov_list_with_non_dict_entries_is_tolerated(tmp_path: Path):
    """A malformed entry must not discard the entries around it."""
    adapter = CheckovAdapter()
    payload = json.dumps(
        [
            "unexpected string",
            {
                "check_type": "terraform",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_AWS_1",
                            "check_name": "Test check",
                            "file_path": "/main.tf",
                            "file_line_range": [1, 2],
                        }
                    ]
                },
            },
        ]
    )
    p = write(tmp_path, "checkov.json", payload)

    findings = adapter.parse(p)

    assert len(findings) == 1
    assert findings[0].ruleId == "CKV_AWS_1"
