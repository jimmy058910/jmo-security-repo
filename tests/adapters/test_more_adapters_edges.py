import json
from pathlib import Path

from scripts.core.adapters.hadolint_adapter import load_hadolint
from scripts.core.adapters.noseyparker_adapter import load_noseyparker
from scripts.core.adapters.tfsec_adapter import load_tfsec
from scripts.core.adapters.checkov_adapter import load_checkov


def _write(p: Path, obj):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj), encoding="utf-8")


def test_hadolint_missing_fields_and_levels(tmp_path: Path):
    # Missing file/line fields; varying levels should map via normalize_severity
    data = [
        {"code": "DL1", "message": "m1", "level": "warning"},
        {"code": "DL2", "message": "m2", "level": "error"},
        {"code": "DL3", "message": "m3", "level": "info"},
        {},  # fallback defaults
    ]
    f = tmp_path / "hadolint.json"
    _write(f, data)
    out = load_hadolint(f)
    assert len(out) == 4
    sevs = {o["ruleId"]: o["severity"] for o in out}
    # warning -> MEDIUM, error -> HIGH, info -> INFO per normalize_severity
    assert sevs["DL1"] == "MEDIUM"
    assert sevs["DL2"] == "HIGH"
    assert sevs["DL3"] == "INFO"


def test_hadolint_reference_and_non_list_payload(tmp_path: Path):
    # reference field becomes remediation; non-list payload returns []
    with_ref = [
        {
            "code": "DL4",
            "file": "Dockerfile",
            "line": 1,
            "message": "m",
            "level": "warning",
            "reference": "https://doc",
        }
    ]
    f1 = tmp_path / "hadolint1.json"
    _write(f1, with_ref)
    out1 = load_hadolint(f1)
    assert out1 and out1[0]["remediation"].startswith("https://")

    not_list = {"code": "x"}
    f2 = tmp_path / "hadolint2.json"
    _write(f2, not_list)
    out2 = load_hadolint(f2)
    assert out2 == []


def test_hadolint_unrecognized_level_maps_info_and_tags(tmp_path: Path):
    data = [{"code": "DLX", "message": "m", "level": "unknown"}]
    f = tmp_path / "hadolint3.json"
    _write(f, data)
    out = load_hadolint(f)
    assert out and out[0]["severity"] == "INFO"
    assert set(out[0].get("tags", [])) >= {"dockerfile", "lint"}


def test_noseyparker_alt_keys(tmp_path: Path):
    # Use DetectorName and nested location.startLine/path
    data = {
        "version": "x",
        "matches": [
            {
                "DetectorName": "Slack Token",
                "location": {"path": "a.txt", "startLine": 42},
                "context": "ctx",
            }
        ],
    }
    f = tmp_path / "np.json"
    _write(f, data)
    out = load_noseyparker(f)
    assert (
        out
        and out[0]["ruleId"] == "Slack Token"
        and out[0]["location"]["startLine"] == 42
    )


def test_tfsec_alt_keys(tmp_path: Path):
    # Use top-level id/filename/start_line instead of location.*
    data = {
        "results": [
            {
                "id": "AWS002",
                "filename": "main.tf",
                "start_line": 9,
                "description": "desc",
                "severity": "LOW",
            }
        ]
    }
    f = tmp_path / "tfsec.json"
    _write(f, data)
    out = load_tfsec(f)
    assert out and out[0]["ruleId"] == "AWS002" and out[0]["severity"] == "LOW"


def test_tfsec_resolution_and_missing_location(tmp_path: Path):
    # has resolution and location missing -> startLine defaults to 0
    data = {
        "results": [
            {
                "rule_id": "AWS003",
                "description": "d",
                "resolution": "fix",
                "severity": "HIGH",
            }
        ]
    }
    f = tmp_path / "tfsec2.json"
    _write(f, data)
    out = load_tfsec(f)
    assert (
        out and out[0]["remediation"] == "fix" and out[0]["location"]["startLine"] == 0
    )


def test_tfsec_description_over_impact(tmp_path: Path):
    data = {
        "results": [
            {
                "rule_id": "AWS004",
                "description": "desc-priority",
                "impact": "impact-fallback",
                "severity": "MEDIUM",
            }
        ]
    }
    f = tmp_path / "tfsec3.json"
    _write(f, data)
    out = load_tfsec(f)
    assert out and out[0]["message"] == "desc-priority"


def test_checkov_alt_keys(tmp_path: Path):
    # Use repo_file_path and no file_line_range list
    data = {
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_K8S_1",
                    "repo_file_path": "deploy.yml",
                    "check_name": "desc",
                    "severity": "LOW",
                    "guideline": "g",
                }
            ]
        }
    }
    f = tmp_path / "checkov.json"
    _write(f, data)
    out = load_checkov(f)
    assert (
        out and out[0]["ruleId"] == "CKV_K8S_1" and out[0]["location"]["startLine"] == 0
    )


def test_checkov_scalar_line_range_and_version(tmp_path: Path):
    data = {
        "checkov_version": "3.0.0",
        "results": {
            "failed_checks": [
                {
                    "check_id": "CKV_SCALAR",
                    "file_path": "main.tf",
                    "file_line_range": 10,
                    "severity": "MEDIUM",
                }
            ]
        },
    }
    f = tmp_path / "checkov2.json"
    _write(f, data)
    out = load_checkov(f)
    assert (
        out
        and out[0]["tool"]["version"] == "3.0.0"
        and out[0]["location"]["startLine"] == 10
    )


def test_checkov_check_name_only_and_invalid_line_range(tmp_path: Path):
    data = {
        "results": {
            "failed_checks": [
                {
                    "check_name": "OnlyName",
                    "repo_file_path": "x.tf",
                    "file_line_range": ["x"],
                    "severity": "LOW",
                }
            ]
        }
    }
    f = tmp_path / "checkov3.json"
    _write(f, data)
    out = load_checkov(f)
    assert (
        out and out[0]["ruleId"] == "OnlyName" and out[0]["location"]["startLine"] == 0
    )
