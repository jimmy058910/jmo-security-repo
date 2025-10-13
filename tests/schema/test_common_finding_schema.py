import json
from pathlib import Path

import pytest

from scripts.core.adapters.gitleaks_adapter import load_gitleaks
from scripts.core.schema_utils import validate_findings


def test_schema_validation_with_samples(tmp_path: Path):
    # use a small gitleaks sample
    sample = [
        {
            "RuleID": "generic-api-key",
            "Description": "Generic API Key",
            "File": "a.py",
            "StartLine": 1,
            "Severity": "HIGH",
        }
    ]
    p = tmp_path / "gitleaks.json"
    p.write_text(json.dumps(sample), encoding="utf-8")
    findings = load_gitleaks(p)
    assert len(findings) == 1
    assert validate_findings(findings) is True


@pytest.mark.skipif(__import__('importlib').util.find_spec('jsonschema') is None, reason="jsonschema not installed")
def test_schema_validation_empty_ok():
    assert validate_findings([]) is True
