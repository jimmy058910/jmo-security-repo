import json
from pathlib import Path

import pytest

from scripts.core.adapters.trufflehog_adapter import TruffleHogAdapter
from scripts.core.schema_utils import validate_findings


def test_schema_validation_with_samples(tmp_path: Path):
    # use a small trufflehog sample
    sample = {
        "SourceMetadata": {"Data": {"Git": {"file": "a.py", "line": 1}}},
        "DetectorName": "API_KEY",
        "Verified": True,
        "Raw": "secret123",
    }
    p = tmp_path / "trufflehog.json"
    p.write_text(json.dumps([sample]), encoding="utf-8")
    adapter = TruffleHogAdapter()
    findings = adapter.parse(p)
    # Convert Finding objects to dicts for validation (excluding None values)
    findings_dicts = [f.to_dict() for f in findings]
    assert len(findings) == 1
    assert validate_findings(findings_dicts) is True


@pytest.mark.skipif(
    __import__("importlib").util.find_spec("jsonschema") is None,
    reason="jsonschema not installed",
)
def test_schema_validation_empty_ok():
    assert validate_findings([]) is True
