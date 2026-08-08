"""
Contract tests: real adapter output must validate against the published schema.

The gap these close: `docs/schemas/common_finding.v1.json` is the schema JMo
publishes, but nothing ever validated *actual scan output* against it.
`schema_validator` was imported only by `scripts/core/validators/scan_validator.py`,
and only with synthetic inputs (`validate_finding({})`, `validate_findings([])`) --
that checks the validator, not the adapters.

So the two drifted. The schema declared `"cvss": {"type": "number"}` while every
producer emitted an object and `history_db.py` read `.get("score")` off it. The
schema was wrong for at least three releases and no test could notice, because no
test ever fed it a real finding.

These tests feed it real findings. They are cheap because they reuse each
adapter's own parse path -- no tools required, no network.

See issue #757.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from scripts.core.schema_validator import (
    JSONSCHEMA_AVAILABLE,
    load_schema,
    validate_finding,
)

pytestmark = pytest.mark.skipif(
    not JSONSCHEMA_AVAILABLE, reason="jsonschema not installed"
)


# --------------------------------------------------------------------------
# Raw tool payloads, shaped like the real thing. Kept minimal but structurally
# faithful -- the point is to exercise the adapter's own mapping code.
# --------------------------------------------------------------------------

GRYPE_RAW: dict[str, Any] = {
    "matches": [
        {
            "vulnerability": {
                "id": "CVE-2024-1234",
                "severity": "High",
                "description": "Example vulnerability in a pinned dependency",
                "cvss": [
                    {
                        "version": "3.1",
                        "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        "metrics": {"baseScore": 9.8},
                    }
                ],
                "fix": {"versions": ["1.2.3"], "state": "fixed"},
            },
            "artifact": {
                "name": "libexample",
                "version": "1.0.0",
                "type": "python",
                "purl": "pkg:pypi/libexample@1.0.0",
                "locations": [{"path": "/app/requirements.txt"}],
            },
        }
    ]
}

DEPENDENCY_CHECK_RAW: dict[str, Any] = {
    "scanInfo": {"engineVersion": "10.0.4"},
    "dependencies": [
        {
            "fileName": "libexample-1.0.0.jar",
            "filePath": "/app/lib/libexample-1.0.0.jar",
            "vulnerabilities": [
                {
                    "name": "CVE-2024-5678",
                    "severity": "CRITICAL",
                    "description": "Example vulnerability in a jar",
                    "cvssv3": {
                        "baseScore": 9.1,
                        "baseSeverity": "CRITICAL",
                        "vectorString": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                    },
                }
            ],
        }
    ],
}


def _parse_grype(path: Path) -> list[dict[str, Any]]:
    from scripts.core.adapters.grype_adapter import _load_grype_internal

    return _load_grype_internal(path)


def _parse_dependency_check(path: Path) -> list[dict[str, Any]]:
    from scripts.core.adapters.dependency_check_adapter import (
        _load_dependency_check_internal,
    )

    return _load_dependency_check_internal(path)


# (label, raw payload, parse function) -- both known cvss producers.
CVSS_PRODUCERS = [
    ("grype", GRYPE_RAW, _parse_grype),
    ("dependency-check", DEPENDENCY_CHECK_RAW, _parse_dependency_check),
]


@pytest.mark.parametrize(
    "label,raw,parse", CVSS_PRODUCERS, ids=[p[0] for p in CVSS_PRODUCERS]
)
def test_adapter_output_validates_against_published_schema(
    label: str, raw: dict[str, Any], parse: Any, tmp_path: Path
) -> None:
    """Findings an adapter really produces must satisfy the published schema."""
    out_file = tmp_path / f"{label}.json"
    out_file.write_text(json.dumps(raw), encoding="utf-8")

    findings = parse(out_file)
    assert findings, f"{label} adapter parsed zero findings from a valid payload"

    schema = load_schema()
    for finding in findings:
        errors = validate_finding(finding, schema)
        assert not errors, f"{label} finding violates the published schema: {errors}"


@pytest.mark.parametrize(
    "label,raw,parse", CVSS_PRODUCERS, ids=[p[0] for p in CVSS_PRODUCERS]
)
def test_cvss_is_an_object_carrying_its_vector(
    label: str, raw: dict[str, Any], parse: Any, tmp_path: Path
) -> None:
    """cvss is an object with a numeric score, not a bare number.

    `history_db.py` reads `finding.get("cvss", {}).get("score")`. A bare float
    there raises AttributeError, so the object shape is load-bearing rather than
    stylistic -- and dropping the vector would discard the score's provenance.
    """
    out_file = tmp_path / f"{label}.json"
    out_file.write_text(json.dumps(raw), encoding="utf-8")

    findings = parse(out_file)
    cvss_values = [f["cvss"] for f in findings if f.get("cvss") is not None]
    assert cvss_values, f"{label} produced no cvss for a payload that carries one"

    for cvss in cvss_values:
        assert isinstance(
            cvss, dict
        ), f"{label} emitted {type(cvss).__name__}, not dict"
        assert isinstance(cvss["score"], (int, float))
        assert 0 <= cvss["score"] <= 10
        assert cvss.get("vector"), "vector dropped -- the score is no longer auditable"
        # The exact accessor history_db.py uses.
        assert cvss.get("score") is not None


def test_schema_rejects_a_bare_number_cvss() -> None:
    """Guard the guard: prove the rule bites instead of merely being permissive.

    Without this, relaxing `cvss` back to something that accepts anything would
    keep every test above green.
    """
    schema = load_schema()
    finding = {
        "schemaVersion": "1.2.0",
        "id": "0123456789abcdef",
        "ruleId": "CVE-2024-1234",
        "severity": "HIGH",
        "tool": {"name": "grype", "version": "0.100.0"},
        "location": {"path": "/app/requirements.txt", "startLine": 0},
        "message": "Example",
        "cvss": 9.8,
    }
    errors = validate_finding(finding, schema)
    assert errors, "schema accepted a bare-number cvss; the object rule is not enforced"
    assert any("object" in e for e in errors), errors


def test_schema_requires_a_score_when_cvss_is_present() -> None:
    """A cvss object without a score is useless to its only consumer."""
    schema = load_schema()
    finding = {
        "schemaVersion": "1.2.0",
        "id": "0123456789abcdef",
        "ruleId": "CVE-2024-1234",
        "severity": "HIGH",
        "tool": {"name": "grype", "version": "0.100.0"},
        "location": {"path": "/app/requirements.txt", "startLine": 0},
        "message": "Example",
        "cvss": {"version": "3.x", "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
    }
    errors = validate_finding(finding, schema)
    assert errors, "schema accepted a cvss object with no score"
