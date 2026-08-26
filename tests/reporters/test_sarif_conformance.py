#!/usr/bin/env python3
"""SARIF 2.1.0 conformance guard for `sarif_reporter`.

`json.loads()` succeeding on a SARIF file proves only that the file is JSON.
It was, and it was also invalid SARIF: a real `deep` scan of 242 findings
produced **340 schema errors**, in five distinct classes, while parsing
perfectly. The oracle has to be the spec, not the artifact.

The schema is vendored so this runs offline and stays stable::

    https://docs.oasis-open.org/sarif/sarif/v2.1.0/errata01/os/schemas/sarif-schema-2.1.0.json
    fetched 2026-08-15, 112,768 bytes,
    sha256 c3b4bb2d6093897483348925aaa73af03b3e3f4bd4ca38cef26dcb4212a2682e

SARIF 2.1.0 errata01 is a finished OASIS standard, so the copy does not drift.
The schema declares draft-04, so the validator is chosen from the schema rather
than assumed -- `validator_for` is part of the oracle.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import jsonschema
import pytest

from scripts.core.reporters.sarif_reporter import SARIF_SCHEMA_URI, to_sarif

SCHEMA_PATH = Path(__file__).parent.parent / "fixtures" / "schemas" / "sarif-2.1.0.json"


@pytest.fixture(scope="module")
def sarif_validator():
    """A validator built from the vendored schema's own declared dialect."""
    schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    validator_cls = jsonschema.validators.validator_for(schema)
    return validator_cls(schema)


def _errors(validator, doc: dict[str, Any]) -> list[str]:
    return [
        f"{'/'.join(str(x) for x in e.absolute_path)}: {e.message}"
        for e in validator.iter_errors(doc)
    ]


# Each entry reproduces one of the five classes measured on the real scan.
HOSTILE_FINDINGS: list[dict[str, Any]] = [
    {
        # dict remediation -- semgrep/checkov adapters emit this shape
        "id": "abcdef0123456789",
        "ruleId": "yaml.docker-compose.security.privileged-service",
        "title": "Privileged service",
        "message": "Service 'web' runs privileged",
        "description": "Grants root-equivalent capabilities on the host",
        "severity": "HIGH",
        "remediation": {
            "fix": "false",
            "steps": ["Apply the suggested fix above", "Test the changes"],
        },
        "tags": ["sast", "CWE-269"],
        "location": {"path": "docker-compose.yml", "startLine": 12, "endLine": 14},
        "context": {"snippet": "privileged: true"},
    },
    {
        # no line information at all -- must NOT become startLine 0
        "id": "fedcba9876543210",
        "ruleId": "SBOM-COMPONENT",
        "message": "Component without license",
        "severity": "LOW",
        "location": {"path": "package-lock.json"},
    },
    {
        # explicit zero, which is what the reporter used to default to
        "id": "0011223344556677",
        "ruleId": "ZERO-LINE",
        "message": "Finding reported against the whole file",
        "severity": "MEDIUM",
        "location": {"path": "Dockerfile", "startLine": 0, "endLine": 0},
    },
    {
        # clustered finding: id rewritten to cluster-<fp> (#847), not a GUID
        "id": "cluster-c9e24f6485fabed0",
        "ruleId": "CKV_K8S_16",
        "message": "Container should not be privileged",
        "severity": "CRITICAL",
        "remediation": "Set securityContext.privileged to false",
        "location": {"path": "iac/pod.yaml", "startLine": 4},
        "detected_by": [
            {"name": "checkov", "version": "3.2.0"},
            {"name": "trivy", "version": "0.58.0"},
        ],
    },
    {
        # a genuine GUID id -- the one case correlationGuid may carry
        "id": "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "ruleId": "GUID-RULE",
        "message": "Finding with a real GUID",
        "severity": "INFO",
        "remediation": "Prose remediation, not a machine-applicable edit",
        "location": {"path": "app.py", "startLine": 7},
        "detected_by": [{"name": "bandit"}, {"name": "semgrep"}],
    },
]


class TestSarifSchemaConformance:
    """The property: the document validates. Not that it parses."""

    def test_hostile_findings_produce_a_valid_sarif_document(self, sarif_validator):
        doc = to_sarif(HOSTILE_FINDINGS)
        errs = _errors(sarif_validator, doc)
        assert errs == [], f"{len(errs)} SARIF schema errors: {errs[:8]}"

    def test_empty_findings_produce_a_valid_sarif_document(self, sarif_validator):
        assert _errors(sarif_validator, to_sarif([])) == []

    def test_every_finding_is_still_represented(self):
        """Validity must not have been bought by dropping results."""
        doc = to_sarif(HOSTILE_FINDINGS)
        assert sum(len(r["results"]) for r in doc["runs"]) == len(HOSTILE_FINDINGS)


class TestSarifRegressions:
    """One test per measured defect, so a reintroduction names itself."""

    def test_dict_remediation_becomes_a_string(self):
        rules = to_sarif(HOSTILE_FINDINGS)["runs"][0]["tool"]["driver"]["rules"]
        helps = [r["help"] for r in rules]
        assert helps, "no rules produced"
        for h in helps:
            assert isinstance(h["text"], str), f"help.text is {type(h['text'])}"
            assert isinstance(h["markdown"], str)
        # the dict's content survives the coercion rather than being discarded
        joined = " ".join(h["text"] for h in helps)
        assert "Apply the suggested fix above" in joined

    def test_missing_or_zero_line_omits_startline(self):
        results = to_sarif(HOSTILE_FINDINGS)["runs"][0]["results"]
        for r in results:
            region = r["locations"][0]["physicalLocation"].get("region", {})
            if "startLine" in region:
                assert region["startLine"] >= 1, r["ruleId"]
        # the two line-less findings must still be reported
        rule_ids = {r["ruleId"] for r in results}
        assert {"SBOM-COMPONENT", "ZERO-LINE"} <= rule_ids

    def test_non_guid_id_is_not_emitted_as_correlation_guid(self):
        results = to_sarif(HOSTILE_FINDINGS)["runs"][0]["results"]
        by_rule = {r["ruleId"]: r for r in results}
        clustered = by_rule["CKV_K8S_16"]
        assert "correlationGuid" not in clustered
        # ...but the id is not lost
        assert (
            clustered["properties"]["jmoFindingId"] == "cluster-c9e24f6485fabed0"
        ), clustered.get("properties")

    def test_a_real_guid_is_still_emitted_as_correlation_guid(self):
        """Negative control: the field is not simply disabled."""
        by_rule = {
            r["ruleId"]: r for r in to_sarif(HOSTILE_FINDINGS)["runs"][0]["results"]
        }
        assert (
            by_rule["GUID-RULE"]["correlationGuid"]
            == "3f2504e0-4f89-41d3-9a0c-0305e82c3301"
        )

    def test_prose_remediation_is_not_claimed_as_a_sarif_fix(self):
        """A SARIF `fix` requires artifactChanges; prose is not one."""
        results = to_sarif(HOSTILE_FINDINGS)["runs"][0]["results"]
        assert all("fixes" not in r for r in results)
        by_rule = {r["ruleId"]: r for r in results}
        assert (
            by_rule["CKV_K8S_16"]["properties"]["remediation"]
            == "Set securityContext.privileged to false"
        )

    def test_schema_uri_is_not_the_retired_schemastore_host(self):
        """`schemastore.azurewebsites.net` answers 403 -- measured 2026-08-15."""
        assert "azurewebsites.net" not in SARIF_SCHEMA_URI
        assert to_sarif([])["$schema"] == SARIF_SCHEMA_URI
        assert SARIF_SCHEMA_URI.startswith("https://")
