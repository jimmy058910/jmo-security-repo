"""Regression tests for #845 - a tool's own CWE must reach `risk.cwe`.

`compliance_mapper` reads CWEs from `finding["risk"]["cwe"]` and nowhere else,
so a CWE the tool reported but the adapter did not lift reaches no framework.

Measured A/B on a real 152-finding `deep` scan, with the backfill disabled and
re-enabled (the disable asserted to have applied):

=================  ======  =====
metric             before  after
=================  ======  =====
`risk.cwe`              0     31
`cweTop25_2024`         0     21
`owaspTop10_2021`      60     80
`mitreAttack`          46     61
findings              152    152
=================  ======  =====

**The safety property these tests exist for** is the checkov case. The issue
put checkov at 13 CWEs in raw. Measured, all 13 are the string ``CWE``
appearing inside ``raw.code_block`` - *the scanned file's own source text*, from
a fixture comment reading ``# Hardcoded credentials (CWE-798)``. checkov's
structured fields are all `None`. Reading that would attribute a CWE to a
finding because the scanned repository mentioned one, so any codebase with
``# CWE-89`` in a comment would acquire spurious compliance mappings.
"""

from __future__ import annotations

import pytest

from scripts.core.cwe_extraction import backfill_risk_cwe, extract_cwes_from_raw

# ---------------------------------------------------------------------------
# What must be read
# ---------------------------------------------------------------------------


def test_bandit_issue_cwe_is_lifted():
    """The shape bandit actually emits, from a real scan."""
    raw = {"issue_cwe": {"id": 502, "link": "https://cwe.mitre.org/..."}}
    assert extract_cwes_from_raw(raw, "bandit") == ["CWE-502"]


def test_horusec_cites_its_cwe_only_in_prose():
    """horusec writes no structured CWE; it names one in its own `details`."""
    raw = {
        "vulnerabilities": {
            "details": (
                "(1/1) * Possible vulnerability detected: AWS Manager ID. For "
                "more information checkout the CWE-798 "
                "(https://cwe.mitre.org/data/definitions/798.html) advisory."
            )
        }
    }
    assert extract_cwes_from_raw(raw, "horusec") == ["CWE-798"]


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ({"cwe": "CWE-89"}, ["CWE-89"]),
        ({"CWE": "CWE-89"}, ["CWE-89"]),
        ({"cwe": 89}, ["CWE-89"]),
        ({"cwe": "89"}, ["CWE-89"]),
        ({"cweid": "79"}, ["CWE-79"]),
        ({"cwe": ["CWE-89", "CWE-943"]}, ["CWE-89", "CWE-943"]),
        ({"cwe": "CWE-522: Insufficiently Protected Credentials"}, ["CWE-522"]),
        ({"issue_cwe": {"id": 78}}, ["CWE-78"]),
    ],
)
def test_structured_shapes_tools_actually_use(raw, expected):
    assert extract_cwes_from_raw(raw, "any") == expected


def test_duplicates_collapse_and_order_is_preserved():
    raw = {"cwe": ["CWE-89", "CWE-79", "cwe_89"]}
    assert extract_cwes_from_raw(raw, "t") == ["CWE-89", "CWE-79"]


# ---------------------------------------------------------------------------
# What must NOT be read
# ---------------------------------------------------------------------------


def test_a_cwe_in_the_scanned_files_source_is_never_read():
    """The whole safety property of this module.

    `code_block` is checkov echoing the scanned file. A CWE mentioned there was
    written by whoever wrote the repository, not by checkov.
    """
    raw = {
        "check_id": "CKV_AWS_23",
        "code_block": [[60, "  # Hardcoded credentials (CWE-798)\n"]],
        "bc_category": None,
        "benchmarks": None,
        "description": None,
        "vulnerability_details": None,
    }
    assert extract_cwes_from_raw(raw, "checkov") == []


def test_prose_is_only_read_from_the_tools_that_declare_it():
    """horusec's `details` is read; the same text under any other tool is not.

    Keeps the allowlist honest: adding a tool here is a decision, not a
    side effect of a field happening to be named `details`.
    """
    raw = {"vulnerabilities": {"details": "see CWE-798 advisory"}}
    assert extract_cwes_from_raw(raw, "horusec") == ["CWE-798"]
    assert extract_cwes_from_raw(raw, "checkov") == []
    assert extract_cwes_from_raw(raw, "") == []


@pytest.mark.parametrize(
    "raw",
    [
        None,
        [],
        "a string",
        {},
        {"cwe": None},
        {"cwe": ""},
        {"cwe": True},  # bool is an int; `cwe: true` is not CWE-1
        {"cwe": "not a cwe"},
        {"issue_cwe": None},
        {"cwe": {"nested": "CWE-89"}},
    ],
)
def test_anything_unreadable_yields_nothing(raw):
    """A wrong CWE produces a wrong compliance mapping, which is worse than none."""
    assert extract_cwes_from_raw(raw, "bandit") == []


def test_a_long_digit_run_is_not_mistaken_for_a_cwe():
    assert extract_cwes_from_raw({"cwe": "CWE-1234567"}, "t") == []


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------


def test_backfill_populates_risk_cwe_as_an_array():
    findings = [{"tool": {"name": "bandit"}, "raw": {"issue_cwe": {"id": 502}}}]

    assert backfill_risk_cwe(findings) == 1

    # An ARRAY of strings per docs/schemas/common_finding.v1.json; a bare string
    # here was the only schema violation in a 242-finding scan.
    assert findings[0]["risk"]["cwe"] == ["CWE-502"]


def test_backfill_never_overwrites_what_an_adapter_already_set():
    """semgrep had the tool's structured metadata; this works from a copy."""
    findings = [
        {
            "tool": {"name": "semgrep"},
            "risk": {"cwe": ["CWE-89"], "confidence": "HIGH"},
            "raw": {"issue_cwe": {"id": 502}},
        }
    ]

    assert backfill_risk_cwe(findings) == 0
    assert findings[0]["risk"]["cwe"] == ["CWE-89"]
    assert findings[0]["risk"]["confidence"] == "HIGH", "siblings must survive"


def test_backfill_preserves_other_risk_keys():
    findings = [
        {
            "tool": {"name": "bandit"},
            "risk": {"confidence": "HIGH"},
            "raw": {"issue_cwe": {"id": 78}},
        }
    ]

    backfill_risk_cwe(findings)

    assert findings[0]["risk"] == {"confidence": "HIGH", "cwe": ["CWE-78"]}


def test_backfill_leaves_findings_with_no_cwe_untouched():
    """A healthy no-CWE tool must not grow an empty `risk`."""
    findings = [{"tool": {"name": "trivy"}, "raw": {"VulnerabilityID": "CVE-1"}}]

    assert backfill_risk_cwe(findings) == 0
    assert "risk" not in findings[0]


def test_backfill_runs_before_compliance_enrichment():
    """Order is the whole point of #845.

    `enrich_finding_with_compliance` reads `risk.cwe` and nowhere else, so a
    CWE lifted afterwards reaches no framework. Asserted against the real
    mapper rather than by reading the call order.
    """
    from scripts.core.compliance_mapper import enrich_finding_with_compliance

    def _finding():
        return {
            "id": "x",
            "ruleId": "B403",
            "severity": "HIGH",
            "tool": {"name": "bandit"},
            "location": {"path": "a.py"},
            "message": "m",
            "raw": {"issue_cwe": {"id": 502}},
        }

    without = enrich_finding_with_compliance(_finding())
    assert not (without.get("compliance") or {}).get("cweTop25_2024")

    lifted = _finding()
    backfill_risk_cwe([lifted])
    with_cwe = enrich_finding_with_compliance(lifted)
    assert (with_cwe.get("compliance") or {}).get(
        "cweTop25_2024"
    ), "CWE-502 is in the CWE Top 25; lifting it must reach the framework"


def test_the_pipeline_actually_calls_the_backfill(tmp_path):
    """A fix can be correct and never run.

    Every other test here exercises the functions directly, so all of them pass
    with the `gather_results` call site deleted - which a mutation run caught.
    This one goes through the real report path with real bandit output.
    """
    import json

    from scripts.core import normalize_and_report as nr

    results = tmp_path / "results"
    (results / "individual-repos" / "r").mkdir(parents=True)
    (results / "individual-repos" / "r" / "bandit.json").write_text(
        json.dumps(
            {
                "errors": [],
                "results": [
                    {
                        "filename": "a.py",
                        "issue_confidence": "HIGH",
                        "issue_severity": "HIGH",
                        "issue_text": "Consider possible security implications.",
                        "issue_cwe": {"id": 502},
                        "line_number": 5,
                        "test_id": "B403",
                        "test_name": "blacklist",
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = nr.gather_results(results)

    assert findings, "the bandit adapter produced nothing to assert on"
    assert [(f.get("risk") or {}).get("cwe") for f in findings] == [["CWE-502"]]
    assert (findings[0].get("compliance") or {}).get(
        "cweTop25_2024"
    ), "the lift must happen before compliance enrichment, or it reaches nothing"
