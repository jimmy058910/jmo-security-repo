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
    ],
)
def test_structured_shapes_tools_actually_use(raw, expected):
    assert extract_cwes_from_raw(raw) == expected


def test_duplicates_collapse_and_order_is_preserved():
    raw = {"cwe": ["CWE-89", "CWE-79", "cwe_89"]}
    assert extract_cwes_from_raw(raw) == ["CWE-89", "CWE-79"]


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
    assert extract_cwes_from_raw(raw) == []


def test_prose_is_never_read():
    """Only structured keys are read, at the top level of `raw`.

    Prose was read for horusec alone, from an allowlist; that tool left in
    v2.0.0 and the allowlist with it. A CWE named in a free-text field is not
    the tool's structured claim, so neither a nested `details` nor a top-level
    description may yield one.
    """
    assert extract_cwes_from_raw({"vulnerabilities": {"details": "CWE-798"}}) == []
    assert extract_cwes_from_raw({"description": "see CWE-89 advisory"}) == []


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
    assert extract_cwes_from_raw(raw) == []


def test_a_long_digit_run_is_not_mistaken_for_a_cwe():
    assert extract_cwes_from_raw({"cwe": "CWE-1234567"}) == []


# ---------------------------------------------------------------------------
# Backfill
# ---------------------------------------------------------------------------


def test_backfill_populates_risk_cwe_as_an_array():
    findings = [{"tool": {"name": "zap"}, "raw": {"cweid": "89"}}]

    assert backfill_risk_cwe(findings) == 1

    # An ARRAY of strings per docs/schemas/common_finding.v1.json; a bare string
    # here was the only schema violation in a 242-finding scan.
    assert findings[0]["risk"]["cwe"] == ["CWE-89"]


def test_backfill_never_overwrites_what_an_adapter_already_set():
    """semgrep had the tool's structured metadata; this works from a copy.

    `raw` carries a readable CWE of its own, so a backfill that ignored the
    adapter's value would have something to overwrite it with.
    """
    findings = [
        {
            "tool": {"name": "semgrep"},
            "risk": {"cwe": ["CWE-89"], "confidence": "HIGH"},
            "raw": {"cwe": "CWE-502"},
        }
    ]

    assert backfill_risk_cwe(findings) == 0
    assert findings[0]["risk"]["cwe"] == ["CWE-89"]
    assert findings[0]["risk"]["confidence"] == "HIGH", "siblings must survive"


def test_backfill_preserves_other_risk_keys():
    findings = [
        {
            "tool": {"name": "zap"},
            "risk": {"confidence": "HIGH"},
            "raw": {"cweid": "78"},
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
            "ruleId": "ZAP-89",
            "severity": "HIGH",
            "tool": {"name": "zap"},
            "location": {"path": "http://example.com/page"},
            "message": "m",
            "raw": {"cweid": "89"},
        }

    without = enrich_finding_with_compliance(_finding())
    assert not (without.get("compliance") or {}).get("cweTop25_2024")

    lifted = _finding()
    backfill_risk_cwe([lifted])
    with_cwe = enrich_finding_with_compliance(lifted)
    assert (with_cwe.get("compliance") or {}).get("cweTop25_2024"), (
        "CWE-89 is in the CWE Top 25; lifting it must reach the framework"
    )


def test_the_pipeline_actually_calls_the_backfill(tmp_path):
    """A fix can be correct and never run.

    Every other test here exercises the functions directly, so all of them pass
    with the `gather_results` call site deleted - which a mutation run caught.
    This one goes through the real report path with real zap output: the zap
    adapter keeps `cweid` in `raw` and sets no `risk`, so the backfill is the
    only thing that can put CWE-89 into `risk.cwe`.
    """
    import json

    from scripts.core import normalize_and_report as nr

    results = tmp_path / "results"
    (results / "individual-repos" / "r").mkdir(parents=True)
    (results / "individual-repos" / "r" / "zap.json").write_text(
        json.dumps(
            {
                "@version": "2.17.0",
                "site": [
                    {
                        "alerts": [
                            {
                                "alert": "SQL Injection",
                                "risk": "High",
                                "confidence": "Medium",
                                "desc": "SQL injection may be possible.",
                                "cweid": "89",
                                "wascid": "19",
                                "instances": [
                                    {
                                        "uri": "http://example.com/page?id=1",
                                        "method": "GET",
                                        "param": "id",
                                    }
                                ],
                            }
                        ]
                    }
                ],
            }
        ),
        encoding="utf-8",
    )

    findings = nr.gather_results(results)

    assert findings, "the zap adapter produced nothing to assert on"
    assert [(f.get("risk") or {}).get("cwe") for f in findings] == [["CWE-89"]]
    assert (findings[0].get("compliance") or {}).get("cweTop25_2024"), (
        "the lift must happen before compliance enrichment, or it reaches nothing"
    )
