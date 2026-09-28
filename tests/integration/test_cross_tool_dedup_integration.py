#!/usr/bin/env python3
"""
Integration test for cross-tool deduplication in normalize_and_report.py

Tests the end-to-end flow of Phase 1 (fingerprint) + Phase 2 (clustering) deduplication.
"""

import itertools
import json
from pathlib import Path

import pytest

from scripts.core.adapters.gitleaks_adapter import GitleaksAdapter
from scripts.core.adapters.trivy_adapter import TrivyAdapter
from scripts.core.adapters.trufflehog_adapter import TruffleHogAdapter
from scripts.core.compliance_mapper import enrich_findings_with_compliance
from scripts.core.cwe_extraction import backfill_risk_cwe
from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates


@pytest.fixture
def fixture_path() -> Path:
    """Path to cross_tool_findings.json fixture."""
    return Path(__file__).parent.parent / "fixtures" / "cross_tool_findings.json"


@pytest.fixture
def sql_injection_cluster(fixture_path):
    """Load SQL injection cluster from fixtures."""
    with open(fixture_path, encoding="utf-8") as f:
        data = json.load(f)

    # Get the SQL injection cluster (first in known_duplicates)
    cluster = data["known_duplicates"][0]
    assert cluster["cluster_id"] == "sql_injection_users_py"
    return cluster["findings"]


def test_cluster_cross_tool_duplicates_function(sql_injection_cluster):
    """Test that _cluster_cross_tool_duplicates correctly clusters similar findings."""
    from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates

    # Add an XSS finding (should NOT cluster with SQL injection)
    xss_finding = {
        "schemaVersion": "1.2.0",
        "id": "xss-finding",
        "tool": {"name": "semgrep", "version": "1.60.0"},
        "severity": "MEDIUM",
        "message": "Cross-Site Scripting (XSS) vulnerability in template rendering",
        "location": {"path": "app/templates.py", "startLine": 100, "endLine": 102},
        "ruleId": "python.flask.security.xss.template-autoescape-off",
        "raw": {"cwe": ["CWE-79"], "owasp": "A03:2021"},
    }

    all_findings = sql_injection_cluster + [xss_finding]

    # Run clustering (uses default 0.75 threshold)
    result = _cluster_cross_tool_duplicates(all_findings)

    # Verify results
    assert len(result) == 2, (
        f"Expected 2 findings after clustering (1 SQL injection consensus + 1 XSS), "
        f"got {len(result)}"
    )

    # Find the SQL injection consensus finding
    sql_injection_consensus = None
    xss_standalone = None

    for finding in result:
        if "detected_by" in finding:
            # This is a consensus finding (should be SQL injection)
            sql_injection_consensus = finding
        else:
            # This is a standalone finding (should be XSS)
            xss_standalone = finding

    # Verify SQL injection consensus
    assert sql_injection_consensus is not None, (
        "Expected SQL injection consensus finding"
    )
    assert "detected_by" in sql_injection_consensus
    assert len(sql_injection_consensus["detected_by"]) == 3, (
        "Expected SQL injection detected by 3 tools"
    )
    tool_names = [t["name"] for t in sql_injection_consensus["detected_by"]]
    assert set(tool_names) == {"trivy", "semgrep", "bandit"}

    # Verify severity elevation (MEDIUM from bandit elevated to HIGH)
    assert sql_injection_consensus["severity"] == "HIGH"

    # Verify XSS remains standalone
    assert xss_standalone is not None, "Expected standalone XSS finding"
    assert "detected_by" not in xss_standalone
    assert xss_standalone["tool"]["name"] == "semgrep"
    assert "CWE-79" in str(xss_standalone["raw"])


def test_cluster_with_fewer_than_two_findings():
    """Test that clustering is skipped when there are fewer than 2 findings."""
    from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates

    single_finding = [
        {
            "schemaVersion": "1.2.0",
            "id": "finding-1",
            "tool": {"name": "trivy", "version": "0.50.0"},
            "severity": "HIGH",
            "message": "Test finding",
            "location": {"path": "test.py", "startLine": 1, "endLine": 1},
            "ruleId": "test-rule",
        }
    ]

    # Run clustering (should be skipped)
    result = _cluster_cross_tool_duplicates(single_finding)

    # Verify no clustering occurred
    assert len(result) == 1
    assert result == single_finding


def test_cluster_empty_list():
    """Test that clustering handles empty list gracefully."""
    from scripts.core.normalize_and_report import _cluster_cross_tool_duplicates

    # Run clustering on empty list (should return empty)
    result = _cluster_cross_tool_duplicates([])

    # Verify empty result
    assert len(result) == 0
    assert result == []


# ===== One secret, three secret scanners, every load order =====
#
# trivy, gitleaks and trufflehog each report one GitHub token on one line.
# trivy's ruleId is `github-pat` (its RuleID, since #1221), the string gitleaks
# prints too, so the two cluster on the id alone (`_rule_id_similarity` scores
# equal strings 1.0), outside `rule_equivalence.py`. trivy's secret is CRITICAL
# and gitleaks' HIGH, so trivy leads whatever cluster it is in, and the
# consensus is a copy of its finding. Before trivy's secrets carried CWE-798,
# measured through this exact path: 2 findings in all 6 orders, one of them
# led by trivy with no `risk.cwe` and no OWASP mapping (trivy+gitleaks in 3
# orders, trivy alone in the other 3). The secret left `owasp-top-10` whenever
# trivy found it. Only the mapping is asserted: that trufflehog's `Github`
# stays a finding of its own is a separate matter.
#
# No token material: trivy masks `Match` itself, the gitleaks record carries no
# snippet, and the trufflehog record no `Raw`.

_SECRET_PATH, _SECRET_LINE = "config/settings.py", 12

_TRIVY_SECRET = {
    "SchemaVersion": 2,
    "Trivy": {"Version": "0.74.0"},
    "ArtifactName": ".",
    "ArtifactType": "filesystem",
    "Results": [
        {
            "Target": _SECRET_PATH,
            "Class": "secret",
            "Secrets": [
                {
                    "RuleID": "github-pat",
                    "Category": "GitHub",
                    "Severity": "CRITICAL",
                    "Title": "GitHub Personal Access Token",
                    "StartLine": _SECRET_LINE,
                    "EndLine": _SECRET_LINE,
                    "Match": 'GITHUB_TOKEN = "****************"',
                }
            ],
        }
    ],
}

_GITLEAKS_SECRET = {
    "version": "2.1.0",
    "runs": [
        {
            "tool": {"driver": {"name": "gitleaks", "semanticVersion": "v8.0.0"}},
            "results": [
                {
                    "message": {
                        "text": f"github-pat has detected secret for file {_SECRET_PATH}."
                    },
                    "ruleId": "github-pat",
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": _SECRET_PATH},
                                "region": {
                                    "startLine": _SECRET_LINE,
                                    "startColumn": 16,
                                    "endLine": _SECRET_LINE,
                                    "endColumn": 56,
                                },
                            }
                        }
                    ],
                }
            ],
        }
    ],
}

_TRUFFLEHOG_SECRET = {
    "SourceMetadata": {
        "Data": {"Filesystem": {"file": _SECRET_PATH, "line": _SECRET_LINE}}
    },
    "DetectorName": "Github",
    "DecoderName": "PLAIN",
    "Verified": False,
}


def _one_secret_from_three_tools(tmp_path: Path) -> dict[str, list[dict]]:
    """Each tool's record, parsed by that tool's real adapter."""
    outputs = {
        "trivy": (TrivyAdapter, json.dumps(_TRIVY_SECRET)),
        "gitleaks": (GitleaksAdapter, json.dumps(_GITLEAKS_SECRET)),
        "trufflehog": (TruffleHogAdapter, json.dumps(_TRUFFLEHOG_SECRET) + "\n"),
    }
    parsed = {}
    for tool, (adapter, text) in outputs.items():
        path = tmp_path / f"{tool}.json"
        path.write_bytes(text.encode("utf-8"))
        parsed[tool] = [f.to_dict() for f in adapter().parse(path)]
        assert len(parsed[tool]) == 1, (tool, parsed[tool])
    return parsed


@pytest.mark.parametrize(
    "order",
    list(itertools.permutations(("trivy", "gitleaks", "trufflehog"))),
    ids="-".join,
)
def test_one_secret_keeps_cwe_798_and_owasp_a02_in_every_load_order(
    tmp_path: Path, order: tuple[str, ...]
):
    parsed = _one_secret_from_three_tools(tmp_path)
    findings = [f for tool in order for f in parsed[tool]]

    # The report phase's order (`normalize_and_report`): backfill, compliance,
    # then clustering.
    backfill_risk_cwe(findings)
    findings = enrich_findings_with_compliance(findings)
    result = _cluster_cross_tool_duplicates(findings, similarity_threshold=0.65)

    # Meta-guards: every tool's report is still in the result, and trivy leads
    # one finding (a consensus is a copy of its lead), which is the case that
    # lost the mapping.
    reported = {
        tool["name"] for f in result for tool in f.get("detected_by") or [f["tool"]]
    }
    assert reported == {"trivy", "gitleaks", "trufflehog"}
    assert any(f["tool"]["name"] == "trivy" for f in result)

    for f in result:
        who = [t["name"] for t in f.get("detected_by") or [f["tool"]]]
        assert "CWE-798" in ((f.get("risk") or {}).get("cwe") or []), (
            who,
            f.get("risk"),
        )
        owasp = (f.get("compliance") or {}).get("owaspTop10_2021") or []
        assert any(o.startswith("A02") for o in owasp), (who, owasp)
