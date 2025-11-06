#!/usr/bin/env python3
"""
Integration test for cross-tool deduplication in normalize_and_report.py

Tests the end-to-end flow of Phase 1 (fingerprint) + Phase 2 (clustering) deduplication.
"""
import json
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def fixture_path() -> Path:
    """Path to cross_tool_findings.json fixture."""
    return Path(__file__).parent.parent / "fixtures" / "cross_tool_findings.json"


@pytest.fixture
def sql_injection_cluster(fixture_path) -> list[dict[str, Any]]:
    """Load SQL injection cluster from fixtures."""
    with open(fixture_path) as f:
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

    # Run clustering (uses default 0.50 threshold)
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
    assert sql_injection_consensus is not None, "Expected SQL injection consensus finding"
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
