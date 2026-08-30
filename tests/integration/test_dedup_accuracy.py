#!/usr/bin/env python3
"""Deduplication accuracy tests for JMo Security.

Every test here drives the real cross-tool deduplicator
(:class:`scripts.core.dedup_enhanced.FindingClusterer`) and asserts a property
of its output. That is the point of the file: it is the tree's only suite named
after deduplication *accuracy*, so a reader looking for the accuracy evidence
must land on tests that actually exercise the engine rather than on fixtures
asserting properties of themselves (#1043).

The suite is self-controlling. The *merge* tests
(``...merge``, ``...reduce_count``, ``reduction_ratio``, ``...highest_severity``)
and the *separation* tests (``...stay_separate``) fail under opposite mutations
of the engine: raising the similarity threshold so nothing clusters reddens the
merge tests while the separation tests stay green, and forcing every pair to be
identical reddens the separation tests while the merge tests stay green. Neither
mutation reddens both, so each half is the other half's control against a
clusterer that silently became a no-op or a merge-everything.

Real unit coverage of the clusterer's internals lives in
``tests/unit/test_dedup_enhanced.py``; this file asserts end-to-end accuracy
properties a maintainer would state in prose ("duplicates from different tools
collapse to one; distinct findings do not").
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import pytest

from scripts.core.dedup_enhanced import FindingClusterer


@dataclass
class Finding:
    """Simplified finding structure for dedup testing."""

    rule_id: str
    severity: str
    path: str
    line: int
    tool: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        """Convert to CommonFinding-like dict the clusterer accepts.

        ``id`` is required: the clusterer keys similarity scores and duplicate
        detection off it. tool + rule + path + line is unique across every
        finding these tests build.
        """
        return {
            "id": f"{self.tool}:{self.rule_id}:{self.path}:{self.line}",
            "ruleId": self.rule_id,
            "severity": self.severity,
            "location": {
                "path": self.path,
                "startLine": self.line,
            },
            "tool": {"name": self.tool},
            "message": self.message,
            "raw": {},
        }


def make_finding(
    tool: str,
    rule_id: str,
    path: str,
    line: int,
    severity: str = "HIGH",
    message: str = "",
) -> dict[str, Any]:
    """Create a finding dict for testing."""
    return Finding(
        rule_id=rule_id,
        severity=severity,
        path=path,
        line=line,
        tool=tool,
        message=message or f"{rule_id} vulnerability in {path}",
    ).to_dict()


def cluster(findings: list[dict[str, Any]]) -> list:
    """Run the real clusterer at its default threshold (0.65)."""
    return FindingClusterer().cluster(findings)


@pytest.mark.integration
class TestDeduplicationLogic:
    """Deduplication merge/separate behaviour on synthetic findings."""

    def test_identical_findings_from_different_tools_merge(self):
        """Same location + same message, two tools -> one consensus cluster.

        Both tools flag the same XSS at src/app.js:42 with the same message, so
        their weighted similarity clears the 0.65 threshold and they collapse
        into a single cluster whose consensus records both tools.
        """
        msg = "XSS vulnerability: unsanitized user input reaches the sink"
        findings = [
            make_finding("semgrep", "CWE-79", "src/app.js", 42, message=msg),
            make_finding(
                "eslint-security", "no-unsafe-innerhtml", "src/app.js", 42, message=msg
            ),
        ]

        clusters = cluster(findings)

        assert len(clusters) == 1
        consensus = clusters[0].to_consensus_finding()
        detected_by = {t["name"] for t in consensus["detected_by"]}
        assert detected_by == {"semgrep", "eslint-security"}

    def test_different_findings_stay_separate(self):
        """Distinct findings from distinct tools are never merged.

        Different rule, path, line and message -> similarity well under
        threshold -> two clusters. This is a control for a clusterer that
        over-merges.
        """
        findings = [
            make_finding(
                "semgrep",
                "CWE-79",
                "src/app.js",
                42,
                message="Cross-site scripting in template output",
            ),
            make_finding(
                "bandit",
                "CWE-89",
                "src/db.py",
                100,
                message="SQL injection via string formatting in query",
            ),
        ]

        clusters = cluster(findings)

        assert len(clusters) == 2

    def test_same_rule_different_locations_stay_separate(self):
        """Same rule at three different locations does not merge.

        Location carries the most weight (0.5), so three findings of the same
        rule at three different files/lines stay in three clusters even though
        their rule ids are identical.
        """
        findings = [
            make_finding("semgrep", "CWE-79", "src/app.js", 42, message="XSS one"),
            make_finding("eslint", "CWE-79", "src/app.js", 100, message="XSS two"),
            make_finding("njsscan", "CWE-79", "src/other.js", 42, message="XSS three"),
        ]

        clusters = cluster(findings)

        assert len(clusters) == 3


@pytest.mark.integration
class TestDeduplicationMetrics:
    """Real reduction achieved by the clusterer on overlapping tool output."""

    def test_synthetic_duplicates_reduce_count(self):
        """Five issues each reported by three tools collapse to five clusters.

        15 raw findings -> 5 consensus clusters. Every location has three tools
        agreeing, so each collapses to one cluster carrying three tools.
        """
        duplicates = []
        for i in range(5):
            shared_message = f"identical issue text for location {i}"
            for tool in ["semgrep", "eslint", "njsscan"]:
                duplicates.append(
                    make_finding(
                        tool=tool,
                        rule_id=f"CWE-{79 + i}",
                        path=f"src/file{i}.js",
                        line=10 * (i + 1),
                        message=shared_message,
                    )
                )

        assert len(duplicates) == 15

        clusters = cluster(duplicates)

        assert len(clusters) == 5
        assert all(len(c.findings) == 3 for c in clusters)

    def test_reduction_ratio_calculation(self):
        """Reduction ratio is computed from a real dedup run, not a constant.

        The old test asserted a property of two hand-written integers and could
        not fail for any change to product code. This runs the clusterer on the
        overlapping set above and asserts the measured reduction, which drops to
        zero if clustering is disabled.
        """
        duplicates = []
        for i in range(5):
            shared_message = f"identical issue text for location {i}"
            for tool in ["semgrep", "eslint", "njsscan"]:
                duplicates.append(
                    make_finding(
                        tool=tool,
                        rule_id=f"CWE-{79 + i}",
                        path=f"src/file{i}.js",
                        line=10 * (i + 1),
                        message=shared_message,
                    )
                )

        raw_count = len(duplicates)
        deduped_count = len(cluster(duplicates))
        reduction = (raw_count - deduped_count) / raw_count

        # Measured 10/15 -> 0.667; assert a band a disabled clusterer (0.0)
        # cannot satisfy, without pinning the exact figure.
        assert reduction >= 0.5


@pytest.mark.integration
class TestFindingClustererIntegration:
    """The previously-skipped integration test, pointed at the real symbol.

    It imported ``scripts.core.dedup`` -- a module that never existed -- so the
    class was skipped for the life of the file. The real engine is
    ``FindingClusterer`` from ``scripts.core.dedup_enhanced`` (#1043).
    """

    def test_finding_clusterer_clusters_similar_findings(self):
        """Two tools' XSS merges; a distinct SQLi stays separate -> 2 clusters."""
        xss_msg = "XSS: unsanitized user input flows to innerHTML"
        findings = [
            make_finding("semgrep", "CWE-79", "src/app.js", 42, message=xss_msg),
            make_finding("eslint", "xss-vuln", "src/app.js", 42, message=xss_msg),
            make_finding(
                "semgrep",
                "CWE-89",
                "src/db.js",
                100,
                message="SQL injection in raw query",
            ),
        ]

        clusters = cluster(findings)

        assert len(clusters) == 2
        sizes = sorted(len(c.findings) for c in clusters)
        assert sizes == [1, 2]


@pytest.mark.integration
class TestDeduplicationEdgeCases:
    """Boundary inputs handled by the real clusterer without raising."""

    def test_empty_findings_list(self):
        """Empty input -> empty output from the real clusterer."""
        assert cluster([]) == []

    def test_single_finding(self):
        """A single finding -> one cluster containing exactly that finding."""
        findings = [make_finding("semgrep", "CWE-79", "src/app.js", 42)]

        clusters = cluster(findings)

        assert len(clusters) == 1
        assert clusters[0].findings[0]["id"] == "semgrep:CWE-79:src/app.js:42"

    def test_findings_with_missing_optional_fields(self):
        """A finding lacking location/tool is clustered without raising.

        Exercises the calculator's tolerance of absent optional fields -- the
        real path that would crash if similarity scoring assumed them present.
        """
        finding = {
            "id": "minimal-1",
            "ruleId": "CWE-79",
            "severity": "HIGH",
            "message": "XSS with no location",
        }

        clusters = cluster([finding])

        assert len(clusters) == 1
        consensus = clusters[0].to_consensus_finding()
        assert consensus["id"] == "cluster-minimal-1"

    def test_findings_with_different_severity_merge_to_highest(self):
        """Merged findings elevate the consensus to the highest severity.

        MEDIUM (semgrep) and HIGH (eslint) at one location, same message, two
        tools -> one cluster whose consensus severity is HIGH.
        """
        msg = "XSS: unsanitized input rendered into the page"
        findings = [
            make_finding(
                "semgrep", "CWE-79", "src/app.js", 42, severity="MEDIUM", message=msg
            ),
            make_finding(
                "eslint", "xss", "src/app.js", 42, severity="HIGH", message=msg
            ),
        ]

        clusters = cluster(findings)

        assert len(clusters) == 1
        assert clusters[0].to_consensus_finding()["severity"] == "HIGH"
