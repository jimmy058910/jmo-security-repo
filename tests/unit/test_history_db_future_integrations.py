#!/usr/bin/env python3
"""
Tests for Phase 7: Future Integrations (React Dashboard, MCP Server, Compliance).

This test module verifies the Phase 7 helper functions for:
- React Dashboard integration (dashboard summary, timeline data, batch fetching, search)
- MCP Server integration (finding context, AI diff, recurring findings)
- Compliance reporting (framework summaries, trend analysis)

Test coverage target: ≥85%
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

from scripts.core.history_db import (
    # React Dashboard helpers
    get_dashboard_summary,
    get_timeline_data,
    get_finding_details_batch,
    search_findings,
    # MCP Server helpers
    get_finding_context,
    get_scan_diff_for_ai,
    get_recurring_findings,
    # Compliance helpers
    get_compliance_summary,
    get_compliance_trend,
    # Core functions for test setup
    get_connection,
    init_database,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_db(tmp_path):
    """Create a temporary test database."""
    db_path = tmp_path / "test_history.db"
    yield db_path
    # Cleanup handled by tmp_path


@pytest.fixture
def db_with_sample_scans(temp_db):
    """
    Create database with 5 sample scans across 30 days.

    Returns:
        Tuple[Path, sqlite3.Connection, List[str], int]: (db_path, conn, scan_ids, current_time)
    """
    init_database(temp_db)
    conn = get_connection(temp_db)

    scan_ids = []
    current_time = int(time.time())  # Capture current time for consistent mocking
    base_time = current_time - (30 * 86400)  # 30 days ago

    for i in range(5):
        # Create scan metadata
        timestamp = base_time + (i * 7 * 86400)  # One scan per week
        scan_id = f"scan-{i:04d}"

        # Insert scan
        conn.execute(
            """
            INSERT INTO scans (
                id, timestamp, timestamp_iso, branch, profile,
                jmo_version, tools, targets, target_type, total_findings,
                critical_count, high_count, medium_count, low_count, info_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                timestamp,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
                "main",
                "balanced",
                "1.0.0",
                json.dumps(["trivy", "semgrep", "checkov"]),
                json.dumps(["repo-test"]),  # targets
                "repo",  # target_type
                50 - (i * 5),  # Decreasing findings (trend improving)
                5 - i,  # CRITICAL
                10 - i,  # HIGH
                20,  # MEDIUM
                10,  # LOW
                5 + i,  # INFO
            ),
        )

        # Insert findings for each scan
        for j in range(50 - (i * 5)):
            severity_choices = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
            severity_weights = [5 - i, 10 - i, 20, 10, 5 + i]
            cumulative_weights = []
            cumulative = 0
            for weight in severity_weights:
                cumulative += weight
                cumulative_weights.append(cumulative)

            # Deterministic severity selection based on j
            rand_val = (j * 17) % cumulative_weights[-1]
            severity = severity_choices[
                next(idx for idx, w in enumerate(cumulative_weights) if rand_val < w)
            ]

            fingerprint = f"fp-{i:04d}-{j:04d}"

            # Add compliance data for some findings
            owasp = json.dumps(["A01:2021", "A03:2021"]) if j % 3 == 0 else None
            cwe = (
                json.dumps([{"id": "79", "name": "XSS", "rank": 2}])
                if j % 4 == 0
                else None
            )
            pci_dss = json.dumps(["6.5.1", "6.5.7"]) if j % 5 == 0 else None

            conn.execute(
                """
                INSERT INTO findings (
                    fingerprint, scan_id, tool, rule_id, severity,
                    path, start_line, message,
                    owasp_top10, cwe_top25, pci_dss
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fingerprint,
                    scan_id,
                    "trivy",
                    f"RULE-{j % 10}",
                    severity,
                    f"src/file{j % 5}.py",
                    100 + j,
                    f"Security issue {j} in scan {i}",
                    owasp,
                    cwe,
                    pci_dss,
                ),
            )

        scan_ids.append(scan_id)

    conn.commit()
    yield temp_db, conn, scan_ids, current_time

    conn.close()


@pytest.fixture
def db_with_recurring_findings(temp_db):
    """
    Create database with recurring findings (same fingerprint across scans).

    Returns:
        Tuple[Path, sqlite3.Connection]: (db_path, conn)
    """
    init_database(temp_db)
    conn = get_connection(temp_db)

    base_time = int(time.time()) - (60 * 86400)  # 60 days ago

    # Create 10 scans
    for i in range(10):
        timestamp = base_time + (i * 6 * 86400)  # One scan per 6 days
        scan_id = f"scan-recurring-{i:04d}"

        conn.execute(
            """
            INSERT INTO scans (
                id, timestamp, timestamp_iso, branch, profile,
                jmo_version, tools, targets, target_type, total_findings,
                critical_count, high_count, medium_count, low_count, info_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                scan_id,
                timestamp,
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(timestamp)),
                "main",
                "balanced",
                "1.0.0",
                json.dumps(["trivy", "semgrep"]),
                json.dumps(["repo-recurring"]),  # targets
                "repo",  # target_type
                10,
                2,
                3,
                3,
                2,
                0,
            ),
        )

        # Add 3 recurring findings (appear in every scan)
        for fp_id in ["recurring-fp-001", "recurring-fp-002", "recurring-fp-003"]:
            conn.execute(
                """
                INSERT INTO findings (
                    fingerprint, scan_id, tool, rule_id, severity,
                    path, start_line, message
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    fp_id,
                    scan_id,
                    "semgrep",
                    "hardcoded-secret",
                    "CRITICAL",
                    "src/config.py",
                    42,
                    "Hardcoded API key detected",
                ),
            )

        # Add 2 findings that appear only in odd scans (intermittent)
        if i % 2 == 1:
            for fp_id in ["intermittent-fp-001", "intermittent-fp-002"]:
                conn.execute(
                    """
                    INSERT INTO findings (
                        fingerprint, scan_id, tool, rule_id, severity,
                        path, start_line, message
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        fp_id,
                        scan_id,
                        "trivy",
                        "CVE-2024-12345",
                        "HIGH",
                        "package.json",
                        10,
                        "Vulnerable dependency",
                    ),
                )

    conn.commit()
    yield temp_db, conn

    conn.close()


# ============================================================================
# React Dashboard Helper Tests
# ============================================================================


class TestReactDashboardHelpers:
    """Tests for React Dashboard integration helpers."""

    def test_get_dashboard_summary(self, db_with_sample_scans):
        """Dashboard summary includes all required sections."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Get summary for first scan
        summary = get_dashboard_summary(conn, scan_ids[0])

        # Verify structure
        assert summary is not None
        assert "scan" in summary
        assert "severity_counts" in summary
        assert "top_rules" in summary
        assert "tools_used" in summary
        assert "findings_by_tool" in summary
        assert "compliance_coverage" in summary

        # Verify scan metadata
        assert summary["scan"]["id"] == scan_ids[0]
        assert summary["scan"]["branch"] == "main"

        # Verify severity counts (check structure, not exact numbers)
        severity_counts = summary["severity_counts"]
        assert "CRITICAL" in severity_counts
        assert "HIGH" in severity_counts
        assert "MEDIUM" in severity_counts
        assert "LOW" in severity_counts
        assert "INFO" in severity_counts
        # Total should be positive
        total = sum(severity_counts.values())
        assert total > 0

        # Verify top rules (should have at least 1 rule)
        assert len(summary["top_rules"]) > 0
        assert "rule_id" in summary["top_rules"][0]
        assert "count" in summary["top_rules"][0]
        assert "severity" in summary["top_rules"][0]

        # Verify tools used
        assert "trivy" in summary["tools_used"]
        assert "semgrep" in summary["tools_used"]

        # Verify findings by tool
        assert summary["findings_by_tool"]["trivy"] == 50

        # Verify compliance coverage
        coverage = summary["compliance_coverage"]
        assert coverage["total_findings"] == 50
        assert coverage["findings_with_compliance"] > 0
        assert 0 <= coverage["coverage_percentage"] <= 100

    def test_get_dashboard_summary_nonexistent_scan(self, db_with_sample_scans):
        """Dashboard summary returns None for nonexistent scan."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        summary = get_dashboard_summary(conn, "nonexistent-scan-id")
        assert summary is None

    def test_get_timeline_data(self, db_with_sample_scans):
        """Timeline data formatted for Recharts."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Get 30-day timeline for main branch
        # Patch time.time() to ensure consistent time window calculation
        with patch("time.time", return_value=current_time):
            timeline = get_timeline_data(conn, "main", days=30)

        # Verify structure (should have 5 scans across 30 days)
        assert len(timeline) == 5

        # Verify each data point
        for point in timeline:
            assert "date" in point
            assert "timestamp" in point
            assert "CRITICAL" in point
            assert "HIGH" in point
            assert "MEDIUM" in point
            assert "LOW" in point
            assert "INFO" in point
            assert "total" in point

        # Verify chronological order
        for i in range(len(timeline) - 1):
            assert timeline[i]["date"] <= timeline[i + 1]["date"]

        # Verify decreasing trend (improving security)
        assert timeline[0]["CRITICAL"] > timeline[-1]["CRITICAL"]
        assert timeline[0]["total"] > timeline[-1]["total"]

    def test_get_timeline_data_empty_branch(self, db_with_sample_scans):
        """Timeline data returns empty list for nonexistent branch."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        timeline = get_timeline_data(conn, "nonexistent-branch", days=30)
        assert timeline == []

    def test_get_finding_details_batch(self, db_with_sample_scans):
        """Batch fetching returns correct findings."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Get first 5 fingerprints from first scan
        fingerprints = [f"fp-0000-{j:04d}" for j in range(5)]

        findings = get_finding_details_batch(conn, fingerprints)

        # Verify correct number returned
        assert len(findings) == 5

        # Verify fingerprints match
        returned_fps = {f["fingerprint"] for f in findings}
        assert returned_fps == set(fingerprints)

        # Verify findings have all expected fields
        for finding in findings:
            assert "fingerprint" in finding
            assert "scan_id" in finding
            assert "tool" in finding
            assert "rule_id" in finding
            assert "severity" in finding
            assert "path" in finding
            assert "message" in finding

    def test_get_finding_details_batch_empty_list(self, db_with_sample_scans):
        """Batch fetching with empty list returns empty result."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        findings = get_finding_details_batch(conn, [])
        assert findings == []

    def test_search_findings(self, db_with_sample_scans):
        """Search + filters work correctly."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Search for "Security issue" (should match all findings)
        findings = search_findings(conn, "Security issue")
        assert len(findings) > 0
        assert all("Security issue" in f["message"] for f in findings)

        # Search with severity filter
        findings = search_findings(conn, "Security", {"severity": "CRITICAL"})
        assert all(f["severity"] == "CRITICAL" for f in findings)

        # Search with tool filter
        findings = search_findings(conn, "", {"tool": "trivy", "limit": 10})
        assert len(findings) <= 10
        assert all(f["tool"] == "trivy" for f in findings)

        # Search with scan_id filter
        findings = search_findings(conn, "", {"scan_id": scan_ids[0], "limit": 100})
        assert all(f["scan_id"] == scan_ids[0] for f in findings)

    def test_search_findings_with_branch_filter(self, db_with_sample_scans):
        """Search with branch filter works correctly."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Search in main branch
        findings = search_findings(conn, "Security", {"branch": "main", "limit": 50})
        assert len(findings) > 0

        # Search in nonexistent branch
        findings = search_findings(conn, "Security", {"branch": "nonexistent"})
        assert len(findings) == 0


# ============================================================================
# MCP Server Helper Tests
# ============================================================================


class TestMCPServerHelpers:
    """Tests for MCP Server integration helpers."""

    def test_get_finding_context(self, db_with_sample_scans):
        """Finding context includes history + similar findings."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Get context for a finding
        fingerprint = "fp-0000-0000"
        context = get_finding_context(conn, fingerprint)

        # Verify structure
        assert context is not None
        assert "finding" in context
        assert "history" in context
        assert "similar_findings" in context
        assert "remediation_history" in context
        assert "compliance_impact" in context

        # Verify finding details
        assert context["finding"]["fingerprint"] == fingerprint

        # Verify history (should have at least 1 entry - the current scan)
        assert len(context["history"]) >= 1
        assert context["history"][0]["scan_id"] == scan_ids[0]

        # Verify compliance impact structure
        assert "frameworks" in context["compliance_impact"]
        assert "severity_justification" in context["compliance_impact"]

    def test_get_finding_context_with_compliance(self, db_with_sample_scans):
        """Finding context extracts compliance frameworks correctly."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Get context for finding with compliance data (every 3rd finding has OWASP)
        fingerprint = "fp-0000-0000"  # j=0, has OWASP (j % 3 == 0)
        context = get_finding_context(conn, fingerprint)

        # Verify compliance frameworks extracted
        frameworks = context["compliance_impact"]["frameworks"]
        assert any("OWASP" in fw for fw in frameworks)

    def test_get_finding_context_nonexistent(self, db_with_sample_scans):
        """Finding context returns None for nonexistent finding."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        context = get_finding_context(conn, "nonexistent-fingerprint")
        assert context is None

    def test_get_scan_diff_for_ai(self, db_with_sample_scans):
        """AI-ready diff format is correct."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Compare first and last scans
        diff = get_scan_diff_for_ai(conn, scan_ids[0], scan_ids[-1])

        # Verify structure
        assert "new_findings" in diff
        assert "resolved_findings" in diff
        assert "context" in diff

        # Verify new findings have priority scores
        if len(diff["new_findings"]) > 0:
            for finding in diff["new_findings"]:
                assert "priority_score" in finding
                assert 1 <= finding["priority_score"] <= 10
                assert "severity" in finding
                assert "rule_id" in finding
                assert "path" in finding

            # Verify sorted by priority DESC
            priorities = [f["priority_score"] for f in diff["new_findings"]]
            assert priorities == sorted(priorities, reverse=True)

        # Verify resolved findings have likely_fix
        if len(diff["resolved_findings"]) > 0:
            for finding in diff["resolved_findings"]:
                assert "likely_fix" in finding

        # Verify context
        assert "scan_1" in diff["context"]
        assert "scan_2" in diff["context"]
        assert "commit_diff" in diff["context"]
        assert "time_delta_days" in diff["context"]
        assert diff["context"]["time_delta_days"] > 0

    def test_get_recurring_findings(self, db_with_recurring_findings):
        """Recurring findings detected correctly."""
        db_path, conn = db_with_recurring_findings

        # Find findings that appear 3+ times
        recurring = get_recurring_findings(conn, "main", min_occurrences=3)

        # Verify we found the 3 recurring findings
        assert len(recurring) >= 3

        # Verify structure
        for finding in recurring:
            assert "fingerprint" in finding
            assert "rule_id" in finding
            assert "path" in finding
            assert "severity" in finding
            assert "occurrence_count" in finding
            assert "first_seen" in finding
            assert "last_seen" in finding
            assert "avg_days_between_fixes" in finding
            assert "message" in finding

        # Verify the 3 truly recurring findings
        recurring_fps = [f["fingerprint"] for f in recurring]
        assert "recurring-fp-001" in recurring_fps
        assert "recurring-fp-002" in recurring_fps
        assert "recurring-fp-003" in recurring_fps

        # Verify occurrence counts
        for finding in recurring:
            if finding["fingerprint"].startswith("recurring-fp"):
                assert finding["occurrence_count"] == 10  # All 10 scans

    def test_get_recurring_findings_empty_result(self, db_with_sample_scans):
        """Recurring findings returns empty list when min_occurrences too high."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # No findings appear 100 times
        recurring = get_recurring_findings(conn, "main", min_occurrences=100)
        assert len(recurring) == 0


# ============================================================================
# Compliance Reporting Helper Tests
# ============================================================================


class TestComplianceHelpers:
    """Tests for Compliance reporting helpers."""

    def test_get_compliance_summary_all_frameworks(self, db_with_sample_scans):
        """All 6 frameworks summarized."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        summary = get_compliance_summary(conn, scan_ids[0], "all")

        # Verify structure
        assert "scan_id" in summary
        assert "timestamp" in summary
        assert "framework_summaries" in summary
        assert "coverage_stats" in summary

        # Verify all 6 frameworks present
        frameworks = summary["framework_summaries"]
        assert "owasp_top10_2021" in frameworks
        assert "cwe_top25_2024" in frameworks
        assert "cis_controls_v8_1" in frameworks
        assert "nist_csf_2_0" in frameworks
        assert "pci_dss_4_0" in frameworks
        assert "mitre_attack" in frameworks

        # Verify coverage stats
        coverage = summary["coverage_stats"]
        assert "total_findings" in coverage
        assert "findings_with_compliance" in coverage
        assert "coverage_percentage" in coverage
        assert "by_framework" in coverage

        # Verify by_framework counts
        by_fw = coverage["by_framework"]
        assert "owasp" in by_fw
        assert "cwe" in by_fw
        assert "cis" in by_fw
        assert "nist" in by_fw
        assert "pci" in by_fw
        assert "mitre" in by_fw

    def test_get_compliance_summary_single_framework(self, db_with_sample_scans):
        """Single framework filtering works."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        summary = get_compliance_summary(conn, scan_ids[0], "owasp")

        # Verify only OWASP framework present
        frameworks = summary["framework_summaries"]
        assert "owasp_top10_2021" in frameworks
        assert "cwe_top25_2024" not in frameworks

        # Verify OWASP categories
        owasp = frameworks["owasp_top10_2021"]
        if len(owasp) > 0:
            # Should have A01:2021 and A03:2021 from test data
            for category, data in owasp.items():
                assert "count" in data
                assert "severities" in data
                assert isinstance(data["severities"], dict)

    def test_get_compliance_summary_nonexistent_scan(self, db_with_sample_scans):
        """Compliance summary raises ValueError for nonexistent scan."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        with pytest.raises(ValueError, match="Scan not found"):
            get_compliance_summary(conn, "nonexistent-scan", "all")

    def test_compliance_coverage_percentage(self, db_with_sample_scans):
        """Coverage percentage accurate."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        summary = get_compliance_summary(conn, scan_ids[0], "all")
        coverage = summary["coverage_stats"]

        # Verify percentage calculation
        total = coverage["total_findings"]
        with_compliance = coverage["findings_with_compliance"]
        percentage = coverage["coverage_percentage"]

        if total > 0:
            expected_percentage = round((with_compliance / total * 100), 1)
            assert percentage == expected_percentage
        else:
            assert percentage == 0.0

    def test_get_compliance_trend(self, db_with_sample_scans):
        """Compliance trends calculated correctly."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        # Get OWASP trend for main branch (30 days)
        trend = get_compliance_trend(conn, "main", "owasp", days=30)

        # Verify structure
        assert "framework" in trend
        assert "branch" in trend
        assert "days" in trend
        assert "trend" in trend
        assert "data_points" in trend
        assert "insights" in trend
        assert "summary_stats" in trend

        # Verify values
        assert trend["framework"] == "owasp"
        assert trend["branch"] == "main"
        assert trend["days"] == 30
        assert trend["trend"] in [
            "improving",
            "degrading",
            "stable",
            "insufficient_data",
        ]

        # Verify data points (should have 5 scans)
        assert len(trend["data_points"]) == 5

        # Verify summary stats
        stats = trend["summary_stats"]
        assert "first_scan_count" in stats
        assert "last_scan_count" in stats
        assert "change_percentage" in stats
        assert "avg_findings_per_scan" in stats

    def test_get_compliance_trend_insufficient_data(self, temp_db):
        """Compliance trend returns insufficient_data for <2 scans."""
        init_database(temp_db)
        conn = get_connection(temp_db)

        # Create single scan
        conn.execute(
            """
            INSERT INTO scans (
                id, timestamp, timestamp_iso, branch, profile,
                jmo_version, tools, targets, target_type, total_findings,
                critical_count, high_count, medium_count, low_count, info_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                "single-scan",
                int(time.time()),
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "main",
                "balanced",
                "1.0.0",
                json.dumps(["trivy"]),
                json.dumps(["repo-single"]),  # targets
                "repo",  # target_type
                10,
                2,
                3,
                3,
                2,
                0,
            ),
        )
        conn.commit()

        # Get trend (should return insufficient_data)
        trend = get_compliance_trend(conn, "main", "owasp", days=30)

        assert trend["trend"] == "insufficient_data"
        assert len(trend["data_points"]) < 2
        assert "Not enough scans" in trend["insights"][0]

        conn.close()

    def test_get_compliance_trend_invalid_framework(self, db_with_sample_scans):
        """Compliance trend raises ValueError for invalid framework."""
        db_path, conn, scan_ids, current_time = db_with_sample_scans

        with pytest.raises(ValueError, match="Invalid framework"):
            get_compliance_trend(conn, "main", "invalid-framework", days=30)
