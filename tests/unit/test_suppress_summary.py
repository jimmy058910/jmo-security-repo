#!/usr/bin/env python3
"""
Tests for SuppressionSummary dataclass and filter_suppressed_with_summary().

Tests cover:
- SuppressionSummary dataclass properties (suppression_percentage, debt_label)
- to_dict() serialization
- filter_suppressed_with_summary() filtering + summary tracking
- Equivalence with filter_suppressed() for active findings
- Edge cases: empty inputs, all suppressed, zero division, unknown severity

Target: comprehensive coverage for suppression debt metric.
"""

from __future__ import annotations

import datetime as dt

from scripts.core.suppress import (
    Suppression,
    SuppressionSummary,
    filter_suppressed,
    filter_suppressed_with_summary,
)

# ============================================================================
# 1. SuppressionSummary Dataclass Tests
# ============================================================================


class TestSuppressionSummaryDataclass:
    """Tests for SuppressionSummary dataclass basic functionality."""

    def test_summary_empty(self):
        """Test SuppressionSummary with all defaults (zero suppressed)."""
        summary = SuppressionSummary()

        assert summary.total_suppressed == 0
        assert summary.total_before_suppression == 0
        assert summary.by_severity == {}
        assert summary.by_rule == {}
        assert summary.suppressed_ids == []

    def test_summary_with_findings(self):
        """Test SuppressionSummary with populated counts."""
        summary = SuppressionSummary(
            total_suppressed=5,
            total_before_suppression=20,
            by_severity={"HIGH": 2, "MEDIUM": 3},
            by_rule={"fp-001": 3, "fp-002": 2},
            suppressed_ids=["id-1", "id-2", "id-3", "id-4", "id-5"],
        )

        assert summary.total_suppressed == 5
        assert summary.total_before_suppression == 20
        assert summary.by_severity == {"HIGH": 2, "MEDIUM": 3}
        assert summary.by_rule == {"fp-001": 3, "fp-002": 2}
        assert len(summary.suppressed_ids) == 5


# ============================================================================
# 2. suppression_percentage Property Tests
# ============================================================================


class TestSuppressionPercentage:
    """Tests for SuppressionSummary.suppression_percentage property."""

    def test_suppression_percentage(self):
        """Test suppression percentage calculation."""
        summary = SuppressionSummary(
            total_suppressed=15,
            total_before_suppression=100,
        )

        assert summary.suppression_percentage == 15.0

    def test_suppression_percentage_zero_total(self):
        """Test that zero total findings avoids division by zero."""
        summary = SuppressionSummary(
            total_suppressed=0,
            total_before_suppression=0,
        )

        assert summary.suppression_percentage == 0.0

    def test_suppression_percentage_all_suppressed(self):
        """Test 100% suppression rate."""
        summary = SuppressionSummary(
            total_suppressed=10,
            total_before_suppression=10,
        )

        assert summary.suppression_percentage == 100.0

    def test_suppression_percentage_fractional(self):
        """Test fractional percentage value."""
        summary = SuppressionSummary(
            total_suppressed=1,
            total_before_suppression=3,
        )

        assert abs(summary.suppression_percentage - 33.333333) < 0.001


# ============================================================================
# 3. debt_label Property Tests
# ============================================================================


class TestDebtLabel:
    """Tests for SuppressionSummary.debt_label property."""

    def test_debt_label_empty(self):
        """Test debt label with zero findings."""
        summary = SuppressionSummary(total_suppressed=0)

        assert summary.debt_label == "Suppression debt: 0 findings"

    def test_debt_label_formatting(self):
        """Test human-readable debt label with severity breakdown."""
        summary = SuppressionSummary(
            total_suppressed=15,
            by_severity={"HIGH": 3, "MEDIUM": 8, "LOW": 4},
        )

        label = summary.debt_label
        assert label == "Suppression debt: 15 findings (3 HIGH, 8 MEDIUM, 4 LOW)"

    def test_debt_label_single_severity(self):
        """Test debt label with only one severity."""
        summary = SuppressionSummary(
            total_suppressed=5,
            by_severity={"CRITICAL": 5},
        )

        assert summary.debt_label == "Suppression debt: 5 findings (5 CRITICAL)"

    def test_debt_label_severity_order(self):
        """Test that severities appear in CRITICAL > HIGH > MEDIUM > LOW > INFO order."""
        summary = SuppressionSummary(
            total_suppressed=10,
            by_severity={"LOW": 2, "CRITICAL": 1, "INFO": 3, "HIGH": 4},
        )

        label = summary.debt_label
        assert (
            label == "Suppression debt: 10 findings (1 CRITICAL, 4 HIGH, 2 LOW, 3 INFO)"
        )

    def test_debt_label_unknown_severity(self):
        """Test debt label with non-standard severity (sorted last)."""
        summary = SuppressionSummary(
            total_suppressed=3,
            by_severity={"HIGH": 1, "UNKNOWN": 2},
        )

        label = summary.debt_label
        # UNKNOWN should appear after standard severities
        assert "1 HIGH" in label
        assert "2 UNKNOWN" in label
        # HIGH should come before UNKNOWN
        assert label.index("HIGH") < label.index("UNKNOWN")


# ============================================================================
# 4. to_dict() Serialization Tests
# ============================================================================


class TestToDict:
    """Tests for SuppressionSummary.to_dict() serialization."""

    def test_to_dict_serialization(self):
        """Test to_dict returns correct JSON-serializable structure."""
        summary = SuppressionSummary(
            total_suppressed=5,
            total_before_suppression=20,
            by_severity={"HIGH": 2, "MEDIUM": 3},
            by_rule={"fp-001": 3, "fp-002": 2},
            suppressed_ids=["id-1", "id-2"],
        )

        d = summary.to_dict()

        assert d["total_suppressed"] == 5
        assert d["total_before_suppression"] == 20
        assert d["suppression_percentage"] == 25.0
        assert d["by_severity"] == {"HIGH": 2, "MEDIUM": 3}
        assert d["by_rule"] == {"fp-001": 3, "fp-002": 2}
        # suppressed_ids not in to_dict (privacy/size)
        assert "suppressed_ids" not in d

    def test_to_dict_empty(self):
        """Test to_dict with empty/default summary."""
        summary = SuppressionSummary()

        d = summary.to_dict()

        assert d["total_suppressed"] == 0
        assert d["total_before_suppression"] == 0
        assert d["suppression_percentage"] == 0.0
        assert d["by_severity"] == {}
        assert d["by_rule"] == {}

    def test_to_dict_percentage_rounding(self):
        """Test that percentage is rounded to 1 decimal place."""
        summary = SuppressionSummary(
            total_suppressed=1,
            total_before_suppression=3,
        )

        d = summary.to_dict()

        # 33.333... should round to 33.3
        assert d["suppression_percentage"] == 33.3


# ============================================================================
# 5. filter_suppressed_with_summary() Tests
# ============================================================================


class TestFilterSuppressedWithSummary:
    """Tests for filter_suppressed_with_summary() function."""

    def test_filter_suppressed_with_summary_same_filtering(self):
        """Test that active findings match original filter_suppressed() exactly."""
        findings = [
            {"id": "fp-001", "severity": "HIGH", "ruleId": "G101"},
            {"id": "real-002", "severity": "MEDIUM", "ruleId": "G102"},
            {"id": "fp-003", "severity": "LOW", "ruleId": "G103"},
            {"id": "real-004", "severity": "INFO", "ruleId": "G104"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001", reason="False positive"),
            "fp-003": Suppression(id="fp-003", reason="Accepted risk"),
        }

        # Original function
        original_active = filter_suppressed(findings, suppressions)
        # New function
        new_active, summary = filter_suppressed_with_summary(findings, suppressions)

        # Active findings must be identical
        assert new_active == original_active
        assert len(new_active) == 2
        assert new_active[0]["id"] == "real-002"
        assert new_active[1]["id"] == "real-004"

    def test_severity_breakdown_correct(self):
        """Test that by_severity counts are correct."""
        findings = [
            {"id": "fp-001", "severity": "HIGH"},
            {"id": "fp-002", "severity": "HIGH"},
            {"id": "fp-003", "severity": "MEDIUM"},
            {"id": "real-004", "severity": "LOW"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001"),
            "fp-002": Suppression(id="fp-002"),
            "fp-003": Suppression(id="fp-003"),
        }

        _, summary = filter_suppressed_with_summary(findings, suppressions)

        assert summary.total_suppressed == 3
        assert summary.total_before_suppression == 4
        assert summary.by_severity == {"HIGH": 2, "MEDIUM": 1}

    def test_by_rule_tracking(self):
        """Test that by_rule counts match suppression rule IDs."""
        findings = [
            {"id": "fp-001", "severity": "HIGH"},
            {"id": "fp-002", "severity": "MEDIUM"},
            {"id": "fp-003", "severity": "LOW"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001", reason="Rule A"),
            "fp-002": Suppression(id="fp-002", reason="Rule B"),
            "fp-003": Suppression(id="fp-003", reason="Rule A"),
        }

        _, summary = filter_suppressed_with_summary(findings, suppressions)

        assert summary.by_rule == {"fp-001": 1, "fp-002": 1, "fp-003": 1}

    def test_all_suppressed(self):
        """Test 100% suppression rate."""
        findings = [
            {"id": "fp-001", "severity": "HIGH"},
            {"id": "fp-002", "severity": "MEDIUM"},
            {"id": "fp-003", "severity": "LOW"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001"),
            "fp-002": Suppression(id="fp-002"),
            "fp-003": Suppression(id="fp-003"),
        }

        active, summary = filter_suppressed_with_summary(findings, suppressions)

        assert active == []
        assert summary.total_suppressed == 3
        assert summary.total_before_suppression == 3
        assert summary.suppression_percentage == 100.0

    def test_no_suppressions(self):
        """Test with empty suppressions dict."""
        findings = [
            {"id": "finding-1", "severity": "HIGH"},
            {"id": "finding-2", "severity": "LOW"},
        ]

        active, summary = filter_suppressed_with_summary(findings, {})

        assert active == findings
        assert summary.total_suppressed == 0
        assert summary.total_before_suppression == 2
        assert summary.suppression_percentage == 0.0

    def test_empty_findings(self):
        """Test with empty findings list."""
        suppressions = {"fp-001": Suppression(id="fp-001")}

        active, summary = filter_suppressed_with_summary([], suppressions)

        assert active == []
        assert summary.total_suppressed == 0
        assert summary.total_before_suppression == 0
        assert summary.suppression_percentage == 0.0

    def test_expired_suppressions_not_counted(self):
        """Test that expired suppressions are not counted in summary."""
        findings = [
            {"id": "fp-001", "severity": "HIGH"},
            {"id": "fp-002", "severity": "MEDIUM"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001", expires=dt.date(2020, 1, 1)),  # Expired
            "fp-002": Suppression(id="fp-002", expires=dt.date(2999, 12, 31)),  # Active
        }

        active, summary = filter_suppressed_with_summary(findings, suppressions)

        # Only fp-002 should be suppressed (fp-001's suppression expired)
        assert len(active) == 1
        assert active[0]["id"] == "fp-001"
        assert summary.total_suppressed == 1
        assert summary.by_severity == {"MEDIUM": 1}

    def test_suppressed_ids_tracked(self):
        """Test that suppressed finding IDs are tracked."""
        findings = [
            {"id": "fp-001", "severity": "HIGH"},
            {"id": "real-002", "severity": "MEDIUM"},
            {"id": "fp-003", "severity": "LOW"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001"),
            "fp-003": Suppression(id="fp-003"),
        }

        _, summary = filter_suppressed_with_summary(findings, suppressions)

        assert set(summary.suppressed_ids) == {"fp-001", "fp-003"}

    def test_finding_without_severity(self):
        """Test finding with missing severity field gets UNKNOWN."""
        findings = [
            {"id": "fp-001"},  # No severity field
        ]
        suppressions = {"fp-001": Suppression(id="fp-001")}

        _, summary = filter_suppressed_with_summary(findings, suppressions)

        assert summary.by_severity == {"UNKNOWN": 1}

    def test_finding_without_id_not_suppressed(self):
        """Test findings without id are never suppressed (same as filter_suppressed)."""
        findings = [
            {"ruleId": "G101", "severity": "HIGH"},
            {"id": None, "severity": "MEDIUM"},
        ]
        suppressions = {"fp-001": Suppression(id="fp-001")}

        active, summary = filter_suppressed_with_summary(findings, suppressions)

        assert len(active) == 2
        assert summary.total_suppressed == 0

    def test_non_string_id_not_suppressed(self):
        """Test findings with non-string IDs are never suppressed."""
        findings = [
            {"id": 12345, "severity": "HIGH"},
        ]
        suppressions = {"12345": Suppression(id="12345")}

        active, summary = filter_suppressed_with_summary(findings, suppressions)

        assert len(active) == 1
        assert summary.total_suppressed == 0
