#!/usr/bin/env python3
"""
Comprehensive tests for scripts/core/suppress.py

Tests cover:
- Suppression dataclass and is_active() method
- load_suppressions() function with various YAML formats
- filter_suppressed() function for filtering findings

Target: ≥85% coverage for scripts/core/suppress.py
"""

from __future__ import annotations

import datetime as dt
from pathlib import Path


from scripts.core.suppress import Suppression, filter_suppressed, load_suppressions


# ============================================================================
# 1. Suppression Dataclass Tests
# ============================================================================


class TestSuppressionDataclass:
    """Tests for Suppression dataclass basic functionality."""

    def test_suppression_creation_minimal(self):
        """Test Suppression creation with minimal fields."""
        sup = Suppression(id="fp-123")

        assert sup.id == "fp-123"
        assert sup.reason == ""
        assert sup.expires is None

    def test_suppression_creation_full(self):
        """Test Suppression creation with all fields."""
        sup = Suppression(id="fp-456", reason="False positive", expires="2025-12-31")

        assert sup.id == "fp-456"
        assert sup.reason == "False positive"
        assert sup.expires == "2025-12-31"

    def test_suppression_creation_with_date_object(self):
        """Test Suppression creation with date object for expires."""
        exp_date = dt.date(2025, 12, 31)
        sup = Suppression(id="fp-789", expires=exp_date)

        assert sup.id == "fp-789"
        assert sup.expires == exp_date


class TestSuppressionIsActive:
    """Tests for Suppression.is_active() method."""

    def test_is_active_no_expiration(self):
        """Test that suppression with no expiration is always active."""
        sup = Suppression(id="fp-123")

        # Should be active regardless of date
        assert sup.is_active() is True
        assert sup.is_active(now=dt.date(2020, 1, 1)) is True
        assert sup.is_active(now=dt.date(2030, 1, 1)) is True

    def test_is_active_future_expiration_string(self):
        """Test suppression with future expiration (ISO string format)."""
        sup = Suppression(id="fp-123", expires="2999-12-31")

        # Should be active before expiration
        assert sup.is_active() is True
        assert sup.is_active(now=dt.date(2025, 1, 1)) is True
        assert sup.is_active(now=dt.date(2999, 12, 31)) is True  # Same day

    def test_is_active_past_expiration_string(self):
        """Test suppression with past expiration (ISO string format)."""
        sup = Suppression(id="fp-123", expires="2020-01-01")

        # Should be inactive after expiration
        assert sup.is_active(now=dt.date(2025, 1, 1)) is False
        assert sup.is_active(now=dt.date(2020, 1, 2)) is False

    def test_is_active_future_expiration_date_object(self):
        """Test suppression with future expiration (date object)."""
        sup = Suppression(id="fp-123", expires=dt.date(2999, 12, 31))

        assert sup.is_active() is True
        assert sup.is_active(now=dt.date(2025, 1, 1)) is True
        assert sup.is_active(now=dt.date(2999, 12, 31)) is True

    def test_is_active_past_expiration_date_object(self):
        """Test suppression with past expiration (date object)."""
        sup = Suppression(id="fp-123", expires=dt.date(2020, 1, 1))

        assert sup.is_active(now=dt.date(2025, 1, 1)) is False
        assert sup.is_active(now=dt.date(2020, 1, 2)) is False

    def test_is_active_boundary_same_day(self):
        """Test suppression expiration on the same day (boundary condition)."""
        sup = Suppression(id="fp-123", expires="2025-06-15")

        # On expiration day, should still be active
        assert sup.is_active(now=dt.date(2025, 6, 15)) is True

        # Day after expiration, should be inactive
        assert sup.is_active(now=dt.date(2025, 6, 16)) is False

    def test_is_active_invalid_date_string(self):
        """Test that invalid date string is treated as never expires."""
        sup = Suppression(id="fp-123", expires="invalid-date")

        # Invalid date treated as never expires (always active)
        assert sup.is_active() is True
        assert sup.is_active(now=dt.date(2025, 1, 1)) is True

    def test_is_active_invalid_date_format(self):
        """Test that invalid ISO format is treated as never expires."""
        sup = Suppression(id="fp-123", expires="2025/12/31")  # Wrong format

        # Invalid format treated as never expires
        assert sup.is_active() is True

    def test_is_active_unexpected_type(self):
        """Test that unexpected expiration type is treated as never expires."""
        sup = Suppression(id="fp-123", expires=12345)  # type: ignore[arg-type]

        # Unexpected type treated as never expires
        assert sup.is_active() is True

    def test_is_active_default_now_uses_today(self):
        """Test that is_active() without now parameter uses today's date."""
        # Create suppression that expires far in the future
        sup = Suppression(id="fp-123", expires="2999-12-31")

        # Should be active when using default now (today)
        assert sup.is_active() is True


# ============================================================================
# 2. load_suppressions() Tests
# ============================================================================


class TestLoadSuppressions:
    """Tests for load_suppressions() function."""

    def test_load_suppressions_no_path(self):
        """Test that None path returns empty dict."""
        result = load_suppressions(None)
        assert result == {}

    def test_load_suppressions_file_not_exists(self, tmp_path: Path):
        """Test that non-existent file returns empty dict."""
        nonexistent = tmp_path / "nonexistent.yml"
        result = load_suppressions(str(nonexistent))
        assert result == {}

    def test_load_suppressions_empty_file(self, tmp_path: Path):
        """Test that empty YAML file returns empty dict."""
        empty_file = tmp_path / "empty.yml"
        empty_file.write_text("")

        result = load_suppressions(str(empty_file))
        assert result == {}

    def test_load_suppressions_with_suppressions_key(self, tmp_path: Path):
        """Test loading from file with 'suppressions' key (preferred)."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - id: fp-123
    reason: False positive
  - id: fp-456
    reason: Accepted risk
    expires: 2025-12-31
"""
        )

        result = load_suppressions(str(suppress_file))

        assert len(result) == 2
        assert "fp-123" in result
        assert "fp-456" in result

        # Check fp-123
        assert result["fp-123"].id == "fp-123"
        assert result["fp-123"].reason == "False positive"
        assert result["fp-123"].expires is None

        # Check fp-456
        assert result["fp-456"].id == "fp-456"
        assert result["fp-456"].reason == "Accepted risk"
        # YAML auto-parses date strings to date objects
        assert result["fp-456"].expires == dt.date(2025, 12, 31)

    def test_load_suppressions_with_suppress_key_legacy(self, tmp_path: Path):
        """Test loading from file with 'suppress' key (backward compat)."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppress:
  - id: fp-legacy
    reason: Old format
"""
        )

        result = load_suppressions(str(suppress_file))

        assert len(result) == 1
        assert "fp-legacy" in result
        assert result["fp-legacy"].reason == "Old format"

    def test_load_suppressions_prefers_suppressions_over_suppress(self, tmp_path: Path):
        """Test that 'suppressions' key takes precedence over 'suppress'."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - id: fp-new
    reason: New format
suppress:
  - id: fp-old
    reason: Old format
"""
        )

        result = load_suppressions(str(suppress_file))

        # Should only load from 'suppressions' key
        assert len(result) == 1
        assert "fp-new" in result
        assert "fp-old" not in result

    def test_load_suppressions_missing_id_field(self, tmp_path: Path):
        """Test that entries without id are skipped."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - reason: No ID provided
  - id: fp-valid
    reason: Valid entry
  - id: ""
    reason: Empty ID
"""
        )

        result = load_suppressions(str(suppress_file))

        # Should only load entry with valid ID
        assert len(result) == 1
        assert "fp-valid" in result

    def test_load_suppressions_whitespace_in_id(self, tmp_path: Path):
        """Test that ID whitespace is stripped."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - id: "  fp-trimmed  "
    reason: ID has whitespace
"""
        )

        result = load_suppressions(str(suppress_file))

        # ID should be trimmed
        assert len(result) == 1
        assert "fp-trimmed" in result

    def test_load_suppressions_missing_reason_field(self, tmp_path: Path):
        """Test that missing reason defaults to empty string."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - id: fp-no-reason
"""
        )

        result = load_suppressions(str(suppress_file))

        assert len(result) == 1
        assert result["fp-no-reason"].reason == ""

    def test_load_suppressions_with_yaml_date_parsing(self, tmp_path: Path):
        """Test that YAML auto-parses date strings to date objects."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - id: fp-date
    expires: 2025-12-31
"""
        )

        result = load_suppressions(str(suppress_file))

        assert len(result) == 1
        # YAML may parse as string or date object depending on implementation
        # Both are supported by Suppression.is_active()
        assert result["fp-date"].expires is not None

    def test_load_suppressions_multiple_entries(self, tmp_path: Path):
        """Test loading multiple suppression entries."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - id: fp-001
    reason: Test 1
  - id: fp-002
    reason: Test 2
  - id: fp-003
    reason: Test 3
    expires: 2025-12-31
"""
        )

        result = load_suppressions(str(suppress_file))

        assert len(result) == 3
        assert all(f"fp-{i:03d}" in result for i in range(1, 4))

    def test_load_suppressions_yaml_with_comments(self, tmp_path: Path):
        """Test loading YAML file with comments."""
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
# Suppression rules for false positives
suppressions:
  # First rule
  - id: fp-123
    reason: False positive  # Verified by security team
"""
        )

        result = load_suppressions(str(suppress_file))

        assert len(result) == 1
        assert "fp-123" in result


# ============================================================================
# 3. filter_suppressed() Tests
# ============================================================================


class TestFilterSuppressed:
    """Tests for filter_suppressed() function."""

    def test_filter_suppressed_empty_findings(self):
        """Test filtering empty findings list."""
        suppressions = {"fp-123": Suppression(id="fp-123")}

        result = filter_suppressed([], suppressions)

        assert result == []

    def test_filter_suppressed_empty_suppressions(self):
        """Test filtering with no suppressions."""
        findings = [
            {"id": "finding-1", "ruleId": "rule-1"},
            {"id": "finding-2", "ruleId": "rule-2"},
        ]

        result = filter_suppressed(findings, {})

        # All findings should pass through
        assert len(result) == 2
        assert result == findings

    def test_filter_suppressed_finding_without_id(self):
        """Test that findings without id are never suppressed."""
        findings = [
            {"ruleId": "rule-1", "message": "No ID field"},
            {"id": None, "ruleId": "rule-2"},
        ]
        suppressions = {"fp-123": Suppression(id="fp-123")}

        result = filter_suppressed(findings, suppressions)

        # Both findings should pass through (no ID to match)
        assert len(result) == 2

    def test_filter_suppressed_single_active_suppression(self):
        """Test filtering with single active suppression."""
        findings = [
            {"id": "fp-123", "ruleId": "G101", "message": "False positive"},
            {"id": "real-456", "ruleId": "G102", "message": "Real issue"},
        ]
        suppressions = {"fp-123": Suppression(id="fp-123", reason="False positive")}

        result = filter_suppressed(findings, suppressions)

        # Only real-456 should remain
        assert len(result) == 1
        assert result[0]["id"] == "real-456"

    def test_filter_suppressed_expired_suppression(self):
        """Test that expired suppressions don't filter findings."""
        findings = [
            {"id": "fp-123", "ruleId": "G101", "message": "Previously suppressed"},
        ]
        suppressions = {
            "fp-123": Suppression(
                id="fp-123", reason="Expired", expires=dt.date(2020, 1, 1)
            )
        }

        # Use current date (2025) - suppression is expired
        result = filter_suppressed(findings, suppressions)

        # Finding should NOT be suppressed (suppression expired)
        assert len(result) == 1
        assert result[0]["id"] == "fp-123"

    def test_filter_suppressed_future_expiration(self):
        """Test that future expiration allows suppression."""
        findings = [
            {"id": "fp-123", "ruleId": "G101", "message": "Suppressed"},
        ]
        suppressions = {
            "fp-123": Suppression(
                id="fp-123", reason="Active", expires=dt.date(2999, 12, 31)
            )
        }

        result = filter_suppressed(findings, suppressions)

        # Finding should be suppressed (not expired)
        assert len(result) == 0

    def test_filter_suppressed_multiple_findings_mixed(self):
        """Test filtering multiple findings with mixed suppressions."""
        findings = [
            {"id": "fp-001", "ruleId": "G101"},
            {"id": "real-002", "ruleId": "G102"},
            {"id": "fp-003", "ruleId": "G103"},
            {"id": "real-004", "ruleId": "G104"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001", reason="False positive"),
            "fp-003": Suppression(id="fp-003", reason="Accepted risk"),
        }

        result = filter_suppressed(findings, suppressions)

        # Only real-002 and real-004 should remain
        assert len(result) == 2
        assert result[0]["id"] == "real-002"
        assert result[1]["id"] == "real-004"

    def test_filter_suppressed_non_string_id(self):
        """Test that findings with non-string id are not suppressed."""
        findings = [
            {"id": 12345, "ruleId": "G101"},  # Integer ID
            {"id": ["fp-123"], "ruleId": "G102"},  # List ID
        ]
        suppressions = {"fp-123": Suppression(id="fp-123")}

        result = filter_suppressed(findings, suppressions)

        # Both findings should pass through (non-string IDs)
        assert len(result) == 2

    def test_filter_suppressed_preserves_finding_data(self):
        """Test that filtering preserves all finding data."""
        findings = [
            {
                "id": "real-001",
                "ruleId": "G101",
                "severity": "HIGH",
                "message": "Security issue",
                "location": {"path": "file.py", "startLine": 42},
            },
        ]
        suppressions = {}

        result = filter_suppressed(findings, suppressions)

        # Finding should be unchanged
        assert len(result) == 1
        assert result[0] == findings[0]
        assert result[0]["severity"] == "HIGH"
        assert result[0]["location"]["startLine"] == 42

    def test_filter_suppressed_suppression_not_in_findings(self):
        """Test that suppressions without matching findings are ignored."""
        findings = [
            {"id": "finding-1", "ruleId": "G101"},
        ]
        suppressions = {
            "fp-123": Suppression(id="fp-123", reason="No matching finding"),
            "fp-456": Suppression(id="fp-456", reason="Also no match"),
        }

        result = filter_suppressed(findings, suppressions)

        # Finding should pass through (no matching suppression)
        assert len(result) == 1
        assert result[0]["id"] == "finding-1"

    def test_filter_suppressed_all_findings_suppressed(self):
        """Test that all findings can be suppressed."""
        findings = [
            {"id": "fp-001", "ruleId": "G101"},
            {"id": "fp-002", "ruleId": "G102"},
            {"id": "fp-003", "ruleId": "G103"},
        ]
        suppressions = {
            "fp-001": Suppression(id="fp-001"),
            "fp-002": Suppression(id="fp-002"),
            "fp-003": Suppression(id="fp-003"),
        }

        result = filter_suppressed(findings, suppressions)

        # All findings suppressed
        assert len(result) == 0

    def test_filter_suppressed_case_sensitive_id_matching(self):
        """Test that ID matching is case-sensitive."""
        findings = [
            {"id": "fp-123", "ruleId": "G101"},
            {"id": "FP-123", "ruleId": "G102"},
        ]
        suppressions = {"fp-123": Suppression(id="fp-123")}

        result = filter_suppressed(findings, suppressions)

        # Only lowercase fp-123 should be suppressed
        assert len(result) == 1
        assert result[0]["id"] == "FP-123"

    def test_filter_suppressed_integration_with_load_suppressions(self, tmp_path: Path):
        """Integration test: load suppressions and filter findings."""
        # Create suppression file
        suppress_file = tmp_path / "jmo.suppress.yml"
        suppress_file.write_text(
            """
suppressions:
  - id: fp-123
    reason: False positive
  - id: fp-456
    reason: Accepted risk
    expires: 2999-12-31
"""
        )

        # Load suppressions
        suppressions = load_suppressions(str(suppress_file))

        # Create findings
        findings = [
            {"id": "fp-123", "ruleId": "G101"},
            {"id": "real-789", "ruleId": "G102"},
            {"id": "fp-456", "ruleId": "G103"},
        ]

        # Filter
        result = filter_suppressed(findings, suppressions)

        # Only real-789 should remain
        assert len(result) == 1
        assert result[0]["id"] == "real-789"
