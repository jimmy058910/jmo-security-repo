"""
Unit tests for PriorityCalculator.

Tests priority scoring formula including:
- Severity-based scoring
- EPSS integration
- KEV integration
- CVE extraction
- Bulk priority calculation
- Score component transparency
"""

from unittest.mock import Mock, patch

import pytest

from scripts.core.epss_integration import EPSSScore
from scripts.core.kev_integration import KEVEntry
from scripts.core.priority_calculator import PriorityCalculator, PriorityScore


@pytest.fixture
def temp_cache_dir(tmp_path):
    """Create temporary cache directory for testing."""
    cache_dir = tmp_path / "cache"
    cache_dir.mkdir()
    return cache_dir


@pytest.fixture
def priority_calculator(temp_cache_dir):
    """Create PriorityCalculator with mocked clients."""
    with (
        patch("scripts.core.priority_calculator.EPSSClient"),
        patch("scripts.core.priority_calculator.KEVClient"),
    ):
        return PriorityCalculator(cache_dir=str(temp_cache_dir))


class TestPriorityScore:
    """Tests for PriorityScore dataclass."""

    def test_create_priority_score(self):
        """Test creating PriorityScore object."""
        score = PriorityScore(
            finding_id="test-001",
            priority=85.5,
            severity="HIGH",
            epss=0.95,
            epss_percentile=0.999,
            is_kev=True,
            kev_due_date="2024-10-15",
            components={
                "severity_score": 7,
                "epss_multiplier": 4.8,
                "kev_multiplier": 3.0,
                "reachability_multiplier": 1.0,
            },
        )

        assert score.finding_id == "test-001"
        assert score.priority == 85.5
        assert score.severity == "HIGH"
        assert score.epss == 0.95
        assert score.epss_percentile == 0.999
        assert score.is_kev is True
        assert score.kev_due_date == "2024-10-15"
        assert score.components["severity_score"] == 7

    def test_priority_score_defaults(self):
        """Test PriorityScore with default values."""
        score = PriorityScore(finding_id="test-002", priority=50.0, severity="MEDIUM")

        assert score.epss is None
        assert score.epss_percentile is None
        assert score.is_kev is False
        assert score.kev_due_date is None
        assert score.components == {}


class TestPriorityCalculator:
    """Tests for PriorityCalculator."""

    def test_calculate_priority_severity_only(self, priority_calculator):
        """Test priority calculation with severity only (no EPSS/KEV data)."""
        finding = {
            "id": "test-001",
            "severity": "HIGH",
            "message": "Security vulnerability detected",
        }

        priority_calculator.epss_client.get_score = Mock(return_value=None)
        priority_calculator.kev_client.is_kev = Mock(return_value=False)

        priority = priority_calculator.calculate_priority(finding)

        assert priority.finding_id == "test-001"
        assert priority.severity == "HIGH"
        assert priority.epss is None
        assert priority.is_kev is False

        # Severity HIGH = 7, no multipliers = 1.0 each
        # (7 * 1.0 * 1.0 * 1.0) / 1.5 * 5.0 = 23.33
        assert 23.0 <= priority.priority <= 24.0

    def test_calculate_priority_with_epss(self, priority_calculator):
        """Test priority calculation with EPSS data."""
        finding = {"id": "test-002", "severity": "CRITICAL", "ruleId": "CVE-2024-1234"}

        epss_score = EPSSScore(
            cve="CVE-2024-1234",
            epss=0.95,  # Very high exploit probability
            percentile=0.999,
            date="2024-10-01",
        )

        priority_calculator.epss_client.get_score = Mock(return_value=epss_score)
        priority_calculator.kev_client.is_kev = Mock(return_value=False)

        priority = priority_calculator.calculate_priority(finding)

        assert priority.finding_id == "test-002"
        assert priority.severity == "CRITICAL"
        assert priority.epss == 0.95
        assert priority.epss_percentile == 0.999
        assert priority.is_kev is False

        # EPSS multiplier = 1.0 + (0.95 * 4.0) = 4.8
        # (10 * 4.8 * 1.0 * 1.0) / 1.5 * 5.0 = 160.0 (capped at 100)
        assert priority.priority == 100.0

        assert priority.components["epss_multiplier"] == 1.0 + (0.95 * 4.0)

    def test_calculate_priority_with_kev(self, priority_calculator):
        """Test priority calculation with KEV status."""
        finding = {"id": "test-003", "severity": "HIGH", "ruleId": "CVE-2024-5678"}

        kev_entry = KEVEntry(
            cve="CVE-2024-5678",
            vendor="Test Vendor",
            product="Test Product",
            vulnerability_name="Critical RCE",
            date_added="2024-09-15",
            short_description="Remote code execution",
            required_action="Apply patches",
            due_date="2024-10-15",
        )

        priority_calculator.epss_client.get_score = Mock(return_value=None)
        priority_calculator.kev_client.is_kev = Mock(return_value=True)
        priority_calculator.kev_client.get_entry = Mock(return_value=kev_entry)

        priority = priority_calculator.calculate_priority(finding)

        assert priority.finding_id == "test-003"
        assert priority.severity == "HIGH"
        assert priority.is_kev is True
        assert priority.kev_due_date == "2024-10-15"

        # KEV multiplier = 3.0
        # (7 * 1.0 * 3.0 * 1.0) / 1.5 * 5.0 = 70.0
        assert 69.0 <= priority.priority <= 71.0

        assert priority.components["kev_multiplier"] == 3.0

    def test_calculate_priority_with_epss_and_kev(self, priority_calculator):
        """Test priority calculation with both EPSS and KEV data."""
        finding = {"id": "test-004", "severity": "CRITICAL", "ruleId": "CVE-2024-9999"}

        epss_score = EPSSScore(
            cve="CVE-2024-9999", epss=0.85, percentile=0.99, date="2024-10-01"
        )

        kev_entry = KEVEntry(
            cve="CVE-2024-9999",
            vendor="Security Inc",
            product="Secure System",
            vulnerability_name="SQL Injection",
            date_added="2024-09-25",
            short_description="SQL injection",
            required_action="Migrate to fixed version",
            due_date="2024-10-25",
        )

        priority_calculator.epss_client.get_score = Mock(return_value=epss_score)
        priority_calculator.kev_client.is_kev = Mock(return_value=True)
        priority_calculator.kev_client.get_entry = Mock(return_value=kev_entry)

        priority = priority_calculator.calculate_priority(finding)

        assert priority.finding_id == "test-004"
        assert priority.severity == "CRITICAL"
        assert priority.epss == 0.85
        assert priority.is_kev is True
        assert priority.kev_due_date == "2024-10-25"

        # EPSS multiplier = 1.0 + (0.85 * 4.0) = 4.4
        # KEV multiplier = 3.0
        # (10 * 4.4 * 3.0 * 1.0) / 1.5 * 5.0 = 440.0 (capped at 100)
        assert priority.priority == 100.0

        assert priority.components["epss_multiplier"] == 1.0 + (0.85 * 4.0)
        assert priority.components["kev_multiplier"] == 3.0

    def test_calculate_priority_low_severity(self, priority_calculator):
        """Test priority calculation for LOW severity finding."""
        finding = {
            "id": "test-005",
            "severity": "LOW",
            "message": "Minor issue detected",
        }

        priority_calculator.epss_client.get_score = Mock(return_value=None)
        priority_calculator.kev_client.is_kev = Mock(return_value=False)

        priority = priority_calculator.calculate_priority(finding)

        assert priority.severity == "LOW"

        # Severity LOW = 2
        # (2 * 1.0 * 1.0 * 1.0) / 1.5 * 5.0 = 6.67
        assert 6.0 <= priority.priority <= 7.0

    def test_calculate_priority_info_severity(self, priority_calculator):
        """Test priority calculation for INFO severity finding."""
        finding = {
            "id": "test-006",
            "severity": "INFO",
            "message": "Informational note",
        }

        priority_calculator.epss_client.get_score = Mock(return_value=None)
        priority_calculator.kev_client.is_kev = Mock(return_value=False)

        priority = priority_calculator.calculate_priority(finding)

        assert priority.severity == "INFO"

        # Severity INFO = 1
        # (1 * 1.0 * 1.0 * 1.0) / 1.5 * 5.0 = 3.33
        assert 3.0 <= priority.priority <= 4.0

    def test_extract_cves_from_rule_id(self, priority_calculator):
        """Test CVE extraction from ruleId field."""
        finding = {"id": "test-007", "severity": "HIGH", "ruleId": "CVE-2024-1234"}

        cves = priority_calculator._extract_cves(finding)

        assert len(cves) == 1
        assert "CVE-2024-1234" in cves

    def test_extract_cves_from_message(self, priority_calculator):
        """Test CVE extraction from message field."""
        finding = {
            "id": "test-008",
            "severity": "HIGH",
            "message": "Vulnerability CVE-2024-1234 and CVE-2024-5678 detected",
        }

        cves = priority_calculator._extract_cves(finding)

        assert len(cves) == 2
        assert "CVE-2024-1234" in cves
        assert "CVE-2024-5678" in cves

    def test_extract_cves_from_raw_field(self, priority_calculator):
        """Test CVE extraction from raw.cve field."""
        finding = {
            "id": "test-009",
            "severity": "HIGH",
            "raw": {"cve": "CVE-2024-9999"},
        }

        cves = priority_calculator._extract_cves(finding)

        assert len(cves) == 1
        assert "CVE-2024-9999" in cves

    def test_extract_cves_from_raw_cve_id_field(self, priority_calculator):
        """Test CVE extraction from raw.cveId field."""
        finding = {
            "id": "test-010",
            "severity": "HIGH",
            "raw": {"cveId": "CVE-2024-1111"},
        }

        cves = priority_calculator._extract_cves(finding)

        assert len(cves) == 1
        assert "CVE-2024-1111" in cves

    def test_extract_cves_deduplicate(self, priority_calculator):
        """Test CVE extraction deduplicates CVEs."""
        finding = {
            "id": "test-011",
            "severity": "HIGH",
            "ruleId": "CVE-2024-1234",
            "message": "CVE-2024-1234 detected",
            "raw": {"cve": "CVE-2024-1234"},
        }

        cves = priority_calculator._extract_cves(finding)

        # Should only have one instance despite being in multiple fields
        assert len(cves) == 1
        assert "CVE-2024-1234" in cves

    def test_extract_cves_no_cves(self, priority_calculator):
        """Test CVE extraction when no CVEs present."""
        finding = {
            "id": "test-012",
            "severity": "HIGH",
            "message": "Security issue detected",
        }

        cves = priority_calculator._extract_cves(finding)

        assert len(cves) == 0

    def test_calculate_priorities_bulk(self, priority_calculator):
        """Test bulk priority calculation for multiple findings."""
        findings = [
            {"id": "test-013", "severity": "CRITICAL", "ruleId": "CVE-2024-1234"},
            {"id": "test-014", "severity": "HIGH", "ruleId": "CVE-2024-5678"},
            {"id": "test-015", "severity": "MEDIUM", "message": "No CVE"},
        ]

        # Mock bulk EPSS fetch
        epss_scores = {
            "CVE-2024-1234": EPSSScore(
                cve="CVE-2024-1234", epss=0.95, percentile=0.999, date="2024-10-01"
            ),
            "CVE-2024-5678": EPSSScore(
                cve="CVE-2024-5678", epss=0.50, percentile=0.80, date="2024-10-01"
            ),
        }

        priority_calculator.epss_client.get_scores_bulk = Mock(return_value=epss_scores)
        priority_calculator.epss_client.get_score = Mock(
            side_effect=lambda cve: epss_scores.get(cve)
        )
        priority_calculator.kev_client.is_kev = Mock(return_value=False)

        priorities = priority_calculator.calculate_priorities_bulk(findings)

        assert len(priorities) == 3
        assert "test-013" in priorities
        assert "test-014" in priorities
        assert "test-015" in priorities

        # Verify bulk API was called
        priority_calculator.epss_client.get_scores_bulk.assert_called_once()

    def test_calculate_priority_default_severity(self, priority_calculator):
        """Test priority calculation with missing severity defaults to MEDIUM."""
        finding = {"id": "test-016", "message": "Issue detected"}

        priority_calculator.epss_client.get_score = Mock(return_value=None)
        priority_calculator.kev_client.is_kev = Mock(return_value=False)

        priority = priority_calculator.calculate_priority(finding)

        assert priority.severity == "MEDIUM"
        assert priority.components["severity_score"] == 4

    def test_calculate_priority_component_transparency(self, priority_calculator):
        """Test that priority score components are exposed for transparency."""
        finding = {"id": "test-017", "severity": "HIGH", "ruleId": "CVE-2024-1234"}

        epss_score = EPSSScore(
            cve="CVE-2024-1234", epss=0.75, percentile=0.95, date="2024-10-01"
        )

        priority_calculator.epss_client.get_score = Mock(return_value=epss_score)
        priority_calculator.kev_client.is_kev = Mock(return_value=False)

        priority = priority_calculator.calculate_priority(finding)

        assert "severity_score" in priority.components
        assert "epss_multiplier" in priority.components
        assert "kev_multiplier" in priority.components
        assert "reachability_multiplier" in priority.components

        assert priority.components["severity_score"] == 7
        assert priority.components["epss_multiplier"] == 1.0 + (0.75 * 4.0)
        assert priority.components["kev_multiplier"] == 1.0
        assert priority.components["reachability_multiplier"] == 1.0
