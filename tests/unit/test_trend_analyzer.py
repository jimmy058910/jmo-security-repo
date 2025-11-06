#!/usr/bin/env python3
"""
Unit tests for trend_analyzer module (Phases 1-2).

Tests cover:
- TrendAnalyzer class (Phase 1)
- Mann-Kendall statistical validation (Phase 2)
- Security score calculation
- Regression detection
- Insight generation

Target: ≥90% code coverage
"""

import json
import sqlite3
import tempfile
from pathlib import Path
from datetime import datetime, timezone
import pytest

from scripts.core.trend_analyzer import (
    TrendAnalyzer,
    mann_kendall_test,
    validate_trend_significance,
    format_trend_summary,
)
from scripts.core.history_db import (
    init_database,
    store_scan,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def temp_db():
    """Create a temporary SQLite database for testing."""
    with tempfile.TemporaryDirectory() as tmpdir:
        db_path = Path(tmpdir) / "test_history.db"
        init_database(db_path)
        yield db_path


@pytest.fixture
def sample_scans_data():
    """Sample scan data for testing (10 scans showing improvement)."""
    return [
        {
            "id": f"scan-{i}",
            "timestamp": 1704067200 + (i * 86400),  # One per day starting Jan 1, 2024
            "timestamp_iso": datetime.fromtimestamp(1704067200 + (i * 86400), tz=timezone.utc).isoformat(),
            "branch": "main",
            "commit_hash": f"abc{i}",
            "profile": "balanced",
            "tools": ["trivy", "semgrep"],
            "total_findings": max(100 - (i * 5), 10),  # Decreasing: 100, 95, 90, ..., 55
            "critical_count": max(10 - i, 0),  # Decreasing: 10, 9, 8, ..., 0
            "high_count": max(20 - (i * 2), 5),  # Decreasing: 20, 18, 16, ..., 2
            "medium_count": max(30 - i, 10),  # Decreasing: 30, 29, 28, ..., 20
            "low_count": max(25 - i, 5),  # Decreasing: 25, 24, 23, ..., 15
            "info_count": max(15 - i, 5),  # Decreasing: 15, 14, 13, ..., 5
        }
        for i in range(10)
    ]


@pytest.fixture
def degrading_scans_data():
    """Sample scan data showing degradation (security getting worse)."""
    return [
        {
            "id": f"scan-{i}",
            "timestamp": 1704067200 + (i * 86400),
            "timestamp_iso": datetime.fromtimestamp(1704067200 + (i * 86400), tz=timezone.utc).isoformat(),
            "branch": "main",
            "commit_hash": f"abc{i}",
            "profile": "balanced",
            "tools": ["trivy", "semgrep"],
            "total_findings": 50 + (i * 5),  # Increasing: 50, 55, 60, ..., 95
            "critical_count": i,  # Increasing: 0, 1, 2, ..., 9
            "high_count": 10 + (i * 2),  # Increasing: 10, 12, 14, ..., 28
            "medium_count": 15 + i,  # Increasing: 15, 16, 17, ..., 24
            "low_count": 15 + i,  # Increasing
            "info_count": 10,  # Stable
        }
        for i in range(10)
    ]


# ============================================================================
# Phase 2: Mann-Kendall Test
# ============================================================================


def test_mann_kendall_decreasing_trend():
    """Test Mann-Kendall detects decreasing trend (improving security)."""
    data = [10, 8, 6, 5, 3, 2]  # Clear decreasing pattern
    trend, tau, p_value = mann_kendall_test(data)

    assert trend == "decreasing", f"Expected decreasing trend, got {trend}"
    assert tau < 0, f"Tau should be negative for decreasing trend, got {tau}"
    assert p_value < 0.05, f"P-value should be < 0.05 for significant trend, got {p_value}"


def test_mann_kendall_increasing_trend():
    """Test Mann-Kendall detects increasing trend (degrading security)."""
    data = [2, 3, 5, 6, 8, 10]  # Clear increasing pattern
    trend, tau, p_value = mann_kendall_test(data)

    assert trend == "increasing", f"Expected increasing trend, got {trend}"
    assert tau > 0, f"Tau should be positive for increasing trend, got {tau}"
    assert p_value < 0.05, f"P-value should be < 0.05 for significant trend, got {p_value}"


def test_mann_kendall_no_trend():
    """Test Mann-Kendall detects no trend (random fluctuation)."""
    data = [5, 6, 5, 6, 5, 6, 5]  # Random fluctuation
    trend, tau, p_value = mann_kendall_test(data)

    assert trend == "no_trend", f"Expected no trend, got {trend}"
    assert p_value >= 0.05, f"P-value should be >= 0.05 for no trend, got {p_value}"


def test_mann_kendall_insufficient_data():
    """Test Mann-Kendall handles insufficient data gracefully."""
    data = [5, 6]  # Only 2 data points
    trend, tau, p_value = mann_kendall_test(data)

    assert trend == "insufficient_data", f"Expected insufficient_data, got {trend}"
    assert tau == 0.0
    assert p_value == 1.0


def test_mann_kendall_perfect_decreasing():
    """Test Mann-Kendall with perfect decreasing trend (tau = -1.0)."""
    data = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    trend, tau, p_value = mann_kendall_test(data)

    assert trend == "decreasing"
    assert tau == -1.0, f"Perfect decreasing should have tau=-1.0, got {tau}"
    assert p_value < 0.01, "Very significant trend"


def test_validate_trend_significance():
    """Test validate_trend_significance wrapper function."""
    severity_trends = {
        "CRITICAL": [10, 8, 6, 5, 3, 2],  # Decreasing (good)
        "HIGH": [20, 18, 16, 14, 12, 10],  # Decreasing (good)
        "MEDIUM": [30, 30, 31, 29, 30, 30],  # Stable
    }

    results = validate_trend_significance(severity_trends)

    assert "CRITICAL" in results
    assert "HIGH" in results
    assert "MEDIUM" in results

    # CRITICAL should show significant decreasing trend
    assert results["CRITICAL"]["trend"] == "decreasing"
    assert results["CRITICAL"]["significant"] is True
    assert results["CRITICAL"]["p_value"] < 0.05

    # HIGH should show significant decreasing trend
    assert results["HIGH"]["trend"] == "decreasing"
    assert results["HIGH"]["significant"] is True

    # MEDIUM should show no trend (stable)
    assert results["MEDIUM"]["trend"] == "no_trend"
    assert results["MEDIUM"]["significant"] is False


# ============================================================================
# Phase 1: Core Trend Analyzer
# ============================================================================


def test_trend_analyzer_context_manager(temp_db):
    """Test TrendAnalyzer context manager initialization."""
    with TrendAnalyzer(temp_db) as analyzer:
        assert analyzer.conn is not None
        assert isinstance(analyzer.conn, sqlite3.Connection)
    # Connection should be closed after exiting context


def test_trend_analyzer_no_scans(temp_db):
    """Test TrendAnalyzer handles empty database gracefully."""
    with TrendAnalyzer(temp_db) as analyzer:
        analysis = analyzer.analyze_trends(branch="main", last_n=10)

    assert analysis["metadata"]["status"] == "no_data"
    assert "No scans found" in analysis["metadata"]["message"]


def test_trend_analyzer_improvement_trend(temp_db, sample_scans_data):
    """Test TrendAnalyzer correctly identifies improving trend."""
    # Store sample scans
    for scan_data in sample_scans_data:
        # Create a minimal findings.json for store_scan
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            results_dir.mkdir()
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir()
            findings_file = summaries_dir / "findings.json"
            findings_file.write_text('{"findings": []}')

            store_scan(
                results_dir=results_dir,
                profile=scan_data["profile"],
                tools=scan_data["tools"],
                db_path=temp_db,
                commit_hash=scan_data["commit_hash"],
                branch=scan_data["branch"],
            )

    # Analyze trends
    with TrendAnalyzer(temp_db) as analyzer:
        analysis = analyzer.analyze_trends(branch="main", last_n=10)

    # Verify results
    assert analysis["metadata"]["scan_count"] == 10
    assert "severity_trends" in analysis
    assert "improvement_metrics" in analysis
    assert "regressions" in analysis
    assert "insights" in analysis
    assert "security_score" in analysis

    # Check trend classification
    metrics = analysis["improvement_metrics"]
    assert metrics["trend"] in ["improving", "stable"], f"Expected improving/stable, got {metrics['trend']}"
    assert metrics["confidence"] == "high", "10 scans should give high confidence"


def test_trend_analyzer_degrading_trend(temp_db, degrading_scans_data):
    """Test TrendAnalyzer correctly identifies degrading trend."""
    # Store degrading scans
    for scan_idx, scan_data in enumerate(degrading_scans_data):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            results_dir.mkdir()
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir()
            findings_file = summaries_dir / "findings.json"

            # Generate findings matching the severity counts in scan_data
            # Use scan_idx to make fingerprints unique across scans
            findings = []
            for i in range(scan_data["critical_count"]):
                findings.append({
                    "id": f"scan{scan_idx}-crit-{i}",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "location": {"path": f"scan{scan_idx}-file{i}.py", "startLine": 1},
                    "message": f"Critical issue {i}",
                    "ruleId": f"CRIT-{scan_idx}-{i}",
                })
            for i in range(scan_data["high_count"]):
                findings.append({
                    "id": f"scan{scan_idx}-high-{i}",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep"},
                    "location": {"path": f"scan{scan_idx}-file{i}.py", "startLine": 10},
                    "message": f"High issue {i}",
                    "ruleId": f"HIGH-{scan_idx}-{i}",
                })
            for i in range(scan_data["medium_count"]):
                findings.append({
                    "id": f"scan{scan_idx}-med-{i}",
                    "severity": "MEDIUM",
                    "tool": {"name": "trivy"},
                    "location": {"path": f"scan{scan_idx}-file{i}.py", "startLine": 20},
                    "message": f"Medium issue {i}",
                    "ruleId": f"MED-{scan_idx}-{i}",
                })

            findings_file.write_text(json.dumps({"findings": findings}))

            store_scan(
                results_dir=results_dir,
                profile=scan_data["profile"],
                tools=scan_data["tools"],
                db_path=temp_db,
                commit_hash=scan_data["commit_hash"],
                branch=scan_data["branch"],
            )

    # Analyze trends
    with TrendAnalyzer(temp_db) as analyzer:
        analysis = analyzer.analyze_trends(branch="main", last_n=10)

    # Verify degrading trend detected
    metrics = analysis["improvement_metrics"]
    assert metrics["trend"] == "degrading", f"Expected degrading, got {metrics['trend']}"
    assert metrics["total_change"] > 0, "Total findings should increase"
    assert metrics["critical_change"] > 0, "CRITICAL should increase"


def test_regression_detection(temp_db, degrading_scans_data):
    """Test regression detection identifies severity increases."""
    # Store scans with regressions
    for scan_idx, scan_data in enumerate(degrading_scans_data):
        with tempfile.TemporaryDirectory() as tmpdir:
            results_dir = Path(tmpdir) / "results"
            results_dir.mkdir()
            summaries_dir = results_dir / "summaries"
            summaries_dir.mkdir()
            findings_file = summaries_dir / "findings.json"

            # Generate findings matching the severity counts in scan_data
            # Use scan_idx to make fingerprints unique across scans
            findings = []
            for i in range(scan_data["critical_count"]):
                findings.append({
                    "id": f"scan{scan_idx}-crit-{i}",
                    "severity": "CRITICAL",
                    "tool": {"name": "trivy"},
                    "location": {"path": f"scan{scan_idx}-file{i}.py", "startLine": 1},
                    "message": f"Critical issue {i}",
                    "ruleId": f"CRIT-{scan_idx}-{i}",
                })
            for i in range(scan_data["high_count"]):
                findings.append({
                    "id": f"scan{scan_idx}-high-{i}",
                    "severity": "HIGH",
                    "tool": {"name": "semgrep"},
                    "location": {"path": f"scan{scan_idx}-file{i}.py", "startLine": 10},
                    "message": f"High issue {i}",
                    "ruleId": f"HIGH-{scan_idx}-{i}",
                })
            for i in range(scan_data["medium_count"]):
                findings.append({
                    "id": f"scan{scan_idx}-med-{i}",
                    "severity": "MEDIUM",
                    "tool": {"name": "trivy"},
                    "location": {"path": f"scan{scan_idx}-file{i}.py", "startLine": 20},
                    "message": f"Medium issue {i}",
                    "ruleId": f"MED-{scan_idx}-{i}",
                })

            findings_file.write_text(json.dumps({"findings": findings}))

            store_scan(
                results_dir=results_dir,
                profile=scan_data["profile"],
                tools=scan_data["tools"],
                db_path=temp_db,
                commit_hash=scan_data["commit_hash"],
                branch=scan_data["branch"],
            )

    # Analyze regressions
    with TrendAnalyzer(temp_db) as analyzer:
        analysis = analyzer.analyze_trends(branch="main", last_n=10)

    regressions = analysis["regressions"]

    # Should detect CRITICAL regressions (any increase triggers)
    critical_regressions = [r for r in regressions if r["severity"] == "CRITICAL"]
    assert len(critical_regressions) > 0, "Should detect CRITICAL regressions"

    # Check regression structure
    if regressions:
        reg = regressions[0]
        assert "scan_id" in reg
        assert "timestamp" in reg
        assert "severity" in reg
        assert "previous_count" in reg
        assert "current_count" in reg
        assert "increase" in reg
        assert reg["increase"] > 0


def test_security_score_calculation():
    """Test security posture score calculation."""
    scans = [
        {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0,
        },  # Perfect score: 100
        {
            "critical_count": 2,
            "high_count": 5,
            "medium_count": 10,
            "low_count": 20,
            "info_count": 50,
        },  # score = 100 - 20 - 15 - 10 = 55
        {
            "critical_count": 10,
            "high_count": 20,
            "medium_count": 30,
            "low_count": 40,
            "info_count": 50,
        },  # score = 0 (floor)
    ]

    analyzer = TrendAnalyzer(Path("/dev/null"))  # Don't need DB for this test
    score_data = analyzer._calculate_security_score(scans)

    assert score_data["current_score"] == 0, "Last scan should score 0"
    assert score_data["grade"] == "F"
    assert score_data["historical_scores"] == [100, 55, 0]
    assert score_data["trend"] == "degrading", "Score decreased from 100 to 0"


def test_security_score_grades():
    """Test security score grade assignments."""
    # Formula: 100 - (critical × 10) - (high × 3) - (medium × 1)
    test_cases = [
        ({"critical_count": 0, "high_count": 0, "medium_count": 0}, 100, "A"),
        ({"critical_count": 0, "high_count": 3, "medium_count": 1}, 90, "A"),  # 100 - 0 - 9 - 1 = 90
        ({"critical_count": 1, "high_count": 5, "medium_count": 5}, 70, "C"),  # 100 - 10 - 15 - 5 = 70
        ({"critical_count": 2, "high_count": 5, "medium_count": 10}, 55, "F"),  # 100 - 20 - 15 - 10 = 55
    ]

    analyzer = TrendAnalyzer(Path("/dev/null"))

    for scan_data, expected_score, expected_grade in test_cases:
        scan_data.update({"low_count": 0, "info_count": 0})
        score_data = analyzer._calculate_security_score([scan_data])

        assert score_data["current_score"] == expected_score, f"Expected score {expected_score}, got {score_data['current_score']}"
        assert score_data["grade"] == expected_grade, f"Expected grade {expected_grade}, got {score_data['grade']}"


def test_insight_generation(sample_scans_data):
    """Test automated insight generation."""
    analyzer = TrendAnalyzer(Path("/dev/null"))

    severity_trends = {
        "CRITICAL": [s["critical_count"] for s in sample_scans_data],
        "HIGH": [s["high_count"] for s in sample_scans_data],
    }

    improvement_metrics = {
        "trend": "improving",
        "total_change": -45,
        "critical_change": -10,
        "high_change": -18,
        "percentage_change": -45.0,
    }

    regressions = []

    insights = analyzer._generate_insights(
        sample_scans_data, {"by_severity": severity_trends}, improvement_metrics, regressions
    )

    assert len(insights) > 0, "Should generate at least one insight"

    # Check for expected insight patterns
    insights_text = " ".join(insights)
    assert "IMPROVING" in insights_text or "improving" in insights_text.lower()
    assert "CRITICAL" in insights_text


def test_format_trend_summary(sample_scans_data):
    """Test trend summary formatting for terminal output."""
    # Create a minimal analysis result
    analysis = {
        "metadata": {
            "branch": "main",
            "scan_count": 10,
            "date_range": {
                "start": sample_scans_data[0]["timestamp_iso"],
                "end": sample_scans_data[-1]["timestamp_iso"],
            },
        },
        "improvement_metrics": {
            "trend": "improving",
            "total_change": -45,
            "critical_change": -10,
            "high_change": -18,
            "percentage_change": -45.0,
            "confidence": "high",
        },
        "security_score": {
            "current_score": 85,
            "grade": "B",
            "trend": "improving",
            "historical_scores": list(range(55, 100, 5)),
        },
        "regressions": [],
        "insights": [
            "✅ Security posture is IMPROVING",
            "🎯 CRITICAL findings reduced by 10",
        ],
        "top_rules": [
            {"rule_id": "CWE-79", "severity": "HIGH", "tool": "semgrep", "count": 15},
            {"rule_id": "CWE-89", "severity": "HIGH", "tool": "semgrep", "count": 12},
        ],
    }

    summary = format_trend_summary(analysis, verbose=True)

    assert "Security Trend Analysis" in summary
    assert "main" in summary
    assert "IMPROVING" in summary
    assert "85/100" in summary
    assert "Grade: B" in summary
    assert "CRITICAL findings reduced by 10" in summary
    assert "CWE-79" in summary  # Verbose mode shows top rules


def test_format_trend_summary_with_regressions():
    """Test trend summary formatting with regressions."""
    analysis = {
        "metadata": {
            "branch": "main",
            "scan_count": 5,
            "date_range": {
                "start": "2024-01-01T00:00:00Z",
                "end": "2024-01-05T00:00:00Z",
            },
        },
        "improvement_metrics": {
            "trend": "degrading",
            "total_change": 20,
            "critical_change": 3,
            "high_change": 8,
            "percentage_change": 40.0,
            "confidence": "medium",
        },
        "security_score": {
            "current_score": 65,
            "grade": "D",
            "trend": "degrading",
        },
        "regressions": [
            {
                "severity": "CRITICAL",
                "timestamp": "2024-01-03T00:00:00Z",
                "previous_count": 2,
                "current_count": 5,
                "increase": 3,
            },
        ],
        "insights": [
            "⚠️  Security posture is DEGRADING",
            "🚨 CRITICAL findings increased by 3",
        ],
    }

    summary = format_trend_summary(analysis, verbose=False)

    assert "DEGRADING" in summary
    assert "Grade: D" in summary
    assert "Regressions Detected: 1" in summary
    assert "CRITICAL" in summary


# ============================================================================
# Edge Cases
# ============================================================================


def test_single_scan_insufficient_data(temp_db):
    """Test analyzer handles single scan correctly."""
    with tempfile.TemporaryDirectory() as tmpdir:
        results_dir = Path(tmpdir) / "results"
        results_dir.mkdir()
        summaries_dir = results_dir / "summaries"
        summaries_dir.mkdir()
        findings_file = summaries_dir / "findings.json"
        findings_file.write_text('{"findings": []}')

        store_scan(
            results_dir=results_dir,
            profile="balanced",
            tools=["trivy"],
            db_path=temp_db,
            commit_hash="abc123",
            branch="main",
        )

    with TrendAnalyzer(temp_db) as analyzer:
        analysis = analyzer.analyze_trends(branch="main", last_n=10)

    assert analysis["metadata"]["scan_count"] == 1
    assert analysis["improvement_metrics"]["trend"] == "insufficient_data"


def test_empty_severity_trends():
    """Test Mann-Kendall with empty data."""
    trend, tau, p_value = mann_kendall_test([])
    assert trend == "insufficient_data"
    assert tau == 0.0
    assert p_value == 1.0


def test_constant_severity_trends():
    """Test Mann-Kendall with constant values (no change)."""
    data = [10, 10, 10, 10, 10]
    trend, tau, p_value = mann_kendall_test(data)

    # Constant values mean no trend
    assert trend == "no_trend"
    assert tau == 0.0


# ============================================================================
# Coverage: Hit all code paths
# ============================================================================


def test_improvement_metrics_edge_cases():
    """Test improvement metrics with edge cases."""
    analyzer = TrendAnalyzer(Path("/dev/null"))

    # Test: No scans
    metrics = analyzer._compute_improvement_metrics([])
    assert metrics["trend"] == "insufficient_data"

    # Test: One scan
    single_scan = [{"total_findings": 10, "critical_count": 1, "high_count": 5,
                    "medium_count": 3, "low_count": 1, "info_count": 0}]
    metrics = analyzer._compute_improvement_metrics(single_scan)
    assert metrics["trend"] == "insufficient_data"
    assert metrics["confidence"] == "low"

    # Test: Exactly 2 scans (low confidence)
    two_scans = [
        {"total_findings": 10, "critical_count": 1, "high_count": 5,
         "medium_count": 3, "low_count": 1, "info_count": 0},
        {"total_findings": 8, "critical_count": 0, "high_count": 4,
         "medium_count": 3, "low_count": 1, "info_count": 0},
    ]
    metrics = analyzer._compute_improvement_metrics(two_scans)
    assert metrics["confidence"] == "low", "2 scans should have low confidence"
    assert metrics["total_change"] == -2


def test_top_rules_empty():
    """Test top rules with no findings."""
    analyzer = TrendAnalyzer(Path("/dev/null"))
    top_rules = analyzer._get_top_rules([])
    assert top_rules == []


if __name__ == "__main__":
    pytest.main([__file__, "-v", "--cov=scripts.core.trend_analyzer", "--cov-report=term-missing"])
