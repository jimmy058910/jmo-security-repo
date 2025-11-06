#!/usr/bin/env python3
"""
Tests for trend analysis formatters.

Phase 4: Visualization formatters testing
"""

from __future__ import annotations

import json

import pytest

from scripts.cli.trend_formatters import (
    format_terminal_report,
    format_json_report,
    format_html_report,
    format_comparison,
    _create_sparkline,
    _format_security_score,
    _format_severity_trends,
    _format_improvement_metrics,
    _format_regressions,
    _format_insights,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_analysis():
    """Sample trend analysis data for testing."""
    return {
        "metadata": {
            "branch": "main",
            "scan_count": 10,
            "date_range": {
                "start": "2025-01-01T00:00:00Z",
                "end": "2025-01-10T00:00:00Z",
            },
            "analysis_timestamp": "2025-01-10T12:00:00Z",
        },
        "scans": [
            {
                "id": f"scan-{i}",
                "timestamp": f"2025-01-{i:02d}T00:00:00Z",
                "total_findings": 100 - i * 5,
                "critical_count": 10 - i,
                "high_count": 20 - i,
                "medium_count": 30 - i,
                "low_count": 20,
                "info_count": 20,
            }
            for i in range(1, 11)
        ],
        "severity_trends": {
            "by_severity": {
                "CRITICAL": [10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
                "HIGH": [20, 19, 18, 17, 16, 15, 14, 13, 12, 11],
                "MEDIUM": [30, 29, 28, 27, 26, 25, 24, 23, 22, 21],
                "LOW": [20] * 10,
                "INFO": [20] * 10,
            },
            "total": [100, 95, 90, 85, 80, 75, 70, 65, 60, 55],
            "timestamps": [f"2025-01-{i:02d}T00:00:00Z" for i in range(1, 11)],
        },
        "improvement_metrics": {
            "net_change": -45,
            "resolved": 60,
            "introduced": 15,
            "percent_change": -45.0,
            "by_severity": {
                "CRITICAL": -9,
                "HIGH": -9,
                "MEDIUM": -9,
                "LOW": 0,
                "INFO": 0,
            },
        },
        "security_score": {
            "current_score": 85.0,
            "grade": "B",
            "trend": "improving",
            "history": [70.0, 72.0, 75.0, 78.0, 80.0, 82.0, 83.0, 84.0, 85.0],
        },
        "regressions": [
            {
                "severity": "HIGH",
                "category": "secrets",
                "message": "Increased secret detections",
                "current_value": 15,
                "previous_value": 10,
            },
        ],
        "insights": [
            {
                "category": "security_posture",
                "severity": "INFO",
                "priority": "HIGH",
                "icon": "✅",
                "message": "Security posture improving",
                "details": "CRITICAL findings reduced by 90%",
                "recommended_action": "Continue current remediation efforts",
            },
            {
                "category": "regression",
                "severity": "MEDIUM",
                "priority": "MEDIUM",
                "icon": "⚠️",
                "message": "Secret detection increased",
                "details": "5 new secrets detected",
                "recommended_action": "Review recent commits for exposed credentials",
            },
        ],
        "top_rules": [
            {"count": 25, "severity": "HIGH", "rule_id": "semgrep-hardcoded-secret"},
            {"count": 20, "severity": "MEDIUM", "rule_id": "bandit-B101"},
            {"count": 15, "severity": "LOW", "rule_id": "trivy-vuln-CVE-2024-1234"},
        ],
    }


@pytest.fixture
def sample_scans():
    """Sample scan metadata for comparison testing."""
    return (
        {
            "id": "scan-abc123",
            "timestamp_iso": "2025-01-01T00:00:00Z",
            "branch": "main",
            "total_findings": 100,
            "critical_count": 10,
            "high_count": 20,
            "medium_count": 30,
            "low_count": 25,
            "info_count": 15,
        },
        {
            "id": "scan-def456",
            "timestamp_iso": "2025-01-10T00:00:00Z",
            "branch": "main",
            "total_findings": 80,
            "critical_count": 5,
            "high_count": 15,
            "medium_count": 25,
            "low_count": 20,
            "info_count": 15,
        },
    )


@pytest.fixture
def sample_diff():
    """Sample diff results for comparison testing."""
    return {
        "new_count": 10,
        "resolved_count": 30,
        "unchanged_count": 70,
    }


# ============================================================================
# Terminal Formatter Tests
# ============================================================================


def test_format_terminal_report_basic(sample_analysis):
    """Test basic terminal report formatting."""
    output = format_terminal_report(sample_analysis, verbose=False)

    # Check for key sections
    assert "SECURITY TREND ANALYSIS REPORT" in output
    assert "Branch: main" in output
    assert "Scans analyzed: 10" in output
    assert "SECURITY POSTURE SCORE" in output
    assert "SEVERITY TRENDS" in output
    assert "IMPROVEMENT METRICS" in output
    assert "INSIGHTS" in output


def test_format_terminal_report_verbose(sample_analysis):
    """Test verbose terminal report with top rules."""
    output = format_terminal_report(sample_analysis, verbose=True)

    # Verbose includes top rules
    assert "TOP RULES" in output
    assert "semgrep-hardcoded-secret" in output


def test_format_security_score(sample_analysis):
    """Test security score formatting."""
    security_score = sample_analysis["security_score"]
    output = _format_security_score(security_score)

    assert "SECURITY POSTURE SCORE" in output
    assert "85.0/100.0" in output
    assert "Grade: B" in output
    assert "GOOD" in output
    assert "IMPROVING" in output
    assert "Change:" in output


def test_format_severity_trends(sample_analysis):
    """Test severity trends formatting with sparklines."""
    severity_trends = sample_analysis["severity_trends"]
    output = _format_severity_trends(severity_trends)

    assert "SEVERITY TRENDS" in output
    assert "CRITICAL" in output
    assert "HIGH" in output
    assert "MEDIUM" in output
    assert "Improving" in output  # Downward trend
    assert "TOTAL" in output


def test_format_improvement_metrics(sample_analysis):
    """Test improvement metrics formatting."""
    improvement = sample_analysis["improvement_metrics"]
    output = _format_improvement_metrics(improvement)

    assert "IMPROVEMENT METRICS" in output
    assert "-45" in output  # Net change
    assert "60" in output  # Resolved
    assert "15" in output  # Introduced
    assert "IMPROVED" in output  # Status


def test_format_regressions(sample_analysis):
    """Test regressions formatting."""
    regressions = sample_analysis["regressions"]
    output = _format_regressions(regressions)

    assert "REGRESSIONS DETECTED (1)" in output
    assert "[HIGH]" in output
    assert "secrets" in output
    assert "Increased secret detections" in output


def test_format_regressions_empty():
    """Test regressions formatting with no regressions."""
    output = _format_regressions([])

    assert "REGRESSIONS DETECTED (0)" in output
    assert "No regressions detected" in output


def test_format_insights_basic(sample_analysis):
    """Test insights formatting without verbose mode."""
    insights = sample_analysis["insights"]
    output = _format_insights(insights, verbose=False)

    assert "INSIGHTS (2)" in output
    assert "[HIGH]" in output
    assert "Security posture improving" in output
    assert "[MEDIUM]" in output


def test_format_insights_verbose(sample_analysis):
    """Test insights formatting with verbose mode."""
    insights = sample_analysis["insights"]
    output = _format_insights(insights, verbose=True)

    # Verbose includes details and actions
    assert "CRITICAL findings reduced by 90%" in output
    assert "Continue current remediation efforts" in output
    assert "Review recent commits for exposed credentials" in output


def test_format_insights_empty():
    """Test insights formatting with no insights."""
    output = _format_insights([], verbose=False)

    assert "INSIGHTS (0)" in output
    assert "No insights generated" in output


# ============================================================================
# Sparkline Tests
# ============================================================================


def test_create_sparkline_basic():
    """Test basic sparkline creation."""
    counts = [1, 2, 3, 4, 5, 6, 7, 8]
    sparkline = _create_sparkline(counts, "HIGH")

    # Should contain spark characters
    assert len(sparkline) > 0
    assert any(char in sparkline for char in "▁▂▃▄▅▆▇█")


def test_create_sparkline_flat():
    """Test sparkline with flat data."""
    counts = [5, 5, 5, 5, 5]
    sparkline = _create_sparkline(counts, "MEDIUM")

    # Flat data should produce lowest spark character
    assert sparkline == "▁" * 5


def test_create_sparkline_empty():
    """Test sparkline with empty data."""
    sparkline = _create_sparkline([], "LOW")
    assert sparkline == ""


def test_create_sparkline_single():
    """Test sparkline with single data point."""
    sparkline = _create_sparkline([10], "CRITICAL")
    assert sparkline == "▄"


def test_create_sparkline_long():
    """Test sparkline truncation for long data."""
    counts = list(range(1, 51))  # 50 data points
    sparkline = _create_sparkline(counts, "INFO")

    # Should truncate to 30 characters
    assert len(sparkline) == 30


# ============================================================================
# Comparison Formatter Tests
# ============================================================================


def test_format_comparison(sample_scans, sample_diff):
    """Test scan comparison formatting."""
    scan1, scan2 = sample_scans
    output = format_comparison(scan1, scan2, sample_diff)

    assert "SCAN COMPARISON" in output
    assert "scan-abc" in output  # Scan 1 ID (first 8 chars)
    assert "scan-def" in output  # Scan 2 ID (first 8 chars)

    # Severity comparison
    assert "CRITICAL" in output
    assert "HIGH" in output
    assert "Scan 1" in output
    assert "Scan 2" in output

    # Diff summary
    assert "10" in output  # New
    assert "30" in output  # Resolved
    assert "70" in output  # Unchanged


def test_format_comparison_improvement(sample_scans, sample_diff):
    """Test comparison shows improvement."""
    scan1, scan2 = sample_scans
    output = format_comparison(scan1, scan2, sample_diff)

    # Should show negative change (improvement)
    assert "-5" in output  # CRITICAL: 10 -> 5
    assert "-5" in output  # HIGH: 20 -> 15


def test_format_comparison_degradation():
    """Test comparison shows degradation."""
    scan1 = {
        "id": "scan1",
        "timestamp_iso": "2025-01-01T00:00:00Z",
        "total_findings": 50,
        "critical_count": 5,
        "high_count": 10,
        "medium_count": 15,
        "low_count": 10,
        "info_count": 10,
    }
    scan2 = {
        "id": "scan2",
        "timestamp_iso": "2025-01-10T00:00:00Z",
        "total_findings": 80,
        "critical_count": 15,
        "high_count": 20,
        "medium_count": 20,
        "low_count": 15,
        "info_count": 10,
    }
    diff = {"new_count": 40, "resolved_count": 10, "unchanged_count": 40}

    output = format_comparison(scan1, scan2, diff)

    # Should show positive change (degradation)
    assert "+10" in output  # CRITICAL: 5 -> 15


# ============================================================================
# JSON Formatter Tests
# ============================================================================


def test_format_json_report_valid(sample_analysis):
    """Test JSON report is valid JSON."""
    output = format_json_report(sample_analysis)

    # Should parse as valid JSON
    parsed = json.loads(output)
    assert parsed is not None


def test_format_json_report_structure(sample_analysis):
    """Test JSON report structure."""
    output = format_json_report(sample_analysis)
    parsed = json.loads(output)

    # Check key sections
    assert "metadata" in parsed
    assert "scans" in parsed
    assert "severity_trends" in parsed
    assert "improvement_metrics" in parsed
    assert "security_score" in parsed
    assert "regressions" in parsed
    assert "insights" in parsed


def test_format_json_report_indentation(sample_analysis):
    """Test JSON report is pretty-printed."""
    output = format_json_report(sample_analysis)

    # Should be indented (not single line)
    assert "\n" in output
    assert "  " in output  # Indentation


# ============================================================================
# HTML Formatter Tests
# ============================================================================


def test_format_html_report_valid(sample_analysis):
    """Test HTML report is valid HTML."""
    output = format_html_report(sample_analysis)

    # Basic HTML structure
    assert "<!DOCTYPE html>" in output
    assert "<html" in output
    assert "</html>" in output
    assert "<head>" in output
    assert "<body>" in output


def test_format_html_report_title(sample_analysis):
    """Test HTML report has correct title."""
    output = format_html_report(sample_analysis)

    assert "<title>Trend Analysis Report</title>" in output


def test_format_html_report_chart_js(sample_analysis):
    """Test HTML report includes Chart.js."""
    output = format_html_report(sample_analysis)

    assert "chart.js" in output.lower()
    assert '<canvas id="trendsChart">' in output


def test_format_html_report_embedded_data(sample_analysis):
    """Test HTML report embeds data in JavaScript."""
    output = format_html_report(sample_analysis)

    # Should embed JSON data
    assert "window.TREND_DATA" in output or "const chartData" in output


def test_format_html_report_security_score(sample_analysis):
    """Test HTML report displays security score."""
    output = format_html_report(sample_analysis)

    assert "Security Posture Score" in output
    assert "85.0/100" in output
    assert "Grade: <strong>B</strong>" in output


def test_format_html_report_insights(sample_analysis):
    """Test HTML report displays insights."""
    output = format_html_report(sample_analysis)

    assert "Insights" in output
    assert "Security posture improving" in output


def test_format_html_report_responsive(sample_analysis):
    """Test HTML report has responsive design."""
    output = format_html_report(sample_analysis)

    assert "viewport" in output
    assert "width=device-width" in output


def test_format_html_report_styling(sample_analysis):
    """Test HTML report has CSS styling."""
    output = format_html_report(sample_analysis)

    assert "<style>" in output
    assert "font-family" in output
    assert "background" in output


# ============================================================================
# Edge Cases and Error Handling
# ============================================================================


def test_format_terminal_report_empty_analysis():
    """Test terminal formatter with empty analysis."""
    analysis = {
        "metadata": {"branch": "main", "scan_count": 0},
        "scans": [],
        "severity_trends": {},
        "improvement_metrics": {},
        "security_score": {},
        "regressions": [],
        "insights": [],
        "top_rules": [],
    }

    output = format_terminal_report(analysis, verbose=False)

    # Should not crash, basic structure still present
    assert "SECURITY TREND ANALYSIS REPORT" in output


def test_format_json_report_unicode():
    """Test JSON formatter handles unicode."""
    analysis = {
        "metadata": {"branch": "main"},
        "insights": [{"message": "Test 🔥 emoji"}],
    }

    output = format_json_report(analysis)
    parsed = json.loads(output)

    assert "🔥" in parsed["insights"][0]["message"]


def test_sparkline_descending_trend():
    """Test sparkline with descending trend."""
    counts = [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
    sparkline = _create_sparkline(counts, "CRITICAL")

    # Should show descending pattern
    assert len(sparkline) == 10
    # First char should be higher than last
    spark_chars = "▁▂▃▄▅▆▇█"
    first_idx = spark_chars.index(sparkline[0])
    last_idx = spark_chars.index(sparkline[-1])
    assert first_idx > last_idx


def test_sparkline_ascending_trend():
    """Test sparkline with ascending trend."""
    counts = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
    sparkline = _create_sparkline(counts, "HIGH")

    # Should show ascending pattern
    spark_chars = "▁▂▃▄▅▆▇█"
    first_idx = spark_chars.index(sparkline[0])
    last_idx = spark_chars.index(sparkline[-1])
    assert first_idx < last_idx
