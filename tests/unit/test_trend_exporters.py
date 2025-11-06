#!/usr/bin/env python3
"""
Tests for trend analysis exporters.

Phase 5: Export & Integration testing (25 tests total)
"""

from __future__ import annotations

import csv
import json

import pytest

from scripts.core.trend_exporters import (
    export_to_csv,
    export_to_prometheus,
    export_to_grafana,
    export_for_dashboard,
)


# ============================================================================
# Test Fixtures
# ============================================================================


@pytest.fixture
def sample_analysis():
    """Sample trend analysis data for testing exporters."""
    return {
        "metadata": {
            "branch": "main",
            "scan_count": 10,
            "scan_ids": [f"scan-{i}" for i in range(1, 11)],
            "date_range": {
                "start": "2025-01-01T00:00:00Z",
                "end": "2025-01-10T00:00:00Z",
            },
            "analysis_timestamp": "2025-01-10T12:00:00Z",
        },
        "scans": [],
        "severity_trends": {
            "by_severity": {
                "CRITICAL": [10, 9, 8, 7, 6, 5, 4, 3, 2, 1],
                "HIGH": [20, 18, 16, 14, 12, 10, 9, 8, 7, 6],
                "MEDIUM": [30, 28, 26, 24, 22, 20, 19, 18, 17, 16],
                "LOW": [20] * 10,
                "INFO": [15] * 10,
            },
            "total": [95, 88, 81, 74, 67, 60, 57, 54, 51, 48],
            "timestamps": [f"2025-01-{i:02d}T00:00:00Z" for i in range(1, 11)],
        },
        "improvement_metrics": {
            "net_change": -47,
            "resolved": 65,
            "introduced": 18,
            "percent_change": -49.5,
            "by_severity": {
                "CRITICAL": -9,
                "HIGH": -14,
                "MEDIUM": -14,
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
        ],
        "top_rules": [
            {"count": 25, "severity": "HIGH", "rule_id": "semgrep-hardcoded-secret"},
            {"count": 20, "severity": "MEDIUM", "rule_id": "bandit-B101"},
            {"count": 15, "severity": "LOW", "rule_id": "trivy-CVE-2024-1234"},
        ],
    }


@pytest.fixture
def empty_analysis():
    """Empty analysis data for edge case testing."""
    return {
        "metadata": {"branch": "main", "scan_count": 0},
        "severity_trends": {},
        "improvement_metrics": {},
        "security_score": {},
        "regressions": [],
        "insights": [],
        "top_rules": [],
    }


# ============================================================================
# CSV Export Tests (5 tests)
# ============================================================================


def test_export_to_csv(sample_analysis, tmp_path):
    """Test CSV export creates valid file."""
    output_path = tmp_path / "trends.csv"
    export_to_csv(sample_analysis, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_csv_format_valid(sample_analysis, tmp_path):
    """Test CSV format is valid and parseable."""
    output_path = tmp_path / "trends.csv"
    export_to_csv(sample_analysis, output_path)

    with open(output_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # Check header
    assert rows[0] == [
        "Timestamp",
        "Scan ID",
        "CRITICAL",
        "HIGH",
        "MEDIUM",
        "LOW",
        "INFO",
        "Total",
        "Security Score",
        "Score Trend",
        "Remediation Rate",
    ]

    # Check data rows
    assert len(rows) == 11  # Header + 10 scans


def test_csv_excel_compatible(sample_analysis, tmp_path):
    """Test CSV is compatible with Excel (no special chars that break parsing)."""
    output_path = tmp_path / "trends.csv"
    export_to_csv(sample_analysis, output_path)

    with open(output_path, newline="", encoding="utf-8") as f:
        content = f.read()

    # Should not contain problematic characters
    assert "\x00" not in content  # Null bytes
    assert content.count(",") > 0  # Has comma separators


def test_csv_unicode_handling(tmp_path):
    """Test CSV handles unicode characters in data."""
    analysis = {
        "metadata": {
            "branch": "main",
            "scan_ids": ["scan-émoji-🔥"],
            "analysis_timestamp": "2025-01-01T00:00:00Z",
        },
        "severity_trends": {
            "by_severity": {
                "CRITICAL": [1],
                "HIGH": [2],
                "MEDIUM": [3],
                "LOW": [4],
                "INFO": [5],
            },
            "timestamps": ["2025-01-01T00:00:00Z"],
        },
        "security_score": {"trend": "improving"},
        "improvement_metrics": {"net_change": -5},
    }

    output_path = tmp_path / "trends.csv"
    export_to_csv(analysis, output_path)

    assert output_path.exists()
    content = output_path.read_text(encoding="utf-8")
    assert "scan-émoji-🔥" in content


def test_csv_empty_report(empty_analysis, tmp_path):
    """Test CSV export handles empty analysis gracefully."""
    output_path = tmp_path / "trends.csv"
    export_to_csv(empty_analysis, output_path)

    assert output_path.exists()

    with open(output_path, newline="", encoding="utf-8") as f:
        reader = csv.reader(f)
        rows = list(reader)

    # Should still have header
    assert len(rows) >= 1
    assert "Timestamp" in rows[0]


# ============================================================================
# Prometheus Export Tests (5 tests)
# ============================================================================


def test_export_to_prometheus(sample_analysis, tmp_path):
    """Test Prometheus export creates valid file."""
    output_path = tmp_path / "metrics.prom"
    export_to_prometheus(sample_analysis, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_prometheus_format_valid(sample_analysis, tmp_path):
    """Test Prometheus format follows text exposition format."""
    output_path = tmp_path / "metrics.prom"
    export_to_prometheus(sample_analysis, output_path)

    content = output_path.read_text()

    # Check for required Prometheus format elements
    assert "# HELP jmo_security_findings" in content
    assert "# TYPE jmo_security_findings gauge" in content
    assert 'jmo_security_findings{severity="critical"}' in content
    assert "# HELP jmo_security_score" in content
    assert "# TYPE jmo_security_score gauge" in content


def test_prometheus_metric_names(sample_analysis, tmp_path):
    """Test all expected Prometheus metrics are present."""
    output_path = tmp_path / "metrics.prom"
    export_to_prometheus(sample_analysis, output_path)

    content = output_path.read_text()

    expected_metrics = [
        "jmo_security_findings",
        "jmo_security_score",
        "jmo_remediation_rate",
        "jmo_introduction_rate",
        "jmo_net_remediation",
        "jmo_scan_count",
    ]

    for metric in expected_metrics:
        assert metric in content, f"Missing metric: {metric}"


def test_prometheus_tool_metrics(sample_analysis, tmp_path):
    """Test per-tool metrics are generated correctly."""
    output_path = tmp_path / "metrics.prom"
    export_to_prometheus(sample_analysis, output_path)

    content = output_path.read_text()

    # Should include top rules as metrics
    assert "jmo_rule_findings" in content
    assert 'rule="semgrep_hardcoded_secret"' in content  # Sanitized name
    assert "25" in content  # Count for top rule


def test_prometheus_empty_tools(empty_analysis, tmp_path):
    """Test Prometheus export handles empty data gracefully."""
    output_path = tmp_path / "metrics.prom"
    export_to_prometheus(empty_analysis, output_path)

    assert output_path.exists()
    content = output_path.read_text()

    # Should have "no data" message
    assert "No trend data available" in content


# ============================================================================
# Grafana Export Tests (5 tests)
# ============================================================================


def test_export_to_grafana(sample_analysis, tmp_path):
    """Test Grafana export creates valid file."""
    output_path = tmp_path / "dashboard.json"
    export_to_grafana(sample_analysis, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_grafana_dashboard_structure(sample_analysis, tmp_path):
    """Test Grafana dashboard has correct JSON structure."""
    output_path = tmp_path / "dashboard.json"
    export_to_grafana(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        dashboard = json.load(f)

    assert "dashboard" in dashboard
    assert "panels" in dashboard["dashboard"]
    assert isinstance(dashboard["dashboard"]["panels"], list)
    assert len(dashboard["dashboard"]["panels"]) > 0


def test_grafana_panel_configuration(sample_analysis, tmp_path):
    """Test Grafana panels are configured correctly."""
    output_path = tmp_path / "dashboard.json"
    export_to_grafana(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        dashboard = json.load(f)

    panels = dashboard["dashboard"]["panels"]

    # Check for expected panel types
    panel_types = [p["type"] for p in panels]
    assert "gauge" in panel_types  # Security score gauge
    assert "timeseries" in panel_types  # Severity timeline
    assert "stat" in panel_types  # Remediation/net stats
    assert "bargauge" in panel_types  # Tool effectiveness


def test_grafana_threshold_configuration(sample_analysis, tmp_path):
    """Test Grafana thresholds are configured properly."""
    output_path = tmp_path / "dashboard.json"
    export_to_grafana(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        dashboard = json.load(f)

    # Find security score gauge panel
    gauge_panels = [p for p in dashboard["dashboard"]["panels"] if p["type"] == "gauge"]
    assert len(gauge_panels) > 0

    gauge = gauge_panels[0]
    thresholds = gauge["fieldConfig"]["defaults"]["thresholds"]["steps"]

    # Should have color-coded thresholds
    assert len(thresholds) == 5
    assert any(t["color"] == "red" for t in thresholds)
    assert any(t["color"] == "green" for t in thresholds)


def test_grafana_json_valid(sample_analysis, tmp_path):
    """Test Grafana dashboard is valid JSON."""
    output_path = tmp_path / "dashboard.json"
    export_to_grafana(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        dashboard = json.load(f)  # Should not raise

    # Verify basic structure
    assert dashboard["dashboard"]["title"] == "JMo Security Trends"
    assert dashboard["dashboard"]["uid"] == "jmo-security-trends"
    assert "security" in dashboard["dashboard"]["tags"]


# ============================================================================
# Dashboard Export Tests (5 tests)
# ============================================================================


def test_export_for_dashboard(sample_analysis, tmp_path):
    """Test dashboard export creates valid file."""
    output_path = tmp_path / "dashboard-data.json"
    export_for_dashboard(sample_analysis, output_path)

    assert output_path.exists()
    assert output_path.stat().st_size > 0


def test_dashboard_json_schema(sample_analysis, tmp_path):
    """Test dashboard JSON has expected schema."""
    output_path = tmp_path / "dashboard-data.json"
    export_for_dashboard(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)

    # Check required fields
    assert "version" in data
    assert "generated_at" in data
    assert "security_score" in data
    assert "score_trend" in data
    assert "metadata" in data
    assert "severity_trends" in data
    assert "insights" in data
    assert "regressions" in data
    assert "improvement_metrics" in data


def test_dashboard_statistical_data(sample_analysis, tmp_path):
    """Test dashboard includes statistical data."""
    output_path = tmp_path / "dashboard-data.json"
    export_for_dashboard(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)

    # Check severity trends structure
    severity_trends = data["severity_trends"]
    assert "by_severity" in severity_trends
    assert "total" in severity_trends
    assert "timestamps" in severity_trends

    # Check improvement metrics
    improvement = data["improvement_metrics"]
    assert "net_change" in improvement
    assert "resolved" in improvement
    assert "introduced" in improvement
    assert "by_severity" in improvement


def test_dashboard_insight_structure(sample_analysis, tmp_path):
    """Test dashboard insights are structured correctly."""
    output_path = tmp_path / "dashboard-data.json"
    export_for_dashboard(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)

    insights = data["insights"]
    assert len(insights) > 0

    # Check first insight structure
    insight = insights[0]
    assert "category" in insight
    assert "severity" in insight
    assert "priority" in insight
    assert "icon" in insight
    assert "message" in insight
    assert "details" in insight
    assert "recommended_action" in insight


def test_dashboard_normalization_included(sample_analysis, tmp_path):
    """Test dashboard includes metadata and normalization."""
    output_path = tmp_path / "dashboard-data.json"
    export_for_dashboard(sample_analysis, output_path)

    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)

    # Check metadata
    metadata = data["metadata"]
    assert "branch" in metadata
    assert "scan_count" in metadata
    assert "date_range" in metadata

    # Check score data
    assert data["security_score"] == 85.0
    assert data["score_trend"] == "improving"
    assert data["score_grade"] == "B"


# ============================================================================
# Integration Tests (5 tests)
# ============================================================================


def test_multi_format_export(sample_analysis, tmp_path):
    """Test exporting to all formats from same analysis."""
    csv_path = tmp_path / "trends.csv"
    prom_path = tmp_path / "metrics.prom"
    grafana_path = tmp_path / "dashboard.json"
    dashboard_path = tmp_path / "dashboard-data.json"

    export_to_csv(sample_analysis, csv_path)
    export_to_prometheus(sample_analysis, prom_path)
    export_to_grafana(sample_analysis, grafana_path)
    export_for_dashboard(sample_analysis, dashboard_path)

    assert csv_path.exists()
    assert prom_path.exists()
    assert grafana_path.exists()
    assert dashboard_path.exists()

    # Verify all files have content
    assert csv_path.stat().st_size > 100
    assert prom_path.stat().st_size > 100
    assert grafana_path.stat().st_size > 100
    assert dashboard_path.stat().st_size > 100


def test_csv_import_to_excel(sample_analysis, tmp_path):
    """Test CSV can be read back and parsed (Excel compatibility)."""
    output_path = tmp_path / "trends.csv"
    export_to_csv(sample_analysis, output_path)

    # Read back CSV
    with open(output_path, newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    # Verify data integrity
    assert len(rows) == 10
    assert rows[0]["Timestamp"].startswith("2025-01-")
    assert int(rows[0]["CRITICAL"]) == 10
    assert int(rows[-1]["CRITICAL"]) == 1


def test_prometheus_scraping_compatible(sample_analysis, tmp_path):
    """Test Prometheus metrics file format is scrape-compatible."""
    output_path = tmp_path / "metrics.prom"
    export_to_prometheus(sample_analysis, output_path)

    content = output_path.read_text()

    # Verify Prometheus text format requirements
    lines = content.strip().split("\n")

    # Should have HELP and TYPE lines
    help_lines = [line for line in lines if line.startswith("# HELP")]
    type_lines = [line for line in lines if line.startswith("# TYPE")]

    assert len(help_lines) > 0
    assert len(type_lines) > 0

    # Metric lines should not have # prefix
    metric_lines = [line for line in lines if not line.startswith("#") and line.strip()]
    assert len(metric_lines) > 0

    # Each metric line should have format: metric_name{labels} value
    for line in metric_lines:
        assert " " in line  # Space between metric and value
        parts = line.split()
        assert len(parts) >= 2  # metric + value


def test_dashboard_data_consumption(sample_analysis, tmp_path):
    """Test dashboard JSON can be consumed by frontend."""
    output_path = tmp_path / "dashboard-data.json"
    export_for_dashboard(sample_analysis, output_path)

    # Simulate frontend consumption
    with open(output_path, encoding="utf-8") as f:
        data = json.load(f)

    # Frontend would need these fields
    assert data["version"] == "1.0.0"
    assert isinstance(data["security_score"], (int, float))
    assert isinstance(data["severity_trends"]["by_severity"], dict)
    assert isinstance(data["insights"], list)

    # Should have usable timestamps
    timestamps = data["severity_trends"]["timestamps"]
    assert len(timestamps) > 0
    assert "T" in timestamps[0]  # ISO format


def test_all_exports_handle_empty_data(empty_analysis, tmp_path):
    """Test all exporters handle empty analysis gracefully."""
    csv_path = tmp_path / "trends.csv"
    prom_path = tmp_path / "metrics.prom"
    grafana_path = tmp_path / "dashboard.json"
    dashboard_path = tmp_path / "dashboard-data.json"

    # Should not crash on empty data
    export_to_csv(empty_analysis, csv_path)
    export_to_prometheus(empty_analysis, prom_path)
    export_to_grafana(empty_analysis, grafana_path)
    export_for_dashboard(empty_analysis, dashboard_path)

    # All files should exist (even if minimal)
    assert csv_path.exists()
    assert prom_path.exists()
    assert grafana_path.exists()
    assert dashboard_path.exists()
