#!/usr/bin/env python3
"""
Manual test script to verify trend visualizations in terminal.

Usage:
    python3 tests/manual/test_visualizations.py
"""

from datetime import datetime, timezone
from scripts.cli.trend_formatters import (
    format_terminal_report,
    format_html_report,
    format_comparison,
    _create_sparkline,
)


def test_sparklines():
    """Test sparkline generation with various patterns."""
    print("\n" + "=" * 80)
    print("SPARKLINE TESTS")
    print("=" * 80)

    tests = [
        ("Improving trend", [10, 9, 8, 7, 6, 5, 4, 3, 2, 1], "CRITICAL"),
        ("Degrading trend", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10], "HIGH"),
        ("Flat trend", [5, 5, 5, 5, 5, 5, 5, 5], "MEDIUM"),
        ("Volatile trend", [1, 5, 2, 8, 3, 7, 4, 6], "LOW"),
        ("Single spike", [2, 2, 2, 10, 2, 2, 2, 2], "INFO"),
    ]

    for name, data, severity in tests:
        sparkline = _create_sparkline(data, severity)
        print(f"\n{name:<20} [{severity:<8}]: {sparkline}")
        print(f"{'Data:':<20} {data}")


def test_terminal_report():
    """Test full terminal report rendering."""
    print("\n" + "=" * 80)
    print("TERMINAL REPORT TEST")
    print("=" * 80)

    # Sample analysis data
    analysis = {
        "metadata": {
            "branch": "main",
            "scan_count": 10,
            "date_range": {
                "start": "2025-01-01T00:00:00Z",
                "end": "2025-01-10T00:00:00Z",
            },
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
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
            "current_score": 89.0,
            "grade": "B",
            "trend": "improving",
            "history": [70.0, 73.0, 76.0, 79.0, 82.0, 84.0, 86.0, 87.0, 88.0, 89.0],
        },
        "regressions": [],
        "insights": [
            {
                "category": "security_posture",
                "severity": "INFO",
                "priority": "HIGH",
                "icon": "✅",
                "message": "Security posture significantly improved",
                "details": "CRITICAL findings reduced by 90% (10 → 1)",
                "recommended_action": "Continue current remediation practices",
            },
            {
                "category": "remediation",
                "severity": "INFO",
                "priority": "MEDIUM",
                "icon": "📈",
                "message": "Strong remediation velocity",
                "details": "65 findings resolved vs 18 introduced",
                "recommended_action": "Maintain focus on high-severity items",
            },
        ],
        "top_rules": [
            {"count": 25, "severity": "HIGH", "rule_id": "semgrep-hardcoded-secret"},
            {"count": 20, "severity": "MEDIUM", "rule_id": "bandit-B101"},
            {"count": 15, "severity": "LOW", "rule_id": "trivy-CVE-2024-1234"},
        ],
    }

    # Format and print
    output = format_terminal_report(analysis, verbose=True)
    print("\n" + output)


def test_comparison():
    """Test scan comparison rendering."""
    print("\n" + "=" * 80)
    print("COMPARISON TEST")
    print("=" * 80)

    scan1 = {
        "id": "baseline-scan-abc123",
        "timestamp_iso": "2025-01-01T00:00:00Z",
        "branch": "main",
        "total_findings": 100,
        "critical_count": 10,
        "high_count": 20,
        "medium_count": 30,
        "low_count": 25,
        "info_count": 15,
    }

    scan2 = {
        "id": "current-scan-def456",
        "timestamp_iso": "2025-01-10T00:00:00Z",
        "branch": "main",
        "total_findings": 60,
        "critical_count": 3,
        "high_count": 10,
        "medium_count": 20,
        "low_count": 17,
        "info_count": 10,
    }

    diff = {
        "new_count": 15,
        "resolved_count": 55,
        "unchanged_count": 45,
    }

    output = format_comparison(scan1, scan2, diff)
    print("\n" + output)


def test_html_generation():
    """Test HTML report generation."""
    print("\n" + "=" * 80)
    print("HTML GENERATION TEST")
    print("=" * 80)

    analysis = {
        "metadata": {
            "branch": "main",
            "scan_count": 5,
            "date_range": {
                "start": "2025-01-01T00:00:00Z",
                "end": "2025-01-05T00:00:00Z",
            },
            "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "severity_trends": {
            "by_severity": {
                "CRITICAL": [5, 4, 3, 2, 1],
                "HIGH": [10, 9, 8, 7, 6],
                "MEDIUM": [15, 14, 13, 12, 11],
                "LOW": [10] * 5,
                "INFO": [8] * 5,
            },
            "timestamps": [f"2025-01-0{i}T00:00:00Z" for i in range(1, 6)],
        },
        "security_score": {
            "current_score": 92.0,
            "grade": "A",
            "trend": "improving",
        },
        "insights": [
            {
                "priority": "HIGH",
                "icon": "✅",
                "message": "Excellent security posture",
            }
        ],
    }

    html = format_html_report(analysis)

    # Save to file
    output_file = "test_trend_report.html"
    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    print(f"\n✅ HTML report generated: {output_file}")
    print(f"   File size: {len(html)} bytes")
    print("   Open in browser to view interactive charts")


if __name__ == "__main__":
    print("\n" + "=" * 80)
    print("TREND ANALYSIS VISUALIZATION TESTS")
    print("=" * 80)

    test_sparklines()
    test_terminal_report()
    test_comparison()
    test_html_generation()

    print("\n" + "=" * 80)
    print("✅ ALL MANUAL TESTS COMPLETED")
    print("=" * 80)
    print()
