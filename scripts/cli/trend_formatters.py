#!/usr/bin/env python3
"""
Terminal formatters for trend analysis visualizations.

Phase 4: Beautiful, actionable charts in the terminal using rich library.

Provides:
- Severity timeline charts with sparklines
- Security score gauges
- Regression alert tables
- Insight cards with priority grouping
- Side-by-side scan comparisons
- JSON export for machine consumption
- HTML export with interactive charts
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, List

from rich.console import Console


console = Console()


# ============================================================================
# Terminal Formatters (Rich-based)
# ============================================================================


def format_terminal_report(analysis: Dict[str, Any], verbose: bool = False) -> str:
    """
    Format trend analysis for rich terminal display.

    Args:
        analysis: Analysis dict from TrendAnalyzer.analyze_trends()
        verbose: Include detailed insights and recommendations

    Returns:
        Formatted string ready for console output
    """
    output_lines = []

    # Header
    metadata = analysis.get("metadata", {})
    output_lines.append("=" * 80)
    output_lines.append("🔍 SECURITY TREND ANALYSIS REPORT")
    output_lines.append("=" * 80)
    output_lines.append(f"Branch: {metadata.get('branch', 'unknown')}")
    output_lines.append(f"Scans analyzed: {metadata.get('scan_count', 0)}")

    date_range = metadata.get("date_range", {})
    if date_range:
        output_lines.append(
            f"Period: {date_range.get('start', 'N/A')} to {date_range.get('end', 'N/A')}"
        )

    output_lines.append("")

    # Security Score
    security_score = analysis.get("security_score", {})
    if security_score:
        output_lines.append(_format_security_score(security_score))
        output_lines.append("")

    # Severity Trends
    severity_trends = analysis.get("severity_trends", {})
    if severity_trends:
        output_lines.append(_format_severity_trends(severity_trends))
        output_lines.append("")

    # Improvement Metrics
    improvement = analysis.get("improvement_metrics", {})
    if improvement:
        output_lines.append(_format_improvement_metrics(improvement))
        output_lines.append("")

    # Regressions
    regressions = analysis.get("regressions", [])
    if regressions:
        output_lines.append(_format_regressions(regressions))
        output_lines.append("")

    # Insights
    insights = analysis.get("insights", [])
    if insights:
        output_lines.append(_format_insights(insights, verbose))
        output_lines.append("")

    # Top Rules
    top_rules = analysis.get("top_rules", [])
    if top_rules and verbose:
        output_lines.append(_format_top_rules(top_rules))
        output_lines.append("")

    return "\n".join(output_lines)


def _format_security_score(security_score: Dict[str, Any]) -> str:
    """Format security score as gauge with color coding."""
    lines = []
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    lines.append("📊 SECURITY POSTURE SCORE")
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    current_score = security_score.get("current_score", 0.0)
    grade = security_score.get("grade", "F")
    trend = security_score.get("trend", "stable")

    # Color code by grade
    if grade == "A":
        color_indicator = "🟢"
        rating = "EXCELLENT"
    elif grade == "B":
        color_indicator = "🔵"
        rating = "GOOD"
    elif grade == "C":
        color_indicator = "🟡"
        rating = "FAIR"
    elif grade == "D":
        color_indicator = "🟠"
        rating = "POOR"
    else:
        color_indicator = "🔴"
        rating = "CRITICAL"

    # Trend indicator
    if trend == "improving":
        trend_icon = "📈 IMPROVING"
    elif trend == "degrading":
        trend_icon = "📉 DEGRADING"
    else:
        trend_icon = "➡️  STABLE"

    # Create progress bar
    bar_length = 50
    filled = int((current_score / 100.0) * bar_length)
    bar = "█" * filled + "░" * (bar_length - filled)

    lines.append(
        f"  Score: {current_score:.1f}/100.0 | Grade: {grade} | {rating} {color_indicator}"
    )
    lines.append(f"  Trend: {trend_icon}")
    lines.append(f"  [{bar}]")

    # Score history if available
    history = security_score.get("history", [])
    if len(history) >= 2:
        oldest = history[0]
        newest = history[-1]
        change = newest - oldest
        lines.append(
            f"  Change: {change:+.1f} points (from {oldest:.1f} to {newest:.1f})"
        )

    return "\n".join(lines)


def _format_severity_trends(severity_trends: Dict[str, Any]) -> str:
    """Format severity trends with sparklines."""
    lines = []
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    lines.append("📈 SEVERITY TRENDS")
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    by_severity = severity_trends.get("by_severity", {})

    # Header row
    lines.append(
        f"  {'Severity':<12} {'Latest':<8} {'Change':<10} {'Trend':<10} {'Chart':<30}"
    )
    lines.append("  " + "-" * 76)

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        counts = by_severity.get(severity, [])
        if not counts:
            continue

        latest = counts[-1] if counts else 0
        oldest = counts[0] if counts else 0
        change = latest - oldest

        # Determine trend direction
        if change < 0:
            trend = "📉 Improving"
            change_str = f"{change:+d}"
        elif change > 0:
            trend = "📈 Degrading"
            change_str = f"{change:+d}"
        else:
            trend = "➡️  Stable"
            change_str = "0"

        # Create sparkline
        sparkline = _create_sparkline(counts, severity)

        lines.append(
            f"  {severity:<12} {latest:<8} {change_str:<10} {trend:<10} {sparkline:<30}"
        )

    # Total row
    total_counts = severity_trends.get("total", [])
    if total_counts:
        latest_total = total_counts[-1] if total_counts else 0
        oldest_total = total_counts[0] if total_counts else 0
        total_change = latest_total - oldest_total

        lines.append("  " + "-" * 76)
        lines.append(f"  {'TOTAL':<12} {latest_total:<8} {total_change:+d}")

    return "\n".join(lines)


def _create_sparkline(counts: List[int], severity: str = "") -> str:
    """
    Create ASCII sparkline chart.

    Args:
        counts: List of count values
        severity: Severity level (for color determination)

    Returns:
        ASCII sparkline string
    """
    if not counts:
        return ""

    if len(counts) == 1:
        return "▄"

    min_val = min(counts)
    max_val = max(counts)

    # Use spark characters for visual representation
    spark_chars = "▁▂▃▄▅▆▇█"

    if max_val == min_val:
        # Flat line
        return spark_chars[0] * min(len(counts), 30)

    # Normalize to 0-7 range
    normalized = [int((count - min_val) / (max_val - min_val) * 7) for count in counts]

    # Truncate to 30 chars for display
    sparkline = "".join(spark_chars[n] for n in normalized[:30])

    return sparkline


def _format_improvement_metrics(improvement: Dict[str, Any]) -> str:
    """Format improvement metrics comparing first and last scan."""
    lines = []
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    lines.append("📊 IMPROVEMENT METRICS")
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    net_change = improvement.get("net_change", 0)
    resolved = improvement.get("resolved", 0)
    introduced = improvement.get("introduced", 0)
    percent_change = improvement.get("percent_change", 0.0)

    # Net change indicator
    if net_change < 0:
        icon = "✅"
        status = "IMPROVED"
    elif net_change > 0:
        icon = "⚠️"
        status = "DEGRADED"
    else:
        icon = "➡️"
        status = "STABLE"

    lines.append(
        f"  {icon} Net Change: {net_change:+d} findings ({percent_change:+.1f}%) - {status}"
    )
    lines.append(f"  🔧 Resolved: {resolved}")
    lines.append(f"  ➕ Introduced: {introduced}")

    # Per-severity breakdown
    by_severity = improvement.get("by_severity", {})
    if by_severity:
        lines.append("")
        lines.append("  By Severity:")
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            change = by_severity.get(severity, 0)
            if change != 0:
                lines.append(f"    {severity:<12} {change:+d}")

    return "\n".join(lines)


def _format_regressions(regressions: List[Dict[str, Any]]) -> str:
    """Format regression alerts as a table."""
    lines = []
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    lines.append(f"⚠️  REGRESSIONS DETECTED ({len(regressions)})")
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    if not regressions:
        lines.append("  No regressions detected")
        return "\n".join(lines)

    for i, reg in enumerate(regressions[:10], 1):  # Show top 10
        severity = reg.get("severity", "UNKNOWN")
        category = reg.get("category", "unknown")
        message = reg.get("message", "No message")

        lines.append(f"  {i}. [{severity}] {category}")
        lines.append(f"     {message}")

        # Additional context
        current_val = reg.get("current_value")
        previous_val = reg.get("previous_value")
        if current_val is not None and previous_val is not None:
            lines.append(
                f"     Count: {previous_val} → {current_val} ({current_val - previous_val:+d})"
            )

        lines.append("")

    if len(regressions) > 10:
        lines.append(f"  ... and {len(regressions) - 10} more")

    return "\n".join(lines)


def _format_insights(insights: List[Dict[str, Any]], verbose: bool = False) -> str:
    """Format automated insights with priority grouping."""
    lines = []
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    lines.append(f"💡 INSIGHTS ({len(insights)})")
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    if not insights:
        lines.append("  No insights generated")
        return "\n".join(lines)

    # Group by priority
    by_priority = {}  # type: ignore[var-annotated]
    for insight in insights:
        priority = insight.get("priority", "MEDIUM")
        if priority not in by_priority:
            by_priority[priority] = []
        by_priority[priority].append(insight)

    # Display in priority order
    for priority in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        priority_insights = by_priority.get(priority, [])
        if not priority_insights:
            continue

        # Priority header
        lines.append(f"\n  [{priority}]")
        lines.append("  " + "-" * 76)

        for insight in priority_insights:
            icon = insight.get("icon", "•")
            message = insight.get("message", "No message")

            lines.append(f"  {icon} {message}")

            if verbose:
                details = insight.get("details")
                if details:
                    for line in details.split("\n"):
                        lines.append(f"     {line}")

                action = insight.get("recommended_action")
                if action:
                    lines.append(f"     → {action}")

            lines.append("")

    return "\n".join(lines)


def _format_top_rules(top_rules: List[Dict[str, Any]]) -> str:
    """Format top rules by frequency."""
    lines = []
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )
    lines.append(f"🔥 TOP RULES ({len(top_rules)})")
    lines.append(
        "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    )

    if not top_rules:
        lines.append("  No rules data available")
        return "\n".join(lines)

    # Header
    lines.append(f"  {'Rank':<6} {'Count':<8} {'Severity':<12} {'Rule ID':<40}")
    lines.append("  " + "-" * 76)

    for i, rule in enumerate(top_rules[:15], 1):  # Show top 15
        count = rule.get("count", 0)
        severity = rule.get("severity", "UNKNOWN")
        rule_id = rule.get("rule_id", "unknown")

        # Truncate long rule IDs
        if len(rule_id) > 37:
            rule_id = rule_id[:34] + "..."

        lines.append(f"  {i:<6} {count:<8} {severity:<12} {rule_id:<40}")

    if len(top_rules) > 15:
        lines.append(f"\n  ... and {len(top_rules) - 15} more")

    return "\n".join(lines)


# ============================================================================
# Comparison Formatters
# ============================================================================


def format_comparison(
    scan1: Dict[str, Any], scan2: Dict[str, Any], diff: Dict[str, Any]
) -> str:
    """
    Format side-by-side comparison of two scans.

    Args:
        scan1: First scan metadata
        scan2: Second scan metadata
        diff: Diff results from compute_diff()

    Returns:
        Formatted comparison string
    """
    lines = []
    lines.append("=" * 80)
    lines.append("🔄 SCAN COMPARISON")
    lines.append("=" * 80)

    # Scan metadata
    lines.append(
        f"\nScan 1: {scan1.get('id', 'unknown')[:8]} ({scan1.get('timestamp_iso', 'N/A')})"
    )
    lines.append(
        f"Scan 2: {scan2.get('id', 'unknown')[:8]} ({scan2.get('timestamp_iso', 'N/A')})"
    )
    lines.append("")

    # Severity comparison table
    lines.append("Severity Comparison:")
    lines.append("-" * 80)
    lines.append(f"  {'Severity':<12} {'Scan 1':<12} {'Scan 2':<12} {'Change':<12}")
    lines.append("  " + "-" * 76)

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        key = f"{severity.lower()}_count"
        count1 = scan1.get(key, 0)
        count2 = scan2.get(key, 0)
        change = count2 - count1

        change_str = f"{change:+d}" if change != 0 else "0"
        lines.append(f"  {severity:<12} {count1:<12} {count2:<12} {change_str:<12}")

    # Total
    total1 = scan1.get("total_findings", 0)
    total2 = scan2.get("total_findings", 0)
    total_change = total2 - total1
    lines.append("  " + "-" * 76)
    lines.append(f"  {'TOTAL':<12} {total1:<12} {total2:<12} {total_change:+d}")
    lines.append("")

    # Diff summary
    new_count = diff.get("new_count", 0)
    resolved_count = diff.get("resolved_count", 0)
    unchanged_count = diff.get("unchanged_count", 0)

    lines.append("Change Summary:")
    lines.append(f"  ➕ New findings: {new_count}")
    lines.append(f"  ✅ Resolved: {resolved_count}")
    lines.append(f"  ➡️  Unchanged: {unchanged_count}")

    return "\n".join(lines)


# ============================================================================
# JSON Formatter (Machine-Readable)
# ============================================================================


def format_json_report(analysis: Dict[str, Any]) -> str:
    """
    Format trend analysis as JSON for machine consumption.

    Args:
        analysis: Analysis dict from TrendAnalyzer.analyze_trends()

    Returns:
        Pretty-printed JSON string
    """
    return json.dumps(analysis, indent=2, default=str)


# ============================================================================
# HTML Formatter (Interactive Charts)
# ============================================================================


def format_html_report(analysis: Dict[str, Any]) -> str:
    """
    Generate interactive HTML report with Chart.js visualizations.

    Args:
        analysis: Analysis dict from TrendAnalyzer.analyze_trends()

    Returns:
        Self-contained HTML string with embedded data and charts
    """
    metadata = analysis.get("metadata", {})
    security_score = analysis.get("security_score", {})
    severity_trends = analysis.get("severity_trends", {})
    insights = analysis.get("insights", [])

    # Prepare chart data
    timestamps = severity_trends.get("timestamps", [])
    by_severity = severity_trends.get("by_severity", {})

    # Format timestamps for Chart.js
    formatted_timestamps = [
        (
            datetime.fromisoformat(ts.replace("Z", "+00:00")).strftime("%Y-%m-%d %H:%M")
            if ts
            else "Unknown"
        )
        for ts in timestamps
    ]

    # Create datasets for Chart.js
    datasets = []
    colors = {
        "CRITICAL": "rgb(220, 38, 38)",
        "HIGH": "rgb(239, 68, 68)",
        "MEDIUM": "rgb(245, 158, 11)",
        "LOW": "rgb(59, 130, 246)",
        "INFO": "rgb(6, 182, 212)",
    }

    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
        if severity in by_severity:
            datasets.append(
                {
                    "label": severity,
                    "data": by_severity[severity],
                    "borderColor": colors[severity],
                    "backgroundColor": colors[severity]
                    .replace("rgb", "rgba")
                    .replace(")", ", 0.1)"),
                    "tension": 0.4,
                }
            )

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Trend Analysis Report</title>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            padding: 20px;
            background: #f5f7fa;
            color: #1f2937;
            line-height: 1.6;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
        }}
        .header {{
            background: white;
            padding: 30px;
            border-radius: 12px;
            margin-bottom: 20px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }}
        .header h1 {{
            font-size: 32px;
            margin-bottom: 10px;
            color: #111827;
        }}
        .header .meta {{
            color: #6b7280;
            font-size: 14px;
        }}
        .score-card {{
            background: white;
            padding: 40px;
            border-radius: 12px;
            margin-bottom: 20px;
            text-align: center;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }}
        .score-value {{
            font-size: 72px;
            font-weight: bold;
            margin: 20px 0;
        }}
        .score-excellent {{ color: #10b981; }}
        .score-good {{ color: #06b6d4; }}
        .score-fair {{ color: #f59e0b; }}
        .score-poor {{ color: #ef4444; }}
        .score-critical {{ color: #dc2626; }}
        .grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }}
        .card {{
            background: white;
            padding: 25px;
            border-radius: 12px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
        }}
        .card h2 {{
            font-size: 20px;
            margin-bottom: 20px;
            color: #111827;
            border-bottom: 2px solid #e5e7eb;
            padding-bottom: 10px;
        }}
        .chart-container {{
            position: relative;
            height: 300px;
        }}
        .insight {{
            padding: 15px;
            margin: 10px 0;
            background: #f9fafb;
            border-left: 4px solid #10b981;
            border-radius: 6px;
            font-size: 14px;
        }}
        .insight.critical {{ border-left-color: #dc2626; background: #fef2f2; }}
        .insight.high {{ border-left-color: #ef4444; background: #fef2f2; }}
        .insight.medium {{ border-left-color: #f59e0b; background: #fffbeb; }}
        .insight.low {{ border-left-color: #06b6d4; background: #f0fdfa; }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: #6b7280;
            font-size: 14px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🔍 Security Trend Analysis</h1>
            <p class="meta">
                {metadata.get('scan_count', 0)} scans analyzed |
                Branch: {metadata.get('branch', 'unknown')} |
                {metadata.get('date_range', {}).get('start', 'N/A')} to {metadata.get('date_range', {}).get('end', 'N/A')}
            </p>
        </div>

        <div class="score-card">
            <h2>Security Posture Score</h2>
            <div class="score-value score-{('excellent' if security_score.get('current_score', 0) >= 90 else 'good' if security_score.get('current_score', 0) >= 70 else 'fair' if security_score.get('current_score', 0) >= 50 else 'poor' if security_score.get('current_score', 0) >= 30 else 'critical')}">
                {security_score.get('current_score', 0.0):.1f}/100
            </div>
            <p style="font-size: 18px; color: #6b7280;">
                Grade: <strong>{security_score.get('grade', 'F')}</strong> |
                Trend: <strong>{security_score.get('trend', 'stable').upper()}</strong>
            </p>
        </div>

        <div class="grid">
            <div class="card" style="grid-column: 1 / -1;">
                <h2>📈 Severity Trends Over Time</h2>
                <div class="chart-container">
                    <canvas id="trendsChart"></canvas>
                </div>
            </div>

            <div class="card">
                <h2>💡 Insights ({len(insights)})</h2>
                {"".join(f'<div class="insight {insight.get("priority", "medium").lower()}">{insight.get("icon", "•")} {insight.get("message", "")}</div>' for insight in insights[:10])}
                {f'<p style="margin-top: 10px; color: #6b7280; font-size: 14px;">... and {len(insights) - 10} more</p>' if len(insights) > 10 else ''}
            </div>
        </div>

        <div class="footer">
            <p>Generated by JMo Security | {metadata.get('analysis_timestamp', 'N/A')}</p>
        </div>
    </div>

    <script>
        // Embedded data
        const chartData = {{
            labels: {json.dumps(formatted_timestamps)},
            datasets: {json.dumps(datasets)}
        }};

        // Render trends chart
        const ctx = document.getElementById('trendsChart').getContext('2d');
        new Chart(ctx, {{
            type: 'line',
            data: chartData,
            options: {{
                responsive: true,
                maintainAspectRatio: false,
                interaction: {{
                    mode: 'index',
                    intersect: false,
                }},
                plugins: {{
                    legend: {{
                        position: 'top',
                    }},
                    tooltip: {{
                        callbacks: {{
                            title: function(context) {{
                                return 'Scan: ' + context[0].label;
                            }}
                        }}
                    }}
                }},
                scales: {{
                    y: {{
                        beginAtZero: true,
                        title: {{
                            display: true,
                            text: 'Finding Count'
                        }}
                    }},
                    x: {{
                        title: {{
                            display: true,
                            text: 'Scan Date'
                        }}
                    }}
                }}
            }}
        }});
    </script>
</body>
</html>"""

    return html
