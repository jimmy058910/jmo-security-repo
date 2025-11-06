#!/usr/bin/env python3
"""
Trend analysis export functionality.

Supports multiple export formats:
- CSV: For Excel and BI tools
- Prometheus: Time-series metrics
- Grafana: Dashboard JSON
- Dashboard: React dashboard optimized format
"""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Any, Dict

def export_to_csv(analysis: Dict[str, Any], output_path: Path) -> None:
    """
    Export trend report to CSV for Excel/BI tools.

    Args:
        analysis: Analysis dict from TrendAnalyzer.analyze_trends()
        output_path: Path where CSV file will be written

    CSV Schema:
        Timestamp, Scan ID, CRITICAL, HIGH, MEDIUM, LOW, INFO,
        Total, Security Score, Score Trend, Remediation Rate
    """
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)

        # Header
        writer.writerow([
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
        ])

        # Extract data from analysis dict
        severity_trends = analysis.get("severity_trends", {})
        by_severity = severity_trends.get("by_severity", {})
        timestamps = severity_trends.get("timestamps", [])
        metadata = analysis.get("metadata", {})
        scan_ids = metadata.get("scan_ids", [])

        security_score = analysis.get("security_score", {})
        score_trend = security_score.get("trend", "")

        improvement = analysis.get("improvement_metrics", {})
        # Calculate remediation rate (resolved findings / days)
        net_change = improvement.get("net_change", 0)
        days = (len(timestamps) - 1) if len(timestamps) > 1 else 1
        remediation_rate = abs(net_change) / days if days > 0 else 0.0

        # Build timeline data
        critical = by_severity.get("CRITICAL", [])
        high = by_severity.get("HIGH", [])
        medium = by_severity.get("MEDIUM", [])
        low = by_severity.get("LOW", [])
        info = by_severity.get("INFO", [])

        # Ensure all lists have same length
        max_len = max(
            len(critical), len(high), len(medium), len(low), len(info), len(timestamps)
        )

        for i in range(max_len):
            crit_count = critical[i] if i < len(critical) else 0
            high_count = high[i] if i < len(high) else 0
            med_count = medium[i] if i < len(medium) else 0
            low_count = low[i] if i < len(low) else 0
            info_count = info[i] if i < len(info) else 0
            total = crit_count + high_count + med_count + low_count + info_count

            timestamp = timestamps[i] if i < len(timestamps) else ""
            scan_id = scan_ids[i] if i < len(scan_ids) else ""

            # Calculate per-scan score (approximation)
            scan_score = 10.0 - (
                crit_count * 3.0
                + high_count * 1.0
                + med_count * 0.3
                + low_count * 0.1
            )
            scan_score = max(0.0, min(10.0, scan_score))

            # Only include trend and remediation rate for latest scan
            is_latest = i == max_len - 1

            writer.writerow([
                timestamp,
                scan_id,
                crit_count,
                high_count,
                med_count,
                low_count,
                info_count,
                total,
                f"{scan_score:.1f}",
                score_trend if is_latest else "",
                f"{remediation_rate:.2f}" if is_latest else "",
            ])


def export_to_prometheus(analysis: Dict[str, Any], output_path: Path) -> None:
    """
    Export as Prometheus metrics format.

    Args:
        analysis: Analysis dict from TrendAnalyzer.analyze_trends()
        output_path: Path where Prometheus metrics will be written

    Output Format:
        Prometheus text exposition format with gauge metrics for:
        - Security findings by severity
        - Security score (raw and normalized)
        - Remediation metrics
        - Per-tool findings
    """
    # Extract latest severity counts
    severity_trends = analysis.get("severity_trends", {})
    by_severity = severity_trends.get("by_severity", {})

    if not by_severity:
        # Write empty metrics if no data
        output_path.write_text("# No trend data available\n")
        return

    # Get latest counts (last value in each severity list)
    critical = by_severity.get("CRITICAL", [])
    high = by_severity.get("HIGH", [])
    medium = by_severity.get("MEDIUM", [])
    low = by_severity.get("LOW", [])
    info = by_severity.get("INFO", [])

    latest_critical = critical[-1] if critical else 0
    latest_high = high[-1] if high else 0
    latest_medium = medium[-1] if medium else 0
    latest_low = low[-1] if low else 0
    latest_info = info[-1] if info else 0

    # Extract metrics
    security_score = analysis.get("security_score", {})
    current_score = security_score.get("current_score", 0.0)

    metadata = analysis.get("metadata", {})
    scan_count = metadata.get("scan_count", 0)

    improvement = analysis.get("improvement_metrics", {})
    net_change = improvement.get("net_change", 0)
    resolved = improvement.get("resolved", 0)
    introduced = improvement.get("introduced", 0)

    # Calculate rates (resolved/introduced per day)
    timestamps = severity_trends.get("timestamps", [])
    days = (len(timestamps) - 1) if len(timestamps) > 1 else 1
    remediation_rate = resolved / days if days > 0 else 0.0
    introduction_rate = introduced / days if days > 0 else 0.0

    metrics = f"""# HELP jmo_security_findings Total security findings by severity
# TYPE jmo_security_findings gauge
jmo_security_findings{{severity="critical"}} {latest_critical}
jmo_security_findings{{severity="high"}} {latest_high}
jmo_security_findings{{severity="medium"}} {latest_medium}
jmo_security_findings{{severity="low"}} {latest_low}
jmo_security_findings{{severity="info"}} {latest_info}

# HELP jmo_security_score Security posture score (0-100)
# TYPE jmo_security_score gauge
jmo_security_score {current_score}

# HELP jmo_remediation_rate Findings remediated per day
# TYPE jmo_remediation_rate gauge
jmo_remediation_rate {remediation_rate:.2f}

# HELP jmo_introduction_rate Findings introduced per day
# TYPE jmo_introduction_rate gauge
jmo_introduction_rate {introduction_rate:.2f}

# HELP jmo_net_remediation Net findings resolved (resolved - introduced)
# TYPE jmo_net_remediation gauge
jmo_net_remediation {net_change}

# HELP jmo_scan_count Total scans analyzed
# TYPE jmo_scan_count counter
jmo_scan_count {scan_count}
"""

    # Add per-tool metrics if available
    top_rules = analysis.get("top_rules", [])
    if top_rules:
        metrics += "\n# HELP jmo_rule_findings Findings per rule\n"
        metrics += "# TYPE jmo_rule_findings gauge\n"
        for rule in top_rules[:10]:  # Limit to top 10 rules
            rule_id = rule.get("rule_id", "unknown")
            count = rule.get("count", 0)
            # Sanitize rule ID for Prometheus (replace - and . with _)
            safe_rule = rule_id.replace("-", "_").replace(".", "_")
            metrics += f'jmo_rule_findings{{rule="{safe_rule}"}} {count}\n'

    output_path.write_text(metrics)


def export_to_grafana(analysis: Dict[str, Any], output_path: Path) -> None:
    """
    Export as Grafana dashboard JSON.

    Args:
        analysis: Analysis dict from TrendAnalyzer.analyze_trends()
        output_path: Path where Grafana dashboard JSON will be written

    Output:
        Grafana dashboard JSON with panels for:
        - Security score gauge
        - Severity timeline chart
        - Remediation rate stat
        - Net remediation stat
        - Rule effectiveness bar gauge
    """
    dashboard = {
        "dashboard": {
            "title": "JMo Security Trends",
            "uid": "jmo-security-trends",
            "tags": ["security", "jmo"],
            "timezone": "utc",
            "schemaVersion": 38,
            "version": 1,
            "panels": [
                {
                    "id": 1,
                    "title": "Security Score",
                    "type": "gauge",
                    "gridPos": {"h": 8, "w": 12, "x": 0, "y": 0},
                    "targets": [{"expr": "jmo_security_score", "refId": "A"}],
                    "options": {
                        "showThresholdLabels": False,
                        "showThresholdMarkers": True,
                    },
                    "fieldConfig": {
                        "defaults": {
                            "min": 0,
                            "max": 10,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"value": 0, "color": "red"},
                                    {"value": 3, "color": "orange"},
                                    {"value": 5, "color": "yellow"},
                                    {"value": 7, "color": "green"},
                                    {"value": 9, "color": "dark-green"},
                                ],
                            },
                        }
                    },
                },
                {
                    "id": 2,
                    "title": "Severity Timeline",
                    "type": "timeseries",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 0},
                    "targets": [
                        {
                            "expr": 'jmo_security_findings{severity="critical"}',
                            "refId": "A",
                            "legendFormat": "CRITICAL",
                        },
                        {
                            "expr": 'jmo_security_findings{severity="high"}',
                            "refId": "B",
                            "legendFormat": "HIGH",
                        },
                        {
                            "expr": 'jmo_security_findings{severity="medium"}',
                            "refId": "C",
                            "legendFormat": "MEDIUM",
                        },
                    ],
                    "fieldConfig": {
                        "defaults": {
                            "custom": {"lineInterpolation": "smooth", "fillOpacity": 10}
                        },
                        "overrides": [
                            {
                                "matcher": {"id": "byName", "options": "CRITICAL"},
                                "properties": [
                                    {
                                        "id": "color",
                                        "value": {
                                            "mode": "fixed",
                                            "fixedColor": "red",
                                        },
                                    }
                                ],
                            },
                            {
                                "matcher": {"id": "byName", "options": "HIGH"},
                                "properties": [
                                    {
                                        "id": "color",
                                        "value": {
                                            "mode": "fixed",
                                            "fixedColor": "orange",
                                        },
                                    }
                                ],
                            },
                        ],
                    },
                },
                {
                    "id": 3,
                    "title": "Remediation Rate",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 6, "x": 0, "y": 8},
                    "targets": [{"expr": "jmo_remediation_rate", "refId": "A"}],
                    "options": {"textMode": "value_and_name", "colorMode": "background"},
                    "fieldConfig": {
                        "defaults": {
                            "unit": "findings/day",
                            "decimals": 2,
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"value": 0, "color": "red"},
                                    {"value": 1, "color": "yellow"},
                                    {"value": 5, "color": "green"},
                                ],
                            },
                        }
                    },
                },
                {
                    "id": 4,
                    "title": "Net Remediation",
                    "type": "stat",
                    "gridPos": {"h": 4, "w": 6, "x": 6, "y": 8},
                    "targets": [{"expr": "jmo_net_remediation", "refId": "A"}],
                    "options": {"textMode": "value_and_name", "colorMode": "background"},
                    "fieldConfig": {
                        "defaults": {
                            "unit": "findings",
                            "thresholds": {
                                "mode": "absolute",
                                "steps": [
                                    {"value": -20, "color": "red"},
                                    {"value": 0, "color": "yellow"},
                                    {"value": 20, "color": "green"},
                                ],
                            },
                        }
                    },
                },
                {
                    "id": 5,
                    "title": "Tool Effectiveness",
                    "type": "bargauge",
                    "gridPos": {"h": 8, "w": 12, "x": 12, "y": 8},
                    "targets": [
                        {
                            "expr": "jmo_tool_findings",
                            "refId": "A",
                            "legendFormat": "{{tool}}",
                        }
                    ],
                    "options": {"orientation": "horizontal", "displayMode": "gradient"},
                },
            ],
        },
        "overwrite": True,
    }

    output_path.write_text(json.dumps(dashboard, indent=2))


def export_for_dashboard(analysis: Dict[str, Any], output_path: Path) -> None:
    """
    Export trend data optimized for React dashboard consumption.

    Args:
        analysis: Analysis dict from TrendAnalyzer.analyze_trends()
        output_path: Path where dashboard JSON will be written

    Output:
        Compact JSON format with:
        - Version metadata
        - Security score
        - Timeline data (severity trends over time)
        - Insights and regressions
        - Remediation metrics
    """
    metadata = analysis.get("metadata", {})
    security_score = analysis.get("security_score", {})
    severity_trends = analysis.get("severity_trends", {})
    insights = analysis.get("insights", [])
    regressions = analysis.get("regressions", [])
    improvement = analysis.get("improvement_metrics", {})

    dashboard_data = {
        "version": "1.0.0",
        "generated_at": metadata.get("analysis_timestamp", ""),
        "security_score": security_score.get("current_score", 0.0),
        "score_trend": security_score.get("trend", ""),
        "score_grade": security_score.get("grade", ""),
        "metadata": {
            "branch": metadata.get("branch", ""),
            "scan_count": metadata.get("scan_count", 0),
            "date_range": metadata.get("date_range", {}),
        },
        "severity_trends": {
            "by_severity": severity_trends.get("by_severity", {}),
            "total": severity_trends.get("total", []),
            "timestamps": severity_trends.get("timestamps", []),
        },
        "insights": [
            {
                "category": i.get("category", ""),
                "severity": i.get("severity", ""),
                "priority": i.get("priority", ""),
                "icon": i.get("icon", ""),
                "message": i.get("message", ""),
                "details": i.get("details", ""),
                "recommended_action": i.get("recommended_action", ""),
            }
            for i in insights
        ],
        "regressions": [
            {
                "severity": r.get("severity", ""),
                "category": r.get("category", ""),
                "message": r.get("message", ""),
                "current_value": r.get("current_value", 0),
                "previous_value": r.get("previous_value", 0),
            }
            for r in regressions
        ],
        "improvement_metrics": {
            "net_change": improvement.get("net_change", 0),
            "resolved": improvement.get("resolved", 0),
            "introduced": improvement.get("introduced", 0),
            "percent_change": improvement.get("percent_change", 0.0),
            "by_severity": improvement.get("by_severity", {}),
        },
        "top_rules": analysis.get("top_rules", [])[:10],  # Top 10 rules
    }

    output_path.write_text(json.dumps(dashboard_data, indent=2, default=str))
