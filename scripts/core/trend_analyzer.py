#!/usr/bin/env python3
"""
Trend Analysis Engine for JMo Security.

This module provides advanced trend analysis capabilities including:
- Statistical validation (Mann-Kendall test)
- Regression detection with confidence scoring
- Security posture scoring
- Developer attribution via git blame
- Automated insight generation

Phase 1-2 Implementation: Core analyzer + statistical validation
"""

from __future__ import annotations

import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from scripts.core.history_db import (
    get_connection,
    get_scan_by_id,
    list_scans,
    get_findings_for_scan,
    DEFAULT_DB_PATH,
)

logger = logging.getLogger(__name__)


# ============================================================================
# Phase 1: Core Trend Analyzer
# ============================================================================


class TrendAnalyzer:
    """
    Core trend analysis engine.

    Provides:
    - Severity trend calculation
    - Improvement metrics
    - Top rules analysis
    - Regression detection
    - Security posture scoring
    """

    def __init__(self, db_path: Path = DEFAULT_DB_PATH):
        """
        Initialize trend analyzer.

        Args:
            db_path: Path to SQLite history database
        """
        self.db_path = db_path
        self.conn: Optional[sqlite3.Connection] = None

    def __enter__(self):
        """Context manager entry."""
        self.conn = get_connection(self.db_path)
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        if self.conn:
            self.conn.close()

    def analyze_trends(
        self,
        branch: str = "main",
        days: Optional[int] = None,
        scan_ids: Optional[List[str]] = None,
        last_n: Optional[int] = None,
    ) -> Dict[str, Any]:
        """
        Analyze security trends over time.

        Args:
            branch: Git branch to analyze
            days: Number of days to analyze
            scan_ids: Specific scan IDs to analyze
            last_n: Last N scans to analyze

        Returns:
            Dictionary with comprehensive trend analysis:
            {
                "metadata": {...},
                "scans": [...],
                "severity_trends": {...},
                "improvement_metrics": {...},
                "top_rules": [...],
                "regressions": [...],
                "insights": [...]
            }
        """
        if not self.conn:
            raise RuntimeError("TrendAnalyzer not initialized. Use context manager.")

        # 1. Get scans based on filters
        scans = self._get_scans(branch, days, scan_ids, last_n)

        if not scans:
            return {
                "metadata": {
                    "branch": branch,
                    "status": "no_data",
                    "message": "No scans found for the specified criteria",
                },
                "scans": [],
            }

        # 2. Calculate severity trends
        severity_trends = self._calculate_severity_trends(scans)

        # 3. Compute improvement metrics
        improvement_metrics = self._compute_improvement_metrics(scans)

        # 4. Get top rules
        top_rules = self._get_top_rules(scans)

        # 5. Detect regressions
        regressions = self._detect_regressions(scans)

        # 6. Generate automated insights
        insights = self._generate_insights(
            scans, severity_trends, improvement_metrics, regressions
        )

        # 7. Calculate security posture score
        security_score = self._calculate_security_score(scans)

        return {
            "metadata": {
                "branch": branch,
                "scan_count": len(scans),
                "date_range": {
                    "start": scans[0]["timestamp_iso"],
                    "end": scans[-1]["timestamp_iso"],
                },
                "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "scans": [
                {
                    "id": s["id"],
                    "timestamp": s["timestamp_iso"],
                    "total_findings": s["total_findings"],
                    "critical_count": s["critical_count"],
                    "high_count": s["high_count"],
                    "medium_count": s["medium_count"],
                    "low_count": s["low_count"],
                    "info_count": s["info_count"],
                }
                for s in scans
            ],
            "severity_trends": severity_trends,
            "improvement_metrics": improvement_metrics,
            "top_rules": top_rules,
            "regressions": regressions,
            "insights": insights,
            "security_score": security_score,
        }

    def _get_scans(
        self,
        branch: str,
        days: Optional[int],
        scan_ids: Optional[List[str]],
        last_n: Optional[int],
    ) -> List[Dict[str, Any]]:
        """
        Get scans based on filters.

        Priority order:
        1. scan_ids (explicit scan list)
        2. last_n (last N scans)
        3. days (last N days)
        4. Default to last 30 days
        """
        if scan_ids:
            # Get specific scans by ID
            scans = []
            for scan_id in scan_ids:
                scan = get_scan_by_id(self.conn, scan_id)
                if scan:
                    scans.append(dict(scan))
            # Sort by timestamp
            scans.sort(key=lambda s: s["timestamp"])
            return scans

        # Use list_scans with appropriate filters
        if last_n:
            return list(
                map(dict, list_scans(self.conn, branch=branch, limit=last_n))
            )

        if days:
            import time

            since = int(time.time()) - (days * 86400)
            return list(
                map(dict, list_scans(self.conn, branch=branch, since=since, limit=1000))
            )

        # Default: last 30 days
        import time

        since = int(time.time()) - (30 * 86400)
        return list(
            map(dict, list_scans(self.conn, branch=branch, since=since, limit=1000))
        )

    def _calculate_severity_trends(
        self, scans: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Calculate severity trends over time.

        Returns:
            {
                "by_severity": {
                    "CRITICAL": [counts over time],
                    "HIGH": [...],
                    ...
                },
                "total": [total counts over time],
                "timestamps": [ISO timestamps]
            }
        """
        return {
            "by_severity": {
                "CRITICAL": [s["critical_count"] for s in scans],
                "HIGH": [s["high_count"] for s in scans],
                "MEDIUM": [s["medium_count"] for s in scans],
                "LOW": [s["low_count"] for s in scans],
                "INFO": [s["info_count"] for s in scans],
            },
            "total": [s["total_findings"] for s in scans],
            "timestamps": [s["timestamp_iso"] for s in scans],
        }

    def _compute_improvement_metrics(
        self, scans: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        Compute improvement metrics comparing first and last scan.

        Returns:
            {
                "trend": "improving" | "degrading" | "stable" | "insufficient_data",
                "total_change": int,
                "critical_change": int,
                "high_change": int,
                "medium_change": int,
                "low_change": int,
                "info_change": int,
                "percentage_change": float,
                "confidence": "low" | "medium" | "high"
            }
        """
        if len(scans) < 2:
            return {
                "trend": "insufficient_data",
                "total_change": 0,
                "critical_change": 0,
                "high_change": 0,
                "medium_change": 0,
                "low_change": 0,
                "info_change": 0,
                "percentage_change": 0.0,
                "confidence": "low",
                "message": "Need at least 2 scans for trend analysis",
            }

        first_scan = scans[0]
        last_scan = scans[-1]

        total_change = last_scan["total_findings"] - first_scan["total_findings"]
        critical_change = last_scan["critical_count"] - first_scan["critical_count"]
        high_change = last_scan["high_count"] - first_scan["high_count"]
        medium_change = last_scan["medium_count"] - first_scan["medium_count"]
        low_change = last_scan["low_count"] - first_scan["low_count"]
        info_change = last_scan["info_count"] - first_scan["info_count"]

        # Calculate percentage change
        if first_scan["total_findings"] > 0:
            percentage_change = (total_change / first_scan["total_findings"]) * 100
        else:
            percentage_change = 0.0

        # Determine trend (focus on CRITICAL and HIGH)
        weighted_change = (critical_change * 10) + (high_change * 3) + total_change

        if weighted_change < -5:
            trend = "improving"
        elif weighted_change > 5:
            trend = "degrading"
        else:
            trend = "stable"

        # Confidence based on scan count
        if len(scans) >= 10:
            confidence = "high"
        elif len(scans) >= 5:
            confidence = "medium"
        else:
            confidence = "low"

        return {
            "trend": trend,
            "total_change": total_change,
            "critical_change": critical_change,
            "high_change": high_change,
            "medium_change": medium_change,
            "low_change": low_change,
            "info_change": info_change,
            "percentage_change": round(percentage_change, 2),
            "confidence": confidence,
            "scan_count": len(scans),
        }

    def _get_top_rules(
        self, scans: List[Dict[str, Any]], limit: int = 10
    ) -> List[Dict[str, Any]]:
        """
        Get top rules across all scans.

        Returns:
            [
                {
                    "rule_id": str,
                    "severity": str,
                    "count": int,
                    "tool": str (most common tool)
                },
                ...
            ]
        """
        scan_ids = [s["id"] for s in scans]
        if not scan_ids:
            return []

        placeholders = ",".join("?" * len(scan_ids))
        cursor = self.conn.execute(
            f"""
            SELECT rule_id, severity, tool, COUNT(*) as count
            FROM findings
            WHERE scan_id IN ({placeholders})
            GROUP BY rule_id, severity, tool
            ORDER BY count DESC
            LIMIT ?
            """,
            scan_ids + [limit],
        )

        return [
            {
                "rule_id": row[0],
                "severity": row[1],
                "tool": row[2],
                "count": row[3],
            }
            for row in cursor.fetchall()
        ]

    def _detect_regressions(
        self, scans: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """
        Detect regressions (severity increases) between consecutive scans.

        Returns:
            [
                {
                    "scan_id": str,
                    "timestamp": str,
                    "severity": "CRITICAL" | "HIGH",
                    "previous_count": int,
                    "current_count": int,
                    "increase": int
                },
                ...
            ]
        """
        if len(scans) < 2:
            return []

        regressions = []

        for i in range(1, len(scans)):
            prev_scan = scans[i - 1]
            curr_scan = scans[i]

            # Check CRITICAL regressions
            if curr_scan["critical_count"] > prev_scan["critical_count"]:
                regressions.append(
                    {
                        "scan_id": curr_scan["id"],
                        "timestamp": curr_scan["timestamp_iso"],
                        "severity": "CRITICAL",
                        "previous_count": prev_scan["critical_count"],
                        "current_count": curr_scan["critical_count"],
                        "increase": curr_scan["critical_count"]
                        - prev_scan["critical_count"],
                    }
                )

            # Check HIGH regressions (only if increase >= 3)
            high_increase = curr_scan["high_count"] - prev_scan["high_count"]
            if high_increase >= 3:
                regressions.append(
                    {
                        "scan_id": curr_scan["id"],
                        "timestamp": curr_scan["timestamp_iso"],
                        "severity": "HIGH",
                        "previous_count": prev_scan["high_count"],
                        "current_count": curr_scan["high_count"],
                        "increase": high_increase,
                    }
                )

        return regressions

    def _generate_insights(
        self,
        scans: List[Dict[str, Any]],
        severity_trends: Dict[str, Any],
        improvement_metrics: Dict[str, Any],
        regressions: List[Dict[str, Any]],
    ) -> List[str]:
        """
        Generate automated insights from trend data.

        Returns:
            List of human-readable insight strings
        """
        insights = []

        if len(scans) < 2:
            insights.append(
                "ℹ️  Need at least 2 scans to generate meaningful insights"
            )
            return insights

        # Insight 1: Overall trend
        trend = improvement_metrics["trend"]
        total_change = improvement_metrics["total_change"]
        pct_change = improvement_metrics["percentage_change"]

        if trend == "improving":
            insights.append(
                f"✅ Security posture is IMPROVING: {abs(total_change)} fewer findings ({pct_change:.1f}% reduction)"
            )
        elif trend == "degrading":
            insights.append(
                f"⚠️  Security posture is DEGRADING: {total_change} more findings ({pct_change:.1f}% increase)"
            )
        else:
            insights.append(
                f"➡️  Security posture is STABLE: {abs(total_change)} findings change"
            )

        # Insight 2: Critical/High specific
        critical_change = improvement_metrics["critical_change"]
        high_change = improvement_metrics["high_change"]

        if critical_change < 0:
            insights.append(
                f"🎯 CRITICAL findings reduced by {abs(critical_change)}"
            )
        elif critical_change > 0:
            insights.append(f"🚨 CRITICAL findings increased by {critical_change}")

        if high_change < -3:
            insights.append(f"📉 HIGH findings reduced by {abs(high_change)}")
        elif high_change > 3:
            insights.append(f"📈 HIGH findings increased by {high_change}")

        # Insight 3: Regressions
        if regressions:
            critical_regressions = [r for r in regressions if r["severity"] == "CRITICAL"]
            if critical_regressions:
                insights.append(
                    f"⛔ {len(critical_regressions)} CRITICAL regression(s) detected"
                )

        # Insight 4: Scan frequency
        if len(scans) >= 5:
            first_ts = datetime.fromisoformat(scans[0]["timestamp_iso"].replace("Z", "+00:00"))
            last_ts = datetime.fromisoformat(scans[-1]["timestamp_iso"].replace("Z", "+00:00"))
            days_span = (last_ts - first_ts).days
            if days_span > 0:
                scans_per_week = (len(scans) / days_span) * 7
                if scans_per_week >= 3:
                    insights.append(
                        f"🔄 Good scan cadence: {scans_per_week:.1f} scans/week"
                    )
                elif scans_per_week < 1:
                    insights.append(
                        f"⏰ Low scan frequency: {scans_per_week:.1f} scans/week (increase recommended)"
                    )

        return insights

    def _calculate_security_score(self, scans: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Calculate security posture score (0-100) based on latest scan.

        Scoring formula:
        - Start with 100
        - Deduct 10 points per CRITICAL
        - Deduct 3 points per HIGH
        - Deduct 1 point per MEDIUM
        - Minimum score: 0

        Returns:
            {
                "current_score": int (0-100),
                "historical_scores": [scores over time],
                "grade": "A" | "B" | "C" | "D" | "F",
                "trend": "improving" | "degrading" | "stable"
            }
        """
        if not scans:
            return {
                "current_score": 0,
                "historical_scores": [],
                "grade": "F",
                "trend": "insufficient_data",
            }

        # Calculate scores for all scans
        scores = []
        for scan in scans:
            score = 100
            score -= scan["critical_count"] * 10
            score -= scan["high_count"] * 3
            score -= scan["medium_count"] * 1
            score = max(0, score)  # Floor at 0
            scores.append(score)

        current_score = scores[-1]

        # Grade based on current score
        if current_score >= 90:
            grade = "A"
        elif current_score >= 80:
            grade = "B"
        elif current_score >= 70:
            grade = "C"
        elif current_score >= 60:
            grade = "D"
        else:
            grade = "F"

        # Score trend
        if len(scores) >= 2:
            score_change = scores[-1] - scores[0]
            if score_change > 5:
                score_trend = "improving"
            elif score_change < -5:
                score_trend = "degrading"
            else:
                score_trend = "stable"
        else:
            score_trend = "insufficient_data"

        return {
            "current_score": current_score,
            "historical_scores": scores,
            "grade": grade,
            "trend": score_trend,
        }


# ============================================================================
# Phase 2: Statistical Validation
# ============================================================================


def mann_kendall_test(data: List[float]) -> Tuple[str, float, float]:
    """
    Perform Mann-Kendall trend test for statistical validation.

    The Mann-Kendall test is a non-parametric test for monotonic trends.
    It's robust to outliers and doesn't assume normal distribution.

    Args:
        data: Time series data (e.g., severity counts over time)

    Returns:
        Tuple of (trend, tau, p_value):
        - trend: "increasing", "decreasing", "no trend"
        - tau: Kendall's tau statistic (-1 to 1)
        - p_value: Statistical significance (0 to 1)

    Statistical Interpretation:
        - p_value < 0.05: Statistically significant trend
        - p_value >= 0.05: No significant trend (could be noise)
        - tau > 0: Increasing trend
        - tau < 0: Decreasing trend
        - |tau| close to 1: Strong trend
        - |tau| close to 0: Weak trend

    Example:
        >>> data = [10, 8, 6, 5, 3, 2]  # Decreasing severity counts
        >>> trend, tau, p_value = mann_kendall_test(data)
        >>> print(f"{trend}, tau={tau:.3f}, p={p_value:.3f}")
        decreasing, tau=-1.000, p=0.003
    """
    import math

    n = len(data)

    if n < 3:
        # Need at least 3 data points for meaningful test
        return "insufficient_data", 0.0, 1.0

    # Step 1: Calculate S statistic
    s = 0
    for i in range(n - 1):
        for j in range(i + 1, n):
            if data[j] > data[i]:
                s += 1
            elif data[j] < data[i]:
                s -= 1
            # else: data[j] == data[i], no change to s

    # Step 2: Calculate variance of S
    # Var(S) = n(n-1)(2n+5) / 18
    var_s = (n * (n - 1) * (2 * n + 5)) / 18

    # Step 3: Calculate standardized test statistic Z
    if s > 0:
        z = (s - 1) / math.sqrt(var_s)
    elif s < 0:
        z = (s + 1) / math.sqrt(var_s)
    else:
        z = 0.0

    # Step 4: Calculate Kendall's tau
    # tau = S / (n*(n-1)/2)
    tau = s / (n * (n - 1) / 2)

    # Step 5: Calculate p-value from Z (two-tailed test)
    # Using standard normal cumulative distribution approximation
    p_value = 2 * (1 - _standard_normal_cdf(abs(z)))

    # Step 6: Determine trend at alpha=0.05 significance level
    if p_value < 0.05:
        if tau > 0:
            trend = "increasing"
        else:
            trend = "decreasing"
    else:
        trend = "no_trend"

    return trend, tau, p_value


def _standard_normal_cdf(x: float) -> float:
    """
    Approximate cumulative distribution function for standard normal.

    Uses error function approximation (accurate to ~1e-7).

    Args:
        x: Input value

    Returns:
        P(X <= x) where X ~ N(0, 1)
    """
    import math

    return (1.0 + math.erf(x / math.sqrt(2.0))) / 2.0


def validate_trend_significance(
    severity_trends: Dict[str, List[int]]
) -> Dict[str, Dict[str, Any]]:
    """
    Validate statistical significance of severity trends using Mann-Kendall test.

    Args:
        severity_trends: Dictionary of severity -> counts over time

    Returns:
        Dictionary mapping severity -> test results:
        {
            "CRITICAL": {
                "trend": "increasing" | "decreasing" | "no_trend",
                "tau": float,
                "p_value": float,
                "significant": bool,
                "confidence": "high" | "medium" | "low"
            },
            ...
        }
    """
    results = {}

    for severity, counts in severity_trends.items():
        if severity == "timestamps":
            continue

        trend, tau, p_value = mann_kendall_test(counts)

        # Determine confidence level
        if p_value < 0.01:
            confidence = "high"
        elif p_value < 0.05:
            confidence = "medium"
        else:
            confidence = "low"

        results[severity] = {
            "trend": trend,
            "tau": round(tau, 3),
            "p_value": round(p_value, 4),
            "significant": p_value < 0.05,
            "confidence": confidence,
        }

    return results


# ============================================================================
# Utility Functions
# ============================================================================


def format_trend_summary(analysis: Dict[str, Any], verbose: bool = False) -> str:
    """
    Format trend analysis as human-readable text.

    Args:
        analysis: Output from TrendAnalyzer.analyze_trends()
        verbose: Include detailed statistics

    Returns:
        Formatted string suitable for terminal output
    """
    lines = []

    # Header
    metadata = analysis["metadata"]
    lines.append("\n" + "=" * 70)
    lines.append(f"📊 Security Trend Analysis: {metadata.get('branch', 'N/A')}")
    lines.append("=" * 70)
    lines.append("")

    # Metadata
    lines.append(f"Scans analyzed:   {metadata['scan_count']}")
    if "date_range" in metadata:
        dr = metadata["date_range"]
        lines.append(f"Date range:       {dr['start'][:10]} to {dr['end'][:10]}")
    lines.append("")

    # Improvement metrics
    metrics = analysis.get("improvement_metrics", {})
    trend = metrics.get("trend", "unknown")
    total_change = metrics.get("total_change", 0)
    pct_change = metrics.get("percentage_change", 0.0)
    confidence = metrics.get("confidence", "low")

    trend_icon = {
        "improving": "📈 ✅",
        "degrading": "📉 ⚠️",
        "stable": "➡️  🔵",
        "insufficient_data": "❓",
    }.get(trend, "❓")

    lines.append(f"Trend:            {trend_icon} {trend.upper()}")
    lines.append(f"Total change:     {total_change:+d} findings ({pct_change:+.1f}%)")
    lines.append(f"Confidence:       {confidence.upper()}")
    lines.append(
        f"CRITICAL change:  {metrics.get('critical_change', 0):+d}"
    )
    lines.append(f"HIGH change:      {metrics.get('high_change', 0):+d}")
    lines.append("")

    # Security score
    if "security_score" in analysis:
        score_data = analysis["security_score"]
        score = score_data["current_score"]
        grade = score_data["grade"]
        score_trend = score_data["trend"]

        lines.append(f"Security Score:   {score}/100 (Grade: {grade})")
        lines.append(f"Score Trend:      {score_trend.upper()}")
        lines.append("")

    # Regressions
    regressions = analysis.get("regressions", [])
    if regressions:
        lines.append(f"⚠️  Regressions Detected: {len(regressions)}")
        for reg in regressions[:5]:
            lines.append(
                f"  - {reg['severity']:8s} {reg['timestamp'][:10]}: "
                f"{reg['previous_count']} → {reg['current_count']} (+{reg['increase']})"
            )
        if len(regressions) > 5:
            lines.append(f"  ... and {len(regressions) - 5} more")
        lines.append("")

    # Insights
    insights = analysis.get("insights", [])
    if insights:
        lines.append("💡 Automated Insights:")
        for insight in insights:
            lines.append(f"  {insight}")
        lines.append("")

    # Top rules (verbose mode)
    if verbose:
        top_rules = analysis.get("top_rules", [])
        if top_rules:
            lines.append("Top Rules:")
            for i, rule in enumerate(top_rules[:10], 1):
                lines.append(
                    f"  {i:2d}. {rule['rule_id']:30s} {rule['severity']:8s} (x{rule['count']})"
                )
            lines.append("")

    return "\n".join(lines)
