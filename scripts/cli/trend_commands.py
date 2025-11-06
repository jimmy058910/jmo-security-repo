#!/usr/bin/env python3
"""
CLI commands for trend analysis (jmo trends).

Phase 3: All 8 CLI commands for comprehensive trend analysis
Phase 4: Rich terminal visualizations with sparklines and charts

Commands:
1. analyze  - Analyze trends with flexible filters
2. show     - Show trend context for a specific scan
3. regressions - List all detected regressions
4. score    - Show security posture score history
5. compare  - Compare two specific scans
6. insights - List all automated insights
7. explain  - Explain how metrics are calculated
8. developers - Show developer remediation rankings (requires git blame)
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from scripts.core.history_db import (
    get_connection,
    get_scan_by_id,
    get_findings_for_scan,
    compute_diff,
    DEFAULT_DB_PATH,
)
from scripts.core.trend_analyzer import (
    TrendAnalyzer,
    validate_trend_significance,
    format_trend_summary,
)
from scripts.cli.trend_formatters import (
    format_terminal_report,
    format_json_report,
    format_html_report,
    format_comparison,
)
from scripts.core.trend_exporters import (
    export_to_csv,
    export_to_prometheus,
    export_to_grafana,
    export_for_dashboard,
)
from scripts.core.developer_attribution import (
    DeveloperAttribution,
    format_developer_stats,
    format_team_stats,
    load_team_mapping,
)


# ============================================================================
# Command 1: jmo trends analyze
# ============================================================================


def cmd_trends_analyze(args) -> int:
    """
    Analyze security trends with flexible filters.

    Usage:
        jmo trends analyze --last 10
        jmo trends analyze --branch main --days 30
        jmo trends analyze --scan-ids abc123 def456 --format json
        jmo trends analyze --last 30 --validate-statistics
    """
    db_path = Path(getattr(args, "db", None) or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        sys.stderr.write("Run scans with history enabled first\n")
        return 1

    try:
        # Parse filters
        branch = getattr(args, "branch", "main")
        days = getattr(args, "days", None)
        last_n = getattr(args, "last", None)
        scan_ids = getattr(args, "scan_ids", None)
        validate_stats = getattr(args, "validate_statistics", False)
        verbose = getattr(args, "verbose", False)

        # Run analysis
        with TrendAnalyzer(db_path) as analyzer:
            analysis = analyzer.analyze_trends(
                branch=branch, days=days, scan_ids=scan_ids, last_n=last_n
            )

        if analysis["metadata"].get("status") == "no_data":
            sys.stdout.write(f"{analysis['metadata']['message']}\n")
            return 1

        # Statistical validation (if requested)
        if validate_stats and "severity_trends" in analysis:
            sys.stdout.write("\nRunning statistical validation (Mann-Kendall test)...\n")
            severity_trends_data = analysis["severity_trends"]["by_severity"]
            validation_results = validate_trend_significance(severity_trends_data)
            analysis["statistical_validation"] = validation_results

        # Output formatting (Phase 4: Enhanced with rich visualizations)
        output_format = getattr(args, "format", "terminal")

        if output_format == "json":
            sys.stdout.write(format_json_report(analysis) + "\n")
        elif output_format == "terminal":
            # Use rich-based terminal formatter with sparklines and charts
            formatted_output = format_terminal_report(analysis, verbose=verbose)
            sys.stdout.write(formatted_output)

            # Show statistical validation if present
            if "statistical_validation" in analysis:
                sys.stdout.write("\n📊 Statistical Validation (Mann-Kendall Test):\n")
                sys.stdout.write("=" * 70 + "\n")
                for severity, results in analysis["statistical_validation"].items():
                    if severity in ["CRITICAL", "HIGH"]:
                        trend = results["trend"]
                        p_value = results["p_value"]
                        significant = "✅ SIGNIFICANT" if results["significant"] else "❌ Not significant"
                        sys.stdout.write(
                            f"{severity:10s}: {trend:15s} (p={p_value:.4f}) {significant}\n"
                        )
                sys.stdout.write("\n")
        elif output_format == "html":
            # Use interactive HTML formatter with Chart.js
            sys.stdout.write(format_html_report(analysis) + "\n")
        else:
            sys.stderr.write(f"Error: Unknown format: {output_format}\n")
            sys.stderr.write("Supported formats: terminal, json, html\n")
            return 1

        # Export to file (if requested)
        if getattr(args, "export_json", None):
            export_path = Path(args.export_json)
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(format_json_report(analysis))
            sys.stdout.write(f"\n✅ Exported JSON to: {export_path}\n")

        if getattr(args, "export_html", None):
            export_path = Path(args.export_html)
            with open(export_path, "w", encoding="utf-8") as f:
                f.write(format_html_report(analysis))
            sys.stdout.write(f"\n✅ Exported HTML to: {export_path}\n")

        # Phase 5: Additional export formats
        if getattr(args, "export_csv", None):
            export_path = Path(args.export_csv)
            export_to_csv(analysis, export_path)
            sys.stdout.write(f"\n✅ Exported CSV to: {export_path}\n")

        if getattr(args, "export_prometheus", None):
            export_path = Path(args.export_prometheus)
            export_to_prometheus(analysis, export_path)
            sys.stdout.write(f"\n✅ Exported Prometheus metrics to: {export_path}\n")

        if getattr(args, "export_grafana", None):
            export_path = Path(args.export_grafana)
            export_to_grafana(analysis, export_path)
            sys.stdout.write(f"\n✅ Exported Grafana dashboard to: {export_path}\n")

        if getattr(args, "export_dashboard", None):
            export_path = Path(args.export_dashboard)
            export_for_dashboard(analysis, export_path)
            sys.stdout.write(f"\n✅ Exported dashboard data to: {export_path}\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error analyzing trends: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


# ============================================================================
# Command 2: jmo trends show
# ============================================================================


def cmd_trends_show(args) -> int:
    """
    Show trend context for a specific scan.

    Usage:
        jmo trends show abc123
        jmo trends show abc123 --context 5
    """
    db_path = Path(getattr(args, "db", None) or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    scan_id = getattr(args, "scan_id", None)
    if not scan_id:
        sys.stderr.write("Error: Provide --scan-id\n")
        sys.stderr.write("Usage: jmo trends show <scan-id>\n")
        return 1

    try:
        conn = get_connection(db_path)

        # Get the target scan
        scan = get_scan_by_id(conn, scan_id)
        if not scan:
            sys.stderr.write(f"Error: Scan not found: {scan_id}\n")
            conn.close()
            return 1

        scan = dict(scan)

        # Get context scans (N before, N after)
        context_size = getattr(args, "context", 5)
        branch = scan.get("branch", "main")

        from scripts.core.history_db import list_scans

        all_scans = list(
            map(dict, list_scans(conn, branch=branch, limit=1000))
        )

        # Find index of target scan
        scan_index = None
        for i, s in enumerate(all_scans):
            if s["id"] == scan_id:
                scan_index = i
                break

        if scan_index is None:
            sys.stderr.write("Error: Could not locate scan in timeline\n")
            conn.close()
            return 1

        # Get context window
        start_idx = max(0, scan_index - context_size)
        end_idx = min(len(all_scans), scan_index + context_size + 1)
        context_scans = all_scans[start_idx:end_idx]

        conn.close()

        # Output
        sys.stdout.write(f"\n📊 Trend Context for Scan: {scan_id[:8]}...\n")
        sys.stdout.write("=" * 70 + "\n\n")

        sys.stdout.write(f"Target Scan:\n")
        sys.stdout.write(f"  Timestamp: {scan['timestamp_iso'][:19]}\n")
        sys.stdout.write(f"  Branch:    {scan['branch'] or 'N/A'}\n")
        sys.stdout.write(f"  Profile:   {scan['profile']}\n")
        sys.stdout.write(f"  Findings:  {scan['total_findings']} total\n")
        sys.stdout.write(
            f"             {scan['critical_count']} CRITICAL, {scan['high_count']} HIGH\n"
        )
        sys.stdout.write("\n")

        sys.stdout.write(f"Context Window ({len(context_scans)} scans):\n")
        sys.stdout.write("-" * 70 + "\n")

        for i, ctx_scan in enumerate(context_scans):
            is_target = ctx_scan["id"] == scan_id
            marker = "👉" if is_target else "  "
            timestamp = ctx_scan["timestamp_iso"][:10]
            total = ctx_scan["total_findings"]
            critical = ctx_scan["critical_count"]
            high = ctx_scan["high_count"]

            sys.stdout.write(
                f"{marker} {timestamp}  {total:3d} total  ({critical} CRIT, {high} HIGH)\n"
            )

        sys.stdout.write("\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error showing trend context: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


# ============================================================================
# Command 3: jmo trends regressions
# ============================================================================


def cmd_trends_regressions(args) -> int:
    """
    List all detected regressions (severity increases).

    Usage:
        jmo trends regressions
        jmo trends regressions --last 30
        jmo trends regressions --severity CRITICAL
        jmo trends regressions --fail-on-any
    """
    db_path = Path(getattr(args, "db", None) or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    try:
        # Parse filters
        branch = getattr(args, "branch", "main")
        last_n = getattr(args, "last", None)
        severity_filter = getattr(args, "severity", None)
        fail_on_any = getattr(args, "fail_on_any", False)

        # Run analysis
        with TrendAnalyzer(db_path) as analyzer:
            analysis = analyzer.analyze_trends(branch=branch, last_n=last_n)

        if analysis["metadata"].get("status") == "no_data":
            sys.stdout.write(f"{analysis['metadata']['message']}\n")
            return 1

        regressions = analysis.get("regressions", [])

        # Filter by severity if requested
        if severity_filter:
            regressions = [
                r for r in regressions if r["severity"] == severity_filter.upper()
            ]

        # Output
        sys.stdout.write(f"\n⚠️  Regression Analysis: {branch}\n")
        sys.stdout.write("=" * 70 + "\n\n")

        if not regressions:
            sys.stdout.write("✅ No regressions detected\n\n")
            return 0

        sys.stdout.write(f"Found {len(regressions)} regression(s):\n\n")

        for i, reg in enumerate(regressions, 1):
            sys.stdout.write(f"{i}. {reg['severity']} Regression\n")
            sys.stdout.write(f"   Scan:      {reg['scan_id'][:8]}...\n")
            sys.stdout.write(f"   Timestamp: {reg['timestamp'][:19]}\n")
            sys.stdout.write(
                f"   Change:    {reg['previous_count']} → {reg['current_count']} (+{reg['increase']})\n"
            )
            sys.stdout.write("\n")

        # Fail if requested
        if fail_on_any and len(regressions) > 0:
            sys.stderr.write(f"❌ FAIL: {len(regressions)} regression(s) detected\n")
            return 1

        return 0

    except Exception as e:
        sys.stderr.write(f"Error detecting regressions: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


# ============================================================================
# Command 4: jmo trends score
# ============================================================================


def cmd_trends_score(args) -> int:
    """
    Show security posture score history.

    Usage:
        jmo trends score --last 30
        jmo trends score --branch main --days 90
    """
    db_path = Path(getattr(args, "db", None) or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    try:
        # Parse filters
        branch = getattr(args, "branch", "main")
        last_n = getattr(args, "last", None)
        days = getattr(args, "days", None)

        # Run analysis
        with TrendAnalyzer(db_path) as analyzer:
            analysis = analyzer.analyze_trends(branch=branch, last_n=last_n, days=days)

        if analysis["metadata"].get("status") == "no_data":
            sys.stdout.write(f"{analysis['metadata']['message']}\n")
            return 1

        score_data = analysis.get("security_score", {})
        scans = analysis.get("scans", [])

        # Output
        sys.stdout.write(f"\n🏆 Security Posture Score: {branch}\n")
        sys.stdout.write("=" * 70 + "\n\n")

        sys.stdout.write(f"Current Score:    {score_data['current_score']}/100\n")
        sys.stdout.write(f"Grade:            {score_data['grade']}\n")
        sys.stdout.write(f"Score Trend:      {score_data['trend'].upper()}\n")
        sys.stdout.write(f"Scans Analyzed:   {len(scans)}\n")
        sys.stdout.write("\n")

        # Show score history
        scores = score_data.get("historical_scores", [])
        if scores:
            sys.stdout.write("Score History:\n")
            sys.stdout.write("-" * 70 + "\n")

            for i, (scan, score) in enumerate(zip(scans, scores)):
                timestamp = scan["timestamp"][:10]
                grade = _score_to_grade(score)
                bar = "█" * (score // 5)
                sys.stdout.write(f"{timestamp}  {score:3d}/100 [{grade}] {bar}\n")

            sys.stdout.write("\n")

            # Summary statistics
            avg_score = sum(scores) / len(scores)
            max_score = max(scores)
            min_score = min(scores)
            sys.stdout.write(f"Average Score:    {avg_score:.1f}/100\n")
            sys.stdout.write(f"Best Score:       {max_score}/100\n")
            sys.stdout.write(f"Worst Score:      {min_score}/100\n")
            sys.stdout.write("\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error analyzing security score: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


def _score_to_grade(score: int) -> str:
    """Convert numeric score to letter grade."""
    if score >= 90:
        return "A"
    elif score >= 80:
        return "B"
    elif score >= 70:
        return "C"
    elif score >= 60:
        return "D"
    else:
        return "F"


# ============================================================================
# Command 5: jmo trends compare
# ============================================================================


def cmd_trends_compare(args) -> int:
    """
    Compare two specific scans side-by-side.

    Usage:
        jmo trends compare abc123 def456
        jmo trends compare abc123 def456 --verbose
    """
    db_path = Path(getattr(args, "db", None) or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    scan_id_1 = getattr(args, "scan_id_1", None)
    scan_id_2 = getattr(args, "scan_id_2", None)

    if not scan_id_1 or not scan_id_2:
        sys.stderr.write("Error: Provide two scan IDs to compare\n")
        sys.stderr.write("Usage: jmo trends compare <scan-id-1> <scan-id-2>\n")
        return 1

    try:
        conn = get_connection(db_path)

        # Get both scans
        scan1 = get_scan_by_id(conn, scan_id_1)
        scan2 = get_scan_by_id(conn, scan_id_2)

        if not scan1:
            sys.stderr.write(f"Error: Scan 1 not found: {scan_id_1}\n")
            conn.close()
            return 1
        if not scan2:
            sys.stderr.write(f"Error: Scan 2 not found: {scan_id_2}\n")
            conn.close()
            return 1

        scan1 = dict(scan1)
        scan2 = dict(scan2)

        # Compute diff
        diff = compute_diff(conn, scan_id_1, scan_id_2)

        conn.close()

        verbose = getattr(args, "verbose", False)

        # Output (Phase 4: Use enhanced comparison formatter)
        diff_dict = {
            "new_count": len(diff["new"]),
            "resolved_count": len(diff["resolved"]),
            "unchanged_count": len(diff["unchanged"]),
        }

        comparison_output = format_comparison(scan1, scan2, diff_dict)
        sys.stdout.write(comparison_output)
        sys.stdout.write("\n")

        # Verbose: Show sample findings
        if verbose:
            if diff["new"]:
                sys.stdout.write("\n📋 New Findings (top 10):\n")
                sys.stdout.write("-" * 80 + "\n")
                for f in diff["new"][:10]:
                    sys.stdout.write(
                        f"  + {f['severity']:8s} {f['rule_id']:30s} {f['path']}\n"
                    )
                sys.stdout.write("\n")

            if diff["resolved"]:
                sys.stdout.write("📋 Resolved Findings (top 10):\n")
                sys.stdout.write("-" * 80 + "\n")
                for f in diff["resolved"][:10]:
                    sys.stdout.write(
                        f"  - {f['severity']:8s} {f['rule_id']:30s} {f['path']}\n"
                    )
                sys.stdout.write("\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error comparing scans: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


# ============================================================================
# Command 6: jmo trends insights
# ============================================================================


def cmd_trends_insights(args) -> int:
    """
    List all automated insights from trend analysis.

    Usage:
        jmo trends insights --last 30
        jmo trends insights --branch main
    """
    db_path = Path(getattr(args, "db", None) or DEFAULT_DB_PATH)

    if not db_path.exists():
        sys.stderr.write(f"Error: History database not found: {db_path}\n")
        return 1

    try:
        # Parse filters
        branch = getattr(args, "branch", "main")
        last_n = getattr(args, "last", None)

        # Run analysis
        with TrendAnalyzer(db_path) as analyzer:
            analysis = analyzer.analyze_trends(branch=branch, last_n=last_n)

        if analysis["metadata"].get("status") == "no_data":
            sys.stdout.write(f"{analysis['metadata']['message']}\n")
            return 1

        insights = analysis.get("insights", [])

        # Output
        sys.stdout.write(f"\n💡 Automated Insights: {branch}\n")
        sys.stdout.write("=" * 70 + "\n\n")

        if not insights:
            sys.stdout.write("No insights generated\n\n")
            return 0

        for i, insight in enumerate(insights, 1):
            sys.stdout.write(f"{i}. {insight}\n")

        sys.stdout.write("\n")

        return 0

    except Exception as e:
        sys.stderr.write(f"Error generating insights: {e}\n")
        import traceback

        traceback.print_exc()
        return 1


# ============================================================================
# Command 7: jmo trends explain
# ============================================================================


def cmd_trends_explain(args) -> int:
    """
    Explain how trend metrics are calculated.

    Usage:
        jmo trends explain score
        jmo trends explain mann-kendall
        jmo trends explain regressions
    """
    metric = getattr(args, "metric", None)

    if not metric:
        sys.stderr.write("Error: Provide a metric to explain\n")
        sys.stderr.write(
            "Usage: jmo trends explain {score|mann-kendall|regressions|all}\n"
        )
        return 1

    explanations = {
        "score": """
🏆 Security Posture Score

**Formula:**
  Score = 100 - (CRITICAL × 10) - (HIGH × 3) - (MEDIUM × 1)
  Minimum: 0, Maximum: 100

**Grading:**
  A: 90-100  (Excellent)
  B: 80-89   (Good)
  C: 70-79   (Fair)
  D: 60-69   (Poor)
  F: 0-59    (Critical)

**Example:**
  Scan with 2 CRITICAL, 5 HIGH, 10 MEDIUM findings:
  Score = 100 - (2×10) - (5×3) - (10×1) = 100 - 20 - 15 - 10 = 55 (Grade F)

**Use Cases:**
  - Track security posture over time
  - Compare branches (main vs dev)
  - Set organizational goals (maintain B+ grade)
""",
        "mann-kendall": """
📊 Mann-Kendall Trend Test

**Purpose:**
  Statistical validation of trends to distinguish real improvements
  from random noise.

**How it works:**
  1. Compares all pairs of data points
  2. Counts increases vs decreases
  3. Calculates significance (p-value)
  4. Determines if trend is statistically valid

**Interpretation:**
  - p-value < 0.05: **Statistically significant** trend
  - p-value ≥ 0.05: No significant trend (could be noise)
  - tau > 0: Increasing trend
  - tau < 0: Decreasing trend
  - |tau| → 1: Strong trend
  - |tau| → 0: Weak trend

**Example:**
  CRITICAL findings: [10, 8, 6, 5, 3, 2]
  Result: trend=decreasing, tau=-1.0, p=0.003
  → ✅ Statistically significant improvement

**Why it matters:**
  Prevents false positives from random variations.
  Ensures trend detection is rigorous and trustworthy.
""",
        "regressions": """
⚠️  Regression Detection

**Definition:**
  A regression is a severity increase between consecutive scans.

**Detection Rules:**
  1. CRITICAL: ANY increase triggers regression
  2. HIGH: Increase ≥3 triggers regression
  3. MEDIUM/LOW: Not tracked (too noisy)

**Example:**
  Scan 1: 2 CRITICAL, 10 HIGH
  Scan 2: 3 CRITICAL, 12 HIGH
  → Detected: 1 CRITICAL regression, 0 HIGH regression (only +2)

**Use Cases:**
  - CI/CD gates: Fail builds on regressions
  - Sprint tracking: Alert team when new CRITICAL appears
  - Compliance: Ensure security doesn't degrade

**Command:**
  jmo trends regressions --fail-on-any
""",
        "trend": """
📈 Trend Classification

**How trends are determined:**
  1. Calculate weighted change:
     weighted_change = (CRITICAL × 10) + (HIGH × 3) + total

  2. Classify:
     - weighted_change < -5: **IMPROVING**
     - weighted_change > +5: **DEGRADING**
     - otherwise: **STABLE**

**Confidence Levels:**
  - High: ≥10 scans
  - Medium: 5-9 scans
  - Low: 2-4 scans
  - Insufficient: <2 scans

**Statistical Validation:**
  Use --validate-statistics flag to run Mann-Kendall test
  for rigorous trend confirmation.
""",
    }

    if metric.lower() == "all":
        # Show all explanations
        for name, explanation in explanations.items():
            sys.stdout.write(f"\n{'=' * 70}\n")
            sys.stdout.write(explanation.strip() + "\n")
        sys.stdout.write(f"\n{'=' * 70}\n\n")
    elif metric.lower() in explanations:
        sys.stdout.write(f"\n{'=' * 70}\n")
        sys.stdout.write(explanations[metric.lower()].strip() + "\n")
        sys.stdout.write(f"\n{'=' * 70}\n\n")
    else:
        sys.stderr.write(f"Error: Unknown metric: {metric}\n")
        sys.stderr.write("Available: score, mann-kendall, regressions, trend, all\n")
        return 1

    return 0


# ============================================================================
# Command 8: jmo trends developers
# ============================================================================


def cmd_trends_developers(args) -> int:
    """
    Show developer remediation rankings via git blame analysis.

    Analyzes git history to attribute security finding remediation efforts
    to developers and teams. Provides insights into:
    - Top remediators by findings resolved
    - Focus areas (files) per developer
    - Tool effectiveness per developer
    - Team performance aggregation

    Usage:
        jmo trends developers --last 30
        jmo trends developers --last 30 --top 10
        jmo trends developers --last 30 --team-file teams.json
        jmo trends developers --days 90 --repo /path/to/repo

    Note: Requires git repository access for attribution.
    """
    try:
        # Get parameters
        last_n = getattr(args, "last", 30)
        top = getattr(args, "top", 10)
        repo_path = Path(getattr(args, "repo", Path.cwd()))
        team_file = getattr(args, "team_file", None)
        db_path = getattr(args, "db", None)
        if db_path:
            db_path = Path(db_path)

        # Validate git repository
        if not (repo_path / ".git").exists():
            sys.stderr.write(f"Error: Not a git repository: {repo_path}\n")
            sys.stderr.write("Git blame attribution requires a git repository.\n")
            sys.stderr.write(
                "Use --repo to specify the repository path, or run from within a repo.\n"
            )
            return 1

        sys.stdout.write("\n👥 Developer Attribution Analysis\n")
        sys.stdout.write("=" * 70 + "\n\n")

        # Analyze trends to get resolved findings
        sys.stdout.write(f"Analyzing last {last_n} scans for resolved findings...\n")

        analyzer = TrendAnalyzer(db_path)
        report = analyzer.analyze(last_n=last_n)

        if report.scan_count < 2:
            sys.stdout.write(
                "⚠️  Need at least 2 scans to detect resolved findings.\n"
            )
            sys.stdout.write(f"   Found {report.scan_count} scan(s) in history.\n")
            sys.stdout.write("   Run more scans to enable developer attribution.\n")
            return 0

        # Get resolved fingerprints (first scan - last scan)
        conn = get_connection(db_path)
        scan_ids = report.scan_ids

        first_scan = get_scan_by_id(conn, scan_ids[0])
        last_scan = get_scan_by_id(conn, scan_ids[-1])

        if not first_scan or not last_scan:
            sys.stderr.write("Error: Could not load scan data from database.\n")
            return 1

        first_findings = get_findings_for_scan(conn, scan_ids[0])
        last_findings = get_findings_for_scan(conn, scan_ids[-1])

        first_fps = {f[1] for f in first_findings}  # (scan_id, fingerprint, ...)
        last_fps = {f[1] for f in last_findings}

        resolved_fps = first_fps - last_fps

        if not resolved_fps:
            sys.stdout.write(
                f"No resolved findings between first and last scan ({report.scan_count} scans).\n"
            )
            sys.stdout.write(
                "Developer attribution requires findings to be resolved over time.\n"
            )
            return 0

        sys.stdout.write(f"Found {len(resolved_fps)} resolved findings.\n")
        sys.stdout.write("Running git blame attribution...\n\n")

        # Perform attribution
        attrib = DeveloperAttribution(repo_path)

        # Create a simple history DB adapter for get_finding_by_fingerprint
        class HistoryDBAdapter:
            """Adapter to provide get_finding_by_fingerprint interface."""

            def __init__(self, connection):
                self.conn = connection

            def get_finding_by_fingerprint(self, fp: str) -> Optional[Dict]:
                """Get finding details by fingerprint."""
                cursor = self.conn.execute(
                    """
                    SELECT
                        f.fingerprint,
                        f.severity,
                        f.tool,
                        f.rule_id,
                        f.path,
                        f.start_line,
                        f.end_line,
                        f.message,
                        f.raw_finding
                    FROM findings f
                    WHERE f.fingerprint = ?
                    LIMIT 1
                    """,
                    (fp,),
                )
                row = cursor.fetchone()
                if not row:
                    return None

                # Parse raw_finding JSON if available
                raw = None
                if row[8]:  # raw_finding column
                    try:
                        raw = json.loads(row[8])
                    except:
                        pass

                return {
                    "fingerprint": row[0],
                    "severity": row[1],
                    "tool": row[2],
                    "rule_id": row[3],
                    "path": row[4],
                    "start_line": row[5],
                    "end_line": row[6],
                    "message": row[7],
                    "risk": raw.get("risk", {}) if raw else {},
                }

        hdb = HistoryDBAdapter(conn)
        dev_stats = attrib.analyze_remediation_by_developer(resolved_fps, hdb)

        if not dev_stats:
            sys.stdout.write(
                "No developer attribution data available.\n"
            )
            sys.stdout.write(
                "This can happen if:\n"
                "- Files were deleted or moved\n"
                "- git blame cannot access the repository\n"
                "- Findings are in non-tracked files\n"
            )
            return 0

        # Display results
        sys.stdout.write(f"📊 Top {min(top, len(dev_stats))} Developers by Remediation:\n")
        sys.stdout.write("=" * 70 + "\n\n")

        for i, dev in enumerate(dev_stats[:top], 1):
            output = format_developer_stats(dev, rank=i)
            sys.stdout.write(output + "\n\n")

        # Team aggregation if team file provided
        if team_file:
            sys.stdout.write("\n")
            sys.stdout.write("=" * 70 + "\n")
            sys.stdout.write("🏢 Team Performance Aggregation\n")
            sys.stdout.write("=" * 70 + "\n\n")

            try:
                team_mapping = load_team_mapping(Path(team_file))
                team_stats = attrib.aggregate_by_team(dev_stats, team_mapping)

                for i, team in enumerate(team_stats[:5], 1):
                    output = format_team_stats(team, rank=i)
                    sys.stdout.write(output + "\n\n")

            except FileNotFoundError:
                sys.stderr.write(f"Warning: Team file not found: {team_file}\n")
            except Exception as e:
                sys.stderr.write(f"Warning: Failed to load team mapping: {e}\n")

        # Summary statistics
        sys.stdout.write("\n")
        sys.stdout.write("=" * 70 + "\n")
        sys.stdout.write("📈 Summary Statistics\n")
        sys.stdout.write("=" * 70 + "\n\n")

        total_resolved = sum(d.findings_resolved for d in dev_stats)
        avg_resolved = total_resolved / len(dev_stats) if dev_stats else 0

        sys.stdout.write(f"Total developers: {len(dev_stats)}\n")
        sys.stdout.write(f"Total findings resolved: {total_resolved}\n")
        sys.stdout.write(f"Average per developer: {avg_resolved:.1f}\n")

        # Top contributors summary
        if len(dev_stats) >= 3:
            top3_resolved = sum(d.findings_resolved for d in dev_stats[:3])
            top3_percent = (top3_resolved / total_resolved * 100) if total_resolved > 0 else 0
            sys.stdout.write(
                f"Top 3 contributors: {top3_resolved} findings ({top3_percent:.1f}%)\n"
            )

        sys.stdout.write("\n")

        conn.close()
        return 0

    except Exception as e:
        sys.stderr.write(f"Error during developer attribution: {e}\n")
        import traceback
        traceback.print_exc()
        return 1


# ============================================================================
# Main Command Router
# ============================================================================


def cmd_trends(args) -> int:
    """Main trends command router."""
    subcommand = getattr(args, "trends_command", None)

    if subcommand == "analyze":
        return cmd_trends_analyze(args)
    elif subcommand == "show":
        return cmd_trends_show(args)
    elif subcommand == "regressions":
        return cmd_trends_regressions(args)
    elif subcommand == "score":
        return cmd_trends_score(args)
    elif subcommand == "compare":
        return cmd_trends_compare(args)
    elif subcommand == "insights":
        return cmd_trends_insights(args)
    elif subcommand == "explain":
        return cmd_trends_explain(args)
    elif subcommand == "developers":
        return cmd_trends_developers(args)
    else:
        sys.stderr.write("Error: Unknown trends subcommand\n")
        sys.stderr.write(
            "Usage: jmo trends {analyze|show|regressions|score|compare|insights|explain|developers}\n"
        )
        return 1
