#!/usr/bin/env python3
"""
Performance Benchmark Comparison Tool for JMo Security.

Compares benchmark results between baseline and current runs to detect
performance regressions. Designed for CI/CD integration with GitHub Actions.

Usage:
    python3 scripts/dev/compare_benchmarks.py \
        --baseline baseline-results.json \
        --current current-results.json \
        --threshold 20 \
        --output comparison.md
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class BenchmarkResult:
    """Single benchmark test result."""

    name: str
    duration_ms: float
    passed: bool
    target_ms: Optional[float] = None


@dataclass
class ComparisonResult:
    """Comparison between baseline and current benchmark."""

    name: str
    baseline_ms: float
    current_ms: float
    change_pct: float
    regression: bool
    target_ms: Optional[float] = None


def parse_pytest_json(json_path: Path) -> List[BenchmarkResult]:
    """
    Parse pytest JSON output to extract benchmark results.

    Args:
        json_path: Path to pytest --json-report output

    Returns:
        List of BenchmarkResult objects
    """
    if not json_path.exists():
        return []

    with open(json_path, "r") as f:
        data = json.load(f)

    results: List[BenchmarkResult] = []

    # Parse pytest results (if using pytest-benchmark plugin)
    if "benchmarks" in data:
        for bench in data["benchmarks"]:
            results.append(
                BenchmarkResult(
                    name=bench["name"],
                    duration_ms=bench["stats"]["mean"] * 1000,  # Convert s to ms
                    passed=True,
                    target_ms=bench.get("target_ms"),
                )
            )
    # Parse custom JSON format (from our test output)
    elif "tests" in data:
        for test in data["tests"]:
            if "benchmark_" in test["nodeid"]:
                # Extract duration from test metadata
                duration_ms = test.get("call", {}).get("duration", 0) * 1000
                results.append(
                    BenchmarkResult(
                        name=test["nodeid"].split("::")[-1],
                        duration_ms=duration_ms,
                        passed=test["outcome"] == "passed",
                    )
                )

    return results


def compare_benchmarks(
    baseline: List[BenchmarkResult],
    current: List[BenchmarkResult],
    threshold_pct: float = 20.0,
) -> List[ComparisonResult]:
    """
    Compare baseline and current benchmark results.

    Args:
        baseline: Baseline benchmark results
        current: Current benchmark results
        threshold_pct: Regression threshold percentage (default: 20%)

    Returns:
        List of ComparisonResult objects
    """
    baseline_map = {b.name: b for b in baseline}
    comparisons: List[ComparisonResult] = []

    for curr in current:
        base = baseline_map.get(curr.name)

        if base is None:
            # New benchmark - no comparison possible
            comparisons.append(
                ComparisonResult(
                    name=curr.name,
                    baseline_ms=0.0,
                    current_ms=curr.duration_ms,
                    change_pct=0.0,
                    regression=False,
                    target_ms=curr.target_ms,
                )
            )
            continue

        # Calculate percentage change
        if base.duration_ms == 0:
            change_pct = 0.0
        else:
            change_pct = ((curr.duration_ms - base.duration_ms) / base.duration_ms) * 100

        # Detect regression (slowdown beyond threshold)
        regression = change_pct > threshold_pct

        comparisons.append(
            ComparisonResult(
                name=curr.name,
                baseline_ms=base.duration_ms,
                current_ms=curr.duration_ms,
                change_pct=change_pct,
                regression=regression,
                target_ms=curr.target_ms,
            )
        )

    return comparisons


def format_markdown_report(
    comparisons: List[ComparisonResult], threshold_pct: float
) -> str:
    """
    Format comparison results as Markdown for GitHub PR comments.

    Args:
        comparisons: List of comparison results
        threshold_pct: Regression threshold percentage

    Returns:
        Markdown-formatted report
    """
    regressions = [c for c in comparisons if c.regression]
    improvements = [c for c in comparisons if c.change_pct < -5.0]  # >5% faster

    md = "# 📊 Performance Benchmark Report\n\n"

    # Summary
    md += "## Summary\n\n"
    md += f"- **Total Benchmarks:** {len(comparisons)}\n"
    md += f"- **Regressions:** {len(regressions)} ❌\n"
    md += f"- **Improvements:** {len(improvements)} ✅\n"
    md += f"- **Regression Threshold:** {threshold_pct}%\n\n"

    # Regressions table
    if regressions:
        md += "## ❌ Performance Regressions\n\n"
        md += "| Benchmark | Baseline (ms) | Current (ms) | Change | Target |\n"
        md += "|-----------|---------------|--------------|--------|--------|\n"

        for c in regressions:
            target = f"{c.target_ms}ms" if c.target_ms else "N/A"
            md += (
                f"| {c.name} | {c.baseline_ms:.2f} | {c.current_ms:.2f} | "
                f"+{c.change_pct:.1f}% | {target} |\n"
            )

        md += "\n"

    # Improvements table
    if improvements:
        md += "## ✅ Performance Improvements\n\n"
        md += "| Benchmark | Baseline (ms) | Current (ms) | Change | Target |\n"
        md += "|-----------|---------------|--------------|--------|--------|\n"

        for c in improvements:
            target = f"{c.target_ms}ms" if c.target_ms else "N/A"
            md += (
                f"| {c.name} | {c.baseline_ms:.2f} | {c.current_ms:.2f} | "
                f"{c.change_pct:.1f}% | {target} |\n"
            )

        md += "\n"

    # All benchmarks table
    md += "## 📈 All Benchmarks\n\n"
    md += "| Benchmark | Baseline (ms) | Current (ms) | Change | Status |\n"
    md += "|-----------|---------------|--------------|--------|--------|\n"

    for c in comparisons:
        status = "❌ Regression" if c.regression else "✅ OK"
        if c.change_pct < -5.0:
            status = "⚡ Faster"

        baseline_str = f"{c.baseline_ms:.2f}" if c.baseline_ms > 0 else "N/A"
        change_str = (
            f"{c.change_pct:+.1f}%" if c.baseline_ms > 0 else "New"
        )

        md += (
            f"| {c.name} | {baseline_str} | {c.current_ms:.2f} | "
            f"{change_str} | {status} |\n"
        )

    md += "\n"

    # Footer
    md += "---\n\n"
    md += "*Generated by JMo Security Performance Regression Detection*\n"

    return md


def main():
    parser = argparse.ArgumentParser(
        description="Compare performance benchmark results and detect regressions"
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        required=True,
        help="Path to baseline benchmark results JSON",
    )
    parser.add_argument(
        "--current",
        type=Path,
        required=True,
        help="Path to current benchmark results JSON",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=20.0,
        help="Regression threshold percentage (default: 20%%)",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("benchmark-comparison.md"),
        help="Path to output Markdown report",
    )

    args = parser.parse_args()

    # Parse results
    baseline_results = parse_pytest_json(args.baseline)
    current_results = parse_pytest_json(args.current)

    if not current_results:
        print("❌ Error: No current benchmark results found")
        sys.exit(1)

    # Compare
    comparisons = compare_benchmarks(baseline_results, current_results, args.threshold)

    # Generate report
    report = format_markdown_report(comparisons, args.threshold)

    # Write to file
    args.output.write_text(report)
    print(f"✅ Benchmark comparison report written to: {args.output}")

    # Print summary to console
    regressions = [c for c in comparisons if c.regression]
    if regressions:
        print(f"\n❌ {len(regressions)} performance regression(s) detected:")
        for r in regressions:
            print(
                f"  - {r.name}: {r.baseline_ms:.2f}ms → {r.current_ms:.2f}ms "
                f"(+{r.change_pct:.1f}%)"
            )

        # Set output for GitHub Actions
        print("::set-output name=regression_detected::true")
        sys.exit(1)
    else:
        print("\n✅ No performance regressions detected")
        print("::set-output name=regression_detected::false")
        sys.exit(0)


if __name__ == "__main__":
    main()
