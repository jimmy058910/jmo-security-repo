#!/usr/bin/env python3
"""
Generate comprehensive test report from E2E test results CSV

Usage:
    python tests/e2e/generate_report.py /path/to/test-results.csv

Output:
    - test-report.md (markdown report)
    - Console output with summary
"""

import sys
import csv
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Tuple


def load_results(csv_path: Path) -> List[Dict[str, str]]:
    """Load test results from CSV file."""
    results = []
    with open(csv_path, 'r') as f:
        reader = csv.DictReader(f)
        for row in reader:
            results.append(row)
    return results


def calculate_stats(results: List[Dict[str, str]]) -> Dict[str, int]:
    """Calculate test statistics."""
    stats = {
        'total': len(results),
        'passed': sum(1 for r in results if r['status'] == 'PASS'),
        'failed': sum(1 for r in results if r['status'] == 'FAIL'),
        'skipped': sum(1 for r in results if r['status'] == 'SKIP'),
    }
    stats['success_rate'] = (
        (stats['passed'] / stats['total'] * 100) if stats['total'] > 0 else 0
    )
    return stats


def format_duration(seconds_str: str) -> str:
    """Format duration in human-readable format."""
    try:
        seconds = int(seconds_str)
        if seconds < 60:
            return f"{seconds}s"
        elif seconds < 3600:
            mins = seconds // 60
            secs = seconds % 60
            return f"{mins}m {secs}s"
        else:
            hours = seconds // 3600
            mins = (seconds % 3600) // 60
            return f"{hours}h {mins}m"
    except (ValueError, TypeError):
        return "0s"


def categorize_tests(results: List[Dict[str, str]]) -> Dict[str, List[Dict[str, str]]]:
    """Categorize tests by suite (Ubuntu, macOS, Windows, Advanced)."""
    categories = {
        'Ubuntu': [],
        'macOS': [],
        'Windows': [],
        'Advanced': [],
    }

    for result in results:
        test_id = result['test_id']
        if test_id.startswith('U'):
            categories['Ubuntu'].append(result)
        elif test_id.startswith('M'):
            categories['macOS'].append(result)
        elif test_id.startswith('W'):
            categories['Windows'].append(result)
        elif test_id.startswith('A'):
            categories['Advanced'].append(result)

    return categories


def generate_markdown_report(
    csv_path: Path,
    results: List[Dict[str, str]],
    stats: Dict[str, int],
    categories: Dict[str, List[Dict[str, str]]],
) -> str:
    """Generate markdown test report."""
    report = []

    # Header
    report.append("# E2E Comprehensive Test Results\n")
    report.append(f"**Generated:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S UTC')}\n")
    report.append(f"**Results File:** `{csv_path}`\n")
    report.append("")

    # Summary
    report.append("## Summary\n")
    report.append("| Metric | Value |")
    report.append("|--------|-------|")
    report.append(f"| Total Tests | {stats['total']} |")
    report.append(f"| ✅ Passed | {stats['passed']} |")
    report.append(f"| ❌ Failed | {stats['failed']} |")
    report.append(f"| ⏭️ Skipped | {stats['skipped']} |")
    report.append(f"| Success Rate | {stats['success_rate']:.1f}% |")

    # Total duration
    total_duration = sum(
        int(r['duration_seconds'])
        for r in results
        if r['status'] in ('PASS', 'FAIL') and r['duration_seconds'].isdigit()
    )
    report.append(f"| Total Duration | {format_duration(str(total_duration))} |")
    report.append("")

    # Status indicator
    if stats['failed'] == 0 and stats['passed'] > 0:
        report.append("### ✅ All Tests Passed!\n")
    elif stats['failed'] > 0:
        report.append(f"### ⚠️ {stats['failed']} Test(s) Failed\n")
    else:
        report.append("### ⚠️ No Tests Ran\n")
    report.append("")

    # Results by category
    report.append("## Results by Test Suite\n")

    for category, cat_results in categories.items():
        if not cat_results:
            continue

        cat_passed = sum(1 for r in cat_results if r['status'] == 'PASS')
        cat_failed = sum(1 for r in cat_results if r['status'] == 'FAIL')
        cat_skipped = sum(1 for r in cat_results if r['status'] == 'SKIP')

        report.append(f"### {category} Tests ({len(cat_results)} total)\n")
        report.append(f"**Passed:** {cat_passed} | **Failed:** {cat_failed} | **Skipped:** {cat_skipped}\n")

        report.append("| Test ID | Status | Duration |")
        report.append("|---------|--------|----------|")

        for result in cat_results:
            status_emoji = {
                'PASS': '✅',
                'FAIL': '❌',
                'SKIP': '⏭️',
            }.get(result['status'], '❓')

            duration = format_duration(result['duration_seconds'])

            report.append(
                f"| {result['test_id']} | {status_emoji} {result['status']} | {duration} |"
            )

        report.append("")

    # Failed tests details
    failed_tests = [r for r in results if r['status'] == 'FAIL']
    if failed_tests:
        report.append("## Failed Tests Details\n")
        for result in failed_tests:
            report.append(f"### ❌ Test {result['test_id']} Failed\n")
            report.append(f"**Duration:** {format_duration(result['duration_seconds'])}\n")
            report.append("**Possible Reasons:**")
            report.append("- Tool installation failure")
            report.append("- Timeout (>15 minutes)")
            report.append("- Output validation failure")
            report.append("- Missing test fixtures")
            report.append("")
            report.append(f"**Check logs:** `{csv_path.parent}/{result['test_id']}/test.log`\n")

    # Skipped tests
    skipped_tests = [r for r in results if r['status'] == 'SKIP']
    if skipped_tests:
        report.append("## Skipped Tests\n")
        for result in skipped_tests:
            report.append(f"- **{result['test_id']}** - Check test script for skip reason\n")

    # Performance analysis
    report.append("## Performance Analysis\n")

    # Calculate average duration by status
    passed_tests = [r for r in results if r['status'] == 'PASS']
    if passed_tests:
        avg_duration = sum(
            int(r['duration_seconds']) for r in passed_tests if r['duration_seconds'].isdigit()
        ) / len(passed_tests)

        report.append(f"**Average Test Duration (Passed):** {format_duration(str(int(avg_duration)))}\n")

        # Find slowest tests
        sorted_tests = sorted(
            passed_tests,
            key=lambda r: int(r['duration_seconds']) if r['duration_seconds'].isdigit() else 0,
            reverse=True,
        )

        report.append("**Slowest Tests (Top 5):**\n")
        for result in sorted_tests[:5]:
            report.append(
                f"- {result['test_id']}: {format_duration(result['duration_seconds'])}"
            )
        report.append("")

    # Recommendations
    report.append("## Recommendations\n")

    if stats['success_rate'] >= 95:
        report.append("✅ **Release Ready** - Test suite shows excellent stability\n")
    elif stats['success_rate'] >= 80:
        report.append("⚠️ **Investigate Failures** - Address failing tests before release\n")
    else:
        report.append("❌ **Not Release Ready** - Critical issues detected, do not release\n")

    if stats['failed'] > 0:
        report.append("**Action Items:**")
        report.append("1. Review failed test logs")
        report.append("2. Verify tool installations")
        report.append("3. Check test fixtures availability")
        report.append("4. Re-run failed tests individually")
        report.append("")

    # Footer
    report.append("---")
    report.append("*Generated by JMo Security E2E Test Suite*")

    return "\n".join(report)


def print_console_summary(stats: Dict[str, int], categories: Dict[str, List[Dict[str, str]]]):
    """Print colorful console summary."""
    # ANSI colors
    GREEN = '\033[0;32m'
    RED = '\033[0;31m'
    YELLOW = '\033[1;33m'
    BLUE = '\033[0;34m'
    BOLD = '\033[1m'
    NC = '\033[0m'  # No Color

    print(f"\n{BLUE}{'=' * 60}{NC}")
    print(f"{BOLD}E2E Test Results Summary{NC}")
    print(f"{BLUE}{'=' * 60}{NC}\n")

    # Overall stats
    print(f"{BOLD}Overall Statistics:{NC}")
    print(f"  Total Tests:   {stats['total']}")
    print(f"  {GREEN}✅ Passed:{NC}      {stats['passed']}")
    print(f"  {RED}❌ Failed:{NC}      {stats['failed']}")
    print(f"  {YELLOW}⏭️  Skipped:{NC}    {stats['skipped']}")
    print(f"  Success Rate:  {stats['success_rate']:.1f}%")
    print()

    # Category breakdown
    print(f"{BOLD}Results by Suite:{NC}")
    for category, cat_results in categories.items():
        if not cat_results:
            continue

        cat_passed = sum(1 for r in cat_results if r['status'] == 'PASS')
        cat_failed = sum(1 for r in cat_results if r['status'] == 'FAIL')
        cat_skipped = sum(1 for r in cat_results if r['status'] == 'SKIP')

        status_color = GREEN if cat_failed == 0 else RED
        print(
            f"  {BOLD}{category}:{NC} "
            f"{status_color}{cat_passed}/{len(cat_results)} passed{NC} "
            f"({cat_failed} failed, {cat_skipped} skipped)"
        )
    print()

    # Release readiness
    if stats['success_rate'] >= 95:
        print(f"{GREEN}{BOLD}✅ RELEASE READY{NC}")
    elif stats['success_rate'] >= 80:
        print(f"{YELLOW}{BOLD}⚠️  INVESTIGATE FAILURES{NC}")
    else:
        print(f"{RED}{BOLD}❌ NOT RELEASE READY{NC}")

    print(f"{BLUE}{'=' * 60}{NC}\n")


def main():
    """Main entry point."""
    if len(sys.argv) < 2:
        print("Usage: python generate_report.py <test-results.csv>")
        print("Example: python tests/e2e/generate_report.py /tmp/jmo-e2e-results-123/test-results.csv")
        sys.exit(1)

    csv_path = Path(sys.argv[1])

    if not csv_path.exists():
        print(f"Error: Results file not found: {csv_path}")
        sys.exit(1)

    # Load and process results
    results = load_results(csv_path)

    if not results:
        print("Error: No test results found in CSV")
        sys.exit(1)

    stats = calculate_stats(results)
    categories = categorize_tests(results)

    # Generate markdown report
    markdown_report = generate_markdown_report(csv_path, results, stats, categories)

    # Write report to file
    report_path = Path('test-report.md')
    with open(report_path, 'w') as f:
        f.write(markdown_report)

    print(f"✅ Markdown report written to: {report_path}")

    # Print console summary
    print_console_summary(stats, categories)

    # Exit with failure if any tests failed
    sys.exit(1 if stats['failed'] > 0 else 0)


if __name__ == '__main__':
    main()
