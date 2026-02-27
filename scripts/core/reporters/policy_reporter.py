#!/usr/bin/env python3
"""Policy-as-Code Reporter for JMo Security.

Evaluates security findings against Open Policy Agent (OPA) Rego policies
and generates policy compliance reports in multiple formats.

Output Formats:
    - **POLICY_REPORT.md**: Detailed Markdown report with policy evaluation results,
      violations grouped by policy, and warnings summary
    - **policy-results.json**: Machine-readable JSON with schema version, policy
      results, violations, warnings, and metadata
    - **POLICY_SUMMARY.md**: Concise summary for inclusion in main SUMMARY.md

v1.0.0 Metadata Wrapper:
    JSON output includes standardized metadata wrapper:
    {
        "schemaVersion": "1.0.0",
        "policies": [
            {
                "name": "no-critical-in-prod",
                "passed": false,
                "violations": [...],
                "warnings": [...],
                "message": "3 CRITICAL findings in production code",
                "metadata": {...}
            }
        ]
    }

Policy Discovery:
    Policies are loaded from two directories (user policies override builtin):
    1. Builtin: policies/ (shipped with JMo Security)
    2. User: ~/.jmo/policies/ (custom user policies)

Rego Policy Interface:
    Policies must define:
    - `violations[msg]`: Findings that violate the policy
    - `warnings[msg]`: Non-blocking warnings
    - `metadata`: Policy metadata (name, description, severity)

Usage:
    >>> from scripts.core.reporters.policy_reporter import (
    ...     evaluate_policies,
    ...     write_policy_report,
    ...     write_policy_json,
    ...     write_policy_summary_md,
    ... )
    >>> # Evaluate findings against policies
    >>> results = evaluate_policies(
    ...     findings,
    ...     policy_names=["no-critical-in-prod", "sla-compliance"],
    ...     builtin_dir=Path("policies"),
    ...     user_dir=Path.home() / ".jmo" / "policies",
    ... )
    >>> # Generate reports
    >>> write_policy_report(results, Path("results/summaries/POLICY_REPORT.md"))
    >>> write_policy_json(results, Path("results/summaries/policy-results.json"))

Functions:
    evaluate_policies: Evaluate findings against Rego policies
    write_policy_report: Generate detailed Markdown report
    write_policy_json: Generate machine-readable JSON output
    write_policy_summary_md: Generate concise summary for SUMMARY.md

See Also:
    - docs/POLICY_AS_CODE.md for policy authoring guide
    - scripts/core/policy_engine.py for OPA integration
    - policies/*.rego for example policy definitions

Author: JMo Security
License: MIT
"""

import json
import logging
from pathlib import Path
from typing import Any, List, Dict

from scripts.core.policy_engine import PolicyEngine, PolicyResult

logger = logging.getLogger(__name__)


def evaluate_policies(
    findings: List[Dict[str, Any]],
    policy_names: List[str],
    builtin_dir: Path,
    user_dir: Path,
) -> Dict[str, PolicyResult]:
    """
    Evaluate findings against specified policies.

    Args:
        findings: List of CommonFinding dictionaries
        policy_names: List of policy names to evaluate (without .rego extension)
        builtin_dir: Path to builtin policies directory
        user_dir: Path to user policies directory (~/.jmo/policies)

    Returns:
        Dict mapping policy name to PolicyResult
    """
    engine = PolicyEngine()
    results = {}

    # Discover all available policies
    policies = {}
    if builtin_dir.exists():
        for policy_file in builtin_dir.glob("*.rego"):
            policies[policy_file.stem] = policy_file
    if user_dir.exists():
        for policy_file in user_dir.glob("*.rego"):
            policies[policy_file.stem] = policy_file  # User policies override builtin

    # Evaluate each requested policy
    for policy_name in policy_names:
        if policy_name not in policies:
            logger.warning(
                f"Policy '{policy_name}' not found. Available: {', '.join(sorted(policies.keys()))}"
            )
            continue

        policy_path = policies[policy_name]
        try:
            logger.info(f"Evaluating policy: {policy_name}")
            result = engine.evaluate(findings, policy_path)
            results[policy_name] = result
        except Exception as e:
            logger.error(f"Failed to evaluate policy '{policy_name}': {e}")
            continue

    return results


def write_policy_report(
    policy_results: Dict[str, PolicyResult], output_path: Path
) -> None:
    """
    Write policy evaluation results to Markdown report.

    Args:
        policy_results: Dict mapping policy name to PolicyResult
        output_path: Path to output markdown file
    """
    if not policy_results:
        logger.info("No policy results to write")
        return

    lines = []
    lines.append("# Policy-as-Code Evaluation Report")
    lines.append("")
    lines.append(f"Evaluated {len(policy_results)} policies against security findings.")
    lines.append("")

    # Summary table
    lines.append("## Summary")
    lines.append("")
    lines.append("| Policy | Status | Violations | Warnings | Message |")
    lines.append("|--------|--------|-----------|----------|---------|")

    for policy_name, result in sorted(policy_results.items()):
        status = "✅ PASSED" if result.passed else "❌ FAILED"
        violations = result.violation_count
        warnings = len(result.warnings)
        message = result.message.replace("|", "\\|")  # Escape pipes for markdown
        lines.append(
            f"| {policy_name} | {status} | {violations} | {warnings} | {message} |"
        )

    lines.append("")

    # Detailed violations by policy
    for policy_name, result in sorted(policy_results.items()):
        if not result.violations and not result.warnings:
            continue

        lines.append(f"## {policy_name}")
        lines.append("")

        if result.violations:
            lines.append(f"### Violations ({result.violation_count})")
            lines.append("")
            for i, violation in enumerate(result.violations, 1):
                lines.append(f"#### Violation {i}")
                lines.append("")
                lines.append("```json")
                lines.append(json.dumps(violation, indent=2))
                lines.append("```")
                lines.append("")

        if result.warnings:
            lines.append(f"### Warnings ({len(result.warnings)})")
            lines.append("")
            for warning in result.warnings:
                lines.append(f"- {warning}")
            lines.append("")

    # Write to file
    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Wrote policy report: {output_path}")


def write_policy_json(
    policy_results: Dict[str, PolicyResult], output_path: Path
) -> None:
    """
    Write policy evaluation results to JSON file.

    Args:
        policy_results: Dict mapping policy name to PolicyResult
        output_path: Path to output JSON file
    """
    if not policy_results:
        logger.info("No policy results to write")
        return

    data: Dict[str, Any] = {
        "schemaVersion": "1.0.0",
        "policies": [],
    }

    for policy_name, result in sorted(policy_results.items()):
        data["policies"].append(
            {
                "name": policy_name,
                "passed": result.passed,
                "violations": result.violations,
                "warnings": result.warnings,
                "message": result.message,
                "metadata": result.metadata,
            }
        )

    output_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    logger.info(f"Wrote policy JSON: {output_path}")


def write_policy_summary_md(
    policy_results: Dict[str, PolicyResult], output_path: Path
) -> None:
    """
    Write concise policy summary for inclusion in main SUMMARY.md.

    Args:
        policy_results: Dict mapping policy name to PolicyResult
        output_path: Path to output markdown file
    """
    if not policy_results:
        return

    lines = []
    lines.append("## Policy Evaluation")
    lines.append("")

    passed = sum(1 for r in policy_results.values() if r.passed)
    failed = len(policy_results) - passed
    total_violations = sum(r.violation_count for r in policy_results.values())

    if failed == 0:
        lines.append(f"✅ **All {len(policy_results)} policies passed** (0 violations)")
    else:
        lines.append(
            f"❌ **{failed}/{len(policy_results)} policies failed** ({total_violations} violations)"
        )

    lines.append("")
    lines.append("| Policy | Status | Violations |")
    lines.append("|--------|--------|-----------|")

    for policy_name, result in sorted(policy_results.items()):
        status = "✅" if result.passed else "❌"
        lines.append(f"| {policy_name} | {status} | {result.violation_count} |")

    lines.append("")
    lines.append("See [POLICY_REPORT.md](POLICY_REPORT.md) for details.")
    lines.append("")

    output_path.write_text("\n".join(lines), encoding="utf-8")
    logger.info(f"Wrote policy summary: {output_path}")
