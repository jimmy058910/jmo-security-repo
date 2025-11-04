#!/usr/bin/env python3
"""
Policy-as-Code Reporter for JMo Security.

Evaluates findings against Rego policies and generates policy reports.

Author: JMo Security
License: MIT
"""

import json
import logging
from pathlib import Path
from typing import Any, List, Dict, Optional

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
    lines.append(
        f"Evaluated {len(policy_results)} policies against security findings."
    )
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

    data = {
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
        lines.append(
            f"✅ **All {len(policy_results)} policies passed** (0 violations)"
        )
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
