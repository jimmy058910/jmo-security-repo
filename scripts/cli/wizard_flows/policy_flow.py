#!/usr/bin/env python3
"""
Policy evaluation wizard flow for JMo Security.

Provides interactive policy selection, evaluation, and violation viewing.
Part of Phase 2.5: Wizard Policy Integration (v1.0.0).
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Tuple

from scripts.core.policy_engine import PolicyEngine, PolicyResult

logger = logging.getLogger(__name__)


def policy_evaluation_menu(
    results_dir: Path,
    profile: str,
    findings: List[Dict[str, Any]],
    non_interactive: bool = False,
) -> Dict[str, PolicyResult]:
    """
    Present policy evaluation menu and evaluate selected policies.

    Args:
        results_dir: Path to scan results directory
        profile: Scan profile name (fast/balanced/deep)
        findings: List of CommonFinding dictionaries
        non_interactive: Skip prompts and use profile defaults

    Returns:
        Dictionary mapping policy names to PolicyResult objects
    """
    print("\n" + "═" * 60)
    print("  📋 Security Policy Evaluation")
    print("═" * 60)

    # Check OPA availability
    try:
        engine = PolicyEngine()
    except RuntimeError as e:
        logger.warning(f"OPA unavailable: {e}")
        print(f"\n⚠️  Policy evaluation unavailable: {e}")
        print("Install OPA: make tools")
        return {}

    # Discover built-in policies
    builtin_dir = Path(__file__).parent.parent.parent.parent / "policies" / "builtin"
    builtin_policies = list(builtin_dir.glob("*.rego"))

    if not builtin_policies:
        print("\n⚠️  No built-in policies found. Skipping policy evaluation.")
        return {}

    # Load policy metadata
    policies_with_metadata: List[Tuple[Path, Dict[str, Any]]] = []
    for policy_path in builtin_policies:
        try:
            metadata = engine.get_metadata(policy_path)
            policies_with_metadata.append((policy_path, metadata))
        except Exception as e:
            logger.debug(f"Failed to load metadata for {policy_path.name}: {e}")
            # Use fallback metadata
            metadata_dict: Dict[str, Any] = {
                "name": policy_path.stem,
                "version": "1.0.0",
                "description": f"Policy: {policy_path.stem}",
            }
            policies_with_metadata.append((policy_path, metadata_dict))

    # Auto-detect recommended policies
    recommended = _detect_recommended_policies(
        findings, profile, policies_with_metadata
    )

    # Display scan summary
    _display_scan_summary(findings)

    # Display policy menu
    print(f"\nRecommended policies for '{profile}' profile:")
    for i, (policy_path, metadata) in enumerate(policies_with_metadata, 1):
        is_recommended = policy_path in recommended
        marker = "✨" if is_recommended else "  "
        tag = " (RECOMMENDED)" if is_recommended else ""
        print(
            f"  {i}. {marker} {metadata.get('name', policy_path.stem):22} {metadata.get('description', '')}{tag}"
        )

    print("\nOther options:")
    print(f"  a. Select all recommended ({len(recommended)} policies)")
    print(f"  r. Select all policies ({len(builtin_policies)} policies)")
    print("  s. Skip policy evaluation")
    print("  c. Custom selection (enter numbers: 1,3,5)")

    # Get user choice
    if non_interactive:
        selected_policies = recommended
        print(f"\n[Non-interactive mode] Using {len(recommended)} recommended policies")
    else:
        choice = input("\nEnter choice [a/r/s/c/1-5]: ").strip().lower()
        selected_policies = _parse_policy_choice(
            choice, policies_with_metadata, recommended
        )

    if not selected_policies:
        print("Skipping policy evaluation.")
        return {}

    # Evaluate selected policies
    print(f"\n🔍 Evaluating {len(selected_policies)} policies...")

    results = {}
    for policy_path in selected_policies:
        policy_name = policy_path.stem
        try:
            result = engine.evaluate(findings, policy_path)
            results[policy_name] = result

            if result.passed:
                print(f"  ✅ {policy_name:25} PASSED")
            else:
                violations_text = f"{result.violation_count} violations"
                print(f"  ❌ {policy_name:25} FAILED ({violations_text})")
        except Exception as e:
            logger.error(f"Policy evaluation failed for {policy_name}: {e}")
            print(f"  ⚠️  {policy_name:25} ERROR: {e}")

    # Summary
    passed = sum(1 for r in results.values() if r.passed)
    failed = len(results) - passed
    print(
        f"\n📊 Policy Evaluation Summary: {passed}/{len(results)} passed, {failed} failed"
    )

    # Offer interactive violation viewer
    if failed > 0 and not non_interactive:
        view_violations = input("\nView policy violations? [Y/n]: ").strip().lower()
        if view_violations in ("y", "yes", ""):
            display_policy_violations_interactive(results)

    return results


def _detect_recommended_policies(
    findings: List[Dict[str, Any]],
    profile: str,
    policies_with_metadata: List[Tuple[Path, Dict[str, Any]]],
) -> List[Path]:
    """
    Auto-detect recommended policies based on scan findings and profile.

    Detection Logic:
    - If verified secrets found → recommend zero-secrets
    - If OWASP violations found → recommend owasp-top-10
    - If profile=deep → recommend all policies
    - If profile=balanced → recommend owasp-top-10 + zero-secrets
    - If profile=fast → recommend zero-secrets only

    Args:
        findings: List of CommonFinding dictionaries
        profile: Scan profile name
        policies_with_metadata: List of (policy_path, metadata) tuples

    Returns:
        List of recommended policy paths
    """
    recommended = []

    # Build policy name → path mapping
    policy_map = {
        metadata.get("name", path.stem): path
        for path, metadata in policies_with_metadata
    }

    # Profile-based defaults
    profile_defaults = {
        "fast": ["zero-secrets"],
        "balanced": ["owasp-top-10", "zero-secrets"],
        "deep": [
            metadata.get("name", path.stem) for path, metadata in policies_with_metadata
        ],
    }

    default_policies = profile_defaults.get(profile, ["zero-secrets"])

    # Scan findings-based recommendations
    has_verified_secrets = any(
        f.get("tool", {}).get("name") == "trufflehog" and f.get("verified") is True
        for f in findings
    )
    has_owasp_violations = any(
        f.get("compliance", {}).get("owaspTop10_2021") for f in findings
    )
    has_pci_violations = any(f.get("compliance", {}).get("pciDss4_0") for f in findings)

    # Add findings-based recommendations
    if has_verified_secrets and "zero-secrets" not in default_policies:
        default_policies.append("zero-secrets")

    if has_owasp_violations and "owasp-top-10" not in default_policies:
        default_policies.append("owasp-top-10")

    if has_pci_violations and "pci-dss" not in default_policies:
        default_policies.append("pci-dss")

    # Convert policy names to paths
    for policy_name in default_policies:
        if policy_name in policy_map:
            recommended.append(policy_map[policy_name])

    return recommended


def _display_scan_summary(findings: List[Dict[str, Any]]) -> None:
    """Display brief scan summary for policy context."""
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    verified_secrets = 0
    owasp_findings = 0

    for finding in findings:
        severity = finding.get("severity", "INFO")
        severity_counts[severity] = severity_counts.get(severity, 0) + 1

        if (
            finding.get("tool", {}).get("name") == "trufflehog"
            and finding.get("verified") is True
        ):
            verified_secrets += 1

        if finding.get("compliance", {}).get("owaspTop10_2021"):
            owasp_findings += 1

    print("\nYour scan found:")
    if severity_counts["CRITICAL"] > 0:
        print(f"  • {severity_counts['CRITICAL']} CRITICAL findings")
    if severity_counts["HIGH"] > 0:
        print(f"  • {severity_counts['HIGH']} HIGH findings")
    if verified_secrets > 0:
        print(f"  • {verified_secrets} verified secrets (TruffleHog)")
    if owasp_findings > 0:
        print(f"  • {owasp_findings} OWASP Top 10 vulnerabilities")


def _parse_policy_choice(
    choice: str,
    policies_with_metadata: List[Tuple[Path, Dict[str, Any]]],
    recommended: List[Path],
) -> List[Path]:
    """Parse user policy selection choice."""
    if choice == "s":
        return []
    elif choice == "a":
        return recommended
    elif choice == "r":
        return [path for path, _ in policies_with_metadata]
    elif choice == "c":
        numbers_input = input("Enter policy numbers (comma-separated, e.g. 1,3,5): ")
        indices = [int(x.strip()) - 1 for x in numbers_input.split(",") if x.strip()]
        return [
            policies_with_metadata[i][0]
            for i in indices
            if 0 <= i < len(policies_with_metadata)
        ]
    elif choice.isdigit():
        index = int(choice) - 1
        if 0 <= index < len(policies_with_metadata):
            return [policies_with_metadata[index][0]]
        else:
            print(f"Invalid choice: {choice}")
            return []
    else:
        print(f"Invalid choice: {choice}. Skipping policy evaluation.")
        return []


def display_policy_violations_interactive(results: Dict[str, PolicyResult]) -> None:
    """
    Display interactive policy violation viewer.

    Features:
    - Paginated violation display
    - Export options (JSON, Markdown)
    - Finding details with compliance mappings
    - Navigation between policies
    """
    failed_policies = {
        name: result for name, result in results.items() if not result.passed
    }

    if not failed_policies:
        print("\n✅ All policies passed! No violations to display.")
        return

    policy_names = list(failed_policies.keys())
    current_index = 0

    while True:
        policy_name = policy_names[current_index]
        result = failed_policies[policy_name]

        print("\n" + "═" * 60)
        print(f"  📋 Policy Violations: {policy_name}")
        print("═" * 60)
        print(f"\nStatus: ❌ FAILED ({result.violation_count} violations)")

        if result.message:
            print(f"Message: {result.message}")

        print("\nViolations:")
        for i, violation in enumerate(result.violations[:10], 1):  # Show first 10
            _display_violation(i, violation)

        if result.violation_count > 10:
            print(f"\n... and {result.violation_count - 10} more violations")

        # Navigation menu
        print("\nActions:")
        print("  1. Export violations as JSON")
        print("  2. Export violations as Markdown")
        if current_index < len(policy_names) - 1:
            print(f"  3. View next policy ({policy_names[current_index + 1]})")
        if current_index > 0:
            print(f"  4. View previous policy ({policy_names[current_index - 1]})")
        print("  5. ← Back to main menu")

        choice = input("\nEnter choice (1-5): ").strip()

        if choice == "1":
            _export_violations_json(policy_name, result)
        elif choice == "2":
            _export_violations_markdown(policy_name, result)
        elif choice == "3" and current_index < len(policy_names) - 1:
            current_index += 1
        elif choice == "4" and current_index > 0:
            current_index -= 1
        elif choice == "5":
            break
        else:
            print(f"Invalid choice: {choice}")


def _display_violation(index: int, violation: Dict[str, Any]) -> None:
    """Display a single policy violation with formatting."""
    print(f"\n  {index}. [{violation.get('category', 'Unknown')}]")
    print(f"     Finding: {violation.get('message', 'No message')}")

    if "finding_id" in violation:
        print(f"     ID: {violation['finding_id']}")

    if "severity" in violation:
        print(f"     Severity: {violation['severity']}")

    if "tool" in violation:
        print(f"     Tool: {violation['tool']}")

    if "path" in violation:
        print(f"     Location: {violation['path']}")


def _export_violations_json(policy_name: str, result: PolicyResult) -> None:
    """Export policy violations to JSON file."""
    output_file = Path(f"policy_violations_{policy_name}.json")
    with open(output_file, "w") as f:
        json.dump(
            {
                "policy": policy_name,
                "passed": result.passed,
                "violation_count": result.violation_count,
                "violations": result.violations,
                "warnings": result.warnings,
                "message": result.message,
            },
            f,
            indent=2,
        )
    print(f"\n✅ Violations exported to: {output_file}")


def _export_violations_markdown(policy_name: str, result: PolicyResult) -> None:
    """Export policy violations to Markdown file."""
    output_file = Path(f"policy_violations_{policy_name}.md")
    with open(output_file, "w") as f:
        f.write(f"# Policy Violations: {policy_name}\n\n")
        f.write(f"**Status:** {'✅ PASSED' if result.passed else '❌ FAILED'}\n")
        f.write(f"**Violations:** {result.violation_count}\n\n")

        if result.message:
            f.write(f"**Message:** {result.message}\n\n")

        f.write("## Violations\n\n")
        for i, violation in enumerate(result.violations, 1):
            f.write(f"### {i}. {violation.get('category', 'Unknown')}\n\n")
            f.write(f"- **Message:** {violation.get('message', 'No message')}\n")
            if "severity" in violation:
                f.write(f"- **Severity:** {violation['severity']}\n")
            if "tool" in violation:
                f.write(f"- **Tool:** {violation['tool']}\n")
            if "path" in violation:
                f.write(f"- **Location:** {violation['path']}\n")
            f.write("\n")

    print(f"\n✅ Violations exported to: {output_file}")
