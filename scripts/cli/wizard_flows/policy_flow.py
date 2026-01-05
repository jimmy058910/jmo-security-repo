#!/usr/bin/env python3
"""
Policy evaluation wizard flow for JMo Security.

Provides interactive policy selection, evaluation, and violation viewing.
Part of Phase 2.5: Wizard Policy Integration (v1.0.0).
"""

from __future__ import annotations

import json
import logging
import re
from pathlib import Path
from typing import Dict, List, Any, Tuple

from scripts.core.policy_engine import PolicyEngine, PolicyResult


# Patterns for sensitive data truncation (Fix 3.3 - Issue #12)
SENSITIVE_PATTERNS = [
    (
        r"-----BEGIN [A-Z ]+ KEY-----.*?-----END [A-Z ]+ KEY-----",
        "PRIVATE_KEY",
    ),
    (
        r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
        "CERTIFICATE",
    ),
    (
        r"[A-Za-z0-9+/]{60,}={0,2}",  # Long base64 (60+ chars)
        "BASE64_DATA",
    ),
]

logger = logging.getLogger(__name__)


def _normalize_policy_name(name: str) -> str:
    """Normalize policy name for fuzzy matching.

    Handles variations like:
    - "OWASP Top 10 2021 Enforcer" vs "owasp-top-10"
    - "Zero Secrets Policy" vs "zero-secrets"
    - "PCI-DSS 4.0 Compliance" vs "pci-dss"
    """
    return (
        name.lower().replace("-", "").replace("_", "").replace(" ", "").replace(".", "")
    )


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

    # Build normalized policy name → path mapping for fuzzy matching
    # Maps both metadata name and file stem (normalized) to path
    policy_map: Dict[str, Path] = {}
    for path, metadata in policies_with_metadata:
        # Add metadata name (normalized)
        meta_name = metadata.get("name", path.stem)
        policy_map[_normalize_policy_name(meta_name)] = path
        # Also add file stem (normalized) for direct matching
        policy_map[_normalize_policy_name(path.stem)] = path

    # Profile-based defaults (using canonical short names)
    profile_defaults = {
        "fast": ["zero-secrets"],
        "slim": ["zero-secrets", "owasp-top-10"],
        "balanced": ["owasp-top-10", "zero-secrets"],
        "deep": [path.stem for path, _ in policies_with_metadata],  # All policies
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

    # Convert policy names to paths using normalized matching
    seen_paths: set = set()  # Avoid duplicates
    for policy_name in default_policies:
        normalized = _normalize_policy_name(policy_name)
        if normalized in policy_map:
            path = policy_map[normalized]
            if path not in seen_paths:
                recommended.append(path)
                seen_paths.add(path)

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
    - Show all violations with pagination (Fix 3.6)
    - Consistent menu numbering (Fix 2.3)
    - Navigation between policies
    """
    failed_policies = {
        name: result for name, result in results.items() if not result.passed
    }

    if not failed_policies:
        print("\n All policies passed! No violations to display.")
        return

    policy_names = list(failed_policies.keys())
    current_index = 0

    while True:
        policy_name = policy_names[current_index]
        result = failed_policies[policy_name]

        print("\n" + "=" * 60)
        print(f"  Policy Violations: {policy_name}")
        print("=" * 60)
        print(f"\nStatus: FAILED ({result.violation_count} violations)")

        if result.message:
            print(f"Message: {result.message}")

        print("\nViolations:")
        for i, violation in enumerate(result.violations[:10], 1):  # Show first 10
            _display_violation(i, violation, policy_name)

        if result.violation_count > 10:
            print(f"\n... and {result.violation_count - 10} more violations")

        # Determine navigation availability
        has_next = current_index < len(policy_names) - 1
        has_prev = current_index > 0

        # Navigation menu with consistent numbering (Fix 2.3)
        print("\nActions:")
        print("  1. Export violations as JSON")
        print("  2. Export violations as Markdown")
        print("  3. Show all violations")  # Fix 3.6

        # Always show options 4 and 5 with disabled state (Fix 2.3)
        if has_next:
            print(f"  4. View next policy ({policy_names[current_index + 1]})")
        else:
            print("  4. (no more policies)")

        if has_prev:
            print(f"  5. View previous policy ({policy_names[current_index - 1]})")
        else:
            print("  5. (first policy)")

        print("  6. Exit policy viewer")  # Fix 2.4

        # Show valid choices
        valid_choices = ["1", "2", "3", "6"]
        if has_next:
            valid_choices.append("4")
        if has_prev:
            valid_choices.append("5")

        choice = input(f"\nChoice [{'/'.join(sorted(valid_choices))}]: ").strip()

        if choice == "1":
            _export_violations_json(policy_name, result)
        elif choice == "2":
            _export_violations_markdown(policy_name, result)
        elif choice == "3":
            _show_all_violations_paginated(result.violations, policy_name)  # Fix 3.6
        elif choice == "4":
            if has_next:
                current_index += 1
            else:
                print("No more policies to view.")
        elif choice == "5":
            if has_prev:
                current_index -= 1
            else:
                print("Already at first policy.")
        elif choice == "6":
            break
        else:
            print(f"Invalid choice: {choice}")


def _truncate_sensitive(text: str, max_visible: int = 20) -> str:
    """Truncate sensitive data in text for display (Fix 3.3 - Issue #12).

    Shows first/last characters with [REDACTED] in middle for security.

    Args:
        text: Text that may contain sensitive data
        max_visible: Number of characters to show at start/end

    Returns:
        Text with sensitive data redacted
    """
    for pattern, label in SENSITIVE_PATTERNS:

        def replacer(match: re.Match[str]) -> str:
            content: str = match.group(0)
            if len(content) <= max_visible * 2:
                return content
            return f"{content[:max_visible]}...[{label} REDACTED]...{content[-max_visible:]}"

        text = re.sub(pattern, replacer, text, flags=re.DOTALL)

    return text


def _extract_rule_id(finding_text: str, policy_type: str) -> str:
    """Extract rule ID from finding text based on policy type (Fix 3.5 - Issue #14).

    Args:
        finding_text: The finding message text
        policy_type: Policy type (owasp, pci-dss, cis, nist, etc.)

    Returns:
        Extracted rule ID or "Unknown"
    """
    policy_lower = policy_type.lower()

    if "pci" in policy_lower:
        # Extract PCI DSS rule like "6.2.4"
        match = re.search(r"PCI\s+DSS\s+(\d+(?:\.\d+)+)", finding_text, re.IGNORECASE)
        if match:
            return f"PCI-{match.group(1)}"

    if "cis" in policy_lower:
        # Extract CIS control number
        match = re.search(
            r"CIS\s+(?:Control\s+)?(\d+(?:\.\d+)*)", finding_text, re.IGNORECASE
        )
        if match:
            return f"CIS-{match.group(1)}"

    if "nist" in policy_lower:
        # Extract NIST control
        match = re.search(
            r"NIST\s+(?:SP\s+)?(\d+-\d+|\w{2}-\d+)", finding_text, re.IGNORECASE
        )
        if match:
            return f"NIST-{match.group(1)}"

    return "Unknown"


def _extract_severity_tag(finding_text: str) -> str:
    """Extract severity from finding text (Fix 3.7 - Issue #17).

    Args:
        finding_text: The finding message text

    Returns:
        Severity level or "security" fallback
    """
    finding_upper = finding_text.upper()

    severity_prefixes = ["CRITICAL:", "HIGH:", "MEDIUM:", "LOW:", "INFO:"]
    for prefix in severity_prefixes:
        if prefix in finding_upper:
            return prefix.rstrip(":")

    return "security"  # Fallback


def _display_violation(
    index: int, violation: Dict[str, Any], policy_type: str = ""
) -> None:
    """Display a single policy violation with formatting.

    Includes:
    - Sensitive data truncation (Fix 3.3 - Issue #12)
    - Empty location handling (Fix 3.4 - Issue #13)
    - Rule ID extraction (Fix 3.5 - Issue #14)
    - Severity tags (Fix 3.7 - Issue #17)

    Args:
        index: Violation number
        violation: Violation dictionary
        policy_type: Policy type for rule ID extraction
    """
    # Get category/tag
    category = violation.get("category", "Unknown")
    message = violation.get("message", "No message")

    # Try to extract better rule ID for policies without one (Fix 3.5)
    if category == "Unknown" and policy_type:
        extracted = _extract_rule_id(message, policy_type)
        if extracted != "Unknown":
            category = extracted

    # Handle production-hardening severity (Fix 3.7)
    if "hardening" in policy_type.lower():
        category = _extract_severity_tag(message)
        # Remove redundant severity prefix from message
        message = re.sub(
            r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO):\s*", "", message, flags=re.IGNORECASE
        )

    # Truncate sensitive data (Fix 3.3)
    message = _truncate_sensitive(message)

    # Truncate long messages
    if len(message) > 200:
        message = message[:200] + "..."

    print(f"\n  {index}. [{category}]")
    print(f"     Finding: {message}")

    if "finding_id" in violation:
        print(f"     ID: {violation['finding_id']}")

    if "severity" in violation:
        print(f"     Severity: {violation['severity']}")

    if "tool" in violation:
        print(f"     Tool: {violation['tool']}")

    # Handle empty location (Fix 3.4)
    path = violation.get("path", "")
    if path and path.strip():
        print(f"     Location: {path}")


def _show_all_violations_paginated(
    violations: List[Dict[str, Any]], policy_type: str = "", page_size: int = 20
) -> None:
    """Show all violations with pagination (Fix 3.6 - Issue #16).

    Args:
        violations: List of violation dictionaries
        policy_type: Policy type for rule ID extraction
        page_size: Number of violations per page
    """
    total = len(violations)
    if total == 0:
        print("\nNo violations to display.")
        return

    pages = (total + page_size - 1) // page_size  # Ceiling division
    current_page = 1

    while True:
        start = (current_page - 1) * page_size
        end = min(start + page_size, total)

        print(f"\n{'=' * 50}")
        print(f"  Violations (Page {current_page}/{pages})")
        print(f"{'=' * 50}\n")

        for i, violation in enumerate(violations[start:end], start + 1):
            _display_violation(i, violation, policy_type)

        print(f"\n[Page {current_page}/{pages}]")

        if pages == 1:
            input("Press Enter to continue...")
            break

        # Navigation options
        options = []
        if current_page > 1:
            options.append("p=prev")
        if current_page < pages:
            options.append("n=next")
        options.append("q=quit")

        choice = input(f"({', '.join(options)}): ").strip().lower()

        if choice == "n" and current_page < pages:
            current_page += 1
        elif choice == "p" and current_page > 1:
            current_page -= 1
        elif choice == "q":
            break
        else:
            print(f"Invalid choice: {choice}")


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
