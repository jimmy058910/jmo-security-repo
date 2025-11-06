#!/usr/bin/env python3
"""
Policy-as-Code CLI commands for JMo Security.

Provides jmo policy * commands for managing OPA policies:
- jmo policy list - List all available policies
- jmo policy validate <policy> - Validate policy syntax
- jmo policy test <policy> - Test policy with findings
- jmo policy show <policy> - Display policy metadata
- jmo policy install <policy> - Install policy to user directory

Author: JMo Security
License: MIT
"""

from __future__ import annotations

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional, cast

from scripts.core.policy_engine import PolicyEngine

logger = logging.getLogger(__name__)


def get_builtin_policies_dir() -> Path:
    """Get builtin policies directory."""
    # From project root: policies/builtin/
    project_root = Path(__file__).parent.parent.parent
    return project_root / "policies" / "builtin"


def get_user_policies_dir() -> Path:
    """Get user policies directory."""
    return Path.home() / ".jmo" / "policies"


def discover_policies() -> dict[str, Path]:
    """Discover all available policies (builtin + user).

    Returns:
        Dict mapping policy name to policy path
    """
    policies = {}

    # Builtin policies
    builtin_dir = get_builtin_policies_dir()
    if builtin_dir.exists():
        for policy_file in builtin_dir.glob("*.rego"):
            policies[policy_file.stem] = policy_file

    # User policies (override builtin with same name)
    user_dir = get_user_policies_dir()
    if user_dir.exists():
        for policy_file in user_dir.glob("*.rego"):
            policies[policy_file.stem] = policy_file

    return policies


def cmd_policy_list(args: argparse.Namespace) -> int:
    """List all available policies.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code (0 = success, 1 = error)
    """
    builtin_dir = get_builtin_policies_dir()
    user_dir = get_user_policies_dir()

    engine = PolicyEngine()

    # Discover builtin policies
    builtin_policies = []
    if builtin_dir.exists():
        for policy_file in sorted(builtin_dir.glob("*.rego")):
            metadata = engine.get_metadata(policy_file)
            builtin_policies.append({
                "name": policy_file.stem,
                "path": policy_file,
                "metadata": metadata,
                "source": "builtin"
            })

    # Discover user policies
    user_policies = []
    if user_dir.exists():
        for policy_file in sorted(user_dir.glob("*.rego")):
            metadata = engine.get_metadata(policy_file)
            user_policies.append({
                "name": policy_file.stem,
                "path": policy_file,
                "metadata": metadata,
                "source": "user"
            })

    # Display results
    if not builtin_policies and not user_policies:
        print("No policies found.")
        print(f"\nBuiltin directory: {builtin_dir}")
        print(f"User directory: {user_dir}")
        return 0

    # Builtin policies
    if builtin_policies:
        print(f"Built-in Policies ({len(builtin_policies)}):")
        print("=" * 80)
        for policy_obj in builtin_policies:
            policy = cast(Dict[str, Any], policy_obj)
            meta = cast(Dict[str, Any], policy["metadata"])
            policy_name = str(policy["name"])
            version = meta.get("version", "unknown")
            desc = meta.get("description", "No description")
            print(f"  {policy_name:25s} v{version:10s} {desc}")
        print()

    # User policies
    if user_policies:
        print(f"User Policies ({len(user_policies)}):")
        print("=" * 80)
        for policy_obj in user_policies:
            policy = cast(Dict[str, Any], policy_obj)
            meta = cast(Dict[str, Any], policy["metadata"])
            policy_name = str(policy["name"])
            version = meta.get("version", "unknown")
            desc = meta.get("description", "No description")
            print(f"  {policy_name:25s} v{version:10s} {desc}")
        print()

    print(f"Total: {len(builtin_policies) + len(user_policies)} policies")
    return 0


def cmd_policy_validate(args: argparse.Namespace) -> int:
    """Validate policy syntax.

    Args:
        args: Parsed command-line arguments (requires args.policy)

    Returns:
        Exit code (0 = valid, 1 = invalid)
    """
    policy_name = args.policy

    # Find policy
    policies = discover_policies()
    if policy_name not in policies:
        logger.error(f"Policy not found: {policy_name}")
        logger.info(f"Available policies: {', '.join(sorted(policies.keys()))}")
        return 1

    policy_path = policies[policy_name]

    # Validate
    engine = PolicyEngine()
    is_valid, error = engine.validate_policy(policy_path)

    if is_valid:
        print(f"✅ Policy '{policy_name}' is valid")
        print(f"   Path: {policy_path}")
        return 0
    else:
        print(f"❌ Policy '{policy_name}' is invalid")
        print(f"   Path: {policy_path}")
        print(f"\nError:\n{error}")
        return 1


def cmd_policy_test(args: argparse.Namespace) -> int:
    """Test policy with findings file.

    Args:
        args: Parsed command-line arguments (requires args.policy, args.findings_file)

    Returns:
        Exit code (0 = passed, 1 = failed/error)
    """
    policy_name = args.policy
    findings_file = Path(args.findings_file)

    # Validate findings file
    if not findings_file.exists():
        logger.error(f"Findings file not found: {findings_file}")
        return 1

    # Find policy
    policies = discover_policies()
    if policy_name not in policies:
        logger.error(f"Policy not found: {policy_name}")
        logger.info(f"Available policies: {', '.join(sorted(policies.keys()))}")
        return 1

    policy_path = policies[policy_name]

    # Test policy
    engine = PolicyEngine()

    try:
        result = engine.test_policy(policy_path, findings_file)

        # Display results
        print(f"Policy Test: {policy_name}")
        print("=" * 80)
        print(f"Policy: {policy_path}")
        print(f"Findings: {findings_file}")
        print()

        if result.passed:
            print("✅ PASSED")
        else:
            print("❌ FAILED")

        print()
        print(f"Message: {result.message}")
        print(f"Violations: {result.violation_count}")
        print(f"Warnings: {len(result.warnings)}")

        if result.violations:
            print("\nViolations:")
            for i, violation in enumerate(result.violations, 1):
                print(f"  {i}. {json.dumps(violation, indent=4)}")

        if result.warnings:
            print("\nWarnings:")
            for warning in result.warnings:
                print(f"  - {warning}")

        return 0 if result.passed else 1

    except Exception as e:
        logger.error(f"Policy test failed: {e}")
        return 1


def cmd_policy_show(args: argparse.Namespace) -> int:
    """Display policy metadata.

    Args:
        args: Parsed command-line arguments (requires args.policy)

    Returns:
        Exit code (0 = success, 1 = error)
    """
    policy_name = args.policy

    # Find policy
    policies = discover_policies()
    if policy_name not in policies:
        logger.error(f"Policy not found: {policy_name}")
        logger.info(f"Available policies: {', '.join(sorted(policies.keys()))}")
        return 1

    policy_path = policies[policy_name]

    # Get metadata
    engine = PolicyEngine()
    metadata = engine.get_metadata(policy_path)

    # Display
    print(f"Policy: {policy_name}")
    print("=" * 80)
    print(f"Path: {policy_path}")
    print(f"Source: {'builtin' if get_builtin_policies_dir() in policy_path.parents else 'user'}")
    print()

    if metadata:
        print("Metadata:")
        for key, value in sorted(metadata.items()):
            if isinstance(value, list):
                print(f"  {key}: {', '.join(value)}")
            else:
                print(f"  {key}: {value}")
    else:
        print("No metadata found in policy")

    # Show first 20 lines of policy
    print("\nPolicy Content (first 20 lines):")
    print("-" * 80)
    lines = policy_path.read_text().split("\n")
    for line in lines[:20]:
        print(line)
    if len(lines) > 20:
        print(f"... ({len(lines) - 20} more lines)")

    return 0


def cmd_policy_install(args: argparse.Namespace) -> int:
    """Install policy to user directory.

    Args:
        args: Parsed command-line arguments (requires args.policy)

    Returns:
        Exit code (0 = success, 1 = error)
    """
    policy_name = args.policy

    # Find builtin policy
    builtin_dir = get_builtin_policies_dir()
    policy_path = builtin_dir / f"{policy_name}.rego"

    if not policy_path.exists():
        logger.error(f"Builtin policy not found: {policy_name}")

        # List available builtin policies
        available = [p.stem for p in builtin_dir.glob("*.rego")] if builtin_dir.exists() else []
        if available:
            logger.info(f"Available builtin policies: {', '.join(sorted(available))}")

        return 1

    # Create user directory if needed
    user_dir = get_user_policies_dir()
    user_dir.mkdir(parents=True, exist_ok=True)

    # Check if already installed
    user_policy_path = user_dir / f"{policy_name}.rego"
    if user_policy_path.exists():
        if not args.force:
            logger.warning(f"Policy '{policy_name}' already installed at: {user_policy_path}")
            logger.info("Use --force to overwrite")
            return 1
        else:
            logger.info(f"Overwriting existing policy: {user_policy_path}")

    # Copy policy
    shutil.copy2(policy_path, user_policy_path)

    print(f"✅ Installed policy '{policy_name}' to: {user_policy_path}")
    print(f"\nYou can now customize the policy and use it with:")
    print(f"  jmo report --policy {policy_name}")

    return 0


def cmd_policy(args: argparse.Namespace) -> int:
    """Main entry point for jmo policy commands.

    Args:
        args: Parsed command-line arguments

    Returns:
        Exit code from subcommand
    """
    # Dispatch to subcommand
    if args.policy_command == "list":
        return cmd_policy_list(args)
    elif args.policy_command == "validate":
        return cmd_policy_validate(args)
    elif args.policy_command == "test":
        return cmd_policy_test(args)
    elif args.policy_command == "show":
        return cmd_policy_show(args)
    elif args.policy_command == "install":
        return cmd_policy_install(args)
    else:
        logger.error(f"Unknown policy command: {args.policy_command}")
        return 1
