#!/usr/bin/env python3
"""
Policy-as-Code CLI commands for JMo Security.

Provides policy management commands:
- jmo policy install <url>       Install policy from URL or local file
- jmo policy validate <policy>   Validate policy syntax and metadata
- jmo policy test <policy>       Test policy against sample data
- jmo policy list                List all installed policies
- jmo policy show <policy>       Show policy details

Author: JMo Security
License: MIT
"""

import argparse
import json
import logging
import shutil
import sys
from pathlib import Path
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse
from urllib.request import urlopen

from scripts.core.policy_engine import PolicyEngine, PolicyMetadata

logger = logging.getLogger(__name__)


class PolicyCommands:
    """Policy-as-Code CLI command handler."""

    def __init__(self):
        """Initialize policy commands."""
        self.policy_engine = PolicyEngine()
        self.builtin_dir = Path(__file__).parent.parent.parent / "policies" / "builtin"
        self.user_dir = Path.home() / ".jmo" / "policies"
        self.user_dir.mkdir(parents=True, exist_ok=True)

    def discover_policies(self) -> Dict[str, Path]:
        """
        Discover all available policies from builtin and user directories.

        Returns:
            Dict mapping policy name to policy file path
        """
        policies = {}

        # Builtin policies
        if self.builtin_dir.exists():
            for policy_file in self.builtin_dir.glob("*.rego"):
                policies[policy_file.stem] = policy_file

        # User policies (override builtin if duplicate)
        if self.user_dir.exists():
            for policy_file in self.user_dir.glob("*.rego"):
                policies[policy_file.stem] = policy_file

        return policies

    def cmd_install(self, args: argparse.Namespace) -> int:
        """
        Install policy from URL or local file.

        Args:
            args: Parsed CLI arguments with 'source' field

        Returns:
            Exit code (0 = success, 1 = error)
        """
        source = args.source

        # Determine if source is URL or local file
        parsed = urlparse(source)
        is_url = parsed.scheme in ("http", "https")

        try:
            if is_url:
                # Download from URL
                logger.info(f"Downloading policy from {source}")
                with urlopen(source, timeout=30) as response:
                    content = response.read().decode("utf-8")
                    filename = Path(parsed.path).name
                    if not filename.endswith(".rego"):
                        logger.error("Policy file must have .rego extension")
                        return 1
            else:
                # Load from local file
                source_path = Path(source).resolve()
                if not source_path.exists():
                    logger.error(f"Policy file not found: {source}")
                    return 1
                if not source_path.suffix == ".rego":
                    logger.error("Policy file must have .rego extension")
                    return 1
                content = source_path.read_text()
                filename = source_path.name

            # Validate policy before installing
            dest_path = self.user_dir / filename
            temp_path = dest_path.with_suffix(".rego.tmp")
            temp_path.write_text(content)

            try:
                is_valid, errors = self.policy_engine.validate_policy(temp_path)
                if not is_valid:
                    logger.error(f"Policy validation failed:\n{errors}")
                    temp_path.unlink()
                    return 1

                # Install policy
                shutil.move(str(temp_path), str(dest_path))
                logger.info(f"✅ Policy installed: {dest_path}")
                print(f"Policy installed to: {dest_path}")
                return 0

            except Exception as e:
                if temp_path.exists():
                    temp_path.unlink()
                raise e

        except Exception as e:
            logger.error(f"Failed to install policy: {e}")
            return 1

    def cmd_validate(self, args: argparse.Namespace) -> int:
        """
        Validate policy syntax and metadata.

        Args:
            args: Parsed CLI arguments with 'policy' field

        Returns:
            Exit code (0 = valid, 1 = invalid)
        """
        policies = self.discover_policies()
        policy_name = args.policy

        # Check if policy exists
        if policy_name not in policies:
            logger.error(f"Policy not found: {policy_name}")
            logger.info(f"Available policies: {', '.join(sorted(policies.keys()))}")
            return 1

        policy_path = policies[policy_name]

        try:
            is_valid, errors = self.policy_engine.validate_policy(policy_path)

            if is_valid:
                print(f"✅ Policy '{policy_name}' is valid")
                logger.info(f"Policy validated: {policy_path}")
                return 0
            else:
                print(f"❌ Policy '{policy_name}' validation failed:")
                print(errors)
                return 1

        except Exception as e:
            logger.error(f"Validation error: {e}")
            return 1

    def cmd_test(self, args: argparse.Namespace) -> int:
        """
        Test policy against sample data or provided input.

        Args:
            args: Parsed CLI arguments with 'policy', 'input', 'dry_run' fields

        Returns:
            Exit code (0 = success, 1 = error)
        """
        policies = self.discover_policies()
        policy_name = args.policy

        # Check if policy exists
        if policy_name not in policies:
            logger.error(f"Policy not found: {policy_name}")
            logger.info(f"Available policies: {', '.join(sorted(policies.keys()))}")
            return 1

        policy_path = policies[policy_name]

        try:
            # Load input data
            if args.input:
                input_path = Path(args.input)
                if not input_path.exists():
                    logger.error(f"Input file not found: {args.input}")
                    return 1
                with open(input_path) as f:
                    input_data = json.load(f)
            else:
                # Use sample data
                logger.info("No input provided, using sample data")
                input_data = {
                    "findings": [
                        {
                            "id": "sample-001",
                            "ruleId": "test-rule",
                            "severity": "HIGH",
                            "message": "Sample finding for testing",
                            "tool": {"name": "test-tool", "version": "1.0.0"},
                            "location": {
                                "path": "test.py",
                                "startLine": 10,
                                "endLine": 10,
                            },
                            "compliance": {
                                "owaspTop10_2021": ["A01:2021"],
                            },
                        }
                    ]
                }

            # Dry-run mode: validate input and policy, don't evaluate
            if args.dry_run:
                is_valid, errors = self.policy_engine.validate_policy(policy_path)
                if not is_valid:
                    print(f"❌ Policy validation failed:\n{errors}")
                    return 1

                print(f"✅ Dry-run successful for policy '{policy_name}'")
                print(f"Policy: {policy_path}")
                print(f"Input findings: {len(input_data.get('findings', []))}")
                return 0

            # Actual test execution
            findings = input_data.get("findings", [])
            result = self.policy_engine.evaluate(findings, policy_path, input_data)

            # Display results
            print(f"\n{'='*60}")
            print(f"Policy: {policy_name}")
            print(f"{'='*60}")
            print(f"Status: {'✅ PASSED' if result.passed else '❌ FAILED'}")
            print(f"Message: {result.message}")
            print(f"Violations: {result.violation_count}")
            if result.warnings:
                print(f"Warnings: {len(result.warnings)}")

            if result.violations:
                print(f"\n{'Violations':-^60}")
                for i, violation in enumerate(result.violations, 1):
                    print(f"\n{i}. {json.dumps(violation, indent=2)}")

            if result.warnings:
                print(f"\n{'Warnings':-^60}")
                for warning in result.warnings:
                    print(f"  ⚠️  {warning}")

            print(f"{'='*60}\n")

            return 0 if result.passed else 1

        except Exception as e:
            logger.error(f"Policy test failed: {e}", exc_info=True)
            return 1

    def cmd_list(self, args: argparse.Namespace) -> int:
        """
        List all installed policies with metadata.

        Args:
            args: Parsed CLI arguments (unused)

        Returns:
            Exit code (0 = success)
        """
        policies = self.discover_policies()

        if not policies:
            print("No policies installed.")
            print(f"Install policies to: {self.user_dir}")
            return 0

        print(f"\n{'Available Policies':-^60}")
        print(f"{'Name':<25} {'Source':<15} {'Status':<10}")
        print("-" * 60)

        for name in sorted(policies.keys()):
            policy_path = policies[name]
            is_builtin = policy_path.parent == self.builtin_dir

            # Validate policy
            try:
                is_valid, _ = self.policy_engine.validate_policy(policy_path)
                status = "✅ Valid" if is_valid else "❌ Invalid"
            except Exception:
                status = "❌ Error"

            source = "builtin" if is_builtin else "user"
            print(f"{name:<25} {source:<15} {status:<10}")

        print(f"\nTotal policies: {len(policies)}")
        print(f"Builtin directory: {self.builtin_dir}")
        print(f"User directory: {self.user_dir}\n")

        return 0

    def cmd_show(self, args: argparse.Namespace) -> int:
        """
        Show detailed policy information including metadata.

        Args:
            args: Parsed CLI arguments with 'policy' field

        Returns:
            Exit code (0 = success, 1 = not found)
        """
        policies = self.discover_policies()
        policy_name = args.policy

        # Check if policy exists
        if policy_name not in policies:
            logger.error(f"Policy not found: {policy_name}")
            logger.info(f"Available policies: {', '.join(sorted(policies.keys()))}")
            return 1

        policy_path = policies[policy_name]
        is_builtin = policy_path.parent == self.builtin_dir

        try:
            # Read policy file
            content = policy_path.read_text()

            # Extract metadata
            metadata = self.policy_engine.get_metadata(policy_path)

            # Display policy details
            print(f"\n{'='*60}")
            print(f"Policy: {policy_name}")
            print(f"{'='*60}")
            print(f"Path: {policy_path}")
            print(f"Source: {'builtin' if is_builtin else 'user'}")
            print(f"Size: {len(content)} bytes")

            if metadata:
                print(f"\n{'Metadata':-^60}")
                for key, value in metadata.items():
                    if isinstance(value, list):
                        print(f"{key}: {', '.join(value)}")
                    else:
                        print(f"{key}: {value}")

            # Validate policy
            is_valid, errors = self.policy_engine.validate_policy(policy_path)
            print(f"\n{'Validation':-^60}")
            if is_valid:
                print("✅ Policy is valid")
            else:
                print("❌ Policy validation failed:")
                print(errors)

            # Show policy content preview
            print(f"\n{'Policy Content (first 20 lines)':-^60}")
            all_lines = content.split("\n")
            lines = all_lines[:20]
            for i, line in enumerate(lines, 1):
                print(f"{i:3d} | {line}")
            if len(all_lines) > 20:
                remaining = len(all_lines) - 20
                print(f"... ({remaining} more lines)")

            print(f"{'='*60}\n")

            return 0

        except Exception as e:
            logger.error(f"Failed to show policy: {e}")
            return 1


def add_policy_subparser(subparsers) -> None:
    """
    Add policy subcommand to argparse parser.

    Args:
        subparsers: Argparse subparsers object
    """
    policy_parser = subparsers.add_parser(
        "policy",
        help="Policy-as-Code management commands",
        description="Manage JMo Security policies (install, validate, test, list, show)",
    )

    policy_subparsers = policy_parser.add_subparsers(
        dest="policy_command",
        required=True,
        help="Policy subcommand",
    )

    # jmo policy install
    install_parser = policy_subparsers.add_parser(
        "install",
        help="Install policy from URL or local file",
    )
    install_parser.add_argument(
        "source",
        help="Policy URL or local file path (.rego)",
    )

    # jmo policy validate
    validate_parser = policy_subparsers.add_parser(
        "validate",
        help="Validate policy syntax and metadata",
    )
    validate_parser.add_argument(
        "policy",
        help="Policy name (without .rego extension)",
    )

    # jmo policy test
    test_parser = policy_subparsers.add_parser(
        "test",
        help="Test policy against sample data or provided input",
    )
    test_parser.add_argument(
        "policy",
        help="Policy name (without .rego extension)",
    )
    test_parser.add_argument(
        "-i",
        "--input",
        help="Input JSON file with findings (uses sample data if not provided)",
    )
    test_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Validate policy and input without executing evaluation",
    )

    # jmo policy list
    policy_subparsers.add_parser(
        "list",
        help="List all installed policies",
    )

    # jmo policy show
    show_parser = policy_subparsers.add_parser(
        "show",
        help="Show detailed policy information",
    )
    show_parser.add_argument(
        "policy",
        help="Policy name (without .rego extension)",
    )


def handle_policy_command(args: argparse.Namespace) -> int:
    """
    Route policy subcommands to appropriate handlers.

    Args:
        args: Parsed CLI arguments

    Returns:
        Exit code from command handler
    """
    commands = PolicyCommands()

    command_map = {
        "install": commands.cmd_install,
        "validate": commands.cmd_validate,
        "test": commands.cmd_test,
        "list": commands.cmd_list,
        "show": commands.cmd_show,
    }

    handler = command_map.get(args.policy_command)
    if handler:
        return handler(args)
    else:
        logger.error(f"Unknown policy command: {args.policy_command}")
        return 1
