#!/usr/bin/env python3
"""
Generate golden test fixtures by running real security tools.

Golden tests verify that adapters produce EXPECTED findings from KNOWN tool outputs.
This catches silent failures when security tools change their output format.

Usage:
    # Generate for all configured tools
    python scripts/dev/generate_golden.py --all

    # Generate for specific tool
    python scripts/dev/generate_golden.py --tool trivy

    # Update existing golden files (when tool version changes)
    python scripts/dev/generate_golden.py --tool trivy --update

    # Check if golden files exist for current tool versions
    python scripts/dev/generate_golden.py --check-current-versions

    # Run in Docker container (recommended for consistency)
    python scripts/dev/generate_golden.py --all --docker

Directory Structure Created:
    tests/fixtures/golden/
    ├── trivy/
    │   └── v0.67.2/
    │       ├── raw-output.json       # Raw tool output
    │       ├── expected-findings.json # Parsed adapter output
    │       └── metadata.json          # Tool version, timestamp, sample used
    ├── bandit/
    │   └── v1.9.2/
    │       └── ...
    └── ...

Requirements:
    - Security tools must be installed (or use --docker flag)
    - Sample fixtures must exist in tests/fixtures/samples/
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import subprocess
import sys
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
VERSIONS_FILE = PROJECT_ROOT / "versions.yaml"
SAMPLES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "samples"
GOLDEN_DIR = PROJECT_ROOT / "tests" / "fixtures" / "golden"


@dataclass
class ToolConfig:
    """Configuration for a security tool's golden test generation."""

    name: str
    version: str
    command: list[str]
    sample_dir: str
    output_file: str
    adapter_module: str
    adapter_class: str
    requires_docker: bool = False
    docker_image: str | None = None


# Tool configurations for golden test generation
# Maps tool name to configuration for running and parsing
TOOL_CONFIGS: dict[str, dict[str, Any]] = {
    "trivy": {
        "sample_dir": "python-vulnerable",
        "output_file": "trivy.json",
        "command": [
            "trivy",
            "fs",
            "--format",
            "json",
            "--output",
            "{output}",
            "{sample}",
        ],
        "adapter_module": "scripts.core.adapters.trivy_adapter",
        "adapter_class": "TrivyAdapter",
    },
    "bandit": {
        "sample_dir": "python-vulnerable",
        "output_file": "bandit.json",
        "command": [
            "bandit",
            "-r",
            "-f",
            "json",
            "-o",
            "{output}",
            "{sample}",
        ],
        "adapter_module": "scripts.core.adapters.bandit_adapter",
        "adapter_class": "BanditAdapter",
    },
    "semgrep": {
        "sample_dir": "python-vulnerable",
        "output_file": "semgrep.json",
        "command": [
            "semgrep",
            "--config",
            "auto",
            "--json",
            "--output",
            "{output}",
            "{sample}",
        ],
        "adapter_module": "scripts.core.adapters.semgrep_adapter",
        "adapter_class": "SemgrepAdapter",
    },
    "hadolint": {
        "sample_dir": "dockerfile-issues",
        "output_file": "hadolint.json",
        "command": [
            "hadolint",
            "--format",
            "json",
            "{sample}/Dockerfile",
        ],
        "adapter_module": "scripts.core.adapters.hadolint_adapter",
        "adapter_class": "HadolintAdapter",
    },
    "checkov": {
        "sample_dir": "terraform-misconfig",
        "output_file": "checkov.json",
        "command": [
            "checkov",
            "-d",
            "{sample}",
            "--output",
            "json",
            "--output-file-path",
            "{output_dir}",
        ],
        "adapter_module": "scripts.core.adapters.checkov_adapter",
        "adapter_class": "CheckovAdapter",
    },
    "trufflehog": {
        "sample_dir": "secrets-exposed",
        "output_file": "trufflehog.json",
        "command": [
            "trufflehog",
            "filesystem",
            "{sample}",
            "--json",
        ],
        "adapter_module": "scripts.core.adapters.trufflehog_adapter",
        "adapter_class": "TruffleHogAdapter",
    },
    "shellcheck": {
        "sample_dir": "shell-issues",
        "output_file": "shellcheck.json",
        "command": [
            "shellcheck",
            "--format=json",
            "{sample}/vulnerable_script.sh",
        ],
        "adapter_module": "scripts.core.adapters.shellcheck_adapter",
        "adapter_class": "ShellCheckAdapter",
    },
}


def load_versions() -> dict[str, Any]:
    """Load tool versions from versions.yaml."""
    if not VERSIONS_FILE.exists():
        logger.error("versions.yaml not found at %s", VERSIONS_FILE)
        sys.exit(1)

    with VERSIONS_FILE.open() as f:
        data: dict[str, Any] = yaml.safe_load(f)
        return data


def get_tool_version(tool_name: str) -> str:
    """Get the configured version for a tool from versions.yaml."""
    versions = load_versions()

    # Check all tool categories
    for category in ["python_tools", "binary_tools", "special_tools"]:
        if category in versions and tool_name in versions[category]:
            return str(versions[category][tool_name].get("version", "unknown"))

    logger.warning("Tool %s not found in versions.yaml", tool_name)
    return "unknown"


def get_installed_version(tool_name: str) -> str | None:
    """Get the installed version of a tool by running it."""
    version_commands = {
        "trivy": ["trivy", "--version"],
        "bandit": ["bandit", "--version"],
        "semgrep": ["semgrep", "--version"],
        "hadolint": ["hadolint", "--version"],
        "checkov": ["checkov", "--version"],
        "trufflehog": ["trufflehog", "--version"],
        "shellcheck": ["shellcheck", "--version"],
    }

    cmd = version_commands.get(tool_name)
    if not cmd:
        return None

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        output = result.stdout + result.stderr
        # Extract version from output (usually first line with version number)
        for line in output.split("\n"):
            if "version" in line.lower() or any(c.isdigit() for c in line):
                # Try to extract version pattern
                import re

                match = re.search(r"(\d+\.\d+\.?\d*)", line)
                if match:
                    return match.group(1)
        return None
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return None


def run_tool(
    tool_name: str, config: dict[str, Any], output_dir: Path
) -> tuple[bool, Path]:
    """Run a security tool and save its output.

    Returns:
        Tuple of (success, output_file_path)
    """
    sample_path = SAMPLES_DIR / config["sample_dir"]
    if not sample_path.exists():
        logger.error("Sample directory not found: %s", sample_path)
        return False, Path()

    output_file = output_dir / config["output_file"]
    output_dir.mkdir(parents=True, exist_ok=True)

    # Build command with substitutions
    cmd = []
    for part in config["command"]:
        part = part.replace("{sample}", str(sample_path))
        part = part.replace("{output}", str(output_file))
        part = part.replace("{output_dir}", str(output_dir))
        cmd.append(part)

    logger.info("Running %s: %s", tool_name, " ".join(cmd))

    try:
        # Some tools write to stdout instead of file
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,  # 5 minute timeout
            cwd=PROJECT_ROOT,
        )

        # Check if output was written to file or stdout
        if not output_file.exists() and result.stdout:
            # Tool wrote to stdout, save it
            output_file.write_text(result.stdout)
            logger.info("Captured stdout to %s", output_file)
        elif output_file.exists():
            logger.info("Output written to %s", output_file)
        else:
            # Tool may have found nothing (valid case)
            logger.warning(
                "%s produced no output (may be valid if no findings)", tool_name
            )
            # Create empty JSON for consistency
            output_file.write_text("[]")

        # Log any errors (but don't fail - some tools exit non-zero when findings exist)
        if result.returncode != 0:
            logger.debug(
                "%s exited with code %d (may be normal)", tool_name, result.returncode
            )
            if result.stderr:
                logger.debug("stderr: %s", result.stderr[:500])

        return True, output_file

    except subprocess.TimeoutExpired:
        logger.error("%s timed out after 5 minutes", tool_name)
        return False, Path()
    except FileNotFoundError:
        logger.error("%s not installed or not in PATH", tool_name)
        return False, Path()
    except OSError as e:
        logger.error("Error running %s: %s", tool_name, e)
        return False, Path()


def run_adapter(
    tool_name: str, config: dict[str, Any], raw_output_path: Path
) -> list[dict[str, Any]]:
    """Run the adapter to parse raw tool output into CommonFinding format."""
    try:
        # Dynamically import the adapter module
        import importlib

        module = importlib.import_module(config["adapter_module"])
        adapter_class = getattr(module, config["adapter_class"])
        adapter = adapter_class()

        # Parse the raw output
        findings = adapter.parse(raw_output_path)

        # Convert Finding objects to dicts for JSON serialization
        findings_dicts = []
        for f in findings:
            if hasattr(f, "__dict__"):
                # It's a dataclass or object
                findings_dicts.append(
                    asdict(f) if hasattr(f, "__dataclass_fields__") else vars(f)
                )
            elif isinstance(f, dict):
                findings_dicts.append(f)
            else:
                logger.warning("Unknown finding type: %s", type(f))

        return findings_dicts

    except ImportError as e:
        logger.error("Failed to import adapter for %s: %s", tool_name, e)
        return []
    except Exception as e:
        logger.error("Error running adapter for %s: %s", tool_name, e)
        return []


def generate_golden_files(tool_name: str, update: bool = False) -> bool:
    """Generate golden test files for a single tool.

    Args:
        tool_name: Name of the tool to generate golden files for
        update: If True, overwrite existing golden files

    Returns:
        True if successful, False otherwise
    """
    if tool_name not in TOOL_CONFIGS:
        logger.error(
            "Unknown tool: %s. Available: %s", tool_name, list(TOOL_CONFIGS.keys())
        )
        return False

    config = TOOL_CONFIGS[tool_name]
    version = get_tool_version(tool_name)

    # Check installed version matches expected
    installed = get_installed_version(tool_name)
    if installed and installed != version:
        logger.warning(
            "%s version mismatch: installed=%s, expected=%s",
            tool_name,
            installed,
            version,
        )

    # Create versioned output directory
    golden_version_dir = GOLDEN_DIR / tool_name / f"v{version}"

    if golden_version_dir.exists() and not update:
        logger.info(
            "Golden files already exist for %s v%s (use --update to overwrite)",
            tool_name,
            version,
        )
        return True

    logger.info("Generating golden files for %s v%s", tool_name, version)

    # Step 1: Run the tool
    success, raw_output_path = run_tool(tool_name, config, golden_version_dir)
    if not success:
        return False

    # Step 2: Run the adapter to get expected findings
    expected_findings = run_adapter(tool_name, config, raw_output_path)

    # Step 3: Save expected findings
    expected_path = golden_version_dir / "expected-findings.json"
    with expected_path.open("w") as f:
        json.dump(expected_findings, f, indent=2, default=str)
    logger.info(
        "Saved %d expected findings to %s", len(expected_findings), expected_path
    )

    # Step 4: Save metadata
    metadata = {
        "tool": tool_name,
        "version": version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "sample_dir": config["sample_dir"],
        "finding_count": len(expected_findings),
        "raw_output_hash": hashlib.sha256(raw_output_path.read_bytes()).hexdigest()[
            :12
        ],
    }
    metadata_path = golden_version_dir / "metadata.json"
    with metadata_path.open("w") as f:
        json.dump(metadata, f, indent=2)

    logger.info("Golden files generated successfully for %s", tool_name)
    return True


def check_current_versions() -> bool:
    """Check that golden files exist for current tool versions.

    Returns:
        True if all tools have up-to-date golden files, False otherwise
    """
    all_current = True

    for tool_name in TOOL_CONFIGS:
        version = get_tool_version(tool_name)
        golden_version_dir = GOLDEN_DIR / tool_name / f"v{version}"
        expected_file = golden_version_dir / "expected-findings.json"

        if expected_file.exists():
            # Load metadata to show info
            metadata_path = golden_version_dir / "metadata.json"
            if metadata_path.exists():
                with metadata_path.open() as f:
                    metadata = json.load(f)
                logger.info(
                    "✅ %s v%s: %d findings (generated %s)",
                    tool_name,
                    version,
                    metadata.get("finding_count", "?"),
                    metadata.get("generated_at", "?")[:10],
                )
            else:
                logger.info("✅ %s v%s: golden files exist", tool_name, version)
        else:
            logger.warning(
                "❌ %s v%s: missing golden files at %s",
                tool_name,
                version,
                golden_version_dir,
            )
            all_current = False

    return all_current


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate golden test fixtures by running real security tools.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument(
        "--tool",
        "-t",
        choices=list(TOOL_CONFIGS.keys()),
        help="Generate golden files for a specific tool",
    )
    parser.add_argument(
        "--all",
        "-a",
        action="store_true",
        help="Generate golden files for all configured tools",
    )
    parser.add_argument(
        "--update",
        "-u",
        action="store_true",
        help="Update/overwrite existing golden files",
    )
    parser.add_argument(
        "--check-current-versions",
        action="store_true",
        help="Check if golden files exist for current tool versions",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run tools in JMo Security Docker container",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Enable verbose logging",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate arguments
    if not any([args.tool, args.all, args.check_current_versions]):
        parser.error("Must specify --tool, --all, or --check-current-versions")

    if args.docker:
        logger.warning("--docker mode not yet implemented, running locally")

    # Check current versions
    if args.check_current_versions:
        success = check_current_versions()
        sys.exit(0 if success else 1)

    # Generate for specific tool
    if args.tool:
        success = generate_golden_files(args.tool, args.update)
        sys.exit(0 if success else 1)

    # Generate for all tools
    if args.all:
        success_count = 0
        fail_count = 0

        for tool_name in TOOL_CONFIGS:
            if generate_golden_files(tool_name, args.update):
                success_count += 1
            else:
                fail_count += 1

        logger.info(
            "Golden file generation complete: %d succeeded, %d failed",
            success_count,
            fail_count,
        )
        sys.exit(0 if fail_count == 0 else 1)


if __name__ == "__main__":
    main()
