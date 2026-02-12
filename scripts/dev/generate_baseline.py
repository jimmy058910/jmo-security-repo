#!/usr/bin/env python3
"""
Generate vulnerability baselines from known-vulnerable targets.

Baselines define expected vulnerabilities for integration testing. They enable
automated validation that JMo Security correctly detects known issues.

Usage:
    # Generate baseline for Juice Shop
    python scripts/dev/generate_baseline.py --target juice-shop --profile balanced

    # Update existing baseline
    python scripts/dev/generate_baseline.py --target juice-shop --update

    # Generate baseline from local directory
    python scripts/dev/generate_baseline.py --target ./path/to/repo --profile fast

    # Validate baseline schema
    python scripts/dev/generate_baseline.py --validate tests/integration/baselines/juice-shop.baseline.json

Supported Targets:
    - juice-shop: OWASP Juice Shop (cloned automatically)
    - webgoat: OWASP WebGoat (cloned automatically)
    - dvwa: Damn Vulnerable Web Application
    - ./local/path: Any local directory

Output:
    tests/integration/baselines/{target}.baseline.json
"""

from __future__ import annotations

import argparse
import json
import logging
import subprocess
import sys
import tempfile
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import jsonschema

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
logger = logging.getLogger(__name__)

# Paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASELINES_DIR = PROJECT_ROOT / "tests" / "integration" / "baselines"
SCHEMA_FILE = BASELINES_DIR / "baseline_schema.json"

# Known target repositories
KNOWN_TARGETS = {
    "juice-shop": {
        "repo": "https://github.com/juice-shop/juice-shop.git",
        "version_cmd": ["git", "describe", "--tags", "--always"],
        "default_profile": "balanced",
    },
    "webgoat": {
        "repo": "https://github.com/WebGoat/WebGoat.git",
        "version_cmd": ["git", "describe", "--tags", "--always"],
        "default_profile": "balanced",
    },
    "dvwa": {
        "repo": "https://github.com/digininja/DVWA.git",
        "version_cmd": ["git", "describe", "--tags", "--always"],
        "default_profile": "balanced",
    },
}

# CWE to category mapping
CWE_CATEGORIES = {
    "CWE-79": "xss",
    "CWE-89": "sqli",
    "CWE-22": "path-traversal",
    "CWE-78": "command-injection",
    "CWE-798": "hardcoded-secrets",
    "CWE-327": "weak-crypto",
    "CWE-502": "deserialization",
    "CWE-611": "xxe",
    "CWE-918": "ssrf",
    "CWE-352": "csrf",
    "CWE-1321": "prototype-pollution",
}


def clone_target(target: str, dest: Path) -> str:
    """Clone a known target repository and return its version."""
    if target not in KNOWN_TARGETS:
        raise ValueError(
            f"Unknown target: {target}. Known: {list(KNOWN_TARGETS.keys())}"
        )

    config = KNOWN_TARGETS[target]
    logger.info(f"Cloning {target} from {config['repo']}...")

    subprocess.run(
        ["git", "clone", "--depth", "1", config["repo"], str(dest)],  # type: ignore[list-item]
        check=True,
        capture_output=True,
    )

    # Get version
    result = subprocess.run(
        config["version_cmd"],
        cwd=dest,
        capture_output=True,
        text=True,
    )
    version = result.stdout.strip() if result.returncode == 0 else "unknown"

    logger.info(f"Cloned {target} version: {version}")
    return version


def run_scan(target_path: Path, profile: str, results_dir: Path) -> int:
    """Run JMo Security scan on target."""
    logger.info(f"Running scan with profile '{profile}'...")

    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(target_path),
        "--profile",
        profile,
        "--results-dir",
        str(results_dir),
    ]

    result = subprocess.run(cmd, capture_output=True, text=True)

    if result.returncode != 0:
        logger.warning(f"Scan exited with code {result.returncode}")
        if result.stderr:
            logger.warning(f"Stderr: {result.stderr[:500]}")

    return result.returncode


def load_findings(results_dir: Path) -> list[dict[str, Any]]:
    """Load findings from scan results."""
    findings_file = results_dir / "findings.json"

    if not findings_file.exists():
        logger.warning(f"No findings.json found in {results_dir}")
        return []

    with open(findings_file) as f:
        data = json.load(f)

    # Handle both list and dict formats
    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "findings" in data:
        return data["findings"]  # type: ignore[no-any-return]
    else:
        return []


def categorize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Categorize findings into expected baseline format."""
    # Count by rule_id and severity
    rule_counts: Counter[tuple[str, str]] = Counter()

    for finding in findings:
        rule_id = finding.get("ruleId", finding.get("rule_id", "unknown"))
        severity = finding.get("severity", "MEDIUM")

        # Normalize CWE IDs
        if rule_id.startswith("CWE-"):
            rule_counts[(rule_id, severity)] += 1
        elif "cwe" in str(finding.get("metadata", {})).lower():
            # Try to extract CWE from metadata
            metadata = finding.get("metadata", {})
            if isinstance(metadata, dict):
                cwe = metadata.get("cwe", metadata.get("CWE"))
                if cwe:
                    rule_counts[(f"CWE-{cwe}", severity)] += 1
                else:
                    rule_counts[(rule_id, severity)] += 1
        else:
            rule_counts[(rule_id, severity)] += 1

    # Convert to baseline format
    expected = []
    for (rule_id, severity), count in rule_counts.most_common():
        category = CWE_CATEGORIES.get(rule_id, rule_id.lower().replace("-", "_"))

        expected.append(
            {
                "rule_id": rule_id,
                "severity": severity,
                "category": category,
                "min_count": max(1, count - 1),  # Allow some variance
            }
        )

    return expected


def calculate_tolerance(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Calculate appropriate tolerance values based on finding distribution."""
    severity_counts = Counter(f.get("severity", "MEDIUM") for f in findings)

    # Calculate tolerance based on distribution
    high = severity_counts.get("HIGH", 0)
    medium = severity_counts.get("MEDIUM", 0)

    return {
        "missing_critical": 0,  # Never allow missing critical
        "missing_high": min(2, high // 5) if high > 0 else 0,
        "missing_medium": min(5, medium // 4) if medium > 0 else 0,
        "extra_findings_ratio": 0.3,  # Allow 30% more findings
    }


def generate_baseline(
    target: str,
    profile: str,
) -> dict[str, Any]:
    """Generate or update a baseline for the given target."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Determine target path
        if target in KNOWN_TARGETS:
            target_path = tmp_path / target
            version = clone_target(target, target_path)
        elif Path(target).is_dir():
            target_path = Path(target).resolve()
            version = "local"
        else:
            raise ValueError(f"Target not found: {target}")

        # Run scan
        results_dir = tmp_path / "results"
        results_dir.mkdir(parents=True)

        run_scan(target_path, profile, results_dir)

        # Load and analyze findings
        findings = load_findings(results_dir)

        if not findings:
            logger.warning("No findings detected - baseline may be incomplete")

        # Determine tools used
        tools_used = list(
            set(f.get("tool", {}).get("name", "unknown") for f in findings)
        )

        return {
            "metadata": {
                "target": f"{target}/{target}" if target in KNOWN_TARGETS else target,
                "version": version,
                "generated": datetime.now(timezone.utc).isoformat(),
                "profile": profile,
                "tools_used": sorted(tools_used),
                "notes": f"Auto-generated baseline from {len(findings)} findings",
            },
            "expected_findings": categorize_findings(findings),
            "tolerance": calculate_tolerance(findings),
        }


def validate_baseline(baseline_path: Path) -> bool:
    """Validate a baseline file against the schema."""
    if not SCHEMA_FILE.exists():
        logger.error(f"Schema file not found: {SCHEMA_FILE}")
        return False

    with open(SCHEMA_FILE) as f:
        schema = json.load(f)

    with open(baseline_path) as f:
        baseline = json.load(f)

    try:
        jsonschema.validate(baseline, schema)
        logger.info(f"Baseline {baseline_path.name} is valid")
        return True
    except jsonschema.ValidationError as e:
        logger.error(f"Baseline validation failed: {e.message}")
        return False


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Generate vulnerability baselines for integration testing",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--target",
        help="Target to scan (juice-shop, webgoat, dvwa, or local path)",
    )
    parser.add_argument(
        "--profile",
        default="balanced",
        choices=["fast", "slim", "balanced", "deep"],
        help="Scan profile to use (default: balanced)",
    )
    parser.add_argument(
        "--update",
        action="store_true",
        help="Update existing baseline instead of creating new",
    )
    parser.add_argument(
        "--validate",
        metavar="FILE",
        help="Validate a baseline file against the schema",
    )
    parser.add_argument(
        "--output",
        help="Custom output path (default: tests/integration/baselines/{target}.baseline.json)",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    # Validate mode
    if args.validate:
        return 0 if validate_baseline(Path(args.validate)) else 1

    # Generate mode
    if not args.target:
        parser.error("--target is required for generation")

    try:
        baseline = generate_baseline(
            target=args.target,
            profile=args.profile,
        )

        # Determine output path
        if args.output:
            output_path = Path(args.output)
        else:
            target_name = args.target.replace("/", "-").replace("\\", "-")
            if args.target in KNOWN_TARGETS:
                target_name = args.target
            output_path = BASELINES_DIR / f"{target_name}.baseline.json"

        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write baseline
        with open(output_path, "w") as f:
            json.dump(baseline, f, indent=2)
            f.write("\n")

        logger.info(f"Baseline written to: {output_path}")
        logger.info(f"Expected findings: {len(baseline['expected_findings'])}")

        return 0

    except Exception as e:
        logger.error(f"Failed to generate baseline: {e}")
        if args.verbose:
            import traceback

            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
