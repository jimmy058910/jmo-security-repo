#!/usr/bin/env python3
"""
Derive vulnerability baselines from known-vulnerable targets.

Baselines define what a scan of a pinned target must still find. The test in
tests/integration/test_baseline_validation.py scans the same commit and fails
when a row goes unmet or a recorded tool stops reporting; this script is how a
baseline is (re-)derived, so re-run it whenever a pin or the tool matrix changes.

Usage:
    # Re-derive Juice Shop's baseline (clones the commit pinned in
    # tests/integration/targets.py)
    python scripts/dev/generate_baseline.py --target juice-shop

    # Derive a baseline from a local directory
    python scripts/dev/generate_baseline.py --target ./path/to/repo

    # Validate baseline schema
    python scripts/dev/generate_baseline.py --validate tests/integration/baselines/juice-shop.baseline.json

Supported Targets:
    - juice-shop: OWASP Juice Shop, at its pinned commit
    - webgoat: OWASP WebGoat, at its pinned commit
    - ./local/path: Any local directory

Run it where the tests run real tools: a scratch HOME that holds the installed
tools (the scan bumps a counter in ~/.jmo/config.yml, which is put back
afterwards), and TMPDIR on a disk with room, since the clone and the scan's
scratch (~150 MB for juice-shop) live in the system temp directory.

Output:
    tests/integration/baselines/{target}.baseline.json
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
import tempfile
from collections import Counter
from datetime import UTC, datetime
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
PROJECT_ROOT = Path(__file__).resolve().parents[2]
BASELINES_DIR = PROJECT_ROOT / "tests" / "integration" / "baselines"
SCHEMA_FILE = BASELINES_DIR / "baseline_schema.json"

# Run directly (`python scripts/dev/generate_baseline.py`) and sys.path[0] is
# scripts/dev, not the repo root, so tests.integration is not importable
# without this. Same bootstrap as scripts/dev/phase_audit.py.
if __package__ in (None, ""):  # pragma: no cover - only on direct execution
    sys.path.insert(0, str(PROJECT_ROOT))

from tests.integration.targets import (  # noqa: E402
    PINNED_TARGETS,
    clone_at_commit,
    count_by_tool,
    finding_cwes,
    load_findings,
    run_scan,
)

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


SEVERITY_RANK = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def categorize_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Turn findings into baseline rows: one per bare CWE id, all severities pooled.

    ``min_count`` is the number of findings carrying the id (a finding counts
    once per distinct id, however many spellings it lists) and ``severity`` the
    highest seen with it. Findings with no CWE produce no row: nothing but a
    tool's own rule id would name them, and rule ids change with the bundle.
    Rows run from most to least common, ties by CWE number, so a re-derivation
    diffs cleanly.
    """
    counts: Counter[str] = Counter()
    highest: dict[str, str] = {}

    for finding in findings:
        severity = finding.get("severity", "MEDIUM")
        for cwe in finding_cwes(finding):
            counts[cwe] += 1
            if SEVERITY_RANK.get(severity, -1) > SEVERITY_RANK.get(
                highest.get(cwe, ""), -1
            ):
                highest[cwe] = severity

    return [
        {
            "rule_id": cwe,
            "severity": highest[cwe],
            "category": CWE_CATEGORIES.get(cwe, cwe.lower()),
            "min_count": counts[cwe],
        }
        for cwe in sorted(counts, key=lambda c: (-counts[c], int(c[len("CWE-") :])))
    ]


def calculate_tolerance() -> dict[str, Any]:
    """Tolerance for a derived baseline: every expected row must be met.

    A row's ``min_count`` is what the scan found when it was derived, so any
    shortfall is a real loss rather than variance. The test asserts no extra
    findings ratio; the key stays because the schema documents it.
    """
    return {
        "missing_critical": 0,
        "missing_high": 0,
        "missing_medium": 0,
        "extra_findings_ratio": 0.3,
    }


def generate_baseline(target: str) -> dict[str, Any]:
    """Scan a target and derive its baseline."""
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)

        # Determine target path
        pin = PINNED_TARGETS.get(target)
        if pin:
            target_path = tmp_path / target
            logger.info(f"Cloning {pin.url} at {pin.commit}...")
            clone_at_commit(pin.url, pin.commit, target_path)
            slug, version, notes = pin.slug, pin.commit, pin.note
        elif Path(target).is_dir():
            target_path = Path(target).resolve()
            slug, version, notes = target, "local", f"Derived from {target}"
        else:
            raise ValueError(
                f"Target not found: {target}. Pinned: {list(PINNED_TARGETS)}"
            )

        # Run scan
        results_dir = tmp_path / "results"
        results_dir.mkdir(parents=True)

        logger.info("Running scan...")
        done = run_scan(target_path, results_dir)
        if done.returncode != 0:
            tail = "\n".join(done.stderr.splitlines()[-20:])
            raise RuntimeError(f"jmo scan exited {done.returncode}:\n{tail}")

        # Load and analyze findings
        findings = load_findings(results_dir)
        if not findings:
            raise RuntimeError(
                "The scan found nothing; a baseline of nothing would assert nothing"
            )

        tool_counts = count_by_tool(findings)
        return {
            "metadata": {
                "target": slug,
                "version": version,
                "generated": datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "tools_used": sorted(tool_counts),
                "findings_per_tool": dict(sorted(tool_counts.items())),
                "finding_count": len(findings),
                "notes": notes,
            },
            "expected_findings": categorize_findings(findings),
            "tolerance": calculate_tolerance(),
        }


def validate_baseline(baseline_path: Path) -> bool:
    """Validate a baseline file against the schema."""
    if not SCHEMA_FILE.exists():
        logger.error(f"Schema file not found: {SCHEMA_FILE}")
        return False

    with open(SCHEMA_FILE, encoding="utf-8") as f:
        schema = json.load(f)

    with open(baseline_path, encoding="utf-8") as f:
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
        help=f"Target to scan ({', '.join(PINNED_TARGETS)}, or local path)",
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
        baseline = generate_baseline(target=args.target)

        # Determine output path
        if args.output:
            output_path = Path(args.output)
        else:
            target_name = args.target.replace("/", "-").replace("\\", "-")
            if args.target in PINNED_TARGETS:
                target_name = args.target
            output_path = BASELINES_DIR / f"{target_name}.baseline.json"

        # Ensure directory exists
        output_path.parent.mkdir(parents=True, exist_ok=True)

        # Write baseline, keeping the line endings the file already has
        text = json.dumps(baseline, indent=2) + "\n"
        if output_path.exists() and b"\r\n" in output_path.read_bytes():
            text = text.replace("\n", "\r\n")
        output_path.write_bytes(text.encode("utf-8"))

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
