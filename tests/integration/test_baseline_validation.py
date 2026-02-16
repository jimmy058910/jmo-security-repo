#!/usr/bin/env python3
"""
Baseline validation tests for JMo Security.

These tests validate scan results against known vulnerability baselines,
ensuring that JMo Security correctly detects expected vulnerabilities in
well-known vulnerable applications.

Requires:
- Security tools installed (profile-dependent)
- Network access to clone target repositories
- ~45 minutes runtime for full validation

Targets:
- OWASP Juice Shop (Node.js)
- OWASP WebGoat (Java)
"""

from __future__ import annotations

import json
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import pytest

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
BASELINES_DIR = PROJECT_ROOT / "tests" / "integration" / "baselines"


@dataclass
class BaselineValidationResult:
    """Results from validating a scan against a baseline."""

    target: str
    total_expected: int
    total_found: int
    missing_critical: int
    missing_high: int
    missing_medium: int
    extra_count: int
    missing_rules: list[str]
    passed: bool


def load_baseline(baseline_file: Path) -> dict[str, Any]:
    """Load a baseline file."""
    with open(baseline_file) as f:
        return json.load(f)


def clone_target(repo_url: str, dest: Path, depth: int = 1) -> None:
    """Clone a target repository.

    Uses core.longpaths=true to support Windows extended-length paths,
    preventing failures when repos have deep directory structures
    (e.g., juice-shop's node_modules).
    """
    subprocess.run(
        [
            "git",
            "clone",
            "--depth",
            str(depth),
            "--config",
            "core.longpaths=true",
            repo_url,
            str(dest),
        ],
        check=True,
        capture_output=True,
    )


def run_scan(target_path: Path, results_dir: Path, profile: str) -> int:
    """Run JMo scan on a target directory."""
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(target_path),
        "--results-dir",
        str(results_dir),
        "--profile",
        profile,
    ]

    result = subprocess.run(cmd, capture_output=True, text=True, timeout=1800)
    return result.returncode


def load_findings(results_dir: Path) -> list[dict[str, Any]]:
    """Load findings from scan results."""
    findings_file = results_dir / "findings.json"

    if not findings_file.exists():
        return []

    with open(findings_file) as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return []


def extract_rule_ids(findings: list[dict[str, Any]]) -> Counter[str]:
    """Extract and count rule IDs from findings."""
    rule_counts: Counter[str] = Counter()

    for finding in findings:
        rule_id = finding.get("ruleId", finding.get("rule_id", ""))

        # Normalize CWE IDs
        if rule_id:
            rule_counts[rule_id] += 1

        # Also check for CWE in metadata
        metadata = finding.get("metadata", {})
        if isinstance(metadata, dict):
            cwe = metadata.get("cwe", metadata.get("CWE"))
            if cwe:
                rule_counts[f"CWE-{cwe}"] += 1

    return rule_counts


def compare_to_baseline(
    findings: list[dict[str, Any]],
    baseline: dict[str, Any],
) -> BaselineValidationResult:
    """Compare scan findings to a baseline."""
    expected = baseline["expected_findings"]
    tolerance = baseline["tolerance"]
    target = baseline["metadata"]["target"]

    # Extract found rule IDs
    found_rules = extract_rule_ids(findings)

    # Track missing findings by severity
    missing_critical = 0
    missing_high = 0
    missing_medium = 0
    missing_rules = []

    for expected_finding in expected:
        rule_id = expected_finding["rule_id"]
        severity = expected_finding["severity"]
        min_count = expected_finding.get("min_count", 1)

        found_count = found_rules.get(rule_id, 0)

        if found_count < min_count:
            missing_rules.append(
                f"{rule_id} (expected {min_count}, found {found_count})"
            )

            if severity == "CRITICAL":
                missing_critical += 1
            elif severity == "HIGH":
                missing_high += 1
            elif severity == "MEDIUM":
                missing_medium += 1

    # Calculate extra findings
    expected_total = sum(e.get("min_count", 1) for e in expected)
    total_found = sum(found_rules.values())
    extra_count = max(0, total_found - expected_total)
    extra_ratio = extra_count / expected_total if expected_total > 0 else 0

    # Determine if passed
    passed = (
        missing_critical <= tolerance.get("missing_critical", 0)
        and missing_high <= tolerance.get("missing_high", 2)
        and missing_medium <= tolerance.get("missing_medium", 5)
        and extra_ratio <= tolerance.get("extra_findings_ratio", 0.3)
    )

    return BaselineValidationResult(
        target=target,
        total_expected=len(expected),
        total_found=len(findings),
        missing_critical=missing_critical,
        missing_high=missing_high,
        missing_medium=missing_medium,
        extra_count=extra_count,
        missing_rules=missing_rules,
        passed=passed,
    )


@pytest.mark.integration
@pytest.mark.baseline
@pytest.mark.slow
class TestBaselineValidation:
    """Validate scan results against known vulnerability baselines."""

    @pytest.mark.parametrize(
        "baseline_file",
        [
            pytest.param("juice-shop.baseline.json", id="juice-shop"),
            pytest.param("webgoat.baseline.json", id="webgoat"),
        ],
    )
    def test_scan_matches_baseline(self, baseline_file: str, short_tmp_path: Path):
        """Scan results should match expected baseline within tolerance."""
        baseline_path = BASELINES_DIR / baseline_file

        if not baseline_path.exists():
            pytest.skip(f"Baseline file not found: {baseline_path}")

        baseline = load_baseline(baseline_path)
        target = baseline["metadata"]["target"]
        profile = baseline["metadata"]["profile"]

        # Determine repo URL from target
        if "juice-shop" in target.lower():
            repo_url = "https://github.com/juice-shop/juice-shop.git"
        elif "webgoat" in target.lower():
            repo_url = "https://github.com/WebGoat/WebGoat.git"
        else:
            pytest.skip(f"Unknown target repository: {target}")

        # Use short_tmp_path to avoid Windows MAX_PATH (260 chars) with deep repos
        target_path = short_tmp_path / "target"
        results_dir = short_tmp_path / "results"

        # Clone target
        clone_target(repo_url, target_path)

        # Run scan
        run_scan(target_path, results_dir, profile)

        # Load and compare findings
        findings = load_findings(results_dir)
        result = compare_to_baseline(findings, baseline)

        # Report results
        print(f"\nBaseline Validation: {result.target}")
        print(f"  Expected: {result.total_expected} findings")
        print(f"  Found: {result.total_found} findings")
        print(f"  Missing CRITICAL: {result.missing_critical}")
        print(f"  Missing HIGH: {result.missing_high}")
        print(f"  Missing MEDIUM: {result.missing_medium}")
        if result.missing_rules:
            print(f"  Missing rules: {result.missing_rules[:5]}...")

        # Assert within tolerance
        tolerance = baseline["tolerance"]
        assert result.missing_critical <= tolerance.get(
            "missing_critical", 0
        ), f"Too many missing CRITICAL findings: {result.missing_critical}"
        assert result.missing_high <= tolerance.get(
            "missing_high", 2
        ), f"Too many missing HIGH findings: {result.missing_high}"


@pytest.mark.integration
@pytest.mark.baseline
class TestBaselineSchemaValidation:
    """Test that baseline files conform to the schema."""

    def test_baseline_files_exist(self):
        """Baseline files should exist."""
        assert BASELINES_DIR.exists(), "Baselines directory not found"

        baseline_files = list(BASELINES_DIR.glob("*.baseline.json"))
        assert len(baseline_files) >= 1, "No baseline files found"

    def test_baseline_files_valid_json(self):
        """All baseline files should be valid JSON."""
        for baseline_file in BASELINES_DIR.glob("*.baseline.json"):
            with open(baseline_file) as f:
                data = json.load(f)

            # Check required top-level keys
            assert "metadata" in data, f"{baseline_file.name} missing metadata"
            assert (
                "expected_findings" in data
            ), f"{baseline_file.name} missing expected_findings"
            assert "tolerance" in data, f"{baseline_file.name} missing tolerance"

    def test_baseline_metadata_complete(self):
        """Baseline metadata should have required fields."""
        for baseline_file in BASELINES_DIR.glob("*.baseline.json"):
            baseline = load_baseline(baseline_file)
            metadata = baseline["metadata"]

            assert "target" in metadata, f"{baseline_file.name} metadata missing target"
            assert (
                "version" in metadata
            ), f"{baseline_file.name} metadata missing version"
            assert (
                "profile" in metadata
            ), f"{baseline_file.name} metadata missing profile"

    def test_expected_findings_have_required_fields(self):
        """Each expected finding should have required fields."""
        for baseline_file in BASELINES_DIR.glob("*.baseline.json"):
            baseline = load_baseline(baseline_file)

            for i, finding in enumerate(baseline["expected_findings"]):
                assert (
                    "rule_id" in finding
                ), f"{baseline_file.name} finding {i} missing rule_id"
                assert (
                    "severity" in finding
                ), f"{baseline_file.name} finding {i} missing severity"
                assert (
                    "category" in finding
                ), f"{baseline_file.name} finding {i} missing category"
