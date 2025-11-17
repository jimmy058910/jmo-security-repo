#!/usr/bin/env python3
"""
Pre-release validation script for JMo Security.

Runs comprehensive checks before allowing release tag.
Validates version consistency, test coverage, documentation, security, and CI status.

Usage:
    python3 scripts/dev/pre_release_check.py

Exit codes:
    0 - All checks passed, ready to release
    1 - One or more checks failed, release blocked
"""

import json
import subprocess
import sys
from pathlib import Path
from typing import Callable, List, Tuple

import tomli  # Use tomli for TOML parsing (pyproject.toml)


def check_version_consistency() -> None:
    """Verify version consistent across all files."""
    # Load version from pyproject.toml
    pyproject_path = Path("pyproject.toml")
    if not pyproject_path.exists():
        raise AssertionError("pyproject.toml not found")

    with open(pyproject_path, "rb") as f:
        pyproject = tomli.load(f)

    version = pyproject["project"]["version"]
    print(f"   Version from pyproject.toml: {version}")

    # Check CHANGELOG.md has version entry
    changelog_path = Path("CHANGELOG.md")
    if not changelog_path.exists():
        raise AssertionError("CHANGELOG.md not found")

    changelog = changelog_path.read_text()
    if f"## [{version}]" not in changelog and f"## {version}" not in changelog:
        raise AssertionError(
            f"Version {version} not found in CHANGELOG.md\n"
            f"   Add release notes under '## [{version}]' or '## {version}'"
        )

    # Check versions.yaml up to date (all tools latest)
    print("   Checking tool versions...")
    versions_yaml = Path("versions.yaml")
    if not versions_yaml.exists():
        print("   WARNING: versions.yaml not found, skipping tool version check")
    else:
        # Run update_versions.py --check-latest to detect outdated tools
        result = subprocess.run(
            ["python3", "scripts/dev/update_versions.py", "--check-latest"],
            capture_output=True,
            text=True,
        )

        # Parse output to find outdated CRITICAL tools
        outdated_critical = []
        for line in result.stdout.split("\n"):
            if "CRITICAL" in line and ("outdated" in line.lower() or "→" in line):
                outdated_critical.append(line.strip())

        if outdated_critical:
            raise AssertionError(
                "CRITICAL tools outdated (must update before release):\n"
                + "\n".join(f"   - {tool}" for tool in outdated_critical)
                + "\n\n   Run: python3 scripts/dev/update_versions.py --update-all"
            )

    print(f"✅ Version {version} consistent across all files")


def check_test_coverage() -> None:
    """Verify test coverage ≥90%."""
    print("   Running pytest with coverage (this may take 30-60 seconds)...")

    result = subprocess.run(
        ["pytest", "--cov=scripts", "--cov-report=term-missing", "--cov-report=term"],
        capture_output=True,
        text=True,
    )

    # Extract coverage percentage from output
    # Look for line like: "TOTAL                            12345   1234    90%"
    coverage_lines = [
        line for line in result.stdout.split("\n") if "TOTAL" in line and "%" in line
    ]

    if not coverage_lines:
        raise AssertionError(
            "Could not parse coverage percentage from pytest output\n"
            f"   Output: {result.stdout[-500:]}"  # Last 500 chars
        )

    coverage_line = coverage_lines[0]
    # Extract percentage (last token ending with %)
    tokens = coverage_line.split()
    coverage_str = [t for t in tokens if t.endswith("%")][-1]
    coverage_pct = float(coverage_str.rstrip("%"))

    if coverage_pct < 90.0:
        raise AssertionError(
            f"Coverage {coverage_pct}% < 90% required for v1.0.0\n"
            f"   Run: pytest --cov=scripts --cov-report=term-missing\n"
            f"   Add tests to increase coverage"
        )

    print(f"✅ Test coverage: {coverage_pct}% (exceeds 90% requirement)")


def check_documentation_completeness() -> None:
    """Verify all v1.0.0 features documented."""
    required_docs = [
        "docs/examples/diff-workflows.md",
        "docs/examples/ci-cd-trends.md",
        "docs/OUTPUT_FORMATS.md",  # Updated for v1.0.0 metadata
    ]

    missing_docs = []
    for doc in required_docs:
        doc_path = Path(doc)
        if not doc_path.exists():
            missing_docs.append(doc)
        else:
            # Verify file is not empty
            content = doc_path.read_text().strip()
            if len(content) < 100:  # At least 100 chars
                missing_docs.append(f"{doc} (file too short, likely incomplete)")

    if missing_docs:
        raise AssertionError(
            "Missing or incomplete required documentation:\n"
            + "\n".join(f"   - {doc}" for doc in missing_docs)
            + "\n\n   Complete documentation before release"
        )

    # Verify key sections exist in USER_GUIDE.md
    user_guide = Path("docs/USER_GUIDE.md")
    if not user_guide.exists():
        raise AssertionError("docs/USER_GUIDE.md not found")

    user_guide_content = user_guide.read_text()
    required_sections = [
        "jmo diff",  # Diff command
        "jmo history",  # History command
        "jmo trends",  # Trends command
    ]

    missing_sections = [
        section for section in required_sections if section not in user_guide_content
    ]

    if missing_sections:
        raise AssertionError(
            "docs/USER_GUIDE.md missing v1.0.0 command documentation:\n"
            + "\n".join(f"   - {section}" for section in missing_sections)
        )

    print("✅ Documentation complete (all v1.0.0 features documented)")


def check_no_known_security_issues() -> None:
    """Verify no known security vulnerabilities."""
    print("   Running Bandit security audit...")

    # Run Bandit on codebase
    bandit_result = subprocess.run(
        ["bandit", "-r", "scripts/", "-c", "bandit.yaml"],
        capture_output=True,
        text=True,
    )

    # Bandit exit codes: 0 = no issues, 1 = issues found
    if bandit_result.returncode not in (0, 1):
        raise AssertionError(
            f"Bandit failed with exit code {bandit_result.returncode}\n"
            f"   Output: {bandit_result.stderr[-500:]}"
        )

    # Parse Bandit output for HIGH/CRITICAL severity issues
    if bandit_result.returncode == 1:
        output = bandit_result.stdout
        if "Severity: High" in output or "Severity: Critical" in output:
            raise AssertionError(
                "Bandit found HIGH/CRITICAL security issues:\n"
                f"   {output[-1000:]}\n\n"  # Last 1000 chars
                "   Fix security issues before release"
            )

    print("   Running TruffleHog secrets scan...")

    # Check if TruffleHog is available
    trufflehog_check = subprocess.run(
        ["which", "trufflehog"], capture_output=True, text=True
    )

    if trufflehog_check.returncode == 0:
        # Run TruffleHog on repository
        trufflehog_result = subprocess.run(
            [
                "trufflehog",
                "filesystem",
                ".",
                "--json",
                "--exclude-paths",
                ".trufflehog-exclude.txt",
            ],
            capture_output=True,
            text=True,
        )

        # Parse JSON output for verified secrets
        verified_secrets = []
        for line in trufflehog_result.stdout.split("\n"):
            if line.strip():
                try:
                    finding = json.loads(line)
                    if finding.get("Verified"):
                        verified_secrets.append(finding)
                except json.JSONDecodeError:
                    pass  # Ignore malformed lines

        if verified_secrets:
            raise AssertionError(
                f"Found {len(verified_secrets)} VERIFIED secrets in codebase:\n"
                + "\n".join(
                    f"   - {s.get('DetectorName')}: {s.get('Raw')[:50]}..."
                    for s in verified_secrets[:5]  # Show first 5
                )
                + "\n\n   Remove secrets before release"
            )
    else:
        print(
            "   WARNING: TruffleHog not installed, skipping secrets scan\n"
            "   Install: brew install trufflehog (macOS) or see docs/QUICKSTART.md"
        )

    print("✅ No security issues detected (Bandit passed, no verified secrets)")


def check_ci_passing() -> None:
    """Verify latest CI run on main branch passed."""
    print("   Checking latest CI run status...")

    # Check if GitHub CLI is available
    gh_check = subprocess.run(["which", "gh"], capture_output=True, text=True)

    if gh_check.returncode != 0:
        print(
            "   WARNING: GitHub CLI (gh) not installed, skipping CI check\n"
            "   Install: brew install gh (macOS) or see https://cli.github.com/"
        )
        return

    # Use GitHub CLI to check latest workflow run
    result = subprocess.run(
        [
            "gh",
            "run",
            "list",
            "--branch",
            "main",
            "--limit",
            "1",
            "--json",
            "conclusion",
        ],
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        raise AssertionError(
            f"Failed to fetch CI status (gh run list failed):\n   {result.stderr}"
        )

    try:
        runs = json.loads(result.stdout)
        if not runs:
            print("   WARNING: No CI runs found on main branch, skipping CI check")
            return

        conclusion = runs[0]["conclusion"]
        if conclusion != "success":
            raise AssertionError(
                f"Latest CI run on main branch: {conclusion}\n"
                "   Fix CI failures before release\n"
                "   View: gh run list --branch main"
            )

        print(f"✅ CI passing on main branch (status: {conclusion})")
    except (json.JSONDecodeError, KeyError, IndexError) as e:
        raise AssertionError(
            f"Failed to parse CI status: {e}\n   Output: {result.stdout}"
        )


def main() -> int:
    """Run all pre-release checks."""
    checks: List[Tuple[str, Callable[[], None]]] = [
        ("Version Consistency", check_version_consistency),
        ("Test Coverage ≥90%", check_test_coverage),
        ("Documentation Complete", check_documentation_completeness),
        ("No Security Issues", check_no_known_security_issues),
        ("CI Passing", check_ci_passing),
    ]

    print("=" * 70)
    print("JMo Security - Pre-Release Validation Checks")
    print("=" * 70)
    print()

    failed: List[str] = []
    passed: List[str] = []

    for name, check in checks:
        print(f"Running: {name}")
        try:
            check()
            passed.append(name)
        except AssertionError as e:
            print(f"❌ {name}: FAILED")
            print(f"   {e}\n")
            failed.append(name)
        except Exception as e:
            print(f"❌ {name}: ERROR")
            print(f"   Unexpected error: {e}\n")
            failed.append(name)
        print()

    print("=" * 70)
    print("Pre-Release Check Summary")
    print("=" * 70)
    print(f"✅ Passed: {len(passed)}/{len(checks)}")
    if failed:
        print(f"❌ Failed: {len(failed)}/{len(checks)}")
        print("\nFailed checks:")
        for name in failed:
            print(f"   - {name}")

    print()

    if failed:
        print("❌ PRE-RELEASE CHECKS FAILED")
        print("   Fix issues above before tagging release\n")
        return 1
    else:
        print("✅ ALL PRE-RELEASE CHECKS PASSED")
        print("   Ready to tag and release v1.0.0!\n")
        return 0


if __name__ == "__main__":
    sys.exit(main())
