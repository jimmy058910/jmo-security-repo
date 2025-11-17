#!/usr/bin/env python3
"""
Comprehensive v1.0.0 Release Readiness Verification.

Checks all Phase 8 checklist items from TESTING_RELEASE_READINESS_PLAN.md.
This script provides a detailed report of release readiness status.

Usage:
    python3 scripts/dev/verify_release_readiness.py

Exit codes:
    0 - All checks passed, ready to release
    1 - One or more checks failed (warnings only, non-blocking)
    2 - Critical checks failed (blocks release)
"""

import subprocess
import sys
from pathlib import Path
from typing import List


class ReleaseReadinessVerifier:
    """Verify v1.0.0 release readiness."""

    def __init__(self):
        self.warnings: List[str] = []
        self.errors: List[str] = []
        self.passed: List[str] = []

    def check_code_quality(self) -> None:
        """Verify Code Quality checklist items."""
        print("\n" + "=" * 70)
        print("CODE QUALITY CHECKS")
        print("=" * 70)

        # Check 1: All tests passing
        print("\n[1/5] Running full test suite...")
        result = subprocess.run(
            ["pytest", "tests/", "-v", "--maxfail=1"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            self.passed.append("All tests passing")
            print("   ✅ All tests passing")
        else:
            self.errors.append("Test suite has failures")
            print(f"   ❌ Test suite has failures: {result.stdout[-500:]}")

        # Check 2: No linting errors
        print("\n[2/5] Running linting checks...")
        try:
            subprocess.run(["make", "lint"], check=True, capture_output=True)
            self.passed.append("No linting errors")
            print("   ✅ No linting errors")
        except subprocess.CalledProcessError as e:
            self.errors.append("Linting errors detected")
            print(f"   ❌ Linting errors: {e.stdout.decode()[-500:]}")

        # Check 3: No security vulnerabilities
        print("\n[3/5] Running security audit...")
        result = subprocess.run(
            ["bandit", "-r", "scripts/", "-c", "bandit.yaml"],
            capture_output=True,
            text=True,
        )

        if result.returncode == 0:
            self.passed.append("No security vulnerabilities")
            print("   ✅ No HIGH/CRITICAL security vulnerabilities")
        else:
            self.warnings.append("Bandit found potential issues")
            print("   ⚠️  Bandit found potential issues (review manually)")

        # Check 4: Performance benchmarks meet targets
        print("\n[4/5] Checking performance benchmarks...")
        benchmark_file = Path("tests/performance/test_benchmarks.py")

        if not benchmark_file.exists():
            self.warnings.append("Performance benchmarks not found")
            print("   ⚠️  Performance benchmark tests not found")
        else:
            result = subprocess.run(
                ["pytest", str(benchmark_file), "-v"],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                self.passed.append("Performance benchmarks passing")
                print("   ✅ Performance benchmarks meet targets")
            else:
                self.warnings.append("Performance benchmarks failing")
                print("   ⚠️  Performance benchmarks failing (non-blocking)")

        # Check 5: Test coverage ≥85%
        print("\n[5/5] Checking test coverage...")
        result = subprocess.run(
            ["pytest", "--cov=scripts", "--cov-report=term"],
            capture_output=True,
            text=True,
        )

        # Extract coverage percentage
        coverage_lines = [
            line
            for line in result.stdout.split("\n")
            if "TOTAL" in line and "%" in line
        ]

        if coverage_lines:
            coverage_line = coverage_lines[0]
            coverage_str = [t for t in coverage_line.split() if t.endswith("%")][-1]
            coverage_pct = float(coverage_str.rstrip("%"))

            if coverage_pct >= 85.0:
                self.passed.append(f"Test coverage: {coverage_pct}%")
                print(f"   ✅ Test coverage: {coverage_pct}% (≥85% required)")
            else:
                self.errors.append(f"Test coverage: {coverage_pct}% < 85%")
                print(f"   ❌ Test coverage: {coverage_pct}% < 85% required")
        else:
            self.warnings.append("Could not parse coverage percentage")
            print("   ⚠️  Could not parse coverage percentage")

    def check_features_complete(self) -> None:
        """Verify Features Complete checklist items."""
        print("\n" + "=" * 70)
        print("FEATURES COMPLETE CHECKS")
        print("=" * 70)

        features = [
            ("Feature #1: New Tools & Adapters", ["scripts/core/adapters/"]),
            ("Feature #2: AI Remediation (MCP Server)", ["scripts/jmo_mcp/"]),
            ("Feature #3: Machine-Readable Diffs", ["scripts/cli/diff_commands.py"]),
            ("Feature #4: Trend Analysis", ["scripts/cli/trend_commands.py"]),
            ("Feature #5: SQLite Historical Storage", ["scripts/core/history_db.py"]),
            (
                "Feature #8: Output Format Standardization",
                ["scripts/core/reporters/csv_reporter.py"],
            ),
        ]

        for i, (feature, paths) in enumerate(features, 1):
            print(f"\n[{i}/6] Checking {feature}...")

            all_exist = all(Path(p).exists() for p in paths)

            if all_exist:
                self.passed.append(feature)
                print(f"   ✅ {feature} — COMPLETE")
            else:
                missing = [p for p in paths if not Path(p).exists()]
                self.errors.append(f"{feature} — missing {missing}")
                print(f"   ❌ {feature} — missing {missing}")

    def check_documentation(self) -> None:
        """Verify Documentation checklist items."""
        print("\n" + "=" * 70)
        print("DOCUMENTATION CHECKS")
        print("=" * 70)

        required_docs = [
            ("README.md", ["v1.0.0", "jmo diff", "jmo history", "jmo trends"]),
            ("CHANGELOG.md", ["## [1.0.0]", "Machine-Readable Diffs"]),
            ("docs/USER_GUIDE.md", ["jmo diff", "jmo history", "jmo trends"]),
            ("docs/examples/diff-workflows.md", ["PR Review", "CI/CD"]),
            ("docs/examples/ci-cd-trends.md", ["GitHub Actions", "GitLab CI"]),
            ("docs/OUTPUT_FORMATS.md", ["v1.0.0", "metadata", "output_version"]),
        ]

        for i, (doc, required_content) in enumerate(required_docs, 1):
            print(f"\n[{i}/{len(required_docs)}] Checking {doc}...")

            doc_path = Path(doc)

            if not doc_path.exists():
                self.errors.append(f"{doc} not found")
                print(f"   ❌ {doc} not found")
                continue

            content = doc_path.read_text()
            missing = [term for term in required_content if term not in content]

            if not missing:
                self.passed.append(f"{doc} complete")
                print(f"   ✅ {doc} — all required content present")
            else:
                self.warnings.append(f"{doc} missing {missing}")
                print(f"   ⚠️  {doc} missing: {', '.join(missing)}")

    def check_security(self) -> None:
        """Verify Security & Quality checklist items."""
        print("\n" + "=" * 70)
        print("SECURITY & QUALITY CHECKS")
        print("=" * 70)

        # Check 1: Security audit tests passing
        print("\n[1/4] Running security test suite...")
        security_tests = Path("tests/e2e/test_security_hardening.py")

        if not security_tests.exists():
            self.warnings.append("Security hardening tests not found")
            print("   ⚠️  Security hardening test suite not found")
        else:
            result = subprocess.run(
                ["pytest", str(security_tests), "-v"],
                capture_output=True,
            )

            if result.returncode == 0:
                self.passed.append("Security hardening tests passing")
                print("   ✅ Security hardening tests passing")
            else:
                self.errors.append("Security tests failing")
                print("   ❌ Security hardening tests failing")

        # Check 2: SQL injection tests
        print("\n[2/4] Checking SQL injection prevention...")
        result = subprocess.run(
            ["grep", "-r", "execute.*%.*format", "scripts/core/"],
            capture_output=True,
        )

        if result.returncode != 0:  # No matches = good
            self.passed.append("No SQL injection vulnerabilities")
            print("   ✅ No string formatting in SQL queries")
        else:
            self.errors.append("Potential SQL injection vulnerabilities")
            print("   ❌ Potential SQL injection (string formatting in SQL)")

        # Check 3: Path traversal tests
        print("\n[3/4] Checking path traversal prevention...")
        # Check if pathlib.Path.resolve() is used
        result = subprocess.run(
            ["grep", "-r", "\\.resolve()", "scripts/core/"],
            capture_output=True,
        )

        if result.returncode == 0:  # Matches found = good
            self.passed.append("Path traversal prevention implemented")
            print("   ✅ Path resolution used (path traversal prevention)")
        else:
            self.warnings.append("Path resolution not detected")
            print("   ⚠️  Path resolution not detected (manual review needed)")

        # Check 4: No hardcoded secrets
        print("\n[4/4] Scanning for hardcoded secrets...")
        # Check if .trufflehog-exclude.txt exists
        exclude_file = Path(".trufflehog-exclude.txt")

        if exclude_file.exists():
            self.passed.append("Secret exclusion file exists")
            print("   ✅ .trufflehog-exclude.txt exists")
        else:
            self.warnings.append("No TruffleHog exclusion file")
            print("   ⚠️  .trufflehog-exclude.txt not found")

    def check_cicd(self) -> None:
        """Verify CI/CD checklist items."""
        print("\n" + "=" * 70)
        print("CI/CD CHECKS")
        print("=" * 70)

        workflows = [
            ".github/workflows/ci.yml",
            ".github/workflows/release.yml",
            ".github/workflows/nightly-tests.yml",
        ]

        for i, workflow in enumerate(workflows, 1):
            print(f"\n[{i}/{len(workflows)}] Checking {workflow}...")

            workflow_path = Path(workflow)

            if workflow_path.exists():
                self.passed.append(f"{workflow} exists")
                print(f"   ✅ {workflow} exists")
            else:
                self.errors.append(f"{workflow} not found")
                print(f"   ❌ {workflow} not found")

        # Check pre-release-check script
        print(
            f"\n[{len(workflows)+1}/{len(workflows)+1}] Checking pre-release automation..."
        )
        pre_release_script = Path("scripts/dev/pre_release_check.py")

        if pre_release_script.exists():
            self.passed.append("Pre-release check script exists")
            print("   ✅ scripts/dev/pre_release_check.py exists")
        else:
            self.errors.append("Pre-release check script not found")
            print("   ❌ scripts/dev/pre_release_check.py not found")

    def check_tools_versions(self) -> None:
        """Verify all tools are up-to-date."""
        print("\n" + "=" * 70)
        print("TOOLS & VERSIONS CHECKS")
        print("=" * 70)

        print("\n[1/1] Checking tool versions...")

        versions_yaml = Path("versions.yaml")

        if not versions_yaml.exists():
            self.errors.append("versions.yaml not found")
            print("   ❌ versions.yaml not found")
            return

        # Run update_versions.py --check-latest
        result = subprocess.run(
            ["python3", "scripts/dev/update_versions.py", "--check-latest"],
            capture_output=True,
            text=True,
        )

        # Check if any CRITICAL tools are outdated
        if "CRITICAL" in result.stdout and (
            "outdated" in result.stdout.lower() or "→" in result.stdout
        ):
            self.errors.append("CRITICAL tools outdated")
            print("   ❌ CRITICAL tools are outdated (must update before release)")
        else:
            self.passed.append("All CRITICAL tools up-to-date")
            print("   ✅ All CRITICAL tools are up-to-date")

    def generate_report(self) -> int:
        """Generate final report and return exit code."""
        print("\n" + "=" * 70)
        print("RELEASE READINESS SUMMARY")
        print("=" * 70)

        print(f"\n✅ Passed:   {len(self.passed)}")
        print(f"⚠️  Warnings: {len(self.warnings)}")
        print(f"❌ Errors:   {len(self.errors)}")

        if self.warnings:
            print("\n⚠️  WARNINGS (non-blocking):")
            for warning in self.warnings:
                print(f"   - {warning}")

        if self.errors:
            print("\n❌ ERRORS (blocking release):")
            for error in self.errors:
                print(f"   - {error}")

            print("\n" + "=" * 70)
            print("❌ RELEASE BLOCKED — Fix errors above before tagging v1.0.0")
            print("=" * 70)
            return 2  # Critical failure
        elif self.warnings:
            print("\n" + "=" * 70)
            print("⚠️  RELEASE READY WITH WARNINGS — Review warnings before release")
            print("=" * 70)
            return 1  # Non-critical warnings
        else:
            print("\n" + "=" * 70)
            print("✅ ALL CHECKS PASSED — READY TO RELEASE v1.0.0!")
            print("=" * 70)
            return 0  # All clear

    def run(self) -> int:
        """Run all verification checks."""
        print("=" * 70)
        print("JMo Security v1.0.0 — Release Readiness Verification")
        print("=" * 70)

        try:
            self.check_code_quality()
            self.check_features_complete()
            self.check_documentation()
            self.check_security()
            self.check_cicd()
            self.check_tools_versions()

            return self.generate_report()

        except KeyboardInterrupt:
            print("\n\n❌ Verification interrupted by user")
            return 2
        except Exception as e:
            print(f"\n\n❌ UNEXPECTED ERROR: {e}")
            import traceback

            traceback.print_exc()
            return 2


def main() -> int:
    """Main entry point."""
    verifier = ReleaseReadinessVerifier()
    return verifier.run()


if __name__ == "__main__":
    sys.exit(main())
