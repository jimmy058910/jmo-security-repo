#!/usr/bin/env python3
"""
Comprehensive wizard tool testing script.

Tests all wizard functionality non-interactively:
- Tool detection and version parsing
- Isolated venv functionality
- Dependency checking (Java, Node.js, bash)
- Platform-specific tool handling

Usage:
    python scripts/dev/test_wizard_tools.py [--profile PROFILE] [--verbose]

Run this BEFORE 'jmo wizard' to verify tool infrastructure is working.
"""

from __future__ import annotations

import argparse
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

# Add project root to path for imports
_project_root = Path(__file__).parent.parent.parent
sys.path.insert(0, str(_project_root))

# Imports after path setup (noqa for linter)
from scripts.cli.tool_installer import (  # noqa: E402
    ISOLATED_TOOLS,
    get_isolated_tool_path,
    get_isolated_venv_path,
)
from scripts.cli.tool_manager import (  # noqa: E402
    ToolManager,
)
from scripts.core.tool_registry import PROFILE_TOOLS, ToolRegistry  # noqa: E402

if TYPE_CHECKING:
    pass


@dataclass
class TestResult:
    """Result of a single test."""

    name: str
    passed: bool
    message: str
    details: str = ""


class WizardToolTester:
    """Comprehensive tester for wizard tool functionality."""

    def __init__(self, verbose: bool = False):
        self.verbose = verbose
        self.tm = ToolManager()
        self.registry = ToolRegistry()
        self.results: list[TestResult] = []

    def log(self, msg: str) -> None:
        """Print message if verbose."""
        if self.verbose:
            print(f"  [DEBUG] {msg}")

    def add_result(
        self, name: str, passed: bool, message: str, details: str = ""
    ) -> None:
        """Add a test result."""
        self.results.append(TestResult(name, passed, message, details))

    def test_isolated_venv_structure(self) -> None:
        """Test that isolated venvs are set up correctly."""
        print("\n" + "=" * 60)
        print("TEST: Isolated Venv Structure")
        print("=" * 60)

        for tool_name in ISOLATED_TOOLS:
            venv_dir = get_isolated_venv_path(tool_name)
            tool_path = get_isolated_tool_path(tool_name)

            self.log(f"{tool_name}: venv_dir={venv_dir}, exists={venv_dir.exists()}")

            if not venv_dir.exists():
                self.add_result(
                    f"venv_{tool_name}",
                    False,
                    "Venv not created",
                    f"Expected at: {venv_dir}",
                )
                print(f"  [SKIP] {tool_name}: venv not installed")
                continue

            if tool_path and tool_path.exists():
                self.add_result(
                    f"venv_{tool_name}",
                    True,
                    "Executable found",
                    f"Path: {tool_path}",
                )
                print(f"  [OK] {tool_name}: {tool_path}")
            else:
                # Check what's in the Scripts/bin directory
                if sys.platform == "win32":
                    bin_dir = venv_dir / "Scripts"
                else:
                    bin_dir = venv_dir / "bin"

                if bin_dir.exists():
                    files = list(bin_dir.glob(f"{tool_name}*"))
                    if files:
                        self.add_result(
                            f"venv_{tool_name}",
                            False,
                            "Executable has different name",
                            f"Found: {[f.name for f in files]}",
                        )
                        print(f"  [WARN] {tool_name}: found {[f.name for f in files]}")
                    else:
                        self.add_result(
                            f"venv_{tool_name}",
                            False,
                            "No executable found",
                            f"Searched in: {bin_dir}",
                        )
                        print(f"  [FAIL] {tool_name}: no executable in {bin_dir}")
                else:
                    self.add_result(
                        f"venv_{tool_name}",
                        False,
                        "Bin directory missing",
                        f"Expected: {bin_dir}",
                    )
                    print(f"  [FAIL] {tool_name}: bin dir missing")

    def test_version_detection(self, profile: str) -> None:
        """Report each profile tool's status, as the product reports it.

        This used to probe `_find_binary` and `_get_tool_version` directly -
        two private helpers that answer narrower questions than `check_tool()`
        does - and so contradicted `jmo tools check` and, in one case, itself.
        Measured on Windows with the balanced profile (#1138):

            [MISS] zap: not installed      while tools check read zap OK 2.17.0
            [OK]   zap: ready to execute   in the SAME run
            cdxgen: version parse failed   while tools check read 12.8.2

        `check_tool()` is the product's own verdict and is memoised per tool, so
        asking it here and again in the readiness test costs a cache hit rather
        than a second probe - and the two can no longer disagree.
        """
        print("\n" + "=" * 60)
        print(f"TEST: Version Detection ({profile} profile)")
        print("=" * 60)

        tools = PROFILE_TOOLS.get(profile, [])

        for tool_name in sorted(tools):
            status = self.tm.check_tool(tool_name)
            self.log(
                f"{tool_name}: installed={status.installed} "
                f"version={status.installed_version} "
                f"ready={status.execution_ready} "
                f"platform_supported={status.platform_supported}"
            )

            if not status.platform_supported:
                reason = (
                    status.platform_reason or f"not available on {self.tm.platform}"
                )
                print(f"  [SKIP] {tool_name}: {reason}")
                self.add_result(
                    f"version_{tool_name}",
                    True,  # Not a failure, just skipped
                    "Platform skip",
                    reason,
                )
                continue

            if not status.installed:
                print(f"  [MISS] {tool_name}: not installed")
                self.add_result(
                    f"version_{tool_name}",
                    False,
                    "Not installed",
                    status.execution_warning or "Binary not found",
                )
                continue

            expected = status.expected_version_display
            if not status.installed_version:
                # `check_tool` reaches this with the binary present and no
                # version: the probe crashed, timed out, or printed something
                # unparseable. Report the reason it gives rather than a bare
                # "parse failed".
                print(f"  [WARN] {tool_name}: no version reported")
                self.add_result(
                    f"version_{tool_name}",
                    False,
                    "No version reported",
                    status.execution_warning or f"Binary: {status.binary_path}",
                )
            elif status.is_outdated:
                print(
                    f"  [DRIFT] {tool_name}: {status.installed_version} "
                    f"(expected {expected})"
                )
                self.add_result(
                    f"version_{tool_name}",
                    True,  # Still working, just a different version
                    "Version drift",
                    f"Got {status.installed_version}, expected {expected}",
                )
            else:
                print(f"  [OK] {tool_name}: {status.installed_version}")
                self.add_result(
                    f"version_{tool_name}",
                    True,
                    f"Version {status.installed_version}",
                    f"Expected: {expected}",
                )

    def test_dependency_checks(self) -> None:
        """Test dependency verification (Java, Node.js, bash)."""
        print("\n" + "=" * 60)
        print("TEST: Dependency Verification")
        print("=" * 60)

        # Test Java (for dependency-check)
        print("\n  Java (required by dependency-check):")
        java_ver = self.tm._get_java_version()
        if java_ver:
            print(f"    [OK] Java {'.'.join(map(str, java_ver))} found")
            self.add_result("dep_java", True, f"Java {java_ver[0]}", "")
        else:
            print("    [MISS] Java not found")
            self.add_result(
                "dep_java",
                False,
                "Java not found",
                "Install JDK 11+ for dependency-check",
            )

        # Test Node.js (for cdxgen)
        print("\n  Node.js (required by cdxgen):")
        node_ver = self.tm._get_node_version()
        if node_ver:
            print(f"    [OK] Node.js {'.'.join(map(str, node_ver))} found")
            self.add_result("dep_nodejs", True, f"Node {node_ver[0]}", "")
        else:
            print("    [MISS] Node.js not found")
            self.add_result(
                "dep_nodejs",
                False,
                "Node.js not found",
                "Install Node.js 20+ for cdxgen",
            )

        # Test bash (for lynis on Windows)
        print("\n  Bash (required by lynis on Windows):")
        import shutil

        bash_path = shutil.which("bash")
        if bash_path:
            print(f"    [OK] Bash found at {bash_path}")
            self.add_result("dep_bash", True, "Bash available", bash_path)
        else:
            if sys.platform == "win32":
                print("    [MISS] Bash not found (lynis won't work)")
                self.add_result(
                    "dep_bash",
                    False,
                    "Bash not found",
                    "Install Git Bash, WSL, or Cygwin",
                )
            else:
                print("    [OK] Unix system (bash assumed)")
                self.add_result("dep_bash", True, "Unix system", "")

    def test_tool_execution_readiness(self, profile: str) -> None:
        """Test _verify_execution for tools with special requirements."""
        print("\n" + "=" * 60)
        print(f"TEST: Execution Readiness ({profile} profile)")
        print("=" * 60)

        # Tools with special requirements
        special_tools = ["cdxgen", "lynis", "dependency-check", "zap"]
        tools = PROFILE_TOOLS.get(profile, [])

        for tool_name in special_tools:
            if tool_name not in tools:
                continue

            # `check_tool`, not `_verify_execution`. The private helper answers
            # "would this run if it were installed"; the product's verdict also
            # accounts for the tool being absent. Asking the narrower question
            # is what let this script print `[MISS] zap: not installed` and
            # `[OK] zap: ready to execute` in one run (#1138).
            status = self.tm.check_tool(tool_name)
            self.log(
                f"{tool_name}: installed={status.installed} "
                f"ready={status.execution_ready} warning={status.execution_warning}"
            )

            if not status.platform_supported:
                print(f"  [SKIP] {tool_name}: not available on {self.tm.platform}")
                self.add_result(f"exec_{tool_name}", True, "Platform skip", "")
            elif status.execution_ready:
                print(f"  [OK] {tool_name}: ready to execute")
                self.add_result(f"exec_{tool_name}", True, "Ready", "")
            else:
                reason = status.execution_warning or "not ready"
                print(f"  [BLOCK] {tool_name}: {reason}")
                self.add_result(
                    f"exec_{tool_name}",
                    False,
                    "Not ready",
                    f"{reason} (missing: {status.missing_deps})",
                )

    def print_summary(self) -> dict:
        """Print test summary and return stats."""
        print("\n" + "=" * 60)
        print("SUMMARY")
        print("=" * 60)

        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)

        print(f"\nTotal: {total} tests")
        print(f"  Passed: {passed}")
        print(f"  Failed: {failed}")

        if failed > 0:
            print("\nFailed tests:")
            for r in self.results:
                if not r.passed:
                    print(f"  - {r.name}: {r.message}")
                    if r.details and self.verbose:
                        print(f"    Details: {r.details}")

        return {"total": total, "passed": passed, "failed": failed}

    def run_all(self, profile: str) -> dict:
        """Run all tests."""
        print("\n" + "#" * 60)
        print("# JMo Security - Wizard Tool Infrastructure Test")
        print("#" * 60)
        print(f"\nProfile: {profile}")
        print(f"Platform: {self.tm.platform}")
        print(f"Tools in profile: {len(PROFILE_TOOLS.get(profile, []))}")

        self.test_isolated_venv_structure()
        self.test_version_detection(profile)
        self.test_dependency_checks()
        self.test_tool_execution_readiness(profile)

        return self.print_summary()


def main() -> int:
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="Test wizard tool detection comprehensively"
    )
    parser.add_argument(
        "--profile",
        default="balanced",
        choices=["fast", "slim", "balanced", "deep"],
        help="Scan profile to test (default: balanced)",
    )
    parser.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        help="Show detailed debug output",
    )

    args = parser.parse_args()

    tester = WizardToolTester(verbose=args.verbose)
    stats = tester.run_all(args.profile)

    print("\n" + "=" * 60)
    if stats["failed"] == 0:
        print("All tests passed! You can now run: jmo wizard")
        return 0
    else:
        print(f"{stats['failed']} test(s) failed. Review issues above.")
        print("\nNext steps:")
        # Derived from what actually failed. This was three hardcoded lines
        # printed whenever anything failed, so a run that had just reported
        # `[OK] Java 21.0.12 found` went on to advise "Install Java 11+ for
        # dependency-check" (#1138).
        steps = []
        failed = {r.name for r in tester.results if not r.passed}
        if any(n.startswith("version_") for n in failed):
            steps.append(
                "Install missing tools: jmo tools install --profile " + args.profile
            )
        for dep, hint in (
            ("dep_java", "Install Java 11+ (dependency-check and zap need it)"),
            ("dep_nodejs", "Install Node.js 20+ (cdxgen needs it)"),
            ("dep_bash", "Install Git Bash, WSL or Cygwin (lynis needs bash)"),
        ):
            if dep in failed:
                steps.append(hint)
        if any(n.startswith("venv_") for n in failed):
            steps.append(
                "Rebuild isolated venvs: jmo tools clean --force, "
                "then jmo tools install --profile " + args.profile
            )
        steps.append("Re-run this test to verify fixes")

        for i, step in enumerate(steps, 1):
            print(f"  {i}. {step}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
