"""Shared fixtures for e2e tests.

Provides:
- jmo_runner: Execute jmo CLI commands and return results
- e2e_fixtures_dir: Path to e2e test fixtures
- validate_basic_scan: Helper to assert scan output files exist and are valid
- validate_multi_target: Helper to assert multi-target scan output
- current_platform: Return current platform as linux/darwin/win32

Note: This conftest defines an e2e-specific ``jmo_runner`` fixture that returns
a (rc, stdout, stderr, results_dir) tuple.  The root-level ``tests/conftest.py``
has a simpler ``jmo_runner`` that returns a ``subprocess.CompletedProcess``; the
e2e version intentionally shadows it within this package.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

# E2E fixture directory
E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def e2e_fixtures_dir() -> Path:
    """Return path to e2e test fixtures directory."""
    return E2E_FIXTURES


@pytest.fixture
def jmo_runner(tmp_path):
    """Execute jmo CLI and return (rc, stdout, stderr, results_dir).

    This e2e-specific fixture automatically creates a results directory under
    ``tmp_path`` and appends ``--results-dir`` to every invocation.  The caller
    only needs to supply the meaningful command arguments.

    Usage::

        def test_scan(jmo_runner):
            rc, stdout, stderr, results_dir = jmo_runner([
                "ci", "--repo", ".", "--profile", "fast"
            ])
            assert rc in (0, 1)
    """

    def _run(args: list[str], timeout: int = 900) -> tuple[int, str, str, Path]:
        results_dir = tmp_path / "results"
        results_dir.mkdir(exist_ok=True)

        full_args = [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            *args,
            "--results-dir",
            str(results_dir),
        ]

        result = subprocess.run(
            full_args,
            capture_output=True,
            text=True,
            timeout=timeout,
            cwd=str(tmp_path),
        )

        return result.returncode, result.stdout, result.stderr, results_dir

    return _run


# ============================================================================
# Assertion Helpers (not fixtures — call directly in test bodies)
# ============================================================================


def validate_basic_scan(results_dir: Path) -> None:
    """Validate basic scan output files exist and are valid JSON.

    Checks:
    - findings.json exists and is valid JSON
    - findings.json contains a JSON array
    - SUMMARY.md exists
    - dashboard.html exists

    Args:
        results_dir: Path returned by ``jmo_runner``.
    """
    findings_file = results_dir / "findings.json"
    assert findings_file.exists(), f"findings.json not found in {results_dir}"

    findings = json.loads(findings_file.read_text())
    assert isinstance(findings, list), "findings.json must be a JSON array"

    summary_file = results_dir / "SUMMARY.md"
    assert summary_file.exists(), f"SUMMARY.md not found in {results_dir}"

    dashboard_file = results_dir / "dashboard.html"
    assert dashboard_file.exists(), f"dashboard.html not found in {results_dir}"


def validate_multi_target(results_dir: Path) -> None:
    """Validate multi-target scan output.

    Checks all basic scan validations plus:
    - No duplicate finding fingerprints across all findings.

    Args:
        results_dir: Path returned by ``jmo_runner``.
    """
    validate_basic_scan(results_dir)

    findings_file = results_dir / "findings.json"
    findings = json.loads(findings_file.read_text())

    if findings:
        fingerprints = [
            f.get("fingerprint_id") for f in findings if f.get("fingerprint_id")
        ]
        assert len(fingerprints) == len(
            set(fingerprints)
        ), "Duplicate fingerprint IDs found"


def current_platform() -> str:
    """Return current platform identifier as linux/darwin/win32."""
    return sys.platform


def pytest_terminal_summary(terminalreporter, exitstatus, config):
    """Generate e2e markdown report after test run."""
    report_path = getattr(config.option, "json_report_file", None)
    if report_path is None:
        return

    # Report generation is handled by pytest-json-report
    # This hook adds a release readiness check
    stats = terminalreporter.stats
    passed = len(stats.get("passed", []))
    failed = len(stats.get("failed", []))
    total = passed + failed

    if total > 0:
        pass_rate = (passed / total) * 100
        status = "PASS" if pass_rate >= 95.0 else "FAIL"
        terminalreporter.write_line("")
        terminalreporter.write_line(
            f"E2E Release Readiness: {status} ({pass_rate:.1f}% pass rate, "
            f"threshold: 95%)"
        )
