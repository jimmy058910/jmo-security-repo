"""Shared fixtures for e2e tests.

Provides:
- jmo_scan_runner: Execute jmo CLI scan commands and return (rc, stdout, stderr, results_dir)
- e2e_fixtures_dir: Path to e2e test fixtures
- validate_basic_scan: Helper to assert a scan scanned a target and wrote valid output
- validate_multi_target: Helper to assert multi-target scan output
- current_platform: Return current platform as linux/darwin/win32

Note: ``jmo_scan_runner`` is intentionally named differently from the root-level
``jmo_runner`` (tests/conftest.py) to avoid shadowing. The root fixture returns
``subprocess.CompletedProcess``; this one returns a tuple with auto-created results_dir.
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
def jmo_scan_runner(tmp_path):
    """Execute jmo CLI and return (rc, stdout, stderr, results_dir).

    This e2e-specific fixture automatically creates a results directory under
    ``tmp_path`` and appends ``--results-dir`` to every invocation.  The caller
    only needs to supply the meaningful command arguments.

    Usage::

        def test_scan(jmo_scan_runner):
            rc, stdout, stderr, results_dir = jmo_scan_runner(["ci", "--repo", "."])
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


def _read_summary(results_dir: Path) -> tuple[dict, list]:
    """Return ``(meta, findings)`` from ``summaries/findings.json``.

    The file is ``{"meta": {...}, "findings": [...]}``. Anything else is a
    failure: a bare list carries no ``meta``, so it cannot say what was scanned.
    """
    findings_file = results_dir / "summaries" / "findings.json"
    assert findings_file.exists(), f"findings.json not found in {findings_file.parent}"

    data = json.loads(findings_file.read_bytes())
    assert isinstance(data, dict) and isinstance(data.get("findings"), list), (
        f"expected {findings_file} to be a JSON object with a 'findings' list, "
        f"read {type(data).__name__}"
    )
    meta = data.get("meta")
    assert isinstance(meta, dict), (
        f"expected {findings_file} to carry a 'meta' object, read keys {sorted(data)}"
    )
    return meta, data["findings"]


def validate_basic_scan(results_dir: Path) -> None:
    """Validate that a scan scanned something and wrote its outputs.

    ``jmo ci`` exits 1 and still writes well-formed, empty outputs when every
    target it was given is rejected (a URL where ``--repo`` takes a path), so
    files that exist prove nothing. This reads what the scan says it scanned:
    ``meta.target_count`` must be at least 1, and a repository target (an
    ``individual-repos/<name>/`` directory) must have produced findings.
    """
    findings_file = results_dir / "summaries" / "findings.json"
    meta, findings = _read_summary(results_dir)

    target_count = meta.get("target_count")
    assert (
        isinstance(target_count, int)
        and not isinstance(target_count, bool)
        and target_count >= 1
    ), (
        "expected meta.target_count >= 1 (the scan scanned at least one target), "
        f"read {target_count!r} in {findings_file}"
    )

    repos_dir = results_dir / "individual-repos"
    repo_targets = (
        sorted(p.name for p in repos_dir.iterdir() if p.is_dir())
        if repos_dir.is_dir()
        else []
    )
    if repo_targets:
        assert findings, (
            f"expected findings from the repository target(s) {repo_targets}, "
            f"read 0 findings in {findings_file}"
        )

    summaries = results_dir / "summaries"
    summary_file = summaries / "SUMMARY.md"
    assert summary_file.exists(), f"SUMMARY.md not found in {summaries}"

    dashboard_file = summaries / "dashboard.html"
    assert dashboard_file.exists(), f"dashboard.html not found in {summaries}"


def validate_multi_target(results_dir: Path) -> None:
    """Validate multi-target scan output."""
    validate_basic_scan(results_dir)

    _, findings = _read_summary(results_dir)
    if findings:
        fingerprints = [
            f.get("fingerprint_id") for f in findings if f.get("fingerprint_id")
        ]
        assert len(fingerprints) == len(set(fingerprints)), (
            "Duplicate fingerprint IDs found"
        )


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
