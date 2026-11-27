"""Shared fixtures for e2e tests.

Provides:
- jmo_scan_runner: Execute jmo CLI scan commands and return (rc, stdout, stderr, results_dir)
- e2e_fixtures_dir: Path to e2e test fixtures
- validate_basic_scan: Helper to assert a scan scanned a target and wrote valid output
- validate_multi_target: Helper to assert multi-target scan output
- validate_scanners_found: Helper to assert named tools ran on every target and found something
- validate_every_target_found_something: Helper to assert each scanned target has a finding
- current_platform: Return current platform as linux/darwin/win32

Note: ``jmo_scan_runner`` is intentionally named differently from the root-level
``jmo_runner`` (tests/conftest.py) to avoid shadowing. The root fixture returns
``subprocess.CompletedProcess``; this one returns a tuple with auto-created results_dir.
"""

from __future__ import annotations

import atexit
import json
import shutil
import sys
import tempfile
from collections import Counter
from pathlib import Path

import pytest


def _outside_any_work_tree(source: Path) -> Path:
    """A copy of the fixtures in a temporary directory, made once per process.

    opengrep 2.0.0 matches its built-in ignore list (`tests/`, `build/`, ...)
    against a target's path from the root of the git work tree that holds it, so a
    fixture under this repository's `tests/` scanned 0 files however it was named
    (measured 2026-11-17, docs/KNOWN_LIMITATIONS.md). A user's repository is
    under no such tree; neither is this copy."""
    root = Path(tempfile.mkdtemp(prefix="jmo-e2e-fixtures-"))
    atexit.register(shutil.rmtree, root, ignore_errors=True)
    return Path(shutil.copytree(source, root / "fixtures"))


# E2E fixture directory: the copy every E2E module scans.
E2E_FIXTURES = _outside_any_work_tree(Path(__file__).parent / "fixtures")


@pytest.fixture
def e2e_fixtures_dir() -> Path:
    """Return path to e2e test fixtures directory."""
    return E2E_FIXTURES


@pytest.fixture
def jmo_scan_runner(tmp_path, jmo_runner):
    """Execute jmo CLI and return (rc, stdout, stderr, results_dir).

    This e2e-specific fixture automatically creates a results directory under
    ``tmp_path`` and appends ``--results-dir`` to every invocation.  The caller
    only needs to supply the meaningful command arguments.

    It runs through ``jmo_runner``: a home of the test's own, with the
    developer's installed scanners linked in, and ``tmp_path`` as the working
    directory. With the real home, U4's zap run created the real
    ``~/.jmo/zap-home`` and failed the guard at teardown (#1425).

    Usage::

        def test_scan(jmo_scan_runner):
            rc, stdout, stderr, results_dir = jmo_scan_runner(["ci", "--repo", "."])
            assert rc in (0, 1)
    """

    def _run(args: list[str], timeout: int = 900) -> tuple[int, str, str, Path]:
        results_dir = tmp_path / "results"
        results_dir.mkdir(exist_ok=True)

        result = jmo_runner([*args, "--results-dir", str(results_dir)], timeout=timeout)

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


# Per-target directories whose entries are repository clones. ``--repo`` writes
# to the first; ``--gitlab-repo`` clones the repository and writes to the second,
# leaving ``individual-repos`` empty.
REPOSITORY_TARGET_DIRS = ("individual-repos", "individual-gitlab")


def validate_basic_scan(results_dir: Path) -> None:
    """Validate that a scan scanned something and wrote its outputs.

    ``jmo ci`` exits 1 and still writes well-formed, empty outputs when every
    target it was given is rejected (a URL where ``--repo`` takes a path), so
    files that exist prove nothing. This reads what the scan says it scanned:
    ``meta.target_count`` must be at least 1, and a repository target (a
    directory under ``individual-repos/`` or ``individual-gitlab/``) must have
    produced findings.
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

    repo_targets = [
        f"{kind}/{p.name}"
        for kind in REPOSITORY_TARGET_DIRS
        if (results_dir / kind).is_dir()
        for p in sorted((results_dir / kind).iterdir())
        if p.is_dir()
    ]
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


def tool_runs(results_dir: Path) -> list[dict]:
    """Every (tool, target) row of `.scan_metadata.json`."""
    metadata = json.loads((results_dir / ".scan_metadata.json").read_bytes())
    return metadata["tool_runs"]


def validate_scanners_found(results_dir: Path, tools: tuple[str, ...]) -> None:
    """Each named tool ran on every target it was given, and found something.

    `validate_basic_scan` asks a target that is not a repository only for
    ``meta.target_count``, and a scan under ``--allow-missing-tools`` exits 0
    with every tool missing, so an image or IaC case passed having run nothing:
    the gap #1550 closed for U4 alone. Rows are read per target, since
    `scanner_states` keeps only the last row of a tool. A finding count is a
    floor of one, not a number: the image's CVEs and the scanners' rules move.
    """
    rows = tool_runs(results_dir)
    _, findings = _read_summary(results_dir)
    found_by = Counter(f["tool"]["name"] for f in findings)
    for tool in tools:
        mine = [r for r in rows if r["tool"] == tool]
        assert mine, f"{tool} has no row in .scan_metadata.json: it was not planned"
        not_ran = {r["target"]: r["state"] for r in mine if r["state"] != "ran"}
        assert not not_ran, f"{tool} did not run on every target: {not_ran}"
        assert found_by[tool] >= 1, (
            f"{tool} ran and contributed no finding; findings by tool: {dict(found_by)}"
        )


def validate_every_target_found_something(results_dir: Path) -> None:
    """Every target the scan planned produced at least one finding.

    A finding names its target in a sanitized form (``alpine_3.19`` for the
    row's ``alpine:3.19``), so this compares how many targets have findings
    with how many the scan ran, rather than the names themselves.
    """
    planned = {(r["target_type"], r["target"]) for r in tool_runs(results_dir)}
    _, findings = _read_summary(results_dir)
    # A finding without a target names none, so it cannot stand for one.
    found = {
        (f["target"].get("type"), f["target"].get("name"))
        for f in findings
        if isinstance(f.get("target"), dict) and f["target"].get("name")
    }
    assert len(found) >= len(planned), (
        f"{len(planned)} target(s) scanned, {len(found)} with findings: "
        f"planned {sorted(planned)}, found {sorted(found, key=str)}"
    )


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
