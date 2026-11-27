"""E2E tests for CI gating with --fail-on threshold (U12).

`jmo ci` with a real scanner on the vulnerable Python fixture, as a CI job runs
it: the build reads the exit code. opengrep alone keeps the scan under a
second; on that fixture it reports 9 HIGH and 9 MEDIUM and no CRITICAL
(measured 2026-11-25 with opengrep 2.0.0 and JMo's rule bundle).

Both tests used to assert behind an `if`: when no findings file existed, or it
held no HIGH, nothing was checked, so a scan that found nothing passed. They
ran from the real home too. They now go through `jmo_scan_runner` (a home and
working directory of their own) and assert every time. The PR-time twin, with
the built-in jmo-native, is tests/cli/test_ci_fail_on_exit_codes.py.
"""

from __future__ import annotations

import json
from collections import Counter

import pytest

from tests.conftest import scanner_states
from tests.e2e.conftest import E2E_FIXTURES


def _gate(jmo_scan_runner, threshold: str) -> tuple[int, Counter, str]:
    rc, _stdout, stderr, results_dir = jmo_scan_runner(
        [
            "ci",
            "--repo",
            str(E2E_FIXTURES / "python"),
            "--tools",
            "opengrep",
            "--fail-on",
            threshold,
        ]
    )
    assert scanner_states(results_dir) == {"opengrep": "ran"}, stderr[-2000:]
    findings = json.loads((results_dir / "summaries" / "findings.json").read_bytes())[
        "findings"
    ]
    return rc, Counter(f["severity"] for f in findings), stderr


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.requires_tools
class TestCIGating:
    """Test CI mode with --fail-on severity threshold."""

    def test_fail_on_high_with_vulnerable_target(self, jmo_scan_runner):
        """U12: CI mode exits 1 when HIGH findings are present."""
        rc, severities, stderr = _gate(jmo_scan_runner, "HIGH")
        assert severities["HIGH"] + severities["CRITICAL"] >= 1, severities
        assert rc == 1, stderr[-2000:]

    def test_fail_on_critical_exits_1_only_for_a_critical(self, jmo_scan_runner):
        """With --fail-on CRITICAL the exit code is 1 exactly when a CRITICAL
        was found (none today), whatever else the scan found."""
        rc, severities, stderr = _gate(jmo_scan_runner, "CRITICAL")
        assert severities["HIGH"] >= 1, severities  # the scan found something
        assert rc == (1 if severities["CRITICAL"] else 0), (severities, stderr[-2000:])
