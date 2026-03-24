"""E2E tests for CI gating with --fail-on threshold.

Replaces bash test U12.
Verifies that jmo ci returns exit code 1 when findings exceed the severity threshold.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
@pytest.mark.slow
class TestCIGating:
    """Test CI mode with --fail-on severity threshold."""

    def test_fail_on_high_with_vulnerable_target(self, tmp_path):
        """U12: CI mode exits 1 when HIGH findings present."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "ci",
                "--repo",
                str(E2E_FIXTURES / "python"),
                "--profile",
                "fast",
                "--fail-on",
                "HIGH",
                "--allow-missing-tools",
                "--results-dir",
                str(results_dir),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        # Should exit 1 (findings above threshold) or 0 (no HIGH findings)
        # The vulnerable fixtures contain known HIGH severity issues
        assert result.returncode in (0, 1), (
            f"CI gating returned unexpected exit code {result.returncode}.\n"
            f"stderr: {result.stderr[:500]}"
        )

        # If tools produced findings, verify gating behavior
        findings_file = results_dir / "summaries" / "findings.json"
        if findings_file.exists():
            data = json.loads(findings_file.read_text())
            findings = data.get("findings", data) if isinstance(data, dict) else data
            high_or_above = [
                f
                for f in findings
                if f.get("severity", "").upper() in ("HIGH", "CRITICAL")
            ]
            if high_or_above:
                assert (
                    result.returncode == 1
                ), f"Found {len(high_or_above)} HIGH+ findings but exit code was 0"

    def test_fail_on_critical_passes_with_medium_only(self, tmp_path):
        """CI mode exits 0 when only MEDIUM findings and threshold is CRITICAL."""
        results_dir = tmp_path / "results"
        results_dir.mkdir()

        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "ci",
                "--repo",
                str(E2E_FIXTURES / "python"),
                "--profile",
                "fast",
                "--fail-on",
                "CRITICAL",
                "--allow-missing-tools",
                "--results-dir",
                str(results_dir),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )

        # With --fail-on CRITICAL, only CRITICAL findings cause exit 1
        assert result.returncode in (0, 1), f"Unexpected exit code {result.returncode}"

        # Verify the contract: if rc==1, there must be CRITICAL findings
        if result.returncode == 1:
            findings_file = results_dir / "summaries" / "findings.json"
            assert findings_file.exists(), "Exit 1 but no findings file"
            data = json.loads(findings_file.read_text())
            findings = data.get("findings", data) if isinstance(data, dict) else data
            critical = [
                f for f in findings if f.get("severity", "").upper() == "CRITICAL"
            ]
            assert (
                critical
            ), "Exit code 1 with --fail-on CRITICAL but no CRITICAL findings found"
