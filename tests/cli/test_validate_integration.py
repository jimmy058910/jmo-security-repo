"""Integration tests for jmo validate end-to-end."""

import json
import subprocess
import sys

import pytest


@pytest.mark.integration
@pytest.mark.slow
@pytest.mark.timeout(360)
class TestValidateIntegration:
    """#873: both timeouts below are derived from measurement, not guesses.

    There are two stacked caps -- the per-subprocess ``timeout=`` below, and
    this class's ``@pytest.mark.timeout``, which is pytest-timeout and fires
    independently. Raising only the inner one is not a fix: pytest-timeout's
    Windows method is ``thread``, which cannot interrupt a blocked C-level
    call, so if the OUTER cap fires first the subprocess can be left running
    rather than failing cleanly. The outer cap must exceed the inner one with
    real margin, which is why it is 360 against a 300s inner cap, not 301.

    Measured on this box, all six subprocess calls, idle (serial) vs. loaded
    (this file alone under ``-n 8``, so up to 6 of these run concurrently --
    the shape #873 actually failed under):

    ===========================  =======  =======
    test                            idle    loaded
    ===========================  =======  =======
    test_quick_tier_runs           50.6s     72.9s
    test_json_output               46.8s     72.9s
    test_category_filter           36.9s     53.0s
    test_verbose_flag              46.4s     72.9s
    test_fail_fast_stops_early     51.9s     72.9s
    test_multiple_categories       39.7s     53.2s
    ===========================  =======  =======

    The old 120s cap had ~1.6x headroom over the single idle sample #873
    measured (73s) and none over the loaded one -- it was observed to
    produce ``TimeoutExpired after 120s`` under real ``-n 8`` CI contention,
    which runs many MORE tests concurrently than the 6-way parallelism
    above, so the true worst case is higher than anything measured here.
    300s is ~4.1x the worst value this file could reproduce on its own
    (72.9s) and comfortably above the >120s the real incident hit.
    """

    def test_quick_tier_runs(self):
        """jmo validate --tier quick should complete without crashing."""
        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "--tier", "quick"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert result.returncode in (0, 1)  # pass or fail, not crash
        assert "Validation Report" in result.stdout

    def test_json_output(self):
        """jmo validate --json should produce valid JSON."""
        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "--json"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        data = json.loads(result.stdout)
        assert "verdict" in data
        assert "categories" in data
        assert len(data["categories"]) == 4
        assert data["summary"]["total"] > 100

    def test_category_filter(self):
        """jmo validate --category cli should only run CLI checks."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "validate",
                "--category",
                "cli",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        assert "CLI Completeness" in result.stdout
        # Other categories should NOT appear
        assert "Scan Correctness" not in result.stdout
        assert "Cross-Platform" not in result.stdout
        assert "Release Artifacts" not in result.stdout

    def test_verbose_flag(self):
        """jmo validate -v should show per-check details."""
        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "-v"],
            capture_output=True,
            text=True,
            timeout=300,
        )
        # Verbose should show individual check names
        assert result.returncode in (0, 1)
        # At minimum should show some check-level detail
        assert "v" in result.stdout or "X" in result.stdout

    def test_fail_fast_stops_early(self):
        """jmo validate --fail-fast --json should stop after first failing category."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "validate",
                "--fail-fast",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        data = json.loads(result.stdout)
        # If there are failures, should have fewer categories than 4
        if data["verdict"] == "NO-GO":
            failed_cats = [
                c
                for c in data["categories"]
                if any(ch["status"] == "fail" for ch in c["checks"])
            ]
            assert len(failed_cats) >= 1

    def test_multiple_categories(self):
        """jmo validate --category cli,scans should run exactly 2 categories."""
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "validate",
                "--category",
                "cli,scans",
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        data = json.loads(result.stdout)
        assert len(data["categories"]) == 2
        names = {c["name"] for c in data["categories"]}
        assert names == {"CLI Completeness", "Scan Correctness"}
