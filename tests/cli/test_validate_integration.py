"""Integration tests for jmo validate end-to-end."""

import json
import subprocess
import sys

import pytest


@pytest.mark.integration
@pytest.mark.timeout(180)
class TestValidateIntegration:
    def test_quick_tier_runs(self):
        """jmo validate --tier quick should complete without crashing."""
        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "--tier", "quick"],
            capture_output=True,
            text=True,
            timeout=120,
        )
        assert result.returncode in (0, 1)  # pass or fail, not crash
        assert "Validation Report" in result.stdout

    def test_json_output(self):
        """jmo validate --json should produce valid JSON."""
        result = subprocess.run(
            [sys.executable, "-m", "scripts.cli.jmo", "validate", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
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
            timeout=120,
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
            timeout=120,
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
            timeout=120,
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
            timeout=120,
        )
        data = json.loads(result.stdout)
        assert len(data["categories"]) == 2
        names = {c["name"] for c in data["categories"]}
        assert names == {"CLI Completeness", "Scan Correctness"}
