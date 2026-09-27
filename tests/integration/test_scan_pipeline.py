#!/usr/bin/env python3
"""
Integration tests for the JMo Security scan pipeline.

These tests validate the complete scan workflow:
- Tool invocation
- Finding normalization
- Output generation
- Deduplication effectiveness

Requires: semgrep, the tool that reports on this fixture (measured
2026-09-26: semgrep 3 findings; trufflehog, if installed, 0).
Runtime: ~15 seconds per scan with semgrep and trufflehog installed

Until #1334 these asserted nothing: they read `findings.json`, `summary.md`
and `individual-sast/` at the results root, where no scan writes, and each
assertion sat behind an `if ... exists()` that never held.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent


@pytest.fixture(autouse=True)
def isolated_jmo_state(tmp_path_factory, monkeypatch):
    """Keep `run_scan`'s child process out of the developer's real state.

    Every test here shells out -- `run_scan` spawns
    ``sys.executable -m scripts.cli.jmo scan``. A child process does not
    inherit ``monkeypatch.setattr(Path, "home", ...)``; the only things that
    cross the boundary are the environment and the working directory. So the
    documented remedy for in-process tests could never work here, and these
    five wrote the real files on every run:

      * ``~/.jmo/config.yml`` -- ``_show_kofi_reminder`` resolves
        ``Path.home()`` in the CHILD, so redirect it with HOME/USERPROFILE.
      * ``.jmo/history.db`` -- relative to the child's cwd, which it inherits,
        so redirect it by chdir-ing the parent.

    Nightly Integration Tests failed on exactly this, every night, from a
    fresh runner where the guards saw the files being CREATED (#985). PR-time
    CI never runs this file -- `-m "not requires_tools"` deselects all of it --
    so the nightly was the only place it could show up.

    Autouse so a test added later is isolated without having to know any of
    the above. ``JMO_NON_INTERACTIVE`` is set for the recorded reason: a
    scan otherwise hangs on the first-run email prompt, and a fresh sandbox
    home is exactly the "first run" that triggers it.
    """
    sandbox = tmp_path_factory.mktemp("jmo-sandbox")
    monkeypatch.setenv("HOME", str(sandbox))
    monkeypatch.setenv("USERPROFILE", str(sandbox))
    monkeypatch.setenv("JMO_NON_INTERACTIVE", "1")
    # `python -m scripts.cli.jmo` must still resolve after the chdir. The
    # editable install already makes it importable from anywhere; this is
    # belt and braces for an environment where it is not.
    existing = os.environ.get("PYTHONPATH", "")
    monkeypatch.setenv(
        "PYTHONPATH",
        (
            os.pathsep.join([str(PROJECT_ROOT), existing])
            if existing
            else str(PROJECT_ROOT)
        ),
    )
    monkeypatch.chdir(sandbox)
    return sandbox


SAMPLES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "samples"
SCHEMA_FILE = PROJECT_ROOT / "docs" / "schemas" / "common_finding.v1.json"


def run_scan(
    target: Path,
    results_dir: Path,
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess:
    """Run JMo scan on a target directory with the default tool matrix."""
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(target),
        "--results-dir",
        str(results_dir),
        "--allow-missing-tools",
    ]
    if extra_args:
        cmd.extend(extra_args)

    # UTF-8, not the locale codec: the scan's log carries non-ASCII, and on
    # Windows a cp1252 decode error loses the capture the assertions print.
    return subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=600,
    )


def assert_scanned(result: subprocess.CompletedProcess, results_dir: Path) -> None:
    """The scan exited 0, and semgrep, the tool that reports on this fixture,
    ran. A semgrep that is not installed skips the test rather than failing
    it; one that ran and failed shows in the return code first."""
    assert result.returncode == 0, result.stderr[-3000:]
    meta = json.loads((results_dir / ".scan_metadata.json").read_bytes())
    semgrep = next(row for row in meta["tool_runs"] if row["tool"] == "semgrep")
    if semgrep["state"] == "skipped" and semgrep["reason"] == "not installed":
        pytest.skip("semgrep is not installed: it is the tool that reports here")
    assert semgrep["state"] == "ran", semgrep


def load_findings(results_dir: Path) -> list[dict[str, Any]]:
    """The report's findings, from `summaries/findings.json`, where the scan's
    own report phase writes them. Missing is an error, not an empty list."""
    data = json.loads((results_dir / "summaries" / "findings.json").read_bytes())
    return data["findings"]


def count_raw_findings(results_dir: Path) -> int:
    """Findings before deduplication: every tool output in each target's own
    folder, parsed by that tool's adapter, as the report reads them."""
    from scripts.core.normalize_and_report import tool_of_output
    from scripts.core.plugin_loader import get_plugin_registry
    from scripts.core.scan_timings import SCAN_TIMINGS_FILENAME

    registry = get_plugin_registry()
    total = 0
    for output in results_dir.glob("individual-*/*/*.json"):
        if output.name == SCAN_TIMINGS_FILENAME:
            continue
        adapter = registry.get(tool_of_output(output).replace("-", "_"))
        if adapter is not None:
            total += len(adapter().parse(output))
    return total


@pytest.fixture
def sample_vulnerable_repo(tmp_path: Path) -> Path:
    """Create a sample vulnerable repository for testing."""
    # Create a minimal vulnerable code sample
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # JavaScript with SQL injection
    (src_dir / "app.js").write_text("""
const express = require('express');
const app = express();
const db = require('./db');

app.get('/user', (req, res) => {
    const userId = req.query.id;
    // SQL Injection vulnerability
    const query = "SELECT * FROM users WHERE id = " + userId;
    db.query(query, (err, results) => {
        res.json(results);
    });
});

app.get('/search', (req, res) => {
    const term = req.query.q;
    // XSS vulnerability
    res.send("<h1>Results for: " + term + "</h1>");
});

module.exports = app;
""")

    # Python with hardcoded secret
    (src_dir / "config.py").write_text("""
# Configuration file
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def get_connection_string():
    return f"postgresql://admin:{DATABASE_PASSWORD}@localhost/db"
""")

    # Create package.json for npm detection
    (tmp_path / "package.json").write_text("""
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.20"
  }
}
""")

    return tmp_path


@pytest.mark.integration
@pytest.mark.requires_tools
class TestScanPipeline:
    """Integration tests for the scan pipeline."""

    def test_scan_produces_valid_output(
        self, sample_vulnerable_repo: Path, tmp_path: Path
    ):
        """Scan should produce valid JSON output with findings."""
        results_dir = tmp_path / "results"

        assert_scanned(run_scan(sample_vulnerable_repo, results_dir), results_dir)

        findings = load_findings(results_dir)
        assert findings, "semgrep ran and the report holds nothing"
        for finding in findings:
            assert finding.get("severity"), finding
            assert finding.get("message") or finding.get("title"), finding
            assert finding.get("tool", {}).get("name"), finding

    def test_scan_output_formats(self, sample_vulnerable_repo: Path, tmp_path: Path):
        """The report writes its JSON and Markdown under `summaries/`."""
        results_dir = tmp_path / "results"

        assert_scanned(run_scan(sample_vulnerable_repo, results_dir), results_dir)

        for name in ("findings.json", "SUMMARY.md"):
            output = results_dir / "summaries" / name
            assert output.is_file() and output.stat().st_size > 0, output


@pytest.mark.integration
@pytest.mark.requires_tools
@pytest.mark.slow
class TestDeduplicationEffectiveness:
    """Test that deduplication reduces noise appropriately."""

    def test_dedup_reduces_findings_count(
        self, sample_vulnerable_repo: Path, tmp_path: Path
    ):
        """The report neither invents findings nor drops them all.

        This fixture has no duplicates to remove (measured 2026-09-26: 3 raw,
        3 reported), so the 20-50% reduction this test used to promise was
        never observable here: the relation, not a ratio, is what holds.
        """
        results_dir = tmp_path / "results"

        assert_scanned(run_scan(sample_vulnerable_repo, results_dir), results_dir)

        findings = load_findings(results_dir)
        raw_count = count_raw_findings(results_dir)

        assert 0 < len(findings) <= raw_count, (len(findings), raw_count)
        ids = [finding["id"] for finding in findings]
        assert len(ids) == len(set(ids)), "the report kept a duplicate id"


@pytest.mark.integration
@pytest.mark.requires_tools
class TestScanReporting:
    """Test report generation from scan results."""

    def test_json_output_is_valid(self, sample_vulnerable_repo: Path, tmp_path: Path):
        """JSON output should be valid and parseable."""
        results_dir = tmp_path / "results"

        assert_scanned(run_scan(sample_vulnerable_repo, results_dir), results_dir)

        data = json.loads((results_dir / "summaries" / "findings.json").read_bytes())
        assert isinstance(data, dict), type(data)
        assert data["meta"]["finding_count"] == len(data["findings"]), data["meta"]

    def test_markdown_summary_generated(
        self, sample_vulnerable_repo: Path, tmp_path: Path
    ):
        """The Markdown summary counts what the JSON report holds."""
        results_dir = tmp_path / "results"

        assert_scanned(run_scan(sample_vulnerable_repo, results_dir), results_dir)

        summary = (results_dir / "summaries" / "SUMMARY.md").read_bytes()
        text = summary.decode("utf-8")
        assert text.startswith("# Security Summary"), text[:200]
        total = len(load_findings(results_dir))
        assert f"Total findings: {total} " in text, text[:300]
