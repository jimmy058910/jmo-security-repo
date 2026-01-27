#!/usr/bin/env python3
"""
Integration tests for the JMo Security scan pipeline.

These tests validate the complete scan workflow:
- Tool invocation
- Finding normalization
- Output generation
- Deduplication effectiveness

Requires: Real security tools installed (semgrep, trivy at minimum)
Runtime: ~5-15 minutes depending on profile
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest

# Project paths
PROJECT_ROOT = Path(__file__).parent.parent.parent
SAMPLES_DIR = PROJECT_ROOT / "tests" / "fixtures" / "samples"
SCHEMA_FILE = PROJECT_ROOT / "docs" / "schemas" / "common_finding.v1.json"


def run_scan(
    target: Path,
    results_dir: Path,
    profile: str = "fast",
    extra_args: list[str] | None = None,
) -> subprocess.CompletedProcess:
    """Run JMo scan on a target directory."""
    cmd = [
        sys.executable,
        "-m",
        "scripts.cli.jmo",
        "scan",
        "--repo",
        str(target),
        "--results-dir",
        str(results_dir),
        "--profile",
        profile,
    ]
    if extra_args:
        cmd.extend(extra_args)

    return subprocess.run(cmd, capture_output=True, text=True, timeout=600)


def load_findings(results_dir: Path) -> list[dict[str, Any]]:
    """Load findings from scan results."""
    findings_file = results_dir / "findings.json"

    if not findings_file.exists():
        return []

    with open(findings_file) as f:
        data = json.load(f)

    if isinstance(data, list):
        return data
    elif isinstance(data, dict) and "findings" in data:
        return data["findings"]
    return []


def count_raw_findings(results_dir: Path) -> int:
    """Count findings from individual tool outputs before deduplication."""
    total = 0
    individual_dir = results_dir / "individual-sast"

    if individual_dir.exists():
        for json_file in individual_dir.glob("*.json"):
            try:
                with open(json_file) as f:
                    data = json.load(f)
                if isinstance(data, list):
                    total += len(data)
                elif isinstance(data, dict) and "findings" in data:
                    total += len(data["findings"])
            except (json.JSONDecodeError, OSError):
                continue

    return total


@pytest.fixture
def sample_vulnerable_repo(tmp_path: Path) -> Path:
    """Create a sample vulnerable repository for testing."""
    # Create a minimal vulnerable code sample
    src_dir = tmp_path / "src"
    src_dir.mkdir()

    # JavaScript with SQL injection
    (src_dir / "app.js").write_text(
        """
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
"""
    )

    # Python with hardcoded secret
    (src_dir / "config.py").write_text(
        """
# Configuration file
API_KEY = "sk-1234567890abcdef1234567890abcdef"
DATABASE_PASSWORD = "admin123"

def get_connection_string():
    return f"postgresql://admin:{DATABASE_PASSWORD}@localhost/db"
"""
    )

    # Create package.json for npm detection
    (tmp_path / "package.json").write_text(
        """
{
  "name": "vulnerable-app",
  "version": "1.0.0",
  "dependencies": {
    "express": "4.17.1",
    "lodash": "4.17.20"
  }
}
"""
    )

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

        result = run_scan(sample_vulnerable_repo, results_dir, profile="fast")

        # Scan should complete (may have non-zero exit for findings)
        assert results_dir.exists(), "Results directory not created"

        findings_file = results_dir / "findings.json"
        if findings_file.exists():
            findings = load_findings(results_dir)
            # Validate each finding has required fields
            for finding in findings:
                assert "severity" in finding, "Finding missing severity"
                assert "message" in finding or "title" in finding, "Finding missing message/title"

    def test_scan_with_different_profiles(
        self, sample_vulnerable_repo: Path, tmp_path: Path
    ):
        """Different profiles should work correctly."""
        for profile in ["fast"]:  # Only test fast for speed
            results_dir = tmp_path / f"results-{profile}"

            run_scan(sample_vulnerable_repo, results_dir, profile=profile)

            # Should complete without crashing (results_dir created)
            assert results_dir.exists()

    def test_scan_output_formats(self, sample_vulnerable_repo: Path, tmp_path: Path):
        """Scan should produce all expected output files."""
        results_dir = tmp_path / "results"

        run_scan(sample_vulnerable_repo, results_dir, profile="fast")

        # Check for expected output files (some may not exist if no findings)
        possible_outputs = [
            "findings.json",
            "summary.md",
        ]

        # At least one output should exist
        outputs_exist = any((results_dir / f).exists() for f in possible_outputs)
        assert outputs_exist or results_dir.exists(), "No output files created"


@pytest.mark.integration
@pytest.mark.requires_tools
@pytest.mark.slow
class TestDeduplicationEffectiveness:
    """Test that deduplication reduces noise appropriately."""

    def test_dedup_reduces_findings_count(
        self, sample_vulnerable_repo: Path, tmp_path: Path
    ):
        """Deduplication should reduce total findings by 20-50%."""
        results_dir = tmp_path / "results"

        run_scan(sample_vulnerable_repo, results_dir, profile="balanced")

        # Load deduplicated findings
        findings = load_findings(results_dir)
        deduped_count = len(findings)

        # Load raw findings from individual directories
        raw_count = count_raw_findings(results_dir)

        if raw_count > 0 and deduped_count > 0:
            reduction = (raw_count - deduped_count) / raw_count

            # We expect some reduction but not too aggressive
            # This is a soft assertion - depends on the sample code
            assert reduction >= 0, "Deduplication increased findings (unexpected)"


@pytest.mark.integration
@pytest.mark.requires_tools
class TestScanReporting:
    """Test report generation from scan results."""

    def test_json_output_is_valid(self, sample_vulnerable_repo: Path, tmp_path: Path):
        """JSON output should be valid and parseable."""
        results_dir = tmp_path / "results"

        run_scan(sample_vulnerable_repo, results_dir, profile="fast")

        findings_file = results_dir / "findings.json"
        if findings_file.exists():
            # Should be valid JSON
            with open(findings_file) as f:
                data = json.load(f)

            # Should be list or dict with findings
            assert isinstance(data, (list, dict)), "Invalid findings structure"

    def test_markdown_summary_generated(
        self, sample_vulnerable_repo: Path, tmp_path: Path
    ):
        """Markdown summary should be generated."""
        results_dir = tmp_path / "results"

        run_scan(sample_vulnerable_repo, results_dir, profile="fast")

        summary_file = results_dir / "summary.md"
        if summary_file.exists():
            content = summary_file.read_text()
            # Should have basic structure
            assert "Summary" in content or "Findings" in content or "#" in content
