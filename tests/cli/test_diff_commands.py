"""Tests for diff CLI commands."""

import json
import sqlite3
from pathlib import Path

import pytest

from scripts.cli.diff_commands import (
    cmd_diff,
    _filter_by_severity,
    _filter_by_tool,
    _filter_by_category,
)
from scripts.core.diff_engine import DiffResult, DiffSource, ModifiedFinding


@pytest.fixture
def sample_scan_directories(tmp_path):
    """Create sample scan result directories for testing."""
    # Create the proper results directory structure that gather_results expects
    baseline_root = tmp_path / "baseline-results"
    current_root = tmp_path / "current-results"

    # Create individual-repos structure (what gather_results scans)
    baseline_repo = baseline_root / "individual-repos" / "test-repo"
    current_repo = current_root / "individual-repos" / "test-repo"

    baseline_repo.mkdir(parents=True)
    current_repo.mkdir(parents=True)

    # Baseline findings - use native tool output formats (as scanner would output)
    # Semgrep native format: {"results": [...], "version": "..."}
    baseline_semgrep = {
        "results": [
            {
                "check_id": "CWE-79",
                "path": "src/views.py",
                "start": {"line": 120},
                "extra": {
                    "message": "XSS vulnerability",
                    "severity": "ERROR",  # Semgrep uses ERROR for HIGH
                },
            }
        ],
        "version": "1.50.0",
    }

    # Trivy native format: {"Results": [{"Target": "...", "Vulnerabilities": [...]}]}
    baseline_trivy = {
        "Version": "0.68.0",
        "Results": [
            {
                "Target": "src/info.py",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CWE-200",
                        "Title": "Information disclosure",
                        "Severity": "MEDIUM",
                        "PkgName": "info",
                    }
                ],
            }
        ],
    }

    # Current findings - fp1 resolved, fp3 new
    current_semgrep = {
        "results": [
            {
                "check_id": "CWE-89",
                "path": "src/db.py",
                "start": {"line": 89},
                "extra": {
                    "message": "SQL injection",
                    "severity": "ERROR",  # Semgrep uses ERROR for HIGH/CRITICAL
                },
            }
        ],
        "version": "1.50.0",
    }

    # fp2 unchanged (same as baseline)
    current_trivy = {
        "Version": "0.68.0",
        "Results": [
            {
                "Target": "src/info.py",
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CWE-200",
                        "Title": "Information disclosure",
                        "Severity": "MEDIUM",
                        "PkgName": "info",
                    }
                ],
            }
        ],
    }

    # Write tool outputs (as adapters would produce)
    (baseline_repo / "semgrep.json").write_text(json.dumps(baseline_semgrep, indent=2))
    (baseline_repo / "trivy.json").write_text(json.dumps(baseline_trivy, indent=2))
    (current_repo / "semgrep.json").write_text(json.dumps(current_semgrep, indent=2))
    (current_repo / "trivy.json").write_text(json.dumps(current_trivy, indent=2))

    # Also create summaries/findings.json (what diff engine expects)
    baseline_summaries = baseline_root / "summaries"
    current_summaries = current_root / "summaries"
    baseline_summaries.mkdir(parents=True, exist_ok=True)
    current_summaries.mkdir(parents=True, exist_ok=True)

    # Create normalized findings (CommonFinding format)
    baseline_findings = [
        {
            "id": "fp1",
            "severity": "HIGH",
            "ruleId": "CWE-79",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/views.py", "startLine": 120},
            "message": "XSS vulnerability",
            "schemaVersion": "1.2.0",
            "compliance": {},
            "risk": {},
        },
        {
            "id": "fp2",
            "severity": "MEDIUM",
            "ruleId": "CWE-200",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "location": {"path": "src/info.py", "startLine": 1},
            "message": "Information disclosure",
            "schemaVersion": "1.2.0",
            "compliance": {},
            "risk": {},
        },
    ]

    current_findings = [
        {
            "id": "fp2",  # Unchanged
            "severity": "MEDIUM",
            "ruleId": "CWE-200",
            "tool": {"name": "trivy", "version": "0.68.0"},
            "location": {"path": "src/info.py", "startLine": 1},
            "message": "Information disclosure",
            "schemaVersion": "1.2.0",
            "compliance": {},
            "risk": {},
        },
        {
            "id": "fp3",  # New
            "severity": "HIGH",
            "ruleId": "CWE-89",
            "tool": {"name": "semgrep", "version": "1.50.0"},
            "location": {"path": "src/db.py", "startLine": 89},
            "message": "SQL injection",
            "schemaVersion": "1.2.0",
            "compliance": {},
            "risk": {},
        },
    ]

    (baseline_summaries / "findings.json").write_text(json.dumps(baseline_findings, indent=2))
    (current_summaries / "findings.json").write_text(json.dumps(current_findings, indent=2))

    return baseline_root, current_root


@pytest.fixture
def sample_sqlite_db(tmp_path):
    """Create sample SQLite database with scans."""
    db_path = tmp_path / "test.db"
    conn = sqlite3.connect(db_path)

    # Create schema
    conn.execute(
        """
        CREATE TABLE scans (
            id TEXT PRIMARY KEY,
            timestamp_iso TEXT,
            profile TEXT,
            total_findings INTEGER
        )
        """
    )
    conn.execute(
        """
        CREATE TABLE findings (
            scan_id TEXT,
            fingerprint TEXT,
            severity TEXT,
            tool TEXT,
            rule_id TEXT,
            path TEXT,
            start_line INTEGER,
            message TEXT,
            raw_finding TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
        """
    )

    # Insert baseline scan
    conn.execute(
        """
        INSERT INTO scans (id, timestamp_iso, profile, total_findings)
        VALUES ('baseline123', '2025-11-04T10:00:00Z', 'balanced', 2)
        """
    )
    conn.execute(
        """
        INSERT INTO findings (scan_id, fingerprint, severity, tool, rule_id, path, start_line, message, raw_finding)
        VALUES
        ('baseline123', 'fp1', 'HIGH', 'semgrep', 'CWE-79', 'src/views.py', 120, 'XSS vulnerability', '{}'),
        ('baseline123', 'fp2', 'MEDIUM', 'trivy', 'CWE-200', 'src/info.py', 15, 'Information disclosure', '{}')
        """
    )

    # Insert current scan
    conn.execute(
        """
        INSERT INTO scans (id, timestamp_iso, profile, total_findings)
        VALUES ('current456', '2025-11-05T10:00:00Z', 'balanced', 2)
        """
    )
    conn.execute(
        """
        INSERT INTO findings (scan_id, fingerprint, severity, tool, rule_id, path, start_line, message, raw_finding)
        VALUES
        ('current456', 'fp2', 'MEDIUM', 'trivy', 'CWE-200', 'src/info.py', 15, 'Information disclosure', '{}'),
        ('current456', 'fp3', 'CRITICAL', 'semgrep', 'CWE-89', 'src/db.py', 89, 'SQL injection', '{}')
        """
    )

    conn.commit()
    conn.close()

    return db_path


def test_cli_directory_mode_json(sample_scan_directories, tmp_path, monkeypatch):
    """Test directory comparison via CLI with JSON output."""
    baseline, current = sample_scan_directories
    output_path = tmp_path / "diff.json"

    # Mock args
    class Args:
        directories = [str(baseline), str(current)]
        scan_ids = None
        format = "json"
        output = str(output_path)
        no_modifications = False
        severity = None
        tool = None
        only = None
        db = None

    args = Args()

    # Run command
    result = cmd_diff(args)

    assert result == 0
    assert output_path.exists()

    # Verify JSON structure
    with open(output_path) as f:
        data = json.load(f)

    assert "meta" in data
    assert "statistics" in data
    assert "new_findings" in data
    assert "resolved_findings" in data

    # Check findings
    assert data["statistics"]["total_new"] == 1
    assert data["statistics"]["total_resolved"] == 1


def test_cli_directory_mode_md(sample_scan_directories, tmp_path):
    """Test directory comparison via CLI with Markdown output."""
    baseline, current = sample_scan_directories
    output_path = tmp_path / "diff.md"

    class Args:
        directories = [str(baseline), str(current)]
        scan_ids = None
        format = "md"
        output = str(output_path)
        no_modifications = False
        severity = None
        tool = None
        only = None
        db = None

    args = Args()

    result = cmd_diff(args)

    assert result == 0
    assert output_path.exists()

    content = output_path.read_text()
    assert "# 🔍 Security Diff Report" in content
    assert "## 📊 Summary" in content


def test_cli_sqlite_mode(sample_sqlite_db, tmp_path):
    """Test SQLite comparison via CLI."""
    output_path = tmp_path / "diff.json"

    class Args:
        directories = []
        scan_ids = ["baseline123", "current456"]
        format = "json"
        output = str(output_path)
        no_modifications = False
        severity = None
        tool = None
        only = None
        db = sample_sqlite_db

    args = Args()

    result = cmd_diff(args)

    assert result == 0
    assert output_path.exists()

    with open(output_path) as f:
        data = json.load(f)

    assert data["statistics"]["total_new"] == 1
    assert data["statistics"]["total_resolved"] == 1


def test_cli_no_modifications(sample_scan_directories, tmp_path):
    """Test --no-modifications flag."""
    baseline, current = sample_scan_directories
    output_path = tmp_path / "diff.json"

    class Args:
        directories = [str(baseline), str(current)]
        scan_ids = None
        format = "json"
        output = str(output_path)
        no_modifications = True  # Disable modification detection
        severity = None
        tool = None
        only = None
        db = None

    args = Args()

    result = cmd_diff(args)

    assert result == 0

    with open(output_path) as f:
        data = json.load(f)

    # No modified findings when detection disabled
    assert data["statistics"]["total_modified"] == 0
    assert len(data["modified_findings"]) == 0


def test_cli_severity_filter(sample_scan_directories, tmp_path):
    """Test --severity filter."""
    baseline, current = sample_scan_directories
    output_path = tmp_path / "diff.json"

    class Args:
        directories = [str(baseline), str(current)]
        scan_ids = None
        format = "json"
        output = str(output_path)
        no_modifications = False
        severity = "CRITICAL,HIGH"  # Only CRITICAL and HIGH
        tool = None
        only = None
        db = None

    args = Args()

    result = cmd_diff(args)

    assert result == 0

    with open(output_path) as f:
        data = json.load(f)

    # Only HIGH finding should be in new (Semgrep ERROR maps to HIGH)
    assert data["statistics"]["total_new"] == 1
    assert data["new_findings"][0]["severity"] == "HIGH"

    # Only HIGH finding should be in resolved
    assert data["statistics"]["total_resolved"] == 1
    assert data["resolved_findings"][0]["severity"] == "HIGH"


def test_cli_tool_filter(sample_scan_directories, tmp_path):
    """Test --tool filter."""
    baseline, current = sample_scan_directories
    output_path = tmp_path / "diff.json"

    class Args:
        directories = [str(baseline), str(current)]
        scan_ids = None
        format = "json"
        output = str(output_path)
        no_modifications = False
        severity = None
        tool = "semgrep"  # Only semgrep findings
        only = None
        db = None

    args = Args()

    result = cmd_diff(args)

    assert result == 0

    with open(output_path) as f:
        data = json.load(f)

    # Only semgrep findings
    assert all(f["tool"]["name"] == "semgrep" for f in data["new_findings"])
    assert all(f["tool"]["name"] == "semgrep" for f in data["resolved_findings"])


def test_cli_only_new(sample_scan_directories, tmp_path):
    """Test --only new filter."""
    baseline, current = sample_scan_directories
    output_path = tmp_path / "diff.json"

    class Args:
        directories = [str(baseline), str(current)]
        scan_ids = None
        format = "json"
        output = str(output_path)
        no_modifications = False
        severity = None
        tool = None
        only = "new"  # Only show new findings
        db = None

    args = Args()

    result = cmd_diff(args)

    assert result == 0

    with open(output_path) as f:
        data = json.load(f)

    # Only new findings should be present
    assert data["statistics"]["total_new"] == 1
    assert data["statistics"]["total_resolved"] == 0
    assert data["statistics"]["total_modified"] == 0


def test_cli_invalid_args():
    """Test error handling for invalid arguments."""
    class Args:
        directories = ["only-one-directory"]  # Need 2 directories
        scan_ids = None
        format = "json"
        output = None
        no_modifications = False
        severity = None
        tool = None
        only = None
        db = None

    args = Args()

    result = cmd_diff(args)

    # Should fail with error
    assert result == 1


def test_cli_missing_directory():
    """Test error when directory doesn't exist."""
    class Args:
        directories = ["/nonexistent1", "/nonexistent2"]
        scan_ids = None
        format = "json"
        output = None
        no_modifications = False
        severity = None
        tool = None
        only = None
        db = None

    args = Args()

    result = cmd_diff(args)

    # Should fail with error
    assert result == 1


def test_filter_by_severity():
    """Test _filter_by_severity function."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    findings = [
        {"id": "fp1", "severity": "CRITICAL"},
        {"id": "fp2", "severity": "HIGH"},
        {"id": "fp3", "severity": "MEDIUM"},
    ]

    diff = DiffResult(
        new=findings,
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 3,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 3,
            "trend": "worsening",
            "new_by_severity": {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    filtered = _filter_by_severity(diff, {"CRITICAL", "HIGH"})

    assert len(filtered.new) == 2
    assert filtered.statistics["total_new"] == 2
    assert all(f["severity"] in ("CRITICAL", "HIGH") for f in filtered.new)


def test_filter_by_tool():
    """Test _filter_by_tool function."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    findings = [
        {"id": "fp1", "severity": "HIGH", "tool": {"name": "semgrep"}},
        {"id": "fp2", "severity": "HIGH", "tool": {"name": "trivy"}},
        {"id": "fp3", "severity": "MEDIUM", "tool": {"name": "semgrep"}},
    ]

    diff = DiffResult(
        new=findings,
        resolved=[],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 3,
            "total_resolved": 0,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 3,
            "trend": "worsening",
            "new_by_severity": {"HIGH": 2, "MEDIUM": 1},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    filtered = _filter_by_tool(diff, {"semgrep"})

    assert len(filtered.new) == 2
    assert filtered.statistics["total_new"] == 2
    assert all(f["tool"]["name"] == "semgrep" for f in filtered.new)


def test_filter_by_category():
    """Test _filter_by_category function."""
    baseline_source = DiffSource(
        source_type="directory",
        path="baseline/",
        timestamp="2025-11-04T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    current_source = DiffSource(
        source_type="directory",
        path="current/",
        timestamp="2025-11-05T10:00:00Z",
        profile="balanced",
        total_findings=3,
    )

    diff = DiffResult(
        new=[{"id": "new1"}],
        resolved=[{"id": "resolved1"}],
        unchanged=[],
        modified=[],
        baseline_source=baseline_source,
        current_source=current_source,
        statistics={
            "total_new": 1,
            "total_resolved": 1,
            "total_unchanged": 0,
            "total_modified": 0,
            "net_change": 0,
            "trend": "stable",
            "new_by_severity": {},
            "resolved_by_severity": {},
            "modifications_by_type": {},
        },
    )

    # Filter to show only new
    filtered = _filter_by_category(diff, "new")
    assert len(filtered.new) == 1
    assert len(filtered.resolved) == 0

    # Filter to show only resolved
    filtered = _filter_by_category(diff, "resolved")
    assert len(filtered.new) == 0
    assert len(filtered.resolved) == 1
