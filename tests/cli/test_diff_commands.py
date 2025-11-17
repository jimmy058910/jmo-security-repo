"""Tests for diff CLI commands."""

import json
import sqlite3
import subprocess
from pathlib import Path

import pytest

from scripts.cli.diff_commands import (
    cmd_diff,
    _filter_by_severity,
    _filter_by_tool,
    _filter_by_category,
)
from scripts.core.diff_engine import DiffResult, DiffSource


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

    (baseline_summaries / "findings.json").write_text(
        json.dumps(baseline_findings, indent=2)
    )
    (current_summaries / "findings.json").write_text(
        json.dumps(current_findings, indent=2)
    )

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


# ===========================
# Unit Tests for Uncovered Code (Target: 90%+ Coverage)
# ===========================


class TestDetectGitContext:
    """Tests for detect_git_context function (lines 38-99)."""

    def test_detect_git_context_success(self, monkeypatch, tmp_path):
        """Test successful git context detection."""
        from scripts.cli.diff_commands import detect_git_context
        from unittest.mock import Mock

        # Mock subprocess.run to simulate git commands
        call_count = {"count": 0}

        def mock_run(cmd, **kwargs):
            result = Mock()
            result.returncode = 0
            call_count["count"] += 1

            if "rev-parse --git-dir" in " ".join(cmd):
                # First call: check if in git repo
                result.stdout = ".git\n"
                return result
            elif "rev-parse --abbrev-ref HEAD" in " ".join(cmd):
                # Second call: get current branch
                result.stdout = "feature-branch\n"
                return result
            elif "config --get remote.origin.url" in " ".join(cmd):
                # Third call: get remote URL
                result.stdout = "git@github.com:user/repo.git\n"
                return result

            return result

        monkeypatch.setattr(subprocess, "run", mock_run)

        context = detect_git_context()

        assert context is not None
        assert context["in_git_repo"] is True
        assert context["current_branch"] == "feature-branch"
        assert context["is_pr"] is False
        assert context["pr_target"] == "main"
        assert context["platform"] == "github"

    def test_detect_git_context_github_pr(self, monkeypatch):
        """Test GitHub PR detection via GITHUB_REF env var."""
        from scripts.cli.diff_commands import detect_git_context
        from unittest.mock import Mock

        def mock_run(cmd, **kwargs):
            result = Mock()
            result.returncode = 0

            if "rev-parse --git-dir" in " ".join(cmd):
                result.stdout = ".git\n"
            elif "rev-parse --abbrev-ref HEAD" in " ".join(cmd):
                result.stdout = "pr-123\n"
            elif "config --get remote.origin.url" in " ".join(cmd):
                result.stdout = "https://github.com/user/repo.git\n"

            return result

        monkeypatch.setattr(subprocess, "run", mock_run)
        monkeypatch.setenv("GITHUB_REF", "refs/pull/123/merge")
        monkeypatch.setenv("GITHUB_BASE_REF", "develop")

        context = detect_git_context()

        assert context is not None
        assert context["is_pr"] is True
        assert context["pr_target"] == "develop"
        assert context["platform"] == "github"

    def test_detect_git_context_gitlab_mr(self, monkeypatch):
        """Test GitLab MR detection via CI env vars."""
        from scripts.cli.diff_commands import detect_git_context
        from unittest.mock import Mock

        def mock_run(cmd, **kwargs):
            result = Mock()
            result.returncode = 0

            if "rev-parse --git-dir" in " ".join(cmd):
                result.stdout = ".git\n"
            elif "rev-parse --abbrev-ref HEAD" in " ".join(cmd):
                result.stdout = "feature\n"
            elif "config --get remote.origin.url" in " ".join(cmd):
                result.stdout = "git@gitlab.com:group/project.git\n"

            return result

        monkeypatch.setattr(subprocess, "run", mock_run)
        monkeypatch.setenv("CI_MERGE_REQUEST_IID", "456")
        monkeypatch.setenv("CI_MERGE_REQUEST_TARGET_BRANCH_NAME", "staging")

        context = detect_git_context()

        assert context is not None
        assert context["is_pr"] is True
        assert context["pr_target"] == "staging"
        assert context["platform"] == "gitlab"

    def test_detect_git_context_not_git_repo(self, monkeypatch):
        """Test behavior when not in a git repository."""
        from scripts.cli.diff_commands import detect_git_context

        def mock_run(cmd, **kwargs):
            raise subprocess.CalledProcessError(128, cmd)

        monkeypatch.setattr(subprocess, "run", mock_run)

        context = detect_git_context()

        assert context is None

    def test_detect_git_context_timeout(self, monkeypatch):
        """Test behavior when git command times out."""
        from scripts.cli.diff_commands import detect_git_context

        def mock_run(cmd, **kwargs):
            raise subprocess.TimeoutExpired(cmd, 5)

        monkeypatch.setattr(subprocess, "run", mock_run)

        context = detect_git_context()

        assert context is None

    def test_detect_git_context_git_not_installed(self, monkeypatch):
        """Test behavior when git is not installed."""
        from scripts.cli.diff_commands import detect_git_context

        def mock_run(cmd, **kwargs):
            raise FileNotFoundError("git not found")

        monkeypatch.setattr(subprocess, "run", mock_run)

        context = detect_git_context()

        assert context is None


class TestAutoDetectScans:
    """Tests for auto_detect_scans function (lines 115-148)."""

    def test_auto_detect_scans_success(self, tmp_path, monkeypatch):
        """Test successful auto-detection of scan directories."""
        from scripts.cli.diff_commands import auto_detect_scans

        # Create baseline directory structure
        baseline = tmp_path / "baseline-results"
        baseline_summaries = baseline / "summaries"
        baseline_summaries.mkdir(parents=True)
        (baseline_summaries / "findings.json").write_text('{"findings": []}')

        # Create current directory structure
        current = tmp_path / "results"
        current_summaries = current / "summaries"
        current_summaries.mkdir(parents=True)
        (current_summaries / "findings.json").write_text('{"findings": []}')

        # Mock Path.cwd() to return tmp_path
        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)

        result = auto_detect_scans(None)

        assert result is not None
        baseline_path, current_path = result
        assert "baseline-results" in baseline_path
        assert "results" in current_path

    def test_auto_detect_scans_alternative_names(self, tmp_path, monkeypatch):
        """Test detection with alternative directory naming conventions."""
        from scripts.cli.diff_commands import auto_detect_scans

        # Create baseline with alternative name
        baseline = tmp_path / "results-baseline"
        baseline_summaries = baseline / "summaries"
        baseline_summaries.mkdir(parents=True)
        (baseline_summaries / "findings.json").write_text('{"findings": []}')

        # Create current with alternative name
        current = tmp_path / "current-results"
        current_summaries = current / "summaries"
        current_summaries.mkdir(parents=True)
        (current_summaries / "findings.json").write_text('{"findings": []}')

        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)

        result = auto_detect_scans(None)

        assert result is not None
        baseline_path, current_path = result
        assert "results-baseline" in baseline_path
        assert "current-results" in current_path

    def test_auto_detect_scans_missing_baseline(self, tmp_path, monkeypatch):
        """Test when baseline directory is missing."""
        from scripts.cli.diff_commands import auto_detect_scans

        # Create only current directory
        current = tmp_path / "results"
        current_summaries = current / "summaries"
        current_summaries.mkdir(parents=True)
        (current_summaries / "findings.json").write_text('{"findings": []}')

        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)

        result = auto_detect_scans(None)

        assert result is None

    def test_auto_detect_scans_missing_current(self, tmp_path, monkeypatch):
        """Test when current directory is missing."""
        from scripts.cli.diff_commands import auto_detect_scans

        # Create only baseline directory
        baseline = tmp_path / "baseline-results"
        baseline_summaries = baseline / "summaries"
        baseline_summaries.mkdir(parents=True)
        (baseline_summaries / "findings.json").write_text('{"findings": []}')

        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)

        result = auto_detect_scans(None)

        assert result is None

    def test_auto_detect_scans_missing_findings_json(self, tmp_path, monkeypatch):
        """Test when directories exist but findings.json is missing."""
        from scripts.cli.diff_commands import auto_detect_scans

        # Create directories but no findings.json
        baseline = tmp_path / "baseline-results"
        baseline.mkdir(parents=True)

        current = tmp_path / "results"
        current.mkdir(parents=True)

        monkeypatch.setattr(Path, "cwd", lambda: tmp_path)

        result = auto_detect_scans(None)

        assert result is None


class TestSuggestOutputFormat:
    """Tests for suggest_output_format function (lines 161-174)."""

    def test_suggest_output_format_github_pr(self):
        """Test SARIF format suggestion for GitHub PR."""
        from scripts.cli.diff_commands import suggest_output_format

        git_context = {
            "in_git_repo": True,
            "is_pr": True,
            "platform": "github",
        }

        format_type = suggest_output_format(git_context)

        assert format_type == "sarif"

    def test_suggest_output_format_gitlab_mr(self):
        """Test Markdown format suggestion for GitLab MR."""
        from scripts.cli.diff_commands import suggest_output_format

        git_context = {
            "in_git_repo": True,
            "is_pr": True,
            "platform": "gitlab",
        }

        format_type = suggest_output_format(git_context)

        assert format_type == "md"

    def test_suggest_output_format_pr_unknown_platform(self):
        """Test Markdown format for PR with unknown platform."""
        from scripts.cli.diff_commands import suggest_output_format

        git_context = {
            "in_git_repo": True,
            "is_pr": True,
            "platform": None,
        }

        format_type = suggest_output_format(git_context)

        assert format_type == "md"

    def test_suggest_output_format_not_pr(self):
        """Test HTML format suggestion when not in PR context."""
        from scripts.cli.diff_commands import suggest_output_format

        git_context = {
            "in_git_repo": True,
            "is_pr": False,
            "platform": "github",
        }

        format_type = suggest_output_format(git_context)

        assert format_type == "html"

    def test_suggest_output_format_no_git_context(self):
        """Test HTML format suggestion when no git context."""
        from scripts.cli.diff_commands import suggest_output_format

        format_type = suggest_output_format(None)

        assert format_type == "html"


class TestCmdDiffAutoMode:
    """Tests for cmd_diff auto mode (lines 265-312)."""

    def test_cmd_diff_auto_mode_success(
        self, sample_scan_directories, tmp_path, monkeypatch
    ):
        """Test auto mode successful execution."""
        baseline, current = sample_scan_directories

        # Mock git context
        def mock_detect_git_context():
            return {
                "in_git_repo": True,
                "current_branch": "feature",
                "is_pr": True,
                "pr_target": "main",
                "platform": "github",
            }

        # Mock auto-detect scans
        def mock_auto_detect_scans(git_context):
            return (str(baseline), str(current))

        from scripts.cli import diff_commands

        monkeypatch.setattr(
            diff_commands, "detect_git_context", mock_detect_git_context
        )
        monkeypatch.setattr(diff_commands, "auto_detect_scans", mock_auto_detect_scans)

        # Create Args object with auto=True
        class Args:
            auto = True
            directories = None
            scan_ids = None
            format = None  # Auto-suggest
            output = None  # Auto-generate
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        # Should succeed
        assert result == 0

    def test_cmd_diff_auto_mode_no_detection(self, monkeypatch, capsys):
        """Test auto mode when directories cannot be detected."""

        # Mock git context
        def mock_detect_git_context():
            return {"in_git_repo": True}

        # Mock auto-detect to return None (failure)
        def mock_auto_detect_scans(git_context):
            return None

        from scripts.cli import diff_commands

        monkeypatch.setattr(
            diff_commands, "detect_git_context", mock_detect_git_context
        )
        monkeypatch.setattr(diff_commands, "auto_detect_scans", mock_auto_detect_scans)

        class Args:
            auto = True
            directories = None
            scan_ids = None
            format = None
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        # Should fail
        assert result == 1

        # Check error message
        captured = capsys.readouterr()
        assert "Could not auto-detect scan directories" in captured.err


class TestCmdDiffValidation:
    """Tests for cmd_diff argument validation (lines 314-335)."""

    def test_cmd_diff_wrong_number_of_directories(self, capsys):
        """Test validation fails with wrong number of directories."""

        class Args:
            auto = False
            directories = ["only-one"]  # Should be 2
            scan_ids = None
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "exactly 2 directories" in captured.err

    def test_cmd_diff_wrong_number_of_scan_ids(self, capsys):
        """Test validation fails with wrong number of scan IDs."""

        class Args:
            auto = False
            directories = None
            scan_ids = ["only-one"]  # Should be 2
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "exactly 2 scan IDs" in captured.err

    def test_cmd_diff_no_input_provided(self, capsys):
        """Test validation fails when no directories or scan IDs provided."""

        class Args:
            auto = False
            directories = None
            scan_ids = None
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Provide directories or --scan IDs" in captured.err

    def test_cmd_diff_baseline_not_found(self, tmp_path, capsys):
        """Test error when baseline directory doesn't exist."""
        current = tmp_path / "current-results"
        current.mkdir(parents=True)

        class Args:
            auto = False
            directories = ["/nonexistent/baseline", str(current)]
            scan_ids = None
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Baseline directory not found" in captured.err

    def test_cmd_diff_current_not_found(self, tmp_path, capsys):
        """Test error when current directory doesn't exist."""
        baseline = tmp_path / "baseline-results"
        baseline.mkdir(parents=True)

        class Args:
            auto = False
            directories = [str(baseline), "/nonexistent/current"]
            scan_ids = None
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Current directory not found" in captured.err


class TestCmdDiffOutputFormats:
    """Tests for cmd_diff output generation (lines 399-443)."""

    def test_cmd_diff_json_to_stdout(self, sample_scan_directories, capsys):
        """Test JSON output to stdout."""
        baseline, current = sample_scan_directories

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = None  # Stdout
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        captured = capsys.readouterr()
        # Should have JSON on stdout
        assert captured.out.strip().startswith("{")
        output_data = json.loads(captured.out)
        assert "meta" in output_data
        assert "new_findings" in output_data

    def test_cmd_diff_markdown_to_stdout(self, sample_scan_directories, capsys):
        """Test Markdown output to stdout."""
        baseline, current = sample_scan_directories

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "md"
            output = None  # Stdout
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        captured = capsys.readouterr()
        # Should have Markdown on stdout
        assert (
            "# 🔍 Security Diff Report" in captured.out
            or "## 📊 Summary" in captured.out
        )

    def test_cmd_diff_html_to_file(self, sample_scan_directories, tmp_path):
        """Test HTML output to file."""
        baseline, current = sample_scan_directories
        output_file = tmp_path / "diff-report.html"

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "html"
            output = str(output_file)
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        assert output_file.exists()
        content = output_file.read_text()
        assert "<html" in content or "<!DOCTYPE" in content

    def test_cmd_diff_sarif_to_file(self, sample_scan_directories, tmp_path):
        """Test SARIF output to file."""
        baseline, current = sample_scan_directories
        output_file = tmp_path / "diff.sarif"

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "sarif"
            output = str(output_file)
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        assert output_file.exists()
        content = json.loads(output_file.read_text())
        # Verify SARIF schema (actual URL uses 'master' branch and 'Schemata' path)
        assert "$schema" in content
        assert "sarif-schema-2.1.0.json" in content["$schema"]


class TestCmdDiffFilters:
    """Tests for cmd_diff filter application in real execution."""

    def test_cmd_diff_severity_filter(self, sample_scan_directories, tmp_path):
        """Test severity filtering in cmd_diff."""
        baseline, current = sample_scan_directories
        output_file = tmp_path / "filtered.json"

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = str(output_file)
            db = None
            severity = "CRITICAL,HIGH"  # Filter to only CRITICAL and HIGH
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text())
        # All findings should be CRITICAL or HIGH
        for finding in data.get("new_findings", []):
            assert finding["severity"] in ["CRITICAL", "HIGH"]

    def test_cmd_diff_tool_filter(self, sample_scan_directories, tmp_path):
        """Test tool filtering in cmd_diff."""
        baseline, current = sample_scan_directories
        output_file = tmp_path / "filtered.json"

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = str(output_file)
            db = None
            severity = None
            tool = "trivy"  # Filter to only trivy findings
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text())
        # All findings should be from trivy
        for finding in data.get("new_findings", []):
            assert finding["tool"]["name"] == "trivy"

    def test_cmd_diff_category_filter(self, sample_scan_directories, tmp_path):
        """Test category filtering (--only new)."""
        baseline, current = sample_scan_directories
        output_file = tmp_path / "new-only.json"

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = str(output_file)
            db = None
            severity = None
            tool = None
            only = "new"  # Only show new findings
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text())
        # Should have new findings but empty resolved/modified
        assert "new_findings" in data
        assert len(data.get("resolved_findings", [])) == 0
        assert len(data.get("modified_findings", [])) == 0


class TestCmdDiffSQLiteMode:
    """Tests for cmd_diff SQLite mode (lines 362-381)."""

    def test_cmd_diff_sqlite_mode_db_not_found(self, tmp_path, capsys):
        """Test error when SQLite database doesn't exist."""

        class Args:
            auto = False
            directories = None
            scan_ids = ["scan1", "scan2"]
            format = "json"
            output = None
            db = str(tmp_path / "nonexistent.db")
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Database not found" in captured.err

    def test_cmd_diff_sqlite_mode_default_db_not_found(
        self, tmp_path, monkeypatch, capsys
    ):
        """Test error when default database (~/.jmo/scans.db) doesn't exist."""
        # Mock Path.home() to return tmp_path
        monkeypatch.setattr(Path, "home", lambda: tmp_path)

        class Args:
            auto = False
            directories = None
            scan_ids = ["scan1", "scan2"]
            format = "json"
            output = None
            db = None  # Use default
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Database not found" in captured.err


class TestCmdDiffEdgeCases:
    """Tests for edge cases and error handling."""

    def test_cmd_diff_html_default_output_path(
        self, sample_scan_directories, tmp_path, monkeypatch
    ):
        """Test HTML format uses default output path when not specified."""
        baseline, current = sample_scan_directories

        # Change to tmp_path so default file is created there
        monkeypatch.chdir(tmp_path)

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "html"
            output = None  # Use default: diff-report.html
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        # Should create diff-report.html in current directory
        default_file = tmp_path / "diff-report.html"
        assert default_file.exists()

    def test_cmd_diff_sarif_default_output_path(
        self, sample_scan_directories, tmp_path, monkeypatch
    ):
        """Test SARIF format uses default output path when not specified."""
        baseline, current = sample_scan_directories

        # Change to tmp_path so default file is created there
        monkeypatch.chdir(tmp_path)

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "sarif"
            output = None  # Use default: diff.sarif
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        # Should create diff.sarif in current directory
        default_file = tmp_path / "diff.sarif"
        assert default_file.exists()

    def test_cmd_diff_no_modifications_flag(self, sample_scan_directories, tmp_path):
        """Test --no-modifications flag disables modification detection."""
        baseline, current = sample_scan_directories
        output_file = tmp_path / "diff.json"

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = str(output_file)
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = True  # Disable modification detection

        result = cmd_diff(Args())

        assert result == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text())
        # Modifications should be empty or not present
        assert len(data.get("modified_findings", [])) == 0

    def test_cmd_diff_with_multiple_filters(self, sample_scan_directories, tmp_path):
        """Test combining multiple filters (severity + tool + category)."""
        baseline, current = sample_scan_directories
        output_file = tmp_path / "multi-filter.json"

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = str(output_file)
            db = None
            severity = "HIGH,CRITICAL"
            tool = "semgrep"
            only = "new"
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 0
        assert output_file.exists()

        data = json.loads(output_file.read_text())
        # All findings should pass all filters
        for finding in data.get("new_findings", []):
            assert finding["severity"] in ["HIGH", "CRITICAL"]
            assert finding["tool"]["name"] == "semgrep"

        # Should have only new findings
        assert len(data.get("resolved_findings", [])) == 0
        assert len(data.get("modified_findings", [])) == 0


class TestCmdDiffExceptionHandling:
    """Tests for exception handling in cmd_diff (lines 373-381, 441-443)."""

    def test_cmd_diff_diff_engine_file_not_found(self, tmp_path, monkeypatch, capsys):
        """Test FileNotFoundError handling from DiffEngine."""
        from scripts.core.diff_engine import DiffEngine

        baseline = tmp_path / "baseline"
        baseline.mkdir()
        current = tmp_path / "current"
        current.mkdir()

        # Mock DiffEngine.compare_directories to raise FileNotFoundError
        _original_compare = DiffEngine.compare_directories

        def mock_compare_directories(self, *args, **kwargs):
            raise FileNotFoundError("Test file not found")

        monkeypatch.setattr(DiffEngine, "compare_directories", mock_compare_directories)

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err
        assert "Test file not found" in captured.err

    def test_cmd_diff_diff_engine_value_error(self, tmp_path, monkeypatch, capsys):
        """Test ValueError handling from DiffEngine."""
        from scripts.core.diff_engine import DiffEngine

        baseline = tmp_path / "baseline"
        baseline.mkdir()
        current = tmp_path / "current"
        current.mkdir()

        # Mock DiffEngine.compare_directories to raise ValueError
        def mock_compare_directories(self, *args, **kwargs):
            raise ValueError("Invalid scan data")

        monkeypatch.setattr(DiffEngine, "compare_directories", mock_compare_directories)

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Error:" in captured.err
        assert "Invalid scan data" in captured.err

    def test_cmd_diff_diff_engine_general_exception(
        self, tmp_path, monkeypatch, capsys
    ):
        """Test general Exception handling from DiffEngine."""
        from scripts.core.diff_engine import DiffEngine

        baseline = tmp_path / "baseline"
        baseline.mkdir()
        current = tmp_path / "current"
        current.mkdir()

        # Mock DiffEngine.compare_directories to raise general Exception
        def mock_compare_directories(self, *args, **kwargs):
            raise RuntimeError("Unexpected error")

        monkeypatch.setattr(DiffEngine, "compare_directories", mock_compare_directories)

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = None
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Error during diff:" in captured.err
        assert "Unexpected error" in captured.err

    def test_cmd_diff_output_generation_error(
        self, sample_scan_directories, monkeypatch, capsys
    ):
        """Test error handling during output generation."""
        baseline, current = sample_scan_directories

        # Mock a reporter to raise an exception
        from scripts.core.reporters import diff_json_reporter

        _original_write = diff_json_reporter.write_json_diff

        def mock_write_json_diff(*args, **kwargs):
            raise IOError("Failed to write file")

        monkeypatch.setattr(diff_json_reporter, "write_json_diff", mock_write_json_diff)

        class Args:
            auto = False
            directories = [str(baseline), str(current)]
            scan_ids = None
            format = "json"
            output = "/tmp/test-output.json"  # Will fail in mock
            db = None
            severity = None
            tool = None
            only = None
            no_modifications = False

        result = cmd_diff(Args())

        assert result == 1
        captured = capsys.readouterr()
        assert "Error generating output:" in captured.err
        assert "Failed to write file" in captured.err
