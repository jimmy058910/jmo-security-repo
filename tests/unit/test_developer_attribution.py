#!/usr/bin/env python3
"""
Unit tests for developer attribution via git blame.

Tests cover:
- DeveloperAttribution class
- Git blame parsing
- Team aggregation
- Developer statistics
- Format functions
"""

import json
import subprocess
from unittest import mock

import pytest

from scripts.core.developer_attribution import (
    DeveloperAttribution,
    DeveloperStats,
    TeamStats,
    format_developer_stats,
    format_team_stats,
    load_team_mapping,
)


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture
def mock_repo(tmp_path):
    """Create a mock git repository."""
    repo_dir = tmp_path / "mock_repo"
    repo_dir.mkdir()
    (repo_dir / ".git").mkdir()

    # Create some test files
    (repo_dir / "src").mkdir()
    (repo_dir / "src" / "main.py").write_text("print('hello')\n")
    (repo_dir / "src" / "auth.py").write_text("def login(): pass\n")

    return repo_dir


@pytest.fixture
def mock_history_db():
    """Create mock history database."""

    class MockHistoryDB:
        def __init__(self):
            self.findings = {
                "fp1": {
                    "fingerprint": "fp1",
                    "path": "src/main.py",
                    "start_line": 1,
                    "severity": "HIGH",
                    "tool": "semgrep",
                    "rule_id": "test-rule-1",
                    "message": "SQL injection vulnerability",
                    "risk": {"cwe": "CWE-89"},
                },
                "fp2": {
                    "fingerprint": "fp2",
                    "path": "src/auth.py",
                    "start_line": 1,
                    "severity": "MEDIUM",
                    "tool": "bandit",
                    "rule_id": "test-rule-2",
                    "message": "Hardcoded password",
                    "risk": {"cwe": "CWE-798"},
                },
                "fp3": {
                    "fingerprint": "fp3",
                    "path": "src/main.py",
                    "start_line": 5,
                    "severity": "CRITICAL",
                    "tool": "trivy",
                    "rule_id": "test-rule-3",
                    "message": "Remote code execution",
                    "risk": {"cwe": "CWE-94"},
                },
            }

        def get_finding_by_fingerprint(self, fp):
            return self.findings.get(fp)

    return MockHistoryDB()


@pytest.fixture
def sample_dev_stats():
    """Create sample developer statistics for testing."""
    return [
        DeveloperStats(
            name="Alice Smith",
            email="alice@example.com",
            findings_resolved=45,
            findings_introduced=3,
            focus_areas=["src/api/auth.py", "src/api/users.py"],
            top_tools=["semgrep", "trivy", "bandit"],
            cwe_categories={"CWE-79", "CWE-89", "CWE-798"},
            severity_breakdown={"CRITICAL": 5, "HIGH": 20, "MEDIUM": 15, "LOW": 5},
        ),
        DeveloperStats(
            name="Bob Johnson",
            email="bob@example.com",
            findings_resolved=38,
            findings_introduced=2,
            focus_areas=["src/lib/utils.py", "src/lib/helpers.py"],
            top_tools=["bandit", "trivy"],
            cwe_categories={"CWE-22", "CWE-78"},
            severity_breakdown={"HIGH": 18, "MEDIUM": 15, "LOW": 5},
        ),
        DeveloperStats(
            name="Charlie Davis",
            email="charlie@example.com",
            findings_resolved=12,
            findings_introduced=8,
            focus_areas=["src/frontend/app.js"],
            top_tools=["semgrep"],
            cwe_categories={"CWE-79"},
            severity_breakdown={"MEDIUM": 10, "LOW": 2},
        ),
    ]


# ============================================================================
# Test DeveloperAttribution Class
# ============================================================================


def test_developer_attribution_init_valid_repo(mock_repo):
    """Test initialization with valid git repository."""
    attrib = DeveloperAttribution(mock_repo)
    assert attrib.repo_path == mock_repo


def test_developer_attribution_init_invalid_repo(tmp_path):
    """Test initialization with invalid repository raises error."""
    non_repo = tmp_path / "not_a_repo"
    non_repo.mkdir()

    with pytest.raises(ValueError, match="Not a git repository"):
        DeveloperAttribution(non_repo)


def test_analyze_remediation_by_developer_empty_set(mock_repo, mock_history_db):
    """Test analysis with empty fingerprint set."""
    attrib = DeveloperAttribution(mock_repo)

    result = attrib.analyze_remediation_by_developer(set(), mock_history_db)

    assert result == []


def test_analyze_remediation_by_developer_with_mocked_blame(mock_repo, mock_history_db):
    """Test analysis with mocked git blame output."""
    attrib = DeveloperAttribution(mock_repo)

    # Mock git blame to return consistent author info
    def mock_git_blame(file_path, line_num):
        return {"name": "Alice Smith", "email": "alice@example.com"}

    attrib._git_blame_line = mock_git_blame

    resolved = {"fp1", "fp2"}
    result = attrib.analyze_remediation_by_developer(resolved, mock_history_db)

    assert len(result) == 1
    assert result[0].name == "Alice Smith"
    assert result[0].email == "alice@example.com"
    assert result[0].findings_resolved == 2
    assert result[0].net_contribution == 2


def test_analyze_remediation_by_developer_multiple_developers(
    mock_repo, mock_history_db
):
    """Test analysis with multiple developers."""
    attrib = DeveloperAttribution(mock_repo)

    # Mock git blame to return different authors
    def mock_git_blame(file_path, line_num):
        if "main.py" in file_path:
            return {"name": "Alice Smith", "email": "alice@example.com"}
        else:
            return {"name": "Bob Johnson", "email": "bob@example.com"}

    attrib._git_blame_line = mock_git_blame

    resolved = {"fp1", "fp2"}  # fp1=main.py, fp2=auth.py
    result = attrib.analyze_remediation_by_developer(resolved, mock_history_db)

    assert len(result) == 2
    # Results should be sorted by net_contribution
    assert result[0].findings_resolved >= result[1].findings_resolved


def test_analyze_remediation_tracks_tools(mock_repo, mock_history_db):
    """Test that analysis tracks tools used by developers."""
    attrib = DeveloperAttribution(mock_repo)

    def mock_git_blame(file_path, line_num):
        return {"name": "Alice Smith", "email": "alice@example.com"}

    attrib._git_blame_line = mock_git_blame

    resolved = {"fp1", "fp2"}  # fp1=semgrep, fp2=bandit
    result = attrib.analyze_remediation_by_developer(resolved, mock_history_db)

    assert len(result) == 1
    assert "semgrep" in result[0].top_tools
    assert "bandit" in result[0].top_tools


def test_analyze_remediation_tracks_cwe(mock_repo, mock_history_db):
    """Test that analysis tracks CWE categories."""
    attrib = DeveloperAttribution(mock_repo)

    def mock_git_blame(file_path, line_num):
        return {"name": "Alice Smith", "email": "alice@example.com"}

    attrib._git_blame_line = mock_git_blame

    resolved = {"fp1", "fp2"}  # CWE-89, CWE-798
    result = attrib.analyze_remediation_by_developer(resolved, mock_history_db)

    assert len(result) == 1
    assert "CWE-89" in result[0].cwe_categories
    assert "CWE-798" in result[0].cwe_categories


def test_analyze_remediation_tracks_severity(mock_repo, mock_history_db):
    """Test that analysis tracks severity breakdown."""
    attrib = DeveloperAttribution(mock_repo)

    def mock_git_blame(file_path, line_num):
        return {"name": "Alice Smith", "email": "alice@example.com"}

    attrib._git_blame_line = mock_git_blame

    resolved = {"fp1", "fp3"}  # HIGH, CRITICAL
    result = attrib.analyze_remediation_by_developer(resolved, mock_history_db)

    assert len(result) == 1
    assert result[0].severity_breakdown["HIGH"] == 1
    assert result[0].severity_breakdown["CRITICAL"] == 1


# ============================================================================
# Test Git Blame Parsing
# ============================================================================


def test_git_blame_line_success(mock_repo):
    """Test successful git blame parsing."""
    attrib = DeveloperAttribution(mock_repo)

    # Mock subprocess.run to return valid porcelain output
    mock_result = mock.Mock()
    mock_result.returncode = 0
    mock_result.stdout = """abcd1234 1 1 1
author Alice Smith
author-mail <alice@example.com>
author-time 1234567890
committer Alice Smith
committer-mail <alice@example.com>
committer-time 1234567890
summary Test commit
filename src/main.py
\tprint('hello')
"""

    with mock.patch("subprocess.run", return_value=mock_result):
        result = attrib._git_blame_line("src/main.py", 1)

    assert result is not None
    assert result["name"] == "Alice Smith"
    assert result["email"] == "alice@example.com"


def test_git_blame_line_file_not_found(mock_repo):
    """Test git blame with non-existent file."""
    attrib = DeveloperAttribution(mock_repo)

    # Mock subprocess.run to return error
    mock_result = mock.Mock()
    mock_result.returncode = 128
    mock_result.stderr = "fatal: no such path"

    with mock.patch("subprocess.run", return_value=mock_result):
        result = attrib._git_blame_line("nonexistent.py", 1)

    assert result is None


def test_git_blame_line_timeout(mock_repo):
    """Test git blame timeout handling."""
    attrib = DeveloperAttribution(mock_repo)

    with mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("git", 10)):
        result = attrib._git_blame_line("src/main.py", 1)

    assert result is None


def test_git_blame_line_malformed_output(mock_repo):
    """Test git blame with malformed porcelain output."""
    attrib = DeveloperAttribution(mock_repo)

    # Mock subprocess.run to return incomplete output
    mock_result = mock.Mock()
    mock_result.returncode = 0
    mock_result.stdout = "author Alice Smith\n"  # Missing author-mail

    with mock.patch("subprocess.run", return_value=mock_result):
        result = attrib._git_blame_line("src/main.py", 1)

    assert result is None


# ============================================================================
# Test Team Aggregation
# ============================================================================


def test_aggregate_by_team_basic(sample_dev_stats, mock_repo):
    """Test basic team aggregation."""
    attrib = DeveloperAttribution(mock_repo)

    team_mapping = {
        "alice@example.com": "Backend",
        "bob@example.com": "Backend",
        "charlie@example.com": "Frontend",
    }

    result = attrib.aggregate_by_team(sample_dev_stats, team_mapping)

    assert len(result) == 2
    # Backend team should be first (more contributions)
    assert result[0].team_name == "Backend"
    assert result[0].member_count == 2
    assert result[0].total_resolved == 45 + 38


def test_aggregate_by_team_unknown_members(sample_dev_stats, mock_repo):
    """Test team aggregation with unmapped developers."""
    attrib = DeveloperAttribution(mock_repo)

    team_mapping = {
        "alice@example.com": "Backend",
    }

    result = attrib.aggregate_by_team(sample_dev_stats, team_mapping)

    # Should have Backend + Unknown team
    assert len(result) >= 2
    team_names = [t.team_name for t in result]
    assert "Backend" in team_names
    assert "Unknown" in team_names


def test_aggregate_by_team_top_remediators(sample_dev_stats, mock_repo):
    """Test that team aggregation identifies top remediators."""
    attrib = DeveloperAttribution(mock_repo)

    team_mapping = {
        "alice@example.com": "Backend",
        "bob@example.com": "Backend",
    }

    result = attrib.aggregate_by_team(sample_dev_stats, team_mapping)

    backend_team = [t for t in result if t.team_name == "Backend"][0]
    assert len(backend_team.top_remediators) == 2
    # Alice should be first (more resolved)
    assert backend_team.top_remediators[0].name == "Alice Smith"


def test_aggregate_by_team_net_contribution(sample_dev_stats, mock_repo):
    """Test team net contribution calculation."""
    attrib = DeveloperAttribution(mock_repo)

    team_mapping = {
        "alice@example.com": "Team A",
        "bob@example.com": "Team A",
    }

    result = attrib.aggregate_by_team(sample_dev_stats, team_mapping)

    team_a = [t for t in result if t.team_name == "Team A"][0]
    # (45 - 3) + (38 - 2) = 78
    assert team_a.net_contribution == 78


# ============================================================================
# Test Data Classes
# ============================================================================


def test_developer_stats_net_contribution():
    """Test DeveloperStats net_contribution property."""
    dev = DeveloperStats(
        name="Test Dev",
        email="test@example.com",
        findings_resolved=50,
        findings_introduced=10,
    )

    assert dev.net_contribution == 40


def test_team_stats_properties():
    """Test TeamStats computed properties."""
    team = TeamStats(
        team_name="Backend",
        members=["alice@example.com", "bob@example.com"],
        total_resolved=100,
        total_introduced=20,
    )

    assert team.net_contribution == 80
    assert team.member_count == 2


# ============================================================================
# Test Format Functions
# ============================================================================


def test_format_developer_stats_basic(sample_dev_stats):
    """Test basic developer stats formatting."""
    dev = sample_dev_stats[0]

    output = format_developer_stats(dev)

    assert "Alice Smith" in output
    assert "alice@example.com" in output
    assert "45 findings" in output


def test_format_developer_stats_with_rank(sample_dev_stats):
    """Test developer stats formatting with rank."""
    dev = sample_dev_stats[0]

    output = format_developer_stats(dev, rank=1)

    assert output.startswith("1. ")
    assert "Alice Smith" in output


def test_format_developer_stats_includes_tools(sample_dev_stats):
    """Test that formatting includes tool list."""
    dev = sample_dev_stats[0]

    output = format_developer_stats(dev)

    assert "semgrep" in output
    assert "trivy" in output
    assert "bandit" in output


def test_format_developer_stats_includes_cwe(sample_dev_stats):
    """Test that formatting includes CWE categories."""
    dev = sample_dev_stats[0]

    output = format_developer_stats(dev)

    assert "CWE-79" in output
    assert "CWE-89" in output


def test_format_team_stats_basic():
    """Test basic team stats formatting."""
    team = TeamStats(
        team_name="Backend Team",
        members=["alice@example.com", "bob@example.com"],
        total_resolved=100,
        total_introduced=10,
    )

    output = format_team_stats(team)

    assert "Backend Team" in output
    assert "Members: 2" in output
    assert "100 findings" in output


def test_format_team_stats_with_rank():
    """Test team stats formatting with rank."""
    team = TeamStats(
        team_name="Backend Team",
        members=["alice@example.com"],
        total_resolved=50,
    )

    output = format_team_stats(team, rank=1)

    assert output.startswith("1. ")


# ============================================================================
# Test Helper Functions
# ============================================================================


def test_load_team_mapping_valid_file(tmp_path):
    """Test loading team mapping from valid JSON file."""
    team_file = tmp_path / "teams.json"
    team_data = {
        "alice@example.com": "Backend",
        "bob@example.com": "Frontend",
    }
    team_file.write_text(json.dumps(team_data))

    result = load_team_mapping(team_file)

    assert result == team_data


def test_load_team_mapping_missing_file(tmp_path):
    """Test loading team mapping from non-existent file."""
    team_file = tmp_path / "nonexistent.json"

    with pytest.raises(FileNotFoundError):
        load_team_mapping(team_file)


# ============================================================================
# Test Edge Cases
# ============================================================================


def test_analyze_remediation_finding_not_in_db(mock_repo):
    """Test analysis when finding not found in database."""
    attrib = DeveloperAttribution(mock_repo)

    class EmptyDB:
        def get_finding_by_fingerprint(self, fp):
            return None

    resolved = {"unknown_fp"}
    result = attrib.analyze_remediation_by_developer(resolved, EmptyDB())

    assert result == []


def test_analyze_remediation_missing_location(mock_repo):
    """Test analysis when finding has missing location info."""
    attrib = DeveloperAttribution(mock_repo)

    class MockDB:
        def get_finding_by_fingerprint(self, fp):
            return {"fingerprint": fp}  # Missing path and start_line

    def mock_git_blame(file_path, line_num):
        return {"name": "Alice", "email": "alice@example.com"}

    attrib._git_blame_line = mock_git_blame

    resolved = {"fp1"}
    result = attrib.analyze_remediation_by_developer(resolved, MockDB())

    assert result == []


def test_analyze_remediation_git_blame_fails(mock_repo, mock_history_db):
    """Test analysis when git blame fails for all files."""
    attrib = DeveloperAttribution(mock_repo)

    # Mock git blame to always return None
    attrib._git_blame_line = lambda f, line_num: None

    resolved = {"fp1", "fp2"}
    result = attrib.analyze_remediation_by_developer(resolved, mock_history_db)

    assert result == []


def test_get_developer_velocity_not_implemented(mock_repo):
    """Test that developer velocity returns empty metrics."""
    attrib = DeveloperAttribution(mock_repo)

    velocity = attrib.get_developer_velocity("alice@example.com", None, 30)

    assert velocity["findings_per_day"] == 0.0
    assert velocity["active_days"] == 0


# ============================================================================
# Integration Tests
# ============================================================================


def test_full_attribution_workflow(mock_repo, mock_history_db):
    """Test full attribution workflow from start to finish."""
    attrib = DeveloperAttribution(mock_repo)

    # Mock git blame
    def mock_git_blame(file_path, line_num):
        if "main.py" in file_path:
            return {"name": "Alice", "email": "alice@example.com"}
        else:
            return {"name": "Bob", "email": "bob@example.com"}

    attrib._git_blame_line = mock_git_blame

    # Analyze
    resolved = {"fp1", "fp2", "fp3"}
    dev_stats = attrib.analyze_remediation_by_developer(resolved, mock_history_db)

    # Aggregate
    team_mapping = {
        "alice@example.com": "Backend",
        "bob@example.com": "Backend",
    }
    team_stats = attrib.aggregate_by_team(dev_stats, team_mapping)

    # Verify
    assert len(dev_stats) == 2
    assert len(team_stats) == 1
    assert team_stats[0].team_name == "Backend"
    assert team_stats[0].total_resolved == 3


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
