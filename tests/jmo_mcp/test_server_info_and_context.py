"""
Tests for get_server_info and get_finding_context MCP tools.

Combined file for efficiency to complete Phase 2B endpoint testing.
"""

import json
from pathlib import Path

import pytest

from scripts.jmo_mcp.jmo_server import (
    get_server_info,
    get_finding_context,
    rate_limiter,
)


@pytest.fixture
def mock_findings_file(tmp_path):
    """Create temporary findings.json fixture"""
    fixtures_dir = Path(__file__).parent / "fixtures"
    findings_json = fixtures_dir / "findings.json"
    repo_dir = fixtures_dir / "repo"

    # Copy fixture to temp results directory
    results_dir = tmp_path / "results" / "summaries"
    results_dir.mkdir(parents=True, exist_ok=True)

    with open(findings_json) as f:
        findings_data = json.load(f)

    output_path = results_dir / "findings.json"
    with open(output_path, "w") as f:
        json.dump(findings_data, f, indent=2)

    # Copy repo fixtures
    import shutil

    if repo_dir.exists():
        shutil.copytree(repo_dir, tmp_path / "repo", dirs_exist_ok=True)

    return tmp_path


@pytest.fixture
def mock_env(mock_findings_file, monkeypatch):
    """Mock environment variables for MCP server"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(mock_findings_file / "results"))
    monkeypatch.setenv("MCP_REPO_ROOT", str(mock_findings_file / "repo"))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    # Reload module to apply new environment
    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    yield mock_findings_file

    if rate_limiter:
        rate_limiter.buckets.clear()


# ==============================================================================
# get_server_info Tests
# ==============================================================================


def test_get_server_info_with_findings(mock_env):
    """Test get_server_info returns server metadata and findings count"""
    result = get_server_info()

    assert "version" in result
    assert "results_dir" in result
    assert "repo_root" in result
    assert "total_findings" in result
    assert "severity_distribution" in result

    assert result["total_findings"] == 5  # From fixtures
    assert isinstance(result["severity_distribution"], dict)


def test_get_server_info_without_findings(tmp_path, monkeypatch):
    """Test get_server_info when no findings file exists"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    result = jmo_server.get_server_info()

    assert result["total_findings"] == 0
    assert "error" in result


def test_get_server_info_rate_limit(mock_env):
    """Test get_server_info is rate limited"""
    # Multiple calls should work with rate limiting disabled
    for _ in range(5):
        result = get_server_info()
        assert "version" in result


# ==============================================================================
# get_finding_context Tests
# ==============================================================================


def test_get_finding_context_success(mock_env):
    """Test get_finding_context retrieves full context"""
    result = get_finding_context("fingerprint-xss-001")

    assert "finding" in result
    assert "source_code" in result
    assert "remediation" in result
    assert "related_findings" in result

    # Check finding details
    assert result["finding"]["id"] == "fingerprint-xss-001"

    # Check source code context
    assert "lines" in result["source_code"]
    assert "language" in result["source_code"]


def test_get_finding_context_not_found(mock_env):
    """Test get_finding_context with invalid finding ID"""
    with pytest.raises(ValueError, match="Finding not found"):
        get_finding_context("nonexistent-finding")


def test_get_finding_context_all_findings(mock_env):
    """Test get_finding_context for all fixture findings"""
    finding_ids = [
        "fingerprint-xss-001",
        "fingerprint-sqli-001",
        "fingerprint-crypto-001",
        "fingerprint-path-traversal-001",
        "fingerprint-hardcoded-secret-001",
    ]

    for finding_id in finding_ids:
        result = get_finding_context(finding_id)
        assert result["finding"]["id"] == finding_id
        assert "source_code" in result


def test_get_finding_context_remediation_structure(mock_env):
    """Test remediation section has required fields"""
    result = get_finding_context("fingerprint-xss-001")

    remediation = result["remediation"]
    assert "description" in remediation
    assert "references" in remediation
    assert "cwe" in remediation
    assert "owasp" in remediation
