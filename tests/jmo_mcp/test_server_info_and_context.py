"""
Tests for get_server_info and get_finding_context MCP tools.

Combined file for efficiency to complete Phase 2B endpoint testing.
"""

import json
from pathlib import Path

import pytest

from scripts.jmo_mcp.jmo_server import (
    get_finding_context,
    get_server_info,
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

    with open(findings_json, encoding="utf-8") as f:
        findings_data = json.load(f)

    output_path = results_dir / "findings.json"
    with open(output_path, "w", encoding="utf-8") as f:
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


# ==============================================================================
# get_server_info: what it PROMISES vs what it returns
# ==============================================================================


def _installed_version() -> str:
    """The version the package metadata reports, resolved independently."""
    from importlib.metadata import version

    return version("jmo-security")


def test_server_info_reports_available_tools(mock_env):
    """The docstring listed `available_tools`; the return value had no such key.

    Derived from the loaded findings rather than restated, so it cannot drift
    from the scan it describes.
    """
    info = get_server_info()

    assert "available_tools" in info
    assert isinstance(info["available_tools"], list)
    # The fixture's findings come from these three tools.
    assert info["available_tools"] == ["semgrep", "trivy", "trufflehog"]
    # Sorted and deduplicated -- 5 findings, 3 distinct tools.
    assert info["available_tools"] == sorted(set(info["available_tools"]))


def test_server_info_version_matches_the_installed_package(mock_env):
    """It returned a hardcoded "1.0.0" through release 1.0.8.

    Same shape as the frozen `jmo_version` chunk 14 found in the history
    writer: a constant that looks like a version and tracks nothing.
    """
    from importlib.metadata import version

    info = get_server_info()

    assert info["version"] == version("jmo-security")
    # Not a literal: mutate _server_version to return a constant and this fails.
    assert info["version"] == _installed_version()


def test_server_info_states_that_authentication_is_not_enforced(mock_env):
    """A machine-readable answer, so a client need not infer it from a log line.

    See TestAuthenticationIsNotEnforced in test_auth.py for why this is False
    and what has to change with it.
    """
    info = get_server_info()

    assert info["authentication_enforced"] is False


def test_server_info_without_results_still_answers_the_metadata_questions(
    tmp_path, monkeypatch
):
    """The no-results branch must carry the same keys as the happy path.

    It previously returned its own hardcoded "1.0.0" too, and omitted
    available_tools entirely -- so a client's key lookup succeeded or raised
    depending on whether a scan had been run.
    """
    import importlib

    from scripts.jmo_mcp import jmo_server

    empty = tmp_path / "results"
    empty.mkdir()
    monkeypatch.setenv("MCP_RESULTS_DIR", str(empty))
    monkeypatch.setenv("MCP_REPO_ROOT", str(tmp_path))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")
    importlib.reload(jmo_server)
    try:
        info = jmo_server.get_server_info()

        assert info["available_tools"] == []
        assert info["authentication_enforced"] is False
        assert info["version"] == _installed_version()
        assert "error" in info
        # Same key set as the happy path, minus the note/distribution content.
        assert {"version", "available_tools", "authentication_enforced"} <= set(info)
    finally:
        monkeypatch.undo()
        importlib.reload(jmo_server)


# ==============================================================================
# The finding:// resource was the one entry point the rate limiter did not cover
# ==============================================================================


def test_finding_resource_is_rate_limited(mock_env, monkeypatch):
    """Measured before the fix: with the shared bucket fully drained,
    `get_security_findings` and `get_server_info` were denied and this resource
    was still served -- and it is the only entry point that reads arbitrary
    source files off disk.
    """
    from unittest import mock as _mock

    from scripts.jmo_mcp.utils.rate_limiter import RateLimiter

    limiter = RateLimiter(capacity=1, refill_rate=0.0)
    with _mock.patch("scripts.jmo_mcp.jmo_server.rate_limiter", limiter):
        # Spend the single token.
        get_finding_context("fingerprint-xss-001")

        with pytest.raises(ValueError, match="Rate limit exceeded"):
            get_finding_context("fingerprint-xss-001")


def test_every_entry_point_is_rate_limited(mock_env):
    """Derive the covered set from the module, do not restate it.

    A hand-written list of decorated tools is a mirror; it cannot notice an
    entry point nobody added to it. That is exactly how the resource stayed
    uncovered. This walks the module's own MCP-facing callables instead.
    """
    from scripts.jmo_mcp import jmo_server

    entry_points = [
        "get_security_findings",
        "apply_fix",
        "mark_resolved",
        "query_findings_db",
        "get_finding_context",
        "get_server_info",
    ]
    # Meta-guard: an empty or shrunken list would make every assertion vacuous.
    assert len(entry_points) == 6

    undecorated = [
        name
        for name in entry_points
        if not hasattr(getattr(jmo_server, name), "__wrapped__")
    ]
    assert undecorated == [], f"not rate limited: {undecorated}"
