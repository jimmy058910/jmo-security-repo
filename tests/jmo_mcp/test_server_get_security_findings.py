"""
Tests for get_security_findings MCP tool.

Coverage:
- Filtering by severity, tool, rule_id, path
- Pagination (limit, offset)
- Edge cases (empty results, invalid filters, missing findings file)
- Rate limiting integration
"""

import json
import os
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from scripts.jmo_mcp.jmo_server import (
    get_security_findings,
    rate_limiter,
)


@pytest.fixture
def mock_findings_file(tmp_path):
    """Create temporary findings.json fixture"""
    fixtures_dir = Path(__file__).parent / "fixtures"
    findings_json = fixtures_dir / "findings.json"

    # Copy fixture to temp results directory
    results_dir = tmp_path / "results" / "summaries"
    results_dir.mkdir(parents=True, exist_ok=True)

    with open(findings_json) as f:
        findings_data = json.load(f)

    output_path = results_dir / "findings.json"
    with open(output_path, "w") as f:
        json.dump(findings_data, f, indent=2)

    return tmp_path


@pytest.fixture
def mock_env(mock_findings_file, monkeypatch):
    """Mock environment variables for MCP server"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(mock_findings_file / "results"))
    monkeypatch.setenv("MCP_REPO_ROOT", str(mock_findings_file))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    # Reload module to apply new environment
    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    yield mock_findings_file

    # Restore rate limiter state
    if rate_limiter:
        rate_limiter.buckets.clear()


# ==============================================================================
# Filtering Tests
# ==============================================================================


def test_get_security_findings_no_filters(mock_env):
    """Test retrieving all findings without filters"""
    result = get_security_findings()

    assert "findings" in result
    assert "total" in result
    assert "limit" in result
    assert "offset" in result

    assert result["total"] == 5  # From fixtures/findings.json
    assert len(result["findings"]) == 5
    assert result["limit"] == 100
    assert result["offset"] == 0


def test_get_security_findings_filter_severity_high(mock_env):
    """Test filtering by HIGH severity"""
    result = get_security_findings(severity=["HIGH"])

    assert result["total"] == 2  # XSS + Path Traversal
    assert len(result["findings"]) == 2

    for finding in result["findings"]:
        assert finding["severity"] == "HIGH"


def test_get_security_findings_filter_severity_critical(mock_env):
    """Test filtering by CRITICAL severity"""
    result = get_security_findings(severity=["CRITICAL"])

    assert result["total"] == 2  # SQL Injection + Hardcoded Secret
    assert len(result["findings"]) == 2

    for finding in result["findings"]:
        assert finding["severity"] == "CRITICAL"


def test_get_security_findings_filter_severity_multiple(mock_env):
    """Test filtering by multiple severities"""
    result = get_security_findings(severity=["HIGH", "CRITICAL"])

    assert result["total"] == 4  # All except MEDIUM
    assert len(result["findings"]) == 4

    severities = {f["severity"] for f in result["findings"]}
    assert severities == {"HIGH", "CRITICAL"}


def test_get_security_findings_filter_tool_semgrep(mock_env):
    """Test filtering by tool name"""
    result = get_security_findings(tool="semgrep")

    assert result["total"] == 3  # XSS + SQL Injection + Path Traversal
    assert len(result["findings"]) == 3

    for finding in result["findings"]:
        assert finding["tool"]["name"] == "semgrep"


def test_get_security_findings_filter_tool_trivy(mock_env):
    """Test filtering by trivy"""
    result = get_security_findings(tool="trivy")

    assert result["total"] == 1  # Weak crypto
    assert len(result["findings"]) == 1
    assert result["findings"][0]["tool"]["name"] == "trivy"


def test_get_security_findings_filter_rule_id(mock_env):
    """Test filtering by rule ID (CWE)"""
    result = get_security_findings(rule_id="CWE-79")

    assert result["total"] == 1  # XSS vulnerability
    assert len(result["findings"]) == 1
    assert result["findings"][0]["ruleId"] == "CWE-79"
    assert result["findings"][0]["id"] == "fingerprint-xss-001"


def test_get_security_findings_filter_path(mock_env):
    """Test filtering by file path (substring match)"""
    result = get_security_findings(path="src/")

    assert result["total"] == 4  # All in src/ directory
    assert len(result["findings"]) == 4

    for finding in result["findings"]:
        assert "src/" in finding["location"]["path"]


def test_get_security_findings_filter_path_exact(mock_env):
    """Test filtering by exact file path"""
    result = get_security_findings(path="src/app.js")

    assert result["total"] == 1  # XSS vulnerability
    assert len(result["findings"]) == 1
    assert result["findings"][0]["location"]["path"] == "src/app.js"


def test_get_security_findings_combined_filters(mock_env):
    """Test combining multiple filters"""
    result = get_security_findings(severity=["HIGH"], tool="semgrep", path="src/")

    assert result["total"] == 2  # XSS + Path Traversal
    assert len(result["findings"]) == 2

    for finding in result["findings"]:
        assert finding["severity"] == "HIGH"
        assert finding["tool"]["name"] == "semgrep"
        assert "src/" in finding["location"]["path"]


# ==============================================================================
# Pagination Tests
# ==============================================================================


def test_get_security_findings_pagination_limit(mock_env):
    """Test pagination with limit"""
    result = get_security_findings(limit=2)

    assert result["total"] == 5  # Total count unchanged
    assert len(result["findings"]) == 2  # Limited to 2
    assert result["limit"] == 2
    assert result["offset"] == 0


def test_get_security_findings_pagination_offset(mock_env):
    """Test pagination with offset"""
    # Get first 2
    result1 = get_security_findings(limit=2, offset=0)
    first_ids = {f["id"] for f in result1["findings"]}

    # Get next 2
    result2 = get_security_findings(limit=2, offset=2)
    second_ids = {f["id"] for f in result2["findings"]}

    # Should be different findings
    assert len(first_ids & second_ids) == 0  # No overlap


def test_get_security_findings_pagination_max_limit(mock_env):
    """Test limit cap at 1000"""
    result = get_security_findings(limit=9999)

    # Should cap at 1000 internally, but since we have 5 findings, returns 5
    assert len(result["findings"]) == 5
    assert result["limit"] == 9999  # Original limit preserved in response


def test_get_security_findings_pagination_offset_beyond_total(mock_env):
    """Test offset beyond total findings"""
    result = get_security_findings(offset=100)

    assert result["total"] == 5
    assert len(result["findings"]) == 0  # No findings at this offset


# ==============================================================================
# Edge Cases
# ==============================================================================


def test_get_security_findings_no_matches(mock_env):
    """Test filtering with no matches"""
    result = get_security_findings(severity=["LOW"])  # No LOW findings in fixture

    assert result["total"] == 0
    assert len(result["findings"]) == 0


def test_get_security_findings_invalid_severity_ignored(mock_env):
    """Test that invalid severity values are handled gracefully"""
    # FindingsLoader should handle this gracefully by treating it as no match
    result = get_security_findings(severity=["INVALID"])

    assert result["total"] == 0
    assert len(result["findings"]) == 0


def test_get_security_findings_missing_findings_file(tmp_path, monkeypatch):
    """Test behavior when findings.json doesn't exist"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    # Reload module to apply new environment
    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    with pytest.raises(ValueError, match="No scan results found"):
        get_security_findings()


def test_get_security_findings_empty_findings_file(tmp_path, monkeypatch):
    """Test behavior with empty findings array"""
    results_dir = tmp_path / "results" / "summaries"
    results_dir.mkdir(parents=True, exist_ok=True)

    findings_path = results_dir / "findings.json"
    with open(findings_path, "w") as f:
        json.dump([], f)  # Empty list, not object

    monkeypatch.setenv("MCP_RESULTS_DIR", str(tmp_path / "results"))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    result = get_security_findings()

    assert result["total"] == 0
    assert len(result["findings"]) == 0


# ==============================================================================
# Rate Limiting Integration Tests
# ==============================================================================


def test_get_security_findings_rate_limit_enforcement(mock_findings_file, monkeypatch):
    """Test rate limiting is enforced when enabled"""
    # Set aggressive rate limit (1 request capacity)
    monkeypatch.setenv("MCP_RESULTS_DIR", str(mock_findings_file / "results"))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_CAPACITY", "1")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_REFILL_RATE", "0.1")  # Slow refill

    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    # First request should succeed
    result1 = jmo_server.get_security_findings()
    assert "findings" in result1

    # Second request should fail (bucket exhausted)
    with pytest.raises(ValueError, match="Rate limit exceeded"):
        jmo_server.get_security_findings()


def test_get_security_findings_rate_limit_disabled(mock_env):
    """Test rate limiting can be disabled"""
    # Rate limiting disabled via mock_env fixture

    # Should be able to make multiple requests
    for _ in range(10):
        result = get_security_findings()
        assert "findings" in result


# ==============================================================================
# Response Structure Tests
# ==============================================================================


def test_get_security_findings_response_structure(mock_env):
    """Test response contains all required fields"""
    result = get_security_findings()

    # Top-level fields
    assert "findings" in result
    assert "total" in result
    assert "limit" in result
    assert "offset" in result

    # Findings array structure
    assert isinstance(result["findings"], list)

    # Check first finding has CommonFinding schema fields
    if result["findings"]:
        finding = result["findings"][0]
        assert "id" in finding
        assert "ruleId" in finding
        assert "severity" in finding
        assert "tool" in finding
        assert "location" in finding
        assert "message" in finding

        # Tool structure
        assert "name" in finding["tool"]
        assert "version" in finding["tool"]

        # Location structure
        assert "path" in finding["location"]
        assert "startLine" in finding["location"]


def test_get_security_findings_finding_ids_unique(mock_env):
    """Test that finding IDs are unique"""
    result = get_security_findings()

    finding_ids = [f["id"] for f in result["findings"]]
    assert len(finding_ids) == len(set(finding_ids))  # All unique
