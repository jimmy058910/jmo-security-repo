"""
Tests for mark_resolved MCP tool.

Coverage:
- All valid resolution types (fixed, false_positive, wont_fix, risk_accepted)
- Invalid resolution types
- Finding validation (existence check)
- Optional comment field
- Edge cases (empty comments, unicode, special characters)
- Rate limiting integration
"""

import json
from pathlib import Path
from datetime import datetime

import pytest

from scripts.jmo_mcp.jmo_server import (
    mark_resolved,
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
# Valid Resolution Types Tests
# ==============================================================================


def test_mark_resolved_fixed(mock_env):
    """Test marking finding as fixed"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Manually fixed by adding DOMPurify sanitization",
    )

    assert result["success"] is True
    assert result["finding_id"] == "fingerprint-xss-001"
    assert result["resolution"] == "fixed"
    assert "timestamp" in result
    assert result["timestamp"].endswith("Z")  # ISO format with UTC marker


def test_mark_resolved_false_positive(mock_env):
    """Test marking finding as false positive"""
    result = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
        comment="This is a test file that intentionally shows SQL injection examples",
    )

    assert result["success"] is True
    assert result["finding_id"] == "fingerprint-sqli-001"
    assert result["resolution"] == "false_positive"
    assert "timestamp" in result


def test_mark_resolved_wont_fix(mock_env):
    """Test marking finding as won't fix"""
    result = mark_resolved(
        finding_id="fingerprint-crypto-001",
        resolution="wont_fix",
        comment="Legacy system compatibility requires MD5",
    )

    assert result["success"] is True
    assert result["finding_id"] == "fingerprint-crypto-001"
    assert result["resolution"] == "wont_fix"
    assert "timestamp" in result


def test_mark_resolved_risk_accepted(mock_env):
    """Test marking finding as risk accepted"""
    result = mark_resolved(
        finding_id="fingerprint-path-traversal-001",
        resolution="risk_accepted",
        comment="Risk accepted after security review, internal tool only",
    )

    assert result["success"] is True
    assert result["finding_id"] == "fingerprint-path-traversal-001"
    assert result["resolution"] == "risk_accepted"
    assert "timestamp" in result


# ==============================================================================
# Optional Comment Tests
# ==============================================================================


def test_mark_resolved_without_comment(mock_env):
    """Test marking resolved without comment (optional field)"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
    )

    assert result["success"] is True
    assert result["finding_id"] == "fingerprint-xss-001"
    assert result["resolution"] == "fixed"


def test_mark_resolved_with_empty_comment(mock_env):
    """Test marking resolved with empty string comment"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="",
    )

    assert result["success"] is True


def test_mark_resolved_with_long_comment(mock_env):
    """Test marking resolved with very long comment"""
    long_comment = "This is a detailed explanation. " * 100  # ~3000 characters

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="false_positive",
        comment=long_comment,
    )

    assert result["success"] is True


# ==============================================================================
# Validation Tests
# ==============================================================================


def test_mark_resolved_invalid_resolution_type(mock_env):
    """Test invalid resolution type raises ValueError"""
    with pytest.raises(ValueError, match="Invalid resolution type"):
        mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="invalid_type",
            comment="Test",
        )


def test_mark_resolved_case_sensitive_resolution(mock_env):
    """Test resolution types are case-sensitive"""
    with pytest.raises(ValueError, match="Invalid resolution type"):
        mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="FIXED",  # Uppercase, should fail
            comment="Test",
        )


def test_mark_resolved_finding_not_found(mock_env):
    """Test marking non-existent finding raises ValueError"""
    with pytest.raises(ValueError, match="Finding not found"):
        mark_resolved(
            finding_id="does-not-exist",
            resolution="fixed",
            comment="Test",
        )


def test_mark_resolved_all_finding_ids_valid(mock_env):
    """Test all fixture finding IDs are recognized"""
    finding_ids = [
        "fingerprint-xss-001",
        "fingerprint-sqli-001",
        "fingerprint-crypto-001",
        "fingerprint-path-traversal-001",
        "fingerprint-hardcoded-secret-001",
    ]

    for finding_id in finding_ids:
        result = mark_resolved(
            finding_id=finding_id,
            resolution="fixed",
            comment="Test validation",
        )
        assert result["success"] is True
        assert result["finding_id"] == finding_id


def test_mark_resolved_all_resolution_types_valid(mock_env):
    """Test all valid resolution types are accepted"""
    resolution_types = ["fixed", "false_positive", "wont_fix", "risk_accepted"]

    for resolution in resolution_types:
        result = mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution=resolution,
            comment=f"Test resolution type: {resolution}",
        )
        assert result["success"] is True
        assert result["resolution"] == resolution


# ==============================================================================
# Timestamp Tests
# ==============================================================================


def test_mark_resolved_timestamp_format(mock_env):
    """Test timestamp is in ISO 8601 format with UTC marker"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Test timestamp",
    )

    timestamp = result["timestamp"]

    # Should be ISO 8601 format ending with Z
    assert timestamp.endswith("Z")

    # Should be parseable by datetime
    try:
        datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError:
        pytest.fail(f"Timestamp {timestamp} is not valid ISO 8601 format")


def test_mark_resolved_multiple_calls_different_timestamps(mock_env):
    """Test multiple resolutions have different timestamps"""
    import time

    result1 = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
    )

    time.sleep(0.1)  # Small delay to ensure different timestamps

    result2 = mark_resolved(
        finding_id="fingerprint-sqli-001",
        resolution="false_positive",
    )

    # Timestamps should be different (at least microseconds different)
    assert result1["timestamp"] != result2["timestamp"]


# ==============================================================================
# Edge Cases
# ==============================================================================


def test_mark_resolved_special_characters_in_comment(mock_env):
    """Test comment with special characters"""
    comment = "Fixed: <script>alert('XSS')</script> & \"quotes\" & 'apostrophes'"

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment=comment,
    )

    assert result["success"] is True


def test_mark_resolved_unicode_in_comment(mock_env):
    """Test comment with unicode characters"""
    comment = "已修复 XSS 漏洞 🔒 使用 DOMPurify 清理用户输入"

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment=comment,
    )

    assert result["success"] is True


def test_mark_resolved_multiline_comment(mock_env):
    """Test comment with newlines"""
    comment = """Fixed the XSS vulnerability by:
1. Adding DOMPurify sanitization
2. Validating all user input
3. Adding CSP headers"""

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment=comment,
    )

    assert result["success"] is True


def test_mark_resolved_comment_with_escape_sequences(mock_env):
    """Test comment with escape sequences"""
    comment = 'Fixed by escaping: \\n\\t\\r\\" and \\u0000'

    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment=comment,
    )

    assert result["success"] is True


def test_mark_resolved_missing_findings_file(tmp_path, monkeypatch):
    """Test behavior when findings.json doesn't exist"""
    monkeypatch.setenv("MCP_RESULTS_DIR", str(tmp_path))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "false")

    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    # Should raise when trying to load findings
    with pytest.raises(Exception):  # FileNotFoundError or ValueError
        mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="fixed",
            comment="Test",
        )


# ==============================================================================
# Rate Limiting Integration Tests
# ==============================================================================


def test_mark_resolved_rate_limit_enforcement(mock_findings_file, monkeypatch):
    """Test rate limiting is enforced when enabled"""
    # Set aggressive rate limit (1 request capacity)
    monkeypatch.setenv("MCP_RESULTS_DIR", str(mock_findings_file / "results"))
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_ENABLED", "true")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_CAPACITY", "1")
    monkeypatch.setenv("JMO_MCP_RATE_LIMIT_REFILL_RATE", "0.1")

    import importlib
    from scripts.jmo_mcp import jmo_server

    importlib.reload(jmo_server)

    # First request should succeed
    result1 = jmo_server.mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Test",
    )
    assert result1["success"] is True

    # Second request should fail (bucket exhausted)
    with pytest.raises(ValueError, match="Rate limit exceeded"):
        jmo_server.mark_resolved(
            finding_id="fingerprint-sqli-001",
            resolution="fixed",
            comment="Test",
        )


def test_mark_resolved_rate_limit_disabled(mock_env):
    """Test rate limiting can be disabled"""
    # Rate limiting disabled via mock_env fixture

    # Should be able to make multiple requests
    for i in range(10):
        result = mark_resolved(
            finding_id="fingerprint-xss-001",
            resolution="fixed",
            comment=f"Test {i}",
        )
        assert result["success"] is True


# ==============================================================================
# Response Structure Tests
# ==============================================================================


def test_mark_resolved_response_structure(mock_env):
    """Test response contains all required fields"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Test",
    )

    # Required fields
    assert "success" in result
    assert "finding_id" in result
    assert "resolution" in result
    assert "timestamp" in result

    # Field types
    assert isinstance(result["success"], bool)
    assert isinstance(result["finding_id"], str)
    assert isinstance(result["resolution"], str)
    assert isinstance(result["timestamp"], str)

    # Values match input
    assert result["success"] is True
    assert result["finding_id"] == "fingerprint-xss-001"
    assert result["resolution"] == "fixed"


def test_mark_resolved_response_note_field(mock_env):
    """Test response contains note about Phase 2 implementation"""
    result = mark_resolved(
        finding_id="fingerprint-xss-001",
        resolution="fixed",
        comment="Test",
    )

    # Note field should indicate resolution tracking is not yet persisted
    assert "note" in result
    assert "Phase 2" in result["note"] or "persist" in result["note"].lower()
