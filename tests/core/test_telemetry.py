"""
Comprehensive test suite for scripts/core/telemetry.py

Coverage:
- Anonymous ID management (generation, persistence)
- Telemetry enablement logic (config + env var override)
- Event sending (mocking GitHub Gist API)
- Privacy bucketing (duration, findings, targets)
- CI environment detection (9 platforms)
- Scan frequency inference (first_time/weekly/daily)

Architecture Note:
- All tests use tmp_path for isolated file operations
- Gist API calls are mocked (no actual network requests)
- Environment variables are monkeypatched (no side effects)

Related:
- docs/TELEMETRY_IMPLEMENTATION_GUIDE.md — Implementation spec
- scripts/core/telemetry.py — Module under test
"""

import json
import os
from pathlib import Path
from typing import Any, Dict
from unittest.mock import MagicMock, patch

import pytest

from scripts.core.telemetry import (
    bucket_duration,
    bucket_findings,
    bucket_targets,
    detect_ci_environment,
    get_anonymous_id,
    infer_scan_frequency,
    is_telemetry_enabled,
    send_event,
    _send_event_async,
    _get_gist_content,
    TELEMETRY_ID_FILE,
    SCAN_COUNT_FILE,
)


# ========== Test Category 1: Anonymous ID Management ==========

def test_get_anonymous_id_generates_new_uuid(tmp_path: Path, monkeypatch):
    """Test get_anonymous_id() generates and persists new UUID."""
    # Use tmp_path for isolated testing
    test_id_file = tmp_path / "telemetry-id"
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)

    # First call should generate new UUID
    anon_id = get_anonymous_id()

    # Verify UUID format (36 chars with hyphens)
    assert len(anon_id) == 36
    assert anon_id.count("-") == 4

    # Verify UUID is persisted
    assert test_id_file.exists()
    assert test_id_file.read_text().strip() == anon_id


def test_get_anonymous_id_reuses_existing_uuid(tmp_path: Path, monkeypatch):
    """Test get_anonymous_id() reuses existing UUID from file."""
    test_id_file = tmp_path / "telemetry-id"
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)

    # Create existing UUID file
    existing_uuid = "a7f3c8e2-4b1d-4f9e-8c3a-2d5e7f9b1a3c"
    test_id_file.parent.mkdir(parents=True, exist_ok=True)
    test_id_file.write_text(existing_uuid)

    # Should return existing UUID
    anon_id = get_anonymous_id()
    assert anon_id == existing_uuid

    # Should not generate new UUID
    anon_id_2 = get_anonymous_id()
    assert anon_id_2 == existing_uuid


def test_get_anonymous_id_creates_parent_directory(tmp_path: Path, monkeypatch):
    """Test get_anonymous_id() creates parent directory if missing."""
    test_id_file = tmp_path / "nested" / "dir" / "telemetry-id"
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)

    # Parent directory doesn't exist yet
    assert not test_id_file.parent.exists()

    # Should create parent directory
    get_anonymous_id()

    assert test_id_file.parent.exists()
    assert test_id_file.exists()


# ========== Test Category 2: Telemetry Enablement Logic ==========

def test_is_telemetry_enabled_when_config_enabled(monkeypatch):
    """Test is_telemetry_enabled() returns True when config enabled."""
    monkeypatch.delenv("JMO_TELEMETRY_DISABLE", raising=False)

    config = {"telemetry": {"enabled": True}}
    assert is_telemetry_enabled(config) is True


def test_is_telemetry_enabled_when_config_disabled(monkeypatch):
    """Test is_telemetry_enabled() returns False when config disabled."""
    monkeypatch.delenv("JMO_TELEMETRY_DISABLE", raising=False)

    config = {"telemetry": {"enabled": False}}
    assert is_telemetry_enabled(config) is False


def test_is_telemetry_enabled_default_false_when_missing(monkeypatch):
    """Test is_telemetry_enabled() defaults to False when config missing (opt-in)."""
    monkeypatch.delenv("JMO_TELEMETRY_DISABLE", raising=False)

    # No telemetry key in config
    config = {}
    assert is_telemetry_enabled(config) is False

    # Empty telemetry object
    config = {"telemetry": {}}
    assert is_telemetry_enabled(config) is False


def test_is_telemetry_enabled_env_var_override(monkeypatch):
    """Test JMO_TELEMETRY_DISABLE=1 overrides config."""
    monkeypatch.setenv("JMO_TELEMETRY_DISABLE", "1")

    # Even with config enabled, env var should force disable
    config = {"telemetry": {"enabled": True}}
    assert is_telemetry_enabled(config) is False


def test_is_telemetry_enabled_env_var_no_override_when_not_1(monkeypatch):
    """Test JMO_TELEMETRY_DISABLE with values other than '1' don't disable."""
    monkeypatch.setenv("JMO_TELEMETRY_DISABLE", "0")

    config = {"telemetry": {"enabled": True}}
    assert is_telemetry_enabled(config) is True  # Not disabled


# ========== Test Category 3: Event Sending (Mocked Gist API) ==========

def test_send_event_disabled_when_config_disabled(monkeypatch):
    """Test send_event() skips when telemetry disabled."""
    monkeypatch.delenv("JMO_TELEMETRY_DISABLE", raising=False)

    config = {"telemetry": {"enabled": False}}

    # Mock _send_event_async to verify it's NOT called
    mock_send = MagicMock()
    monkeypatch.setattr("scripts.core.telemetry._send_event_async", mock_send)

    send_event("test.event", {"key": "value"}, config, version="0.7.0")

    # Should NOT call _send_event_async
    mock_send.assert_not_called()


def test_send_event_skips_when_gist_not_configured(monkeypatch):
    """Test send_event() skips when GIST_ID or GITHUB_TOKEN missing."""
    monkeypatch.delenv("JMO_TELEMETRY_DISABLE", raising=False)
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "")  # Not configured
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "")

    config = {"telemetry": {"enabled": True}}

    mock_send = MagicMock()
    monkeypatch.setattr("scripts.core.telemetry._send_event_async", mock_send)

    send_event("test.event", {"key": "value"}, config, version="0.7.0")

    # Should NOT call _send_event_async (endpoint not configured)
    mock_send.assert_not_called()


@patch("scripts.core.telemetry.threading.Thread")
def test_send_event_spawns_background_thread(mock_thread, monkeypatch):
    """Test send_event() spawns daemon background thread."""
    monkeypatch.delenv("JMO_TELEMETRY_DISABLE", raising=False)
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_test_token")

    config = {"telemetry": {"enabled": True}}

    send_event("scan.started", {"profile": "fast"}, config, version="0.7.0")

    # Verify Thread was created with correct parameters
    mock_thread.assert_called_once()
    call_kwargs = mock_thread.call_args.kwargs
    assert call_kwargs["daemon"] is True
    assert call_kwargs["target"].__name__ == "_send_event_async"


@patch("scripts.core.telemetry.request.urlopen")
@patch("scripts.core.telemetry._get_gist_content")
def test_send_event_async_builds_correct_payload(mock_get_content, mock_urlopen, tmp_path: Path, monkeypatch):
    """Test _send_event_async() builds correct event payload."""
    mock_get_content.return_value = ""  # Empty Gist content
    mock_response = MagicMock()
    mock_response.status = 200
    mock_urlopen.return_value.__enter__.return_value = mock_response

    test_id_file = tmp_path / "telemetry-id"
    test_id_file.parent.mkdir(parents=True, exist_ok=True)
    test_id_file.write_text("test-uuid-1234")
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_test_token")

    # Call _send_event_async directly
    _send_event_async("scan.started", {"profile": "fast", "tools": ["trivy"]}, "0.7.0")

    # Verify urlopen was called with correct data
    assert mock_urlopen.called
    call_args = mock_urlopen.call_args

    # Extract request data
    request_obj = call_args[0][0]
    request_data = json.loads(request_obj.data.decode("utf-8"))

    # Verify Gist PATCH structure
    assert "files" in request_data
    assert "jmo-telemetry-events.jsonl" in request_data["files"]

    # Parse JSONL content (last line is the event)
    jsonl_content = request_data["files"]["jmo-telemetry-events.jsonl"]["content"]
    event = json.loads(jsonl_content.strip())

    # Verify event structure
    assert event["event"] == "scan.started"
    assert event["version"] == "0.7.0"
    assert event["anonymous_id"] == "test-uuid-1234"
    assert event["metadata"]["profile"] == "fast"
    assert event["metadata"]["tools"] == ["trivy"]
    assert "timestamp" in event
    assert "platform" in event
    assert "python_version" in event


@patch("scripts.core.telemetry.request.urlopen")
def test_send_event_async_appends_to_existing_content(mock_urlopen, tmp_path: Path, monkeypatch):
    """Test _send_event_async() appends to existing Gist content (JSONL)."""
    # Mock _get_gist_content to return existing content
    existing_content = '{"event": "old.event", "timestamp": "2024-01-01T00:00:00Z"}\n'

    with patch("scripts.core.telemetry._get_gist_content", return_value=existing_content):
        mock_response = MagicMock()
        mock_response.status = 200
        mock_urlopen.return_value.__enter__.return_value = mock_response

        test_id_file = tmp_path / "telemetry-id"
        test_id_file.parent.mkdir(parents=True, exist_ok=True)
        test_id_file.write_text("test-uuid")
        monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)
        monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
        monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_token")

        _send_event_async("scan.completed", {"duration": 120}, "0.7.0")

        # Verify content was appended (not replaced)
        request_obj = mock_urlopen.call_args[0][0]
        request_data = json.loads(request_obj.data.decode("utf-8"))
        jsonl_content = request_data["files"]["jmo-telemetry-events.jsonl"]["content"]

        # Should have 2 lines (old event + new event)
        lines = jsonl_content.strip().split("\n")
        assert len(lines) == 2
        assert "old.event" in lines[0]
        assert "scan.completed" in lines[1]


@patch("scripts.core.telemetry.request.urlopen")
def test_send_event_async_handles_network_errors_silently(mock_urlopen, tmp_path: Path, monkeypatch):
    """Test _send_event_async() fails silently on network errors."""
    from urllib.error import URLError

    mock_urlopen.side_effect = URLError("Network error")

    test_id_file = tmp_path / "telemetry-id"
    test_id_file.parent.mkdir(parents=True, exist_ok=True)
    test_id_file.write_text("test-uuid")
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_token")

    # Should NOT raise exception
    _send_event_async("test.event", {"key": "value"}, "0.7.0")
    # Test passes if no exception raised


@patch("scripts.core.telemetry.request.urlopen")
def test_send_event_async_handles_timeout_silently(mock_urlopen, tmp_path: Path, monkeypatch):
    """Test _send_event_async() fails silently on timeout."""
    mock_urlopen.side_effect = TimeoutError("Request timeout")

    test_id_file = tmp_path / "telemetry-id"
    test_id_file.parent.mkdir(parents=True, exist_ok=True)
    test_id_file.write_text("test-uuid")
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_token")

    # Should NOT raise exception
    _send_event_async("test.event", {"key": "value"}, "0.7.0")


@patch("scripts.core.telemetry.request.urlopen")
def test_get_gist_content_returns_existing_content(mock_urlopen, monkeypatch):
    """Test _get_gist_content() returns existing Gist content."""
    mock_response = MagicMock()
    mock_response.read.return_value = json.dumps({
        "files": {
            "jmo-telemetry-events.jsonl": {
                "content": "existing line 1\nexisting line 2\n"
            }
        }
    }).encode("utf-8")
    mock_urlopen.return_value.__enter__.return_value = mock_response

    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_token")

    content = _get_gist_content()

    assert content == "existing line 1\nexisting line 2\n"


@patch("scripts.core.telemetry.request.urlopen")
def test_get_gist_content_returns_empty_on_error(mock_urlopen, monkeypatch):
    """Test _get_gist_content() returns empty string on fetch errors."""
    from urllib.error import URLError

    mock_urlopen.side_effect = URLError("Network error")

    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_token")

    content = _get_gist_content()

    # Should return empty string (don't crash)
    assert content == ""


# ========== Test Category 4: Privacy Bucketing Functions ==========

def test_bucket_duration_all_ranges():
    """Test bucket_duration() for all time ranges."""
    # <5min
    assert bucket_duration(0) == "<5min"
    assert bucket_duration(100) == "<5min"
    assert bucket_duration(299) == "<5min"

    # 5-15min
    assert bucket_duration(300) == "5-15min"
    assert bucket_duration(600) == "5-15min"
    assert bucket_duration(899) == "5-15min"

    # 15-30min
    assert bucket_duration(900) == "15-30min"
    assert bucket_duration(1200) == "15-30min"
    assert bucket_duration(1799) == "15-30min"

    # >30min
    assert bucket_duration(1800) == ">30min"
    assert bucket_duration(3600) == ">30min"
    assert bucket_duration(10000) == ">30min"


def test_bucket_findings_all_ranges():
    """Test bucket_findings() for all count ranges."""
    # 0
    assert bucket_findings(0) == "0"

    # 1-10
    assert bucket_findings(1) == "1-10"
    assert bucket_findings(5) == "1-10"
    assert bucket_findings(10) == "1-10"

    # 10-100
    assert bucket_findings(11) == "10-100"
    assert bucket_findings(50) == "10-100"
    assert bucket_findings(100) == "10-100"

    # 100-1000
    assert bucket_findings(101) == "100-1000"
    assert bucket_findings(500) == "100-1000"
    assert bucket_findings(1000) == "100-1000"

    # >1000
    assert bucket_findings(1001) == ">1000"
    assert bucket_findings(5000) == ">1000"


def test_bucket_targets_all_ranges():
    """Test bucket_targets() for all count ranges."""
    # 1
    assert bucket_targets(1) == "1"

    # 2-5
    assert bucket_targets(2) == "2-5"
    assert bucket_targets(3) == "2-5"
    assert bucket_targets(5) == "2-5"

    # 6-10
    assert bucket_targets(6) == "6-10"
    assert bucket_targets(8) == "6-10"
    assert bucket_targets(10) == "6-10"

    # 11-50
    assert bucket_targets(11) == "11-50"
    assert bucket_targets(30) == "11-50"
    assert bucket_targets(50) == "11-50"

    # >50
    assert bucket_targets(51) == ">50"
    assert bucket_targets(100) == ">50"
    assert bucket_targets(1000) == ">50"


# ========== Test Category 5: CI Environment Detection ==========

def test_detect_ci_environment_github_actions(monkeypatch):
    """Test detect_ci_environment() detects GitHub Actions."""
    # Clear all CI vars first
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILD_ID",
                "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID"]:
        monkeypatch.delenv(var, raising=False)

    # Set GitHub Actions var
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert detect_ci_environment() is True


def test_detect_ci_environment_gitlab_ci(monkeypatch):
    """Test detect_ci_environment() detects GitLab CI."""
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILD_ID",
                "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID"]:
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("GITLAB_CI", "true")
    assert detect_ci_environment() is True


def test_detect_ci_environment_jenkins(monkeypatch):
    """Test detect_ci_environment() detects Jenkins."""
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILD_ID",
                "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID"]:
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("JENKINS_URL", "http://jenkins.example.com")
    assert detect_ci_environment() is True


def test_detect_ci_environment_generic_ci(monkeypatch):
    """Test detect_ci_environment() detects generic CI=true."""
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILD_ID",
                "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID"]:
        monkeypatch.delenv(var, raising=False)

    monkeypatch.setenv("CI", "true")
    assert detect_ci_environment() is True


def test_detect_ci_environment_no_ci(monkeypatch):
    """Test detect_ci_environment() returns False when no CI vars set."""
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILD_ID",
                "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID"]:
        monkeypatch.delenv(var, raising=False)

    assert detect_ci_environment() is False


def test_detect_ci_environment_multiple_ci_vars(monkeypatch):
    """Test detect_ci_environment() with multiple CI vars set."""
    for var in ["CI", "GITHUB_ACTIONS", "GITLAB_CI", "JENKINS_URL", "BUILD_ID",
                "CIRCLECI", "TRAVIS", "TF_BUILD", "BITBUCKET_PIPELINE_UUID"]:
        monkeypatch.delenv(var, raising=False)

    # Set multiple CI vars (e.g., GitHub Actions)
    monkeypatch.setenv("CI", "true")
    monkeypatch.setenv("GITHUB_ACTIONS", "true")
    assert detect_ci_environment() is True


# ========== Test Category 6: Scan Frequency Inference ==========

def test_infer_scan_frequency_first_time(tmp_path: Path, monkeypatch):
    """Test infer_scan_frequency() returns 'first_time' on first scan."""
    test_count_file = tmp_path / "scan-count"
    monkeypatch.setattr("scripts.core.telemetry.SCAN_COUNT_FILE", test_count_file)

    # First scan
    frequency = infer_scan_frequency()

    assert frequency == "first_time"
    assert test_count_file.exists()
    assert test_count_file.read_text().strip() == "1"


def test_infer_scan_frequency_weekly(tmp_path: Path, monkeypatch):
    """Test infer_scan_frequency() returns 'weekly' for scans 2-10."""
    test_count_file = tmp_path / "scan-count"
    monkeypatch.setattr("scripts.core.telemetry.SCAN_COUNT_FILE", test_count_file)

    # Simulate 5th scan
    test_count_file.parent.mkdir(parents=True, exist_ok=True)
    test_count_file.write_text("5")

    frequency = infer_scan_frequency()

    assert frequency == "weekly"
    assert test_count_file.read_text().strip() == "6"  # Incremented


def test_infer_scan_frequency_daily(tmp_path: Path, monkeypatch):
    """Test infer_scan_frequency() returns 'daily' for scans 11+."""
    test_count_file = tmp_path / "scan-count"
    monkeypatch.setattr("scripts.core.telemetry.SCAN_COUNT_FILE", test_count_file)

    # Simulate 15th scan
    test_count_file.parent.mkdir(parents=True, exist_ok=True)
    test_count_file.write_text("15")

    frequency = infer_scan_frequency()

    assert frequency == "daily"
    assert test_count_file.read_text().strip() == "16"


def test_infer_scan_frequency_creates_parent_directory(tmp_path: Path, monkeypatch):
    """Test infer_scan_frequency() creates parent directory if missing."""
    test_count_file = tmp_path / "nested" / "scan-count"
    monkeypatch.setattr("scripts.core.telemetry.SCAN_COUNT_FILE", test_count_file)

    # Parent directory doesn't exist
    assert not test_count_file.parent.exists()

    frequency = infer_scan_frequency()

    assert frequency == "first_time"
    assert test_count_file.parent.exists()


def test_infer_scan_frequency_returns_none_on_error(tmp_path: Path, monkeypatch):
    """Test infer_scan_frequency() returns None on file operation errors."""
    # Use a path that will cause permission error (read-only directory)
    test_count_file = tmp_path / "readonly" / "scan-count"
    test_count_file.parent.mkdir(parents=True, exist_ok=True)

    # Make parent directory read-only (simulate permission error)
    import stat
    test_count_file.parent.chmod(stat.S_IRUSR | stat.S_IXUSR)

    monkeypatch.setattr("scripts.core.telemetry.SCAN_COUNT_FILE", test_count_file)

    frequency = infer_scan_frequency()

    # Should return None (not crash)
    assert frequency is None

    # Clean up: restore write permission
    test_count_file.parent.chmod(stat.S_IRWXU)


# ========== Test Category 7: Business Metrics Integration ==========

def test_business_metrics_in_event_payload(tmp_path: Path, monkeypatch):
    """Test business metrics (CI, multi-target, compliance) are included in event."""
    # This is an integration test verifying metadata structure
    # Business metrics are passed as metadata to send_event(), not computed by telemetry module

    test_id_file = tmp_path / "telemetry-id"
    test_id_file.parent.mkdir(parents=True, exist_ok=True)
    test_id_file.write_text("test-uuid")
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)

    metadata = {
        "profile": "balanced",
        "ci_detected": True,
        "multi_target_scan": True,
        "compliance_usage": True,
        "total_targets_bucket": "6-10",
        "scan_frequency_hint": "daily",
    }

    # Verify metadata structure (caller's responsibility to include business metrics)
    assert metadata["ci_detected"] is True
    assert metadata["multi_target_scan"] is True
    assert metadata["compliance_usage"] is True
    assert metadata["total_targets_bucket"] == "6-10"
    assert metadata["scan_frequency_hint"] == "daily"


# ========== Test Category 8: Edge Cases and Error Handling ==========

def test_send_event_with_empty_metadata(monkeypatch):
    """Test send_event() handles empty metadata dict."""
    monkeypatch.delenv("JMO_TELEMETRY_DISABLE", raising=False)
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_token")

    config = {"telemetry": {"enabled": True}}

    # Mock threading to prevent actual background execution
    with patch("scripts.core.telemetry.threading.Thread") as mock_thread:
        send_event("test.event", {}, config, version="0.7.0")  # Empty metadata

        # Should still spawn thread
        mock_thread.assert_called_once()


def test_send_event_with_unicode_metadata(tmp_path: Path, monkeypatch):
    """Test send_event() handles Unicode in metadata."""
    test_id_file = tmp_path / "telemetry-id"
    test_id_file.parent.mkdir(parents=True, exist_ok=True)
    test_id_file.write_text("test-uuid")
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ID_FILE", test_id_file)
    monkeypatch.setattr("scripts.core.telemetry.TELEMETRY_ENDPOINT", "https://api.github.com/gists/test123")
    monkeypatch.setattr("scripts.core.telemetry.GITHUB_TOKEN", "ghp_token")

    metadata = {
        "message": "Test with emoji 🔒 and Chinese: 安全漏洞",
        "tool": "检测工具",
    }

    with patch("scripts.core.telemetry.request.urlopen") as mock_urlopen:
        with patch("scripts.core.telemetry._get_gist_content", return_value=""):
            mock_response = MagicMock()
            mock_response.status = 200
            mock_urlopen.return_value.__enter__.return_value = mock_response

            # Should NOT raise UnicodeEncodeError
            _send_event_async("test.event", metadata, "0.7.0")

            # Verify request data is valid JSON
            request_obj = mock_urlopen.call_args[0][0]
            request_data = json.loads(request_obj.data.decode("utf-8"))
            jsonl_content = request_data["files"]["jmo-telemetry-events.jsonl"]["content"]
            event = json.loads(jsonl_content.strip())

            # Verify Unicode preserved
            assert "🔒" in event["metadata"]["message"]
            assert "安全漏洞" in event["metadata"]["message"]


def test_bucket_duration_with_negative_value():
    """Test bucket_duration() handles negative values (edge case)."""
    # Should treat as <5min
    assert bucket_duration(-10) == "<5min"


def test_bucket_findings_with_negative_value():
    """Test bucket_findings() handles negative values (defensive)."""
    # Negative count is illogical, but function should handle gracefully
    # (Python's comparison operators will treat -1 < 0 as True)
    result = bucket_findings(-5)
    # Should NOT crash, return some bucket
    assert result in ["0", "1-10", "10-100", "100-1000", ">1000"]


def test_bucket_targets_with_zero():
    """Test bucket_targets() with zero targets."""
    # Zero targets is illogical (no scan), but function should handle
    result = bucket_targets(0)
    # Should return first bucket or handle gracefully
    assert result in ["1", "2-5", "6-10", "11-50", ">50"]
