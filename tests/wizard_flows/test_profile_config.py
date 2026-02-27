"""Tests for scripts.cli.wizard_flows.profile_config - profile data and time estimation."""

import pytest

from scripts.cli.wizard_flows.profile_config import (
    PROFILES,
    TOOL_TIME_ESTIMATES,
    calculate_time_estimate,
    format_time_range,
    get_profile_warning,
)


class TestProfiles:
    """Tests for PROFILES data structure."""

    def test_all_profiles_exist(self):
        assert set(PROFILES.keys()) == {"fast", "slim", "balanced", "deep"}

    @pytest.mark.parametrize("profile", ["fast", "slim", "balanced", "deep"])
    def test_profile_has_required_keys(self, profile):
        p = PROFILES[profile]
        assert "name" in p
        assert "description" in p
        assert "tools" in p
        assert "timeout" in p
        assert "threads" in p
        assert "est_time" in p
        assert "use_case" in p

    def test_profile_tools_are_lists(self):
        for profile in PROFILES.values():
            assert isinstance(profile["tools"], list)
            assert len(profile["tools"]) > 0

    def test_fast_is_smallest_profile(self):
        assert len(PROFILES["fast"]["tools"]) <= len(PROFILES["slim"]["tools"])
        assert len(PROFILES["slim"]["tools"]) <= len(PROFILES["balanced"]["tools"])
        assert len(PROFILES["balanced"]["tools"]) <= len(PROFILES["deep"]["tools"])

    def test_profile_tool_counts(self):
        assert len(PROFILES["fast"]["tools"]) == 9
        assert len(PROFILES["slim"]["tools"]) == 14
        assert len(PROFILES["balanced"]["tools"]) == 18
        assert len(PROFILES["deep"]["tools"]) == 29


class TestCalculateTimeEstimate:
    """Tests for calculate_time_estimate()."""

    def test_empty_tools(self):
        min_t, max_t = calculate_time_estimate([])
        assert min_t == 0
        assert max_t == 0

    def test_single_known_tool(self):
        min_t, max_t = calculate_time_estimate(["trufflehog"])
        expected = TOOL_TIME_ESTIMATES["trufflehog"]
        assert min_t == int(expected * 0.6)
        assert max_t == int(expected * 1.2)

    def test_unknown_tool_uses_default(self):
        min_t, max_t = calculate_time_estimate(["unknown_tool"])
        default = TOOL_TIME_ESTIMATES["_default"]
        assert min_t == int(default * 0.6)
        assert max_t == int(default * 1.2)

    def test_min_less_than_max(self):
        min_t, max_t = calculate_time_estimate(["semgrep", "trivy", "checkov"])
        assert min_t < max_t

    def test_more_tools_longer_time(self):
        _, max_1 = calculate_time_estimate(["semgrep"])
        _, max_3 = calculate_time_estimate(["semgrep", "trivy", "checkov"])
        assert max_3 > max_1


class TestFormatTimeRange:
    """Tests for format_time_range()."""

    def test_seconds_format(self):
        result = format_time_range(30, 50)
        assert "30s" in result
        assert "50s" in result

    def test_minutes_format(self):
        result = format_time_range(120, 300)
        assert "2 min" in result
        assert "5 min" in result

    def test_hours_format(self):
        result = format_time_range(3600, 7200)
        assert "1h" in result
        assert "2h" in result

    def test_mixed_format(self):
        result = format_time_range(45, 120)
        assert "45s" in result
        assert "2 min" in result


class TestGetProfileWarning:
    """Tests for get_profile_warning()."""

    def test_deep_has_warning(self):
        warning = get_profile_warning("deep")
        assert warning is not None
        assert "dependency-check" in warning.lower() or "NVD" in warning

    def test_fast_no_warning(self):
        assert get_profile_warning("fast") is None

    def test_nonexistent_profile(self):
        assert get_profile_warning("nonexistent") is None
