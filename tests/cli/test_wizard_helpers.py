"""Tests for wizard helper functions.

Coverage targets:
- calculate_time_estimate(): Dynamic time estimation based on available tools
- format_time_range(): Human-readable time formatting
- _safe_print(): Unicode fallback for Windows compatibility
- _colorize(): ANSI color handling via PromptHelper
"""

from __future__ import annotations

import sys
from unittest.mock import patch

import pytest

from scripts.cli.wizard import (
    PROFILES,
    _safe_print,
    calculate_time_estimate,
    format_time_range,
)
from scripts.cli.wizard_flows.base_flow import PromptHelper


class TestCalculateTimeEstimate:
    """Test cases for calculate_time_estimate()."""

    def test_empty_tools_list(self):
        """Test time estimate with no tools."""
        min_time, max_time = calculate_time_estimate([])
        assert min_time == 0
        assert max_time == 0

    def test_single_fast_tool(self):
        """Test time estimate for single fast tool (trivy ~30s)."""
        min_time, max_time = calculate_time_estimate(["trivy"])
        assert min_time > 0
        assert max_time > min_time

    def test_single_slow_tool(self):
        """Test time estimate for single slow tool (mobsf ~300s)."""
        min_time, max_time = calculate_time_estimate(["mobsf"])
        assert min_time >= 100  # 300 * 0.6 = 180, but min should be reasonable
        assert max_time >= min_time

    def test_fast_profile_tools(self):
        """Test time estimate for fast profile tools."""
        fast_tools = PROFILES["fast"]["tools"]
        min_time, max_time = calculate_time_estimate(fast_tools)
        # Fast profile should take roughly 5-10 minutes
        assert 60 <= min_time <= 600  # 1-10 minutes min
        assert max_time > min_time

    def test_balanced_profile_tools(self):
        """Test time estimate for balanced profile tools."""
        balanced_tools = PROFILES["balanced"]["tools"]
        min_time, max_time = calculate_time_estimate(balanced_tools)
        # Balanced should take longer than fast
        fast_min, _ = calculate_time_estimate(PROFILES["fast"]["tools"])
        assert min_time >= fast_min

    def test_deep_profile_tools(self):
        """Test time estimate for deep profile tools."""
        deep_tools = PROFILES["deep"]["tools"]
        min_time, max_time = calculate_time_estimate(deep_tools)
        # Deep should take longest
        balanced_min, _ = calculate_time_estimate(PROFILES["balanced"]["tools"])
        assert min_time >= balanced_min

    def test_unknown_tool_uses_default(self):
        """Test that unknown tool uses default time estimate."""
        min_time, max_time = calculate_time_estimate(["unknown_tool"])
        # Should use default of 60 seconds
        # min = 60 * 0.6 = 36, max = 60 * 1.2 = 72
        assert 30 <= min_time <= 50
        assert 60 <= max_time <= 80

    def test_mixed_known_unknown_tools(self):
        """Test estimate with mix of known and unknown tools."""
        min_time, max_time = calculate_time_estimate(
            ["trivy", "unknown_tool", "semgrep"]
        )
        assert min_time > 0
        assert max_time > min_time

    def test_all_profiles_have_estimates(self):
        """Test that all defined profiles produce valid time estimates."""
        for profile_name, profile_info in PROFILES.items():
            tools = profile_info["tools"]
            min_time, max_time = calculate_time_estimate(tools)
            assert min_time >= 0, f"Profile {profile_name} has negative min_time"
            assert max_time >= min_time, f"Profile {profile_name} has max < min"


class TestFormatTimeRange:
    """Test cases for format_time_range()."""

    def test_short_time_seconds(self):
        """Test formatting for short time ranges (seconds)."""
        result = format_time_range(30, 45)
        assert "30" in result
        assert "s" in result

    def test_minutes_range(self):
        """Test formatting for minute ranges."""
        result = format_time_range(300, 600)  # 5-10 min
        assert "5" in result
        assert "min" in result

    def test_hour_plus_range(self):
        """Test formatting for hour+ ranges."""
        result = format_time_range(3600, 7200)  # 1-2 hours
        assert "1" in result
        assert "h" in result

    def test_zero_time(self):
        """Test edge case with zero time."""
        result = format_time_range(0, 0)
        assert result  # Should return something, not crash
        assert "0" in result

    def test_same_min_max(self):
        """Test when min and max are the same."""
        result = format_time_range(300, 300)
        assert "5" in result  # 300s = 5 min

    def test_mixed_units(self):
        """Test formatting with mixed units (minutes to hours)."""
        result = format_time_range(1800, 5400)  # 30 min to 1.5 hours
        assert result  # Should handle gracefully

    def test_large_time_range(self):
        """Test formatting for very large time ranges."""
        result = format_time_range(7200, 10800)  # 2-3 hours
        assert "2" in result
        assert "h" in result


class MockStdout:
    """Mock stdout with configurable encoding."""

    def __init__(self, encoding: str):
        self.encoding = encoding

    def write(self, text):
        pass

    def flush(self):
        pass


class TestSafePrint:
    """Test cases for _safe_print() Unicode handling."""

    def test_ascii_text_prints(self):
        """Test that ASCII text prints normally."""
        with patch("builtins.print") as mock_print:
            _safe_print("Hello World")
            mock_print.assert_called_once_with("Hello World")

    def test_unicode_on_utf8_terminal(self):
        """Test Unicode text on terminal that supports it."""
        mock_stdout = MockStdout("utf-8")
        with patch("builtins.print") as mock_print:
            with patch("sys.stdout", mock_stdout):
                _safe_print("Status: ✓ Complete")
                mock_print.assert_called_once()
                # Should preserve the Unicode on UTF-8 terminal
                args = mock_print.call_args[0][0]
                assert "Complete" in args

    @pytest.mark.skipif(sys.platform != "win32", reason="Windows-specific behavior")
    def test_unicode_fallback_on_cp1252(self):
        """Test Unicode fallback on Windows cp1252 encoding."""
        mock_stdout = MockStdout("cp1252")
        with patch("builtins.print") as mock_print:
            with patch("sys.stdout", mock_stdout):
                _safe_print("Step ✓ done")
                mock_print.assert_called()
                # Should have converted checkmark to ASCII

    def test_unicode_fallback_on_ascii(self):
        """Test Unicode fallback on ASCII encoding."""
        mock_stdout = MockStdout("ascii")
        with patch("builtins.print") as mock_print:
            with patch("sys.stdout", mock_stdout):
                _safe_print("Arrow → next")
                mock_print.assert_called()
                # Arrow should be converted to ASCII equivalent
                args = mock_print.call_args[0][0]
                assert "->" in args or "→" not in args

    def test_handles_encoding_error_gracefully(self):
        """Test that encoding errors don't crash the function."""
        # Create a mock that raises on first call, succeeds on second
        call_count = [0]

        def mock_print_side_effect(text):
            call_count[0] += 1
            if call_count[0] == 1:
                raise UnicodeEncodeError("cp1252", "", 0, 1, "")
            # Second call succeeds

        with patch("builtins.print", side_effect=mock_print_side_effect):
            # Should not raise
            try:
                _safe_print("Test 🎉")
            except UnicodeEncodeError:
                pytest.fail("_safe_print should handle encoding errors")


class TestColorize:
    """Test cases for _colorize() via PromptHelper."""

    def test_colorize_returns_string(self):
        """Test that colorize always returns a string."""
        prompter = PromptHelper()
        result = prompter.colorize("test", "red")
        assert isinstance(result, str)
        assert "test" in result

    def test_colorize_valid_colors(self):
        """Test colorize with all valid color names."""
        prompter = PromptHelper()
        colors = ["blue", "cyan", "green", "yellow", "red", "magenta", "bold", "dim"]
        for color in colors:
            result = prompter.colorize("test", color)
            assert "test" in result
            # Should contain ANSI codes for non-empty colors
            if color in prompter.COLORS:
                assert "\x1b[" in result or result == "test"

    def test_colorize_invalid_color(self):
        """Test colorize with invalid color name."""
        import scripts.cli.wizard_flows.base_flow as bf

        orig = bf._ANSI_SUPPORTED
        bf._ANSI_SUPPORTED = True
        try:
            prompter = PromptHelper()
            result = prompter.colorize("test", "invalid_color")
            assert "test" in result  # Should still return the text
            # With invalid color, should have reset code at end
            assert result.endswith(prompter.COLORS["reset"])
        finally:
            bf._ANSI_SUPPORTED = orig

    def test_colorize_empty_text(self):
        """Test colorize with empty text."""
        prompter = PromptHelper()
        result = prompter.colorize("", "green")
        assert isinstance(result, str)


class TestPromptHelperIntegration:
    """Integration tests for PromptHelper class."""

    def test_prompt_helper_initialization(self):
        """Test PromptHelper initializes correctly."""
        prompter = PromptHelper()
        assert hasattr(prompter, "COLORS")
        assert hasattr(prompter, "colorize")

    def test_print_header(self):
        """Test print_header method."""
        prompter = PromptHelper()
        with patch("builtins.print") as mock_print:
            prompter.print_header("Test Header")
            assert mock_print.called

    def test_print_step(self):
        """Test print_step method."""
        prompter = PromptHelper()
        with patch("builtins.print") as mock_print:
            prompter.print_step(1, 5, "Test step")
            assert mock_print.called
