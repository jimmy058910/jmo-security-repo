"""Tests for scripts/cli/wizard_flows/ui_helpers.py.

Covers:
- UNICODE_FALLBACKS: Mapping validation
- safe_print(): Unicode fallback for different encodings
- prompt_text(): Text input with defaults
- prompt_choice(): Numbered choice selection (numeric + key input)
- select_mode(): Mode selection wrapper
- TOOL_TIME_ESTIMATES, calculate_time_estimate(), format_time_range()
  (moved here when the wizard's profile module was deleted)
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from scripts.cli.wizard_flows.ui_helpers import (
    TOOL_TIME_ESTIMATES,
    UNICODE_FALLBACKS,
    calculate_time_estimate,
    format_time_range,
    prompt_choice,
    prompt_text,
    safe_print,
    select_mode,
)
from scripts.core.tool_registry import TOOL_MATRIX

# ========== Category 1: UNICODE_FALLBACKS ==========


class TestUnicodeFallbacks:
    """Tests for UNICODE_FALLBACKS mapping."""

    def test_is_dict(self):
        """Test UNICODE_FALLBACKS is a dict."""
        assert isinstance(UNICODE_FALLBACKS, dict)

    def test_all_keys_are_unicode(self):
        """Test all keys are unicode strings."""
        for key in UNICODE_FALLBACKS:
            assert isinstance(key, str)
            # Check it contains non-ASCII characters
            assert any(ord(c) > 127 for c in key)

    def test_all_values_are_ascii(self):
        """Test all fallback values are ASCII-safe."""
        for value in UNICODE_FALLBACKS.values():
            assert isinstance(value, str)
            # Values should be ASCII-representable
            value.encode("ascii")

    def test_known_mappings(self):
        """Test specific known fallback mappings."""
        assert UNICODE_FALLBACKS["\u2713"] == "[v]"  # check mark
        assert UNICODE_FALLBACKS["\u274c"] == "[X]"  # cross mark
        assert UNICODE_FALLBACKS["\u2192"] == "->"  # arrow


# ========== Category 2: safe_print() ==========


class TestSafePrint:
    """Tests for safe_print() Unicode fallback."""

    def test_utf8_passthrough(self, capsys):
        """Test UTF-8 encoding passes text through unchanged."""
        # Default stdout encoding is typically utf-8 in pytest
        safe_print("Hello World")
        captured = capsys.readouterr()
        assert "Hello World" in captured.out

    def test_cp1252_replaces_unicode(self):
        """Test cp1252 encoding triggers Unicode replacement."""
        mock_stdout = MagicMock()
        mock_stdout.encoding = "cp1252"
        mock_stdout.write = lambda x: None  # Suppress output

        with patch("builtins.print") as mock_print:
            with patch("sys.stdout", mock_stdout):
                safe_print("\u2713 passed \u274c failed")
                # Verify print was called with replaced text
                call_args = mock_print.call_args[0][0]
                assert "[v]" in call_args
                assert "[X]" in call_args

    def test_ascii_encoding_replaces_unicode(self):
        """Test ascii encoding triggers Unicode replacement."""
        mock_stdout = MagicMock()
        mock_stdout.encoding = "ascii"

        with patch("builtins.print") as mock_print:
            with patch("sys.stdout", mock_stdout):
                safe_print("\u2192 arrow")
                call_args = mock_print.call_args[0][0]
                assert "->" in call_args

    def test_unicode_encode_error_fallback(self):
        """Test UnicodeEncodeError triggers fallback path."""
        mock_stdout = MagicMock()
        mock_stdout.encoding = "utf-8"

        with (
            patch("sys.stdout", mock_stdout),
            patch(
                "builtins.print",
                side_effect=[UnicodeEncodeError("utf-8", "", 0, 1, "err"), None],
            ),
        ):
            safe_print("\u2713 test")

    def test_none_encoding_defaults_to_utf8(self, capsys):
        """Test None encoding defaults to utf-8 (no replacement)."""
        mock_stdout = MagicMock()
        mock_stdout.encoding = None

        with patch("builtins.print") as mock_print:
            with patch("sys.stdout", mock_stdout):
                safe_print("Hello")
                mock_print.assert_called_once()
                # Assert the text, not the whole call: safe_print now passes an
                # explicit file= so it can also write to stderr.
                assert mock_print.call_args[0][0] == "Hello"


# ========== Category 3: prompt_text() ==========


class TestPromptText:
    """Tests for prompt_text() simple text input."""

    def test_returns_user_input(self):
        """Test returns stripped user input."""
        with patch("builtins.input", return_value="  my value  "):
            result = prompt_text("Enter value")
            assert result == "my value"

    def test_returns_default_on_empty(self):
        """Test returns default when user presses Enter."""
        with patch("builtins.input", return_value=""):
            result = prompt_text("Enter value", default="fallback")
            assert result == "fallback"

    def test_prompt_format_with_default(self):
        """Test prompt displays default value."""
        with patch("builtins.input", return_value="") as mock_input:
            prompt_text("Question", default="yes")
            prompt_str = mock_input.call_args[0][0]
            assert "[yes]" in prompt_str

    def test_prompt_format_without_default(self):
        """Test prompt format when no default."""
        with patch("builtins.input", return_value="val") as mock_input:
            prompt_text("Question")
            prompt_str = mock_input.call_args[0][0]
            assert "Question: " in prompt_str

    def test_empty_input_no_default_returns_empty(self):
        """Test empty input with no default returns empty string."""
        with patch("builtins.input", return_value=""):
            result = prompt_text("Question")
            assert result == ""


# ========== Category 4: prompt_choice() ==========


class TestPromptChoice:
    """Tests for prompt_choice() numbered selection."""

    def test_numeric_selection(self):
        """Test selecting by number."""
        choices = [("repo", "Repositories"), ("image", "Container images")]
        with patch("builtins.input", return_value="1"):
            result = prompt_choice("Choose target:", choices)
            assert result == "repo"

    def test_numeric_selection_second_item(self):
        """Test selecting second item by number."""
        choices = [("repo", "Repositories"), ("image", "Container images")]
        with patch("builtins.input", return_value="2"):
            result = prompt_choice("Choose target:", choices)
            assert result == "image"

    def test_key_input(self):
        """Test selecting by key name."""
        choices = [("repo", "Repositories"), ("image", "Container images")]
        with patch("builtins.input", return_value="image"):
            result = prompt_choice("Choose:", choices)
            assert result == "image"

    def test_key_input_case_insensitive(self):
        """Test key input is case-insensitive."""
        choices = [("repo", "Repositories"), ("IAC", "Infrastructure as Code")]
        with patch("builtins.input", return_value="iac"):
            result = prompt_choice("Choose:", choices)
            assert result == "IAC"

    def test_default_on_empty(self):
        """Test default selection on empty input."""
        choices = [("repo", "Repositories"), ("image", "Container images")]
        with patch("builtins.input", return_value=""):
            result = prompt_choice("Choose:", choices, default="image")
            assert result == "image"

    def test_invalid_then_valid(self):
        """Test recovery from invalid input."""
        choices = [("a", "Option A"), ("b", "Option B")]
        # First call returns invalid "99", second returns valid "1"
        with (
            patch("builtins.input", side_effect=["99", "1"]),
            patch(
                "scripts.cli.wizard_flows.ui_helpers._get_colorize",
                return_value=lambda text, _: text,
            ),
        ):
            result = prompt_choice("Choose:", choices)
            assert result == "a"

    def test_invalid_key_then_valid(self):
        """Test recovery from invalid key input."""
        choices = [("a", "Option A"), ("b", "Option B")]
        with (
            patch("builtins.input", side_effect=["invalid_key", "a"]),
            patch(
                "scripts.cli.wizard_flows.ui_helpers._get_colorize",
                return_value=lambda text, _: text,
            ),
        ):
            result = prompt_choice("Choose:", choices)
            assert result == "a"


# ========== Category 5: select_mode() ==========


class TestSelectMode:
    """Tests for select_mode() wrapper."""

    def test_delegates_to_prompt_choice(self):
        """Test select_mode calls prompt_choice."""
        modes = [("repo", "Repositories"), ("iac", "Infrastructure as Code")]
        with patch(
            "scripts.cli.wizard_flows.ui_helpers.prompt_choice",
            return_value="iac",
        ) as mock_choice:
            result = select_mode("Target types", modes, default="repo")
            assert result == "iac"
            mock_choice.assert_called_once()
            # First arg should include the title
            call_args = mock_choice.call_args
            assert "Target types" in call_args[0][0]

    def test_passes_default(self):
        """Test default is forwarded to prompt_choice."""
        modes = [("a", "A"), ("b", "B")]
        with patch(
            "scripts.cli.wizard_flows.ui_helpers.prompt_choice",
            return_value="a",
        ) as mock_choice:
            select_mode("Title", modes, default="b")
            assert (
                mock_choice.call_args[1]["default"] == "b"
                or mock_choice.call_args[0][2] == "b"
            )


# ========== Category 6: time estimates ==========


class TestToolTimeEstimates:
    """TOOL_TIME_ESTIMATES has one entry per matrix tool, and nothing else.

    It used to carry an estimate for every tool any profile had ever named, so
    it outlived the tools it described. A tool added to TOOL_MATRIX without an
    estimate silently gets `_default`; a tool removed from it leaves a dead row.
    Both directions fail here.
    """

    def test_keys_are_exactly_the_matrix(self):
        assert set(TOOL_TIME_ESTIMATES) - {"_default"} == set(TOOL_MATRIX)

    def test_default_is_present_and_positive(self):
        assert TOOL_TIME_ESTIMATES["_default"] > 0


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
