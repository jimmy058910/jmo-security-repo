"""Tests for scripts/cli/wizard_flows/ui_helpers.py.

Covers:
- UNICODE_FALLBACKS: Mapping validation
- safe_print(): Unicode fallback for different encodings
- prompt_text(): Text input with defaults
- prompt_choice(): Numbered choice selection (numeric + key input)
- select_mode(): Mode selection wrapper
"""

from __future__ import annotations

from unittest.mock import patch, MagicMock


from scripts.cli.wizard_flows.ui_helpers import (
    UNICODE_FALLBACKS,
    safe_print,
    prompt_text,
    prompt_choice,
    select_mode,
)


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

        with patch("sys.stdout", mock_stdout):
            with patch(
                "builtins.print",
                side_effect=[UnicodeEncodeError("utf-8", "", 0, 1, "err"), None],
            ):
                safe_print("\u2713 test")

    def test_none_encoding_defaults_to_utf8(self, capsys):
        """Test None encoding defaults to utf-8 (no replacement)."""
        mock_stdout = MagicMock()
        mock_stdout.encoding = None

        with patch("builtins.print") as mock_print:
            with patch("sys.stdout", mock_stdout):
                safe_print("Hello")
                mock_print.assert_called_once_with("Hello")


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
        choices = [("fast", "Fast scan"), ("balanced", "Balanced scan")]
        with patch("builtins.input", return_value="1"):
            result = prompt_choice("Choose profile:", choices)
            assert result == "fast"

    def test_numeric_selection_second_item(self):
        """Test selecting second item by number."""
        choices = [("fast", "Fast scan"), ("balanced", "Balanced scan")]
        with patch("builtins.input", return_value="2"):
            result = prompt_choice("Choose profile:", choices)
            assert result == "balanced"

    def test_key_input(self):
        """Test selecting by key name."""
        choices = [("fast", "Fast scan"), ("balanced", "Balanced scan")]
        with patch("builtins.input", return_value="balanced"):
            result = prompt_choice("Choose:", choices)
            assert result == "balanced"

    def test_key_input_case_insensitive(self):
        """Test key input is case-insensitive."""
        choices = [("fast", "Fast scan"), ("DEEP", "Deep scan")]
        with patch("builtins.input", return_value="deep"):
            result = prompt_choice("Choose:", choices)
            assert result == "DEEP"

    def test_default_on_empty(self):
        """Test default selection on empty input."""
        choices = [("fast", "Fast"), ("balanced", "Balanced")]
        with patch("builtins.input", return_value=""):
            result = prompt_choice("Choose:", choices, default="balanced")
            assert result == "balanced"

    def test_invalid_then_valid(self):
        """Test recovery from invalid input."""
        choices = [("a", "Option A"), ("b", "Option B")]
        # First call returns invalid "99", second returns valid "1"
        with patch("builtins.input", side_effect=["99", "1"]):
            with patch(
                "scripts.cli.wizard_flows.ui_helpers._get_colorize",
                return_value=lambda text, _: text,
            ):
                result = prompt_choice("Choose:", choices)
                assert result == "a"

    def test_invalid_key_then_valid(self):
        """Test recovery from invalid key input."""
        choices = [("a", "Option A"), ("b", "Option B")]
        with patch("builtins.input", side_effect=["invalid_key", "a"]):
            with patch(
                "scripts.cli.wizard_flows.ui_helpers._get_colorize",
                return_value=lambda text, _: text,
            ):
                result = prompt_choice("Choose:", choices)
                assert result == "a"


# ========== Category 5: select_mode() ==========


class TestSelectMode:
    """Tests for select_mode() wrapper."""

    def test_delegates_to_prompt_choice(self):
        """Test select_mode calls prompt_choice."""
        modes = [("fast", "Quick scan"), ("deep", "Full scan")]
        with patch(
            "scripts.cli.wizard_flows.ui_helpers.prompt_choice",
            return_value="deep",
        ) as mock_choice:
            result = select_mode("Scan modes", modes, default="fast")
            assert result == "deep"
            mock_choice.assert_called_once()
            # First arg should include the title
            call_args = mock_choice.call_args
            assert "Scan modes" in call_args[0][0]

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
