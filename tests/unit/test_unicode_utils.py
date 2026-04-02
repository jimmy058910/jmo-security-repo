"""Tests for scripts.core.unicode_utils module.

Covers safe_print() and UNICODE_FALLBACKS with edge cases including
empty strings, ASCII-only, mixed Unicode/ASCII, CJK, and emoji.
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest

from scripts.core.unicode_utils import UNICODE_FALLBACKS, safe_print


class _FakeStdout(StringIO):
    """StringIO subclass with a writable encoding attribute for testing."""

    def __init__(self, encoding: str = "utf-8") -> None:
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self) -> str:
        return self._encoding


class _NoEncodingStdout(StringIO):
    """StringIO subclass that hides the encoding attribute."""

    @property  # type: ignore[override]
    def encoding(self) -> None:  # type: ignore[override]
        return None


class TestUnicodeFallbacks:
    """Verify the UNICODE_FALLBACKS mapping is well-formed."""

    def test_non_empty(self) -> None:
        assert len(UNICODE_FALLBACKS) > 0

    def test_keys_are_unicode_strings(self) -> None:
        for key in UNICODE_FALLBACKS:
            assert isinstance(key, str)
            assert len(key) > 0

    def test_values_are_ascii_strings(self) -> None:
        for key, value in UNICODE_FALLBACKS.items():
            assert isinstance(value, str)
            # Fallback values should be pure ASCII
            assert value.encode("ascii"), f"Fallback for {key!r} is not ASCII"


class TestSafePrint:
    """Tests for safe_print() function."""

    def test_empty_string(self, capsys: pytest.CaptureFixture[str]) -> None:
        safe_print("")
        assert capsys.readouterr().out == "\n"

    def test_ascii_only(self, capsys: pytest.CaptureFixture[str]) -> None:
        safe_print("hello world")
        assert capsys.readouterr().out == "hello world\n"

    def test_unicode_passthrough_on_utf8(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """On UTF-8 terminals, Unicode should pass through unchanged."""
        safe_print("\u2705 OK")
        output = capsys.readouterr().out
        assert "\u2705" in output or "[OK]" in output

    def test_fallback_on_cp1252(self) -> None:
        """On cp1252 terminals, Unicode should be replaced with ASCII fallback."""
        mock_stdout = _FakeStdout("cp1252")
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("\u2705 Done")
        output = mock_stdout.getvalue()
        assert "[OK] Done" in output

    def test_fallback_on_ascii(self) -> None:
        mock_stdout = _FakeStdout("ascii")
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("\u274c Failed")
        output = mock_stdout.getvalue()
        assert "[X] Failed" in output

    def test_fallback_on_latin1(self) -> None:
        mock_stdout = _FakeStdout("latin-1")
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("\u2192 next")
        output = mock_stdout.getvalue()
        assert "-> next" in output

    def test_fallback_on_iso_8859_1(self) -> None:
        mock_stdout = _FakeStdout("iso-8859-1")
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("\u2022 item")
        output = mock_stdout.getvalue()
        assert "* item" in output

    def test_mixed_unicode_and_ascii(self) -> None:
        mock_stdout = _FakeStdout("cp1252")
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("Status: \u2705 check \u274c fail")
        output = mock_stdout.getvalue()
        assert "[OK]" in output
        assert "[X]" in output
        assert "check" in output

    def test_no_encoding_attribute(self) -> None:
        """If stdout encoding is None, should default to utf-8 (no fallback)."""
        mock_stdout = _NoEncodingStdout()
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("\u2705 test")
        output = mock_stdout.getvalue()
        # Should pass through (utf-8 default)
        assert "\u2705" in output

    def test_custom_fallbacks(self) -> None:
        """Test passing custom fallback dict."""
        custom = {"\u2764": "<heart>"}
        mock_stdout = _FakeStdout("cp1252")
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("\u2764 love", fallbacks=custom)
        output = mock_stdout.getvalue()
        assert "<heart>" in output

    def test_unicode_encode_error_fallback(self) -> None:
        """If print raises UnicodeEncodeError, fallback should be used."""
        with patch("builtins.print") as mock_print:
            call_count = 0

            def side_effect(*args, **kwargs):
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise UnicodeEncodeError("utf-8", "\u2705", 0, 1, "test")
                # Second call succeeds

            mock_print.side_effect = side_effect
            safe_print("\u2705 test")
            # Should have been called twice (first fails, second with fallback)
            assert mock_print.call_count == 2
            # Second call should have the replaced text
            second_call_arg = mock_print.call_args_list[1][0][0]
            assert "[OK]" in second_call_arg

    def test_cjk_characters_passthrough(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """CJK characters not in fallback map should pass through."""
        safe_print("Chinese: \u4f60\u597d")
        output = capsys.readouterr().out
        assert "\u4f60\u597d" in output

    def test_emoji_not_in_fallback_passthrough(
        self, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """Emoji not in the fallback map should pass through on UTF-8."""
        safe_print("Rocket: \U0001f680")
        output = capsys.readouterr().out
        assert "\U0001f680" in output

    def test_multiple_same_emoji(self) -> None:
        """Multiple occurrences of the same emoji should all be replaced."""
        mock_stdout = _FakeStdout("cp1252")
        with patch("scripts.core.unicode_utils.sys.stdout", mock_stdout):
            safe_print("\u2705 one \u2705 two \u2705 three")
        output = mock_stdout.getvalue()
        assert output.count("[OK]") == 3
