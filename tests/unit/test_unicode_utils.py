"""Tests for scripts.core.unicode_utils module.

Covers safe_print(), safe_write() and UNICODE_FALLBACKS with edge cases
including empty strings, ASCII-only, mixed Unicode/ASCII, CJK, and emoji.
"""

from __future__ import annotations

from io import StringIO
from unittest.mock import patch

import pytest

from scripts.core.unicode_utils import (
    UNICODE_FALLBACKS,
    harden_console_streams,
    safe_print,
    safe_write,
)


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


class _StrictStream(StringIO):
    """Stream that rejects unencodable text, exactly as a real console does.

    StringIO alone accepts anything, so it cannot catch the bug these helpers
    exist to prevent. This raises on write like a genuine encoded stream.
    """

    def __init__(self, encoding: str) -> None:
        super().__init__()
        self._encoding = encoding

    @property
    def encoding(self) -> str:
        return self._encoding

    def write(self, s: str) -> int:
        s.encode(self._encoding)
        return super().write(s)


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

    def test_character_absent_from_fallback_table_does_not_raise(self) -> None:
        """A character with no fallback entry must degrade, not crash.

        Regression: the old implementation re-ran the same substitution in its
        except handler. For a character absent from UNICODE_FALLBACKS that is a
        no-op, so the retry raised again -- uncaught -- and killed the command.
        """
        stream = _StrictStream("cp1252")
        with patch("scripts.core.unicode_utils.sys.stdout", stream):
            safe_print("Rocket: \U0001f680")  # not in UNICODE_FALLBACKS
        assert "Rocket: ?" in stream.getvalue()

    def test_writes_to_supplied_stream(self) -> None:
        stream = _FakeStdout("cp1252")
        safe_print("\u2705 done", stream=stream)
        assert stream.getvalue() == "[OK] done\n"


class TestSafeWrite:
    """Tests for safe_write() -- the no-newline analogue of safe_print()."""

    def test_appends_no_newline(self) -> None:
        stream = _FakeStdout("utf-8")
        safe_write("no newline", stream=stream)
        assert stream.getvalue() == "no newline"

    def test_defaults_to_stdout(self) -> None:
        stream = _FakeStdout("cp1252")
        with patch("scripts.core.unicode_utils.sys.stdout", stream):
            safe_write("\u2705 ok")
        assert stream.getvalue() == "[OK] ok"

    def test_unicode_passthrough_on_utf8(self) -> None:
        stream = _StrictStream("utf-8")
        safe_write("scan \U0001f50d done", stream=stream)
        assert stream.getvalue() == "scan \U0001f50d done"

    @pytest.mark.parametrize("codec", ["cp1252", "cp437", "cp850"])
    def test_degrades_on_every_legacy_console_codec(self, codec: str) -> None:
        """cp437/cp850 are the trap: they contain box-drawing but not emoji.

        A guard that recognises unsafe encodings by *name* passes them through
        and crashes. Probing the actual text against the actual codec does not.
        """
        stream = _StrictStream(codec)
        safe_write("\u2705 Score \u2500\u2500\n", stream=stream)
        assert stream.getvalue() == "[OK] Score --\n"

    def test_character_absent_from_fallback_table_does_not_raise(self) -> None:
        stream = _StrictStream("cp437")
        safe_write("Rocket: \U0001f680", stream=stream)
        assert "Rocket: ?" in stream.getvalue()

    def test_custom_fallbacks(self) -> None:
        stream = _StrictStream("cp1252")
        safe_write("\u2764 love", stream=stream, fallbacks={"\u2764": "<heart>"})
        assert stream.getvalue() == "<heart> love"

    def test_no_encoding_attribute_defaults_to_utf8(self) -> None:
        stream = _NoEncodingStdout()
        safe_write("\u2705 test", stream=stream)
        assert "\u2705" in stream.getvalue()

    def test_unknown_codec_degrades_instead_of_raising(self) -> None:
        """An unresolvable encoding name must not become a LookupError."""
        stream = _FakeStdout("not-a-real-codec")
        safe_write("\u2705 ok", stream=stream)
        assert "[OK] ok" in stream.getvalue()


class TestHardenConsoleStreams:
    """Tests for harden_console_streams().

    This is the guarantee the fallback table cannot give: it covers every write
    on the stream, including ones from rich, argparse and third-party code that
    no call-site audit reaches.
    """

    class _Reconfigurable:
        def __init__(self) -> None:
            self.calls: list[dict[str, str]] = []

        def reconfigure(self, **kwargs: str) -> None:
            self.calls.append(kwargs)

    def test_sets_replace_on_both_streams(self) -> None:
        out, err = self._Reconfigurable(), self._Reconfigurable()
        with (
            patch("scripts.core.unicode_utils.sys.stdout", out),
            patch("scripts.core.unicode_utils.sys.stderr", err),
        ):
            harden_console_streams()
        assert out.calls == [{"errors": "replace"}]
        assert err.calls == [{"errors": "replace"}]

    def test_does_not_touch_encoding(self) -> None:
        """Forcing UTF-8 onto a cp437 console yields mojibake, not a fix."""
        out = self._Reconfigurable()
        with (
            patch("scripts.core.unicode_utils.sys.stdout", out),
            patch("scripts.core.unicode_utils.sys.stderr", self._Reconfigurable()),
        ):
            harden_console_streams()
        assert "encoding" not in out.calls[0]

    def test_tolerates_stream_without_reconfigure(self) -> None:
        """pytest capture objects and plain file-likes have no reconfigure()."""
        with (
            patch("scripts.core.unicode_utils.sys.stdout", StringIO()),
            patch("scripts.core.unicode_utils.sys.stderr", StringIO()),
        ):
            harden_console_streams()  # must not raise

    def test_tolerates_reconfigure_raising(self) -> None:
        """A detached or closed stream must not take the whole CLI down."""

        class _Detached:
            def reconfigure(self, **_: str) -> None:
                raise ValueError("underlying buffer has been detached")

        with (
            patch("scripts.core.unicode_utils.sys.stdout", _Detached()),
            patch("scripts.core.unicode_utils.sys.stderr", _Detached()),
        ):
            harden_console_streams()  # must not raise
