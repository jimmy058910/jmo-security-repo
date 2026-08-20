#!/usr/bin/env python3
"""Shared Unicode fallback utilities for consoles that are not UTF-8.

Provides safe_print(), safe_write() and UNICODE_FALLBACKS for console output on
terminals that cannot render Unicode. Windows is the case that matters: stdout
gets the ANSI codepage (cp1252 on a US box) when piped, and the OEM codepage
(cp437/cp850) when attached to a real console. None of them can encode an emoji,
so an unguarded write raises UnicodeEncodeError and kills the command.

Two rules make these helpers correct where hand-rolled versions were not:

1. **Probe the text against the stream's actual codec.** Deciding by encoding
   *name* ("is it cp1252?") passes cp437/cp850 through, and those contain the
   box-drawing characters but not the emoji -- so the check says "safe" and the
   write still crashes.
2. **UNICODE_FALLBACKS is a quality layer, not the guarantee.** It exists to
   render "[OK]" instead of "?", and it will always be incomplete (scripts/
   currently emits ~74 characters it does not list). The guarantee is the final
   errors="replace" pass, which cannot fail regardless of the table's contents.
"""

from __future__ import annotations

import sys
from typing import TextIO

# Combined Unicode fallback mappings for cp1252 compatibility.
# Canonical superset merging all fallback dicts used across the codebase.
UNICODE_FALLBACKS: dict[str, str] = {
    # Box drawing — horizontal/vertical lines
    "\u2500": "-",  # ─ Box drawing horizontal
    "\u2501": "=",  # ━ Box drawing heavy horizontal
    "\u2502": "|",  # │ Box drawing vertical
    # Box drawing — corners and intersections
    "\u250c": "+",  # ┌
    "\u2510": "+",  # ┐
    "\u2514": "+",  # └
    "\u2518": "+",  # ┘
    "\u251c": "+",  # ├
    "\u2524": "+",  # ┤
    "\u252c": "+",  # ┬
    "\u2534": "+",  # ┴
    "\u253c": "+",  # ┼
    # Box drawing — double lines
    "\u2550": "=",  # ═ Double horizontal
    "\u2551": "|",  # ║ Double vertical
    "\u2554": "+",  # ╔
    "\u2557": "+",  # ╗
    "\u255a": "+",  # ╚
    "\u255d": "+",  # ╝
    # Arrows
    "\u2190": "<-",  # ← Left arrow
    "\u2191": "^",  # ↑ Up arrow
    "\u2192": "->",  # → Right arrow
    "\u2193": "v",  # ↓ Down arrow
    # Punctuation / symbols
    "\u2022": "*",  # • Bullet
    "\u2713": "[v]",  # ✓ Check mark small
    "\u2717": "[x]",  # ✗ X mark
    # Status / alert symbols
    "\u2705": "[OK]",  # ✅ Check mark
    "\u274c": "[X]",  # ❌ Cross mark
    "\u26a0": "[!]",  # ⚠ Warning (without variation selector)
    "\u26a0\ufe0f": "[!]",  # ⚠️ Warning (with VS-16)
    # Emoji — CLI / jmo.py
    "\U0001f389": "[*]",  # 🎉 Party popper
    "\U0001f4e7": "[@]",  # 📧 Email
    "\U0001f49a": "<3",  # 💚 Green heart
    "\U0001f44d": "[+1]",  # 👍 Thumbs up
    # Emoji — telemetry / core
    "\U0001f4ca": "[#]",  # 📊 Chart (bar chart)
    "\U0001f4c8": "[^]",  # 📈 Chart increasing
    "\U0001f4c9": "[v]",  # 📉 Chart decreasing
    "\U0001f512": "[L]",  # 🔒 Lock
    "\U0001f310": "[W]",  # 🌐 Globe
    "\U0001f4a1": "[i]",  # 💡 Light bulb
    "\U0001f4d6": "[?]",  # 📖 Book
    "\U0001f50d": "[?]",  # 🔍 Magnifying glass
    # Emoji — trends headers. Absent from this table until chunk 15, so
    # `jmo trends score` and `developers` printed a bare '?' as their title
    # even though every other glyph on the line fell back cleanly.
    "\U0001f3c6": "[*]",  # 🏆 Trophy (posture score)
    "\U0001f465": "[@]",  # 👥 Busts (developer attribution)
    "\U0001f4cb": "[=]",  # 📋 Clipboard (finding lists)
    "\u27a1\ufe0f": "->",  # ➡️ Right arrow (stable trend)
    "\u2139\ufe0f": "[i]",  # ℹ️ Information (insufficient data)
    # Sparkline / bar ramp — trend_formatters renders severity charts and the
    # posture-score bar out of these. Mapped to an ordered ASCII ramp rather
    # than one shared character: a bar chart whose every cell is the same
    # glyph renders, but stops being a chart. Same reasoning as the spinner
    # frames below. U+2588 is in cp437 but not cp1252, and the sparkline was
    # a row of '?' on any redirected Windows stream.
    "\u2581": "_",  # ▁ lower one eighth block
    "\u2582": ".",  # ▂ lower one quarter
    "\u2583": ".",  # ▃ lower three eighths
    "\u2584": "-",  # ▄ lower half
    "\u2585": "-",  # ▅ lower five eighths
    "\u2586": "=",  # ▆ lower three quarters
    "\u2587": "=",  # ▇ lower seven eighths
    "\u2588": "#",  # █ full block
    "\u2591": ".",  # ░ light shade (bar remainder)
    # Severity dots — trend_formatters' insight and regression markers.
    "\U0001f534": "(!)",  # 🔴 red
    "\U0001f7e0": "(*)",  # 🟠 orange
    "\U0001f7e1": "(o)",  # 🟡 yellow
    "\U0001f535": "(-)",  # 🔵 blue
    "\U0001f7e2": "(+)",  # 🟢 green
    # Remaining trends glyphs.
    "\u27a1": "->",  # ➡ right arrow, bare (no VS-16)
    "\u2139": "[i]",  # ℹ information, bare
    "\u2795": "+",  # ➕ heavy plus
    "\U0001f527": "[T]",  # 🔧 wrench
    "\U0001f525": "[!]",  # 🔥 fire
    "\U0001f504": "[~]",  # 🔄 cycle arrows
    # Mathematical symbols. Neither is safe everywhere and they fail in
    # opposite directions: U+00D7 encodes in cp1252 but not cp437, U+2265 in
    # cp437 but not cp1252 -- which is why encodability cannot be decided
    # from a codec's name.
    "\u00d7": "x",  # × multiplication sign
    "\u2265": ">=",  # ≥ greater than or equal
    "\u2264": "<=",  # ≤ less than or equal
    # An orphaned VARIATION SELECTOR-16 is handled per-emoji, by giving the
    # sequence its own two-character key (see "⚠️" above) rather than by
    # mapping U+FE0F to the empty string globally. Both work, but only the
    # per-emoji form keeps every value in this table a non-empty ASCII token,
    # which `test_values_are_ascii_strings` relies on.
    # Braille spinner frames — ProgressTracker._SPINNER_FRAMES (scan progress).
    # Measured: all ten are unrenderable in cp1252 AND cp437 AND cp850, i.e. in
    # every codec a real Windows console uses, and none was in this table. The
    # stream hardening turned each into "?", so the scan spinner was a motionless
    # "?" for the whole run -- an animation conveying nothing, and one that reads
    # as an error rather than as progress.
    #
    # Mapped onto a 4-phase ASCII cycle *in frame order* rather than all to one
    # character, so the substitute still animates. A static replacement would
    # have removed the only thing a spinner is for.
    "⠋": "|",  # ⠋ frame 1
    "⠙": "/",  # ⠙ frame 2
    "⠹": "-",  # ⠹ frame 3
    "⠸": "\\",  # ⠸ frame 4
    "⠼": "|",  # ⠼ frame 5
    "⠴": "/",  # ⠴ frame 6
    "⠦": "-",  # ⠦ frame 7
    "⠧": "\\",  # ⠧ frame 8
    "⠇": "|",  # ⠇ frame 9
    "⠏": "/",  # ⠏ frame 10
}


def harden_console_streams() -> None:
    """Make stdout/stderr degrade unencodable characters instead of raising.

    Call this once, before any output, at a CLI entry point.

    safe_print()/safe_write() only protect the call sites that use them. This
    protects the *stream*, so it also covers writes from rich, from argparse and
    from third-party libraries -- paths no call-site audit can reach, and where
    a UnicodeEncodeError today kills the command outright.

    errors="replace" is a no-op on a UTF-8 stream: every character encodes, so
    the handler never runs. `encoding` is deliberately left alone -- forcing
    UTF-8 onto a cp437 console produces mojibake, not a fix.
    """
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            # Replaced by a capture object or a plain file-like; nothing to do.
            continue
        try:
            reconfigure(errors="replace")
        except (OSError, ValueError):
            # Detached or already-closed stream. Hardening is best-effort; a
            # failure here must not be the thing that kills the command.
            continue


def _substitute(text: str, fallbacks: dict[str, str]) -> str:
    """Apply the fallback table. Cosmetic only -- makes no encodability promise.

    Longest key first. Some entries are multi-codepoint sequences whose first
    codepoint is itself an entry -- "⚠️" (warning sign plus VS-16)
    and "⚠". In insertion order the bare sign matched first, substituted
    "[!]", and left the orphaned variation selector behind to be replaced with
    "?" by the final encode. Every "⚠️" in the product rendered as
    "[!]?" on a non-UTF-8 console, including in the generated Markdown diff
    report. Sorting by length makes the table order-independent, so a future
    sequence entry cannot be shadowed by its own prefix.
    """
    for unicode_char in sorted(fallbacks, key=len, reverse=True):
        text = text.replace(unicode_char, fallbacks[unicode_char])
    return text


def _encodable(text: str, encoding: str) -> bool:
    """Whether `text` survives `encoding`. False for an unresolvable codec name."""
    try:
        text.encode(encoding)
    except (UnicodeEncodeError, LookupError):
        return False
    return True


def _for_stream(text: str, stream: TextIO, fallbacks: dict[str, str]) -> str:
    """Reduce `text` to something `stream` can actually encode."""
    encoding = getattr(stream, "encoding", None) or "utf-8"
    if _encodable(text, encoding):
        return text

    text = _substitute(text, fallbacks)
    if _encodable(text, encoding):
        return text

    # Whatever the table missed. errors="replace" against the stream's OWN codec
    # rather than ascii, so a codec keeps the characters it can represent (cp437
    # renders box drawing) and only the rest become "?".
    try:
        return text.encode(encoding, "replace").decode(encoding)
    except LookupError:
        return text.encode("ascii", "replace").decode("ascii")


def safe_print(
    text: str,
    fallbacks: dict[str, str] | None = None,
    stream: TextIO | None = None,
) -> None:
    """Print with Unicode fallback for consoles that are not UTF-8.

    Args:
        text: Text to print (may contain Unicode characters).
        fallbacks: Optional custom fallback mapping. If None, uses
            the module-level UNICODE_FALLBACKS.
        stream: Optional destination. Defaults to sys.stdout.
    """
    if fallbacks is None:
        fallbacks = UNICODE_FALLBACKS
    if stream is None:
        stream = sys.stdout
    try:
        print(_for_stream(text, stream, fallbacks), file=stream)
    except UnicodeEncodeError:
        # The stream's real codec disagreed with its advertised .encoding.
        print(_substitute(text, fallbacks).encode("ascii", "replace").decode("ascii"))


def safe_write(
    text: str,
    stream: TextIO | None = None,
    fallbacks: dict[str, str] | None = None,
) -> None:
    """Write with Unicode fallback, without appending a newline.

    The no-newline analogue of safe_print(), for callers that build a fully
    formatted block themselves (rich-rendered reports) or that must write to
    stderr.

    Args:
        text: Text to write (may contain Unicode characters).
        stream: Optional destination. Defaults to sys.stdout.
        fallbacks: Optional custom fallback mapping. If None, uses
            the module-level UNICODE_FALLBACKS.
    """
    if fallbacks is None:
        fallbacks = UNICODE_FALLBACKS
    if stream is None:
        stream = sys.stdout
    try:
        stream.write(_for_stream(text, stream, fallbacks))
    except UnicodeEncodeError:
        # The stream's real codec disagreed with its advertised .encoding.
        stream.write(
            _substitute(text, fallbacks).encode("ascii", "replace").decode("ascii")
        )
