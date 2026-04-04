#!/usr/bin/env python3
"""Shared Unicode fallback utilities for Windows cp1252 compatibility.

Provides safe_print() and UNICODE_FALLBACKS for console output on terminals
that cannot render Unicode characters (e.g., Windows cmd.exe with cp1252).
"""

from __future__ import annotations

import sys

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
}


def safe_print(text: str, fallbacks: dict[str, str] | None = None) -> None:
    """Print with Unicode fallback for Windows cp1252 compatibility.

    Args:
        text: Text to print (may contain Unicode characters).
        fallbacks: Optional custom fallback mapping. If None, uses
            the module-level UNICODE_FALLBACKS.
    """
    if fallbacks is None:
        fallbacks = UNICODE_FALLBACKS
    try:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        if encoding.lower() in ("cp1252", "ascii", "latin-1", "iso-8859-1"):
            for unicode_char, ascii_fallback in fallbacks.items():
                text = text.replace(unicode_char, ascii_fallback)
        print(text)
    except UnicodeEncodeError:
        for unicode_char, ascii_fallback in fallbacks.items():
            text = text.replace(unicode_char, ascii_fallback)
        print(text)
