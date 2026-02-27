#!/usr/bin/env python3
"""Shared Unicode fallback utilities for Windows cp1252 compatibility.

Provides safe_print() and UNICODE_FALLBACKS for console output on terminals
that cannot render Unicode characters (e.g., Windows cmd.exe with cp1252).
"""

from __future__ import annotations

import sys

# Combined Unicode fallback mappings for cp1252 compatibility.
# Merges all emoji→ASCII mappings used across the codebase.
UNICODE_FALLBACKS: dict[str, str] = {
    # CLI / jmo.py
    "\U0001f389": "[*]",  # Party popper
    "\U0001f4e7": "[@]",  # Email
    "\U0001f49a": "<3",  # Green heart
    "\U0001f44d": "[+1]",  # Thumbs up
    # Telemetry
    "\U0001f4ca": "[*]",  # Chart
    "\U0001f512": "[L]",  # Lock
    "\U0001f310": "[W]",  # Globe
    "\U0001f4a1": "[i]",  # Light bulb
    # Shared
    "\u2705": "[OK]",  # Check mark
    "\u274c": "[X]",  # Cross mark
    "\u26a0\ufe0f": "[!]",  # Warning
    "\u2192": "->",  # Right arrow
    "\u2022": "*",  # Bullet
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
