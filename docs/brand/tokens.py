"""JMo Security brand tokens — Python constants.

Mirrors ``tokens.css``. Use these for terminal output, generated reports, and
any Python code that emits user-facing colour. Spec lives in ``IDENTITY.md``.

This module lives under ``docs/brand/`` as the canonical reference. Phase 4
adoption (see [JMOAA-55]) promotes a copy into ``scripts/core/`` so it is
importable from CLI code. Until then, callers either copy values or read this
file directly.

Usage (post-adoption)::

    from scripts.core.brand_tokens import SEVERITY_ANSI, ANSI

    print(f"{ANSI['critical']}CRITICAL{ANSI['reset']} unpatched RCE")

The terminal palette is split in two:

- ``SEVERITY_ANSI`` — ANSI 16-colour codes for maximum compatibility with the
  widest set of terminals (the default JMo CLI palette).
- ``SEVERITY_TRUECOLOR`` — 24-bit ANSI for terminals that support it. Matches
  the hex values exactly so CLI output and the dashboard agree visually.

Colour hex values are load-bearing — they map to scanner output. Do NOT change
them without updating ``IDENTITY.md`` and ``tokens.css`` in the same change.
"""

from __future__ import annotations

from typing import Final

# ----- Severity (load-bearing) -------------------------------------------------

SEVERITY_HEX: Final[dict[str, str]] = {
    "critical": "#d32f2f",
    "high": "#f57c00",
    "medium": "#fbc02d",
    "low": "#7cb342",
    "info": "#757575",
}

# ANSI 16-colour codes (works in almost any terminal)
SEVERITY_ANSI: Final[dict[str, str]] = {
    "critical": "\033[1;31m",  # bold red
    "high": "\033[1;33m",  # bold yellow (orange-ish in most palettes)
    "medium": "\033[33m",  # yellow
    "low": "\033[32m",  # green
    "info": "\033[90m",  # bright black (grey)
    "reset": "\033[0m",
}

# 24-bit truecolor — exact hex match. Use when the terminal supports it.
SEVERITY_TRUECOLOR: Final[dict[str, str]] = {
    "critical": "\033[38;2;211;47;47m",
    "high": "\033[38;2;245;124;0m",
    "medium": "\033[38;2;251;192;45m",
    "low": "\033[38;2;124;179;66m",
    "info": "\033[38;2;117;117;117m",
    "reset": "\033[0m",
}

# ----- Brand primary -----------------------------------------------------------

BRAND_HEX: Final[dict[str, str]] = {
    "primary": "#1976d2",
    "primary_dark": "#0d47a1",  # logo navy
    "accent": "#42a5f5",
}

# ----- Neutrals ----------------------------------------------------------------

NEUTRAL_HEX: Final[dict[str, str]] = {
    "50": "#fafafa",
    "100": "#f5f5f5",
    "200": "#eeeeee",
    "300": "#e0e0e0",
    "500": "#9e9e9e",
    "700": "#616161",
    "800": "#424242",
    "900": "#212121",
    "950": "#121212",
}

# ----- Semantic UI (distinct from severity — see IDENTITY.md §3) ---------------

UI_HEX: Final[dict[str, str]] = {
    "success": "#2e7d32",
    "warning": "#ed6c02",
    "error": "#c62828",
    "info": "#0288d1",
}

# ANSI for UI semantics (mostly used by ``jmo tools install`` etc.)
UI_ANSI: Final[dict[str, str]] = {
    "success": "\033[32m",
    "warning": "\033[33m",
    "error": "\033[31m",
    "info": "\033[36m",
    "reset": "\033[0m",
}

# ----- Convenience exports -----------------------------------------------------

# What CLI code most often imports.
ANSI: Final[dict[str, str]] = {**SEVERITY_ANSI, **UI_ANSI}

# Severity ordering (highest first) for sort stability across reports.
SEVERITY_ORDER: Final[tuple[str, ...]] = ("critical", "high", "medium", "low", "info")


def severity_color(severity: str, *, truecolor: bool = False) -> str:
    """Return the ANSI escape for a severity token.

    Falls back to an empty string for unknown severities so callers can
    concatenate without guarding.
    """
    table = SEVERITY_TRUECOLOR if truecolor else SEVERITY_ANSI
    return table.get(severity.lower(), "")


def reset() -> str:
    """ANSI reset sequence."""
    return "\033[0m"
