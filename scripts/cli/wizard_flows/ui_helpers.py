"""
UI helper functions for the wizard.

Contains:
- UNICODE_FALLBACKS: Windows cp1252 compatibility mappings
- safe_print(): Print with Unicode fallback
- prompt_text(): Simple text input prompt
- prompt_choice(): Numbered choice selection prompt
- select_mode(): Helper for mode selection with consistent formatting

These functions complement PromptHelper from base_flow.py, providing
simpler input primitives. They depend only on base_flow.PromptHelper
for colorization.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from typing import Callable

# Import colorize from PromptHelper lazily to avoid import cycles at module load
_colorize: Callable[[str, str], str] | None = None


def _get_colorize() -> Callable[[str, str], str]:
    """Get the colorize function, initializing lazily."""
    global _colorize
    if _colorize is None:
        from scripts.cli.wizard_flows.base_flow import PromptHelper

        _colorize = PromptHelper().colorize
    assert _colorize is not None  # For type checker
    return _colorize


# Windows-safe Unicode fallback mappings for cp1252 compatibility
UNICODE_FALLBACKS: dict[str, str] = {
    "\U0001f4ca": "[#]",  # Chart (📊)
    "\U0001f4d6": "[?]",  # Book (📖)
    "\u26a0": "[!]",  # Warning (⚠)
    "\u2705": "[OK]",  # Check mark (✅)
    "\u274c": "[X]",  # Cross mark (❌)
    "\u2717": "[x]",  # X mark (✗)
    "\u2713": "[v]",  # Check mark small (✓)
    "\u2022": "*",  # Bullet (•)
    "\u2192": "->",  # Arrow (→)
}


def safe_print(text: str) -> None:
    """Print with Unicode fallback for Windows cp1252 compatibility.

    Automatically replaces Unicode characters with ASCII equivalents
    when the terminal doesn't support them (e.g., Windows cmd.exe).

    Args:
        text: Text to print, may contain Unicode characters
    """
    try:
        encoding = getattr(sys.stdout, "encoding", None) or "utf-8"
        if encoding.lower() in ("cp1252", "ascii", "latin-1", "iso-8859-1"):
            for unicode_char, ascii_fallback in UNICODE_FALLBACKS.items():
                text = text.replace(unicode_char, ascii_fallback)
        print(text)
    except UnicodeEncodeError:
        for unicode_char, ascii_fallback in UNICODE_FALLBACKS.items():
            text = text.replace(unicode_char, ascii_fallback)
        print(text)


def prompt_text(question: str, default: str = "") -> str:
    """Simple text prompt helper.

    Args:
        question: Question to display
        default: Default value if user presses Enter

    Returns:
        User input or default value
    """
    prompt = f"{question} [{default}]: " if default else f"{question}: "
    value = input(prompt).strip()
    return value if value else default


def prompt_choice(
    question: str, choices: list[tuple[str, str]], default: str = ""
) -> str:
    """Prompt user for a choice from a list with numbered display.

    Accepts both numeric input (1, 2, 3) and key input (balanced, fast)
    for backward compatibility.

    Args:
        question: Question to ask
        choices: List of (key, description) tuples
        default: Default choice key

    Returns:
        Selected choice key
    """
    colorize = _get_colorize()
    choice_keys = [c[0] for c in choices]

    # Print question and choices with numbered format
    print(f"\n{question}")
    for i, (key, desc) in enumerate(choices, 1):
        default_marker = " (default)" if key == default else ""
        print(f"  {i}. {key:<12} - {desc}{default_marker}")

    # Build prompt
    choice_range = f"1-{len(choices)}"
    if default:
        prompt = f"Choice ({choice_range}) [{default}]: "
    else:
        prompt = f"Choice ({choice_range}): "

    while True:
        raw = input(prompt).strip()

        # Handle empty input with default
        if not raw and default:
            return default

        # Handle numeric input
        if raw.isdigit():
            idx = int(raw)
            if 1 <= idx <= len(choices):
                return choice_keys[idx - 1]
            print(colorize(f"Invalid choice. Enter 1-{len(choices)}", "red"))
            continue

        # Handle key input (backward compatibility, case-insensitive)
        raw_lower = raw.lower()
        for key in choice_keys:
            if key.lower() == raw_lower:
                return key

        print(
            colorize(
                f"Invalid choice. Enter 1-{len(choices)} or type option name",
                "red",
            )
        )


def select_mode(title: str, modes: list[tuple[str, str]], default: str = "") -> str:
    """Helper to select from modes with consistent formatting.

    Uses numbered selection format with backward-compatible key input.

    Args:
        title: Mode category title (e.g., "Repository modes")
        modes: List of (key, description) tuples
        default: Default mode key

    Returns:
        Selected mode key
    """
    # prompt_choice handles the display and input
    return prompt_choice(f"{title}:", modes, default=default)
