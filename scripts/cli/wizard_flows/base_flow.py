"""Base classes and utilities for wizard workflows."""

from __future__ import annotations

import os
import shutil
import sys
from pathlib import Path


def _supports_ansi() -> bool:
    """Check if terminal supports ANSI escape codes.

    Returns:
        True if ANSI codes should work, False otherwise
    """
    # Check NO_COLOR environment variable (standard)
    if os.environ.get("NO_COLOR"):
        return False

    # Check for modern terminal emulators that support ANSI (before isatty check)
    # These terminals handle ANSI even when stdout is redirected
    wt_session = os.environ.get("WT_SESSION")  # Windows Terminal
    term = os.environ.get("TERM", "")
    if wt_session or "xterm" in term or "256color" in term:
        return True

    # For other cases, require stdout to be a TTY
    if not getattr(sys.stdout, "isatty", lambda: False)():
        return False

    # Always True on non-Windows (Unix terminals generally support ANSI)
    if sys.platform != "win32":
        return True

    # Try to enable ANSI on Windows 10+ via SetConsoleMode
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        # STD_OUTPUT_HANDLE = -11
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        handle = kernel32.GetStdHandle(-11)

        # Check for invalid handle
        if handle == -1 or handle is None or handle == 0:
            return False

        mode = ctypes.c_ulong()
        # GetConsoleMode returns non-zero on success
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False

        # SetConsoleMode returns non-zero on success
        if not kernel32.SetConsoleMode(handle, mode.value | 0x0004):
            return False

        return True
    except Exception:
        pass

    return False


def _get_terminal_width() -> int:
    """Get terminal width with safe fallback.

    Returns:
        Terminal width in columns (minimum 40, maximum 120)
    """
    try:
        columns = shutil.get_terminal_size().columns
        return max(40, min(columns, 120))
    except Exception:
        return 80  # Safe default


# Module-level ANSI support flag (computed once at import)
_ANSI_SUPPORTED = _supports_ansi()


class TargetDetector:
    """Unified target detection for wizard workflows."""

    def detect_repos(self, search_dir: Path | None = None) -> list[Path]:
        """Detect Git repositories in directory.

        Args:
            search_dir: Directory to search (defaults to current directory)

        Returns:
            List of Path objects pointing to Git repositories
        """
        if search_dir is None:
            search_dir = Path.cwd()

        repos: list[Path] = []
        if not search_dir.exists():
            return repos

        for item in search_dir.iterdir():
            if item.is_dir() and (item / ".git").exists():
                repos.append(item)

        return repos


class PromptHelper:
    """Helper for interactive prompts with colored output."""

    # ANSI color codes
    COLORS = {
        "blue": "\x1b[36m",
        "cyan": "\x1b[96m",
        "green": "\x1b[32m",
        "yellow": "\x1b[33m",
        "red": "\x1b[31m",
        "magenta": "\x1b[35m",
        "bold": "\x1b[1m",
        "dim": "\x1b[2m",
        "reset": "\x1b[0m",
    }

    # Visual elements
    ICONS = {
        "check": "✓",
        "cross": "✗",
        "arrow": "→",
        "bullet": "•",
        "star": "★",
        "rocket": "🚀",
        "lock": "🔒",
        "package": "📦",
        "chart": "📊",
        "warning": "⚠️",
        "info": "ℹ️",
        "success": "✅",
        "hourglass": "⏳",
    }

    def colorize(self, text: str, color: str) -> str:
        """Apply ANSI color codes to text.

        Respects NO_COLOR environment variable and gracefully degrades
        on older Windows terminals that don't support ANSI escape codes.

        Args:
            text: Text to colorize
            color: Color name (blue, cyan, green, yellow, red, magenta, bold, dim)

        Returns:
            Colorized text with reset code, or plain text if ANSI not supported
        """
        # Re-check NO_COLOR at runtime (can be set after import)
        if os.environ.get("NO_COLOR"):
            return text
        # Also check cached ANSI support (Windows VT enablement)
        if not _ANSI_SUPPORTED:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def print_header(self, text: str, icon: str = "star") -> None:
        """Print a formatted section header with icon.

        Adapts to terminal width for better display on narrow terminals.

        Args:
            text: Header text
            icon: Icon name (star, rocket, lock, package, chart)
        """
        # Get dynamic width: clamp to [40, 80] first, then calculate inner
        box_width = max(40, min(_get_terminal_width(), 80))
        inner_width = box_width - 4  # Account for box borders (2 chars each side)

        print()
        print(self.colorize("╔" + "═" * inner_width + "╗", "cyan"))
        icon_char = self.ICONS.get(icon, self.ICONS["star"])
        header_text = f"{icon_char}  {text}  {icon_char}"
        # Truncate header if too long
        if len(header_text) > inner_width:
            header_text = header_text[: max(0, inner_width - 1)] + "…"
        print(self.colorize(f"║{header_text.center(inner_width)}║", "bold"))
        print(self.colorize("╚" + "═" * inner_width + "╝", "cyan"))
        print()

    def print_step(self, step: int, total: int, text: str) -> None:
        """Print a step indicator with progress bar.

        Args:
            step: Current step number
            total: Total number of steps
            text: Step description
        """
        # Get dynamic width: clamp to [40, 80] first
        line_width = max(40, min(_get_terminal_width(), 80))

        # Progress bar
        progress_width = 20
        filled = int((step / total) * progress_width)
        bar = "█" * filled + "░" * (progress_width - filled)
        percentage = int((step / total) * 100)

        # Step indicator
        step_text = f"[Step {step}/{total}]"
        progress_text = f"[{bar}] {percentage}%"

        print()
        print(self.colorize("─" * line_width, "dim"))
        print(
            self.colorize(f"{self.ICONS['arrow']} {step_text} {text}", "bold")
            + f"  {self.colorize(progress_text, 'cyan')}"
        )
        print()

    def prompt_choice(
        self, question: str, choices: list[str], default: str | None = None
    ) -> str:
        """Prompt user to select from choices.

        Accepts both numeric input (1, 2, 3) and text input for backward
        compatibility. Text matching is case-insensitive.

        Args:
            question: Question to ask
            choices: List of choice strings
            default: Default choice (optional)

        Returns:
            Selected choice
        """
        print(f"\n{question}")
        for i, choice in enumerate(choices, 1):
            default_marker = " (default)" if choice == default else ""
            print(f"  {i}. {choice}{default_marker}")

        choice_range = f"1-{len(choices)}"
        while True:
            if default:
                response = input(f"Choice ({choice_range}) [{default}]: ").strip()
            else:
                response = input(f"Choice ({choice_range}): ").strip()

            if not response and default:
                return default

            # Handle numeric input
            if response.isdigit():
                idx = int(response) - 1
                if 0 <= idx < len(choices):
                    return choices[idx]
                print(self.colorize(f"Invalid choice. Enter 1-{len(choices)}", "red"))
                continue

            # Handle text input (case-insensitive match)
            response_lower = response.lower()
            for choice in choices:
                if choice.lower() == response_lower:
                    return choice

            print(
                self.colorize(
                    f"Invalid choice. Enter 1-{len(choices)} or type option name",
                    "red",
                )
            )

    def prompt_yes_no(self, question: str, default: bool = True) -> bool:
        """Prompt user for yes/no.

        Args:
            question: Question to ask
            default: Default value

        Returns:
            True for yes, False for no
        """
        default_str = "Y/n" if default else "y/N"
        while True:
            response = input(f"{question} [{default_str}]: ").strip().lower()
            if not response:
                return default
            if response in ("y", "yes"):
                return True
            if response in ("n", "no"):
                return False
            print("Please enter 'y' or 'n'")
