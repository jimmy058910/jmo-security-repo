"""
UI helper functions for the wizard.

Contains:
- UNICODE_FALLBACKS, safe_print(): re-exported from scripts.core.unicode_utils
- prompt_text(): Simple text input prompt
- prompt_choice(): Numbered choice selection prompt
- select_mode(): Helper for mode selection with consistent formatting
- WIZARD_TOTAL_STEPS, DIFF_WIZARD_TOTAL_STEPS: "Step X/Y" denominators
- TOOL_TIME_ESTIMATES, calculate_time_estimate(), format_time_range():
  the scan-time estimate shown before a scan starts

These functions complement PromptHelper from base_flow.py, providing
simpler input primitives. They depend only on base_flow.PromptHelper
for colorization.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

# Re-exported: callers (wizard_flows.tool_checker, tests) import these from here.
# The redundant `as` alias marks them as intentional re-exports for the linter.
from scripts.core.unicode_utils import UNICODE_FALLBACKS as UNICODE_FALLBACKS
from scripts.core.unicode_utils import safe_print as safe_print

if TYPE_CHECKING:
    from collections.abc import Callable

# Wizard step configuration - ensures consistent "Step X/Y" display
WIZARD_TOTAL_STEPS = (
    6  # Execution, Target Type, Target Config, Advanced, Review, Execute
)
DIFF_WIZARD_TOTAL_STEPS = 5  # Mode, Directories, Filters, Format, Execute

# Empirical per-tool timing estimates in seconds (Fix 2.2 - Issue #10), one per
# TOOL_MATRIX scanner. Based on actual runs against medium-sized repos
# (~10k-50k LOC).
TOOL_TIME_ESTIMATES: dict[str, int] = {
    # Fast tools (< 30s)
    "trufflehog": 15,
    "gitleaks": 10,
    "semgrep": 25,
    "hadolint": 5,
    "shellcheck": 10,
    # Medium tools (30s - 2min)
    "trivy": 45,
    "grype": 40,
    "syft": 30,
    "checkov": 60,
    "nuclei": 90,
    "gosec": 45,
    "yara": 45,
    # Slow tools (2min+)
    "zap": 300,  # 5 min for DAST baseline
    # Default for unknown tools
    "_default": 60,
}

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
    return value or default


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


def calculate_time_estimate(available_tools: list[str]) -> tuple[int, int]:
    """Calculate dynamic time estimate based on available tools.

    Uses TOOL_TIME_ESTIMATES with parallelization factor for best-case
    and retry buffer for worst-case estimates.

    Args:
        available_tools: List of tool names that will actually run

    Returns:
        Tuple of (min_seconds, max_seconds) estimate
    """
    total = 0
    for tool in available_tools:
        total += TOOL_TIME_ESTIMATES.get(tool, TOOL_TIME_ESTIMATES["_default"])

    # Add buffer for overhead (parallel execution reduces time, but overhead adds)
    min_time = int(total * 0.6)  # Best case with parallelization
    max_time = int(total * 1.2)  # Worst case with retries

    return min_time, max_time


def format_time_range(min_sec: int, max_sec: int) -> str:
    """Format time range as human-readable string.

    Args:
        min_sec: Minimum time in seconds
        max_sec: Maximum time in seconds

    Returns:
        Human-readable time range (e.g., "4 min - 7 min")
    """

    def fmt(s: int) -> str:
        if s < 60:
            return f"{s}s"
        elif s < 3600:
            return f"{s // 60} min"
        else:
            return f"{s // 3600}h {(s % 3600) // 60}m"

    return f"{fmt(min_sec)} - {fmt(max_sec)}"
