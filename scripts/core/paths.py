"""
Path utilities for JMo Security tool management.

Handles paths for isolated virtual environments used by tools with
dependency conflicts. Extracted from tool_installer.py for reuse
across multiple modules.
"""

from __future__ import annotations

import logging
import shutil
import sys
from pathlib import Path

from scripts.core.install_config import ISOLATED_TOOLS

logger = logging.getLogger(__name__)


def get_isolated_venv_path(tool_name: str) -> Path:
    """Get the path to an isolated venv for a tool.

    Isolated venvs are used for tools with known dependency conflicts
    that cannot coexist in the same Python environment.

    Args:
        tool_name: Name of the tool

    Returns:
        Path to the venv directory (~/.jmo/tools/venvs/<tool_name>/)
    """
    return Path.home() / ".jmo" / "tools" / "venvs" / tool_name


def get_isolated_tool_path(tool_name: str) -> Path | None:
    """Get the path to a tool executable in an isolated venv.

    Checks for the primary executable name and common alternate names
    that different packages may use.

    Args:
        tool_name: Name of the tool

    Returns:
        Path to the executable, or None if not found
    """
    venv_dir = get_isolated_venv_path(tool_name)
    if not venv_dir.exists():
        return None

    # Platform-specific bin directory and extensions
    # On Windows, pip may create .exe, .cmd, or no-extension scripts
    if sys.platform == "win32":
        bin_dir = venv_dir / "Scripts"
        # Order matters: prefer .exe, then .cmd, then no extension
        extensions = [".exe", ".cmd", ""]
    else:
        bin_dir = venv_dir / "bin"
        extensions = [""]

    # Try primary name first, then alternate names
    # Order: tool_name, tool_name-cli, tool_name_cli, underscored version
    names_to_try = [
        tool_name,
        f"{tool_name}-cli",
        f"{tool_name}_cli",
        tool_name.replace("-", "_"),
    ]

    # Try each name with each extension
    for name in names_to_try:
        for ext in extensions:
            exe_path = bin_dir / f"{name}{ext}"
            if exe_path.exists():
                return exe_path

    return None


def clean_isolated_venvs(dry_run: bool = True) -> list[str]:
    """Remove isolated venv directories.

    Used by 'jmo tools clean' command to remove isolated virtual environments
    when they are no longer needed or to fix corrupted installations.

    Args:
        dry_run: If True, only list what would be deleted without actually deleting

    Returns:
        List of deleted (or would-delete if dry_run) paths
    """
    venvs_dir = Path.home() / ".jmo" / "tools" / "venvs"
    if not venvs_dir.exists():
        return []

    removed: list[str] = []
    for venv_dir in venvs_dir.iterdir():
        if venv_dir.is_dir():
            if dry_run:
                logger.info(f"Would remove: {venv_dir}")
            else:
                logger.info(f"Removing: {venv_dir}")
                shutil.rmtree(venv_dir)
            removed.append(str(venv_dir))

    return removed


# Re-export ISOLATED_TOOLS for convenience (modules importing paths.py
# often also need to check if a tool requires isolation)
__all__ = [
    "get_isolated_venv_path",
    "get_isolated_tool_path",
    "clean_isolated_venvs",
    "ISOLATED_TOOLS",
]
