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

# Where the Docker image keeps the pinned rules it fetches at build time
# (Dockerfile): outside ~/.jmo, which a persistence mount would cover.
IMAGE_YARA_RULES_DIR = Path("/opt/jmo/yara-rules")


def get_yara_rules_install_dir() -> Path:
    """Where `jmo tools install yara-x` puts the pinned rule bundle.

    Returns:
        Path to the user's rules directory (~/.jmo/yara-rules/)
    """
    return Path.home() / ".jmo" / "yara-rules"


def get_yara_rules_dir() -> Path:
    """Get the directory holding the YARA rule set yara-x reads.

    Defined once because readiness, the scan's default `--rules` and the
    installer's "already installed" check have to agree; a rules path that
    silently points at nothing makes yara-x report a clean scan of an
    unexamined tree.

    The user's install wins whenever it exists, even at an older pin:
    readiness then says to re-install it, where falling through to the image's
    rules would hide that the user's own tree is stale. Without it, the Docker
    image's rules are read; they live outside ~/.jmo because that is the
    documented persistence mount, and a volume there hides whatever the image
    put beneath it (#1282). With neither, the user's path: the one
    `jmo tools install yara-x` fills and the runner names when it is empty.

    Read-only: the installer writes to get_yara_rules_install_dir(). The
    image's tree is root's, and would not outlive a `--rm` container.

    The previous default was the hardcoded `/usr/share/yara/rules`, which does
    not exist on Windows *or* on stock Ubuntu - measured absent on both - so
    yara could never have found rules on either platform.

    Returns:
        Path to the rules directory (~/.jmo/yara-rules/, or the image's)
    """
    user = get_yara_rules_install_dir()
    if user.exists() or not IMAGE_YARA_RULES_DIR.exists():
        return user
    return IMAGE_YARA_RULES_DIR


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


def get_isolated_venv_bin(executable: str | Path) -> Path | None:
    """Return the isolated-venv bin directory ``executable`` lives in, if any.

    A pip console script does not know which interpreter installed it. On
    Windows, checkov ships `checkov.cmd`, a polyglot launcher that searches
    **PATH** for `python.cmd/bat/exe` and then falls back to the `.py` file
    association; it never looks at the venv it sits in. So the same absolute
    path either works or raises ``ModuleNotFoundError: No module named
    'checkov'`` depending only on what PATH the caller handed it.

    Measured on Windows 11 with checkov 3.3.16 in `~/.jmo/tools/venvs/checkov`,
    running the identical `checkov.cmd --version`:

    | child PATH                     | rc | duration | output              |
    |--------------------------------|----|----------|---------------------|
    | `<venv>/Scripts` prepended     | 0  | 9.1s     | `3.3.16`            |
    | `~/.jmo/bin` prepended only    | 1  | 0.5s     | ModuleNotFoundError |

    This lives beside `get_isolated_tool_path` on purpose: it is the inverse of
    that function, and re-spelling the `~/.jmo/tools/venvs` layout in a second
    module is what let the version probe and the scan runner disagree for four
    releases.

    Args:
        executable: Path to a resolved tool executable (argv[0]).

    Returns:
        The `<venv>/Scripts` (or `<venv>/bin`) directory, or None if
        ``executable`` does not live in an isolated venv.
    """
    try:
        bin_dir = Path(executable).parent
    except (TypeError, ValueError):
        return None

    # Windows venvs use "Scripts", POSIX venvs use "bin".
    if bin_dir.name.lower() not in ("scripts", "bin"):
        return None

    venvs_root = Path.home() / ".jmo" / "tools" / "venvs"
    try:
        relative = bin_dir.parent.relative_to(venvs_root)
    except ValueError:
        return None

    # Exactly one component: `<venvs_root>/<tool_name>`, nothing deeper.
    if len(relative.parts) != 1:
        return None

    return bin_dir


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
    "ISOLATED_TOOLS",
    "clean_isolated_venvs",
    "get_isolated_tool_path",
    "get_isolated_venv_bin",
    "get_isolated_venv_path",
]
