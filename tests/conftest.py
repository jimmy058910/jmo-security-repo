#!/usr/bin/env python3
"""
Shared pytest fixtures and utilities for JMo Security tests.

This module provides:
- Cross-platform Python executable detection
- Platform-specific skip conditions
- Common test utilities
"""

import subprocess
import sys
from pathlib import Path

import pytest

# ============================================================================
# Platform Detection Constants
# ============================================================================

IS_WINDOWS = sys.platform == "win32"
IS_LINUX = sys.platform == "linux"
IS_MACOS = sys.platform == "darwin"


# ============================================================================
# Platform Skip Decorators
# ============================================================================
# Usage: @skip_on_windows("chmod doesn't work like Unix")

skip_on_windows = pytest.mark.skipif(
    IS_WINDOWS, reason="Test requires Unix-specific features"
)
skip_on_linux = pytest.mark.skipif(IS_LINUX, reason="Test not applicable on Linux")
skip_on_macos = pytest.mark.skipif(IS_MACOS, reason="Test not applicable on macOS")
windows_only = pytest.mark.skipif(not IS_WINDOWS, reason="Windows-only test")
unix_only = pytest.mark.skipif(IS_WINDOWS, reason="Unix-only test (Linux/macOS)")


# ============================================================================
# Cross-Platform Python Executable
# ============================================================================


def get_python_executable() -> str:
    """
    Get the Python executable path that works on all platforms.

    On Windows, 'python3' doesn't exist - only 'python.exe'.
    Using sys.executable ensures we use the same Python running the tests.

    Returns:
        Path to the Python executable (e.g., '/usr/bin/python3' or 'C:\\Python313\\python.exe')
    """
    return sys.executable


def run_jmo_command(args: list[str], **kwargs) -> subprocess.CompletedProcess:
    """
    Run a JMo CLI command using the correct Python executable.

    This helper replaces patterns like:
        subprocess.run(["python3", "-m", "scripts.cli.jmo", ...])

    With a cross-platform version:
        run_jmo_command(["scan", "--help"])

    Args:
        args: JMo command arguments (without 'python3 -m scripts.cli.jmo' prefix)
        **kwargs: Additional arguments passed to subprocess.run

    Returns:
        subprocess.CompletedProcess result

    Example:
        >>> result = run_jmo_command(["scan", "--help"], capture_output=True, text=True)
        >>> assert result.returncode == 0
    """
    cmd = [sys.executable, "-m", "scripts.cli.jmo"] + args
    return subprocess.run(cmd, **kwargs)


@pytest.fixture
def python_executable() -> str:
    """
    Pytest fixture providing the Python executable path.

    Use this fixture in tests that need to spawn Python subprocesses:

        def test_something(python_executable):
            result = subprocess.run(
                [python_executable, "-m", "scripts.cli.jmo", "scan", "--help"],
                capture_output=True,
                text=True
            )
            assert result.returncode == 0

    Returns:
        Path to the Python executable
    """
    return sys.executable


@pytest.fixture
def jmo_runner():
    """
    Pytest fixture providing a helper to run JMo commands.

    Use this fixture for cleaner test code:

        def test_scan_help(jmo_runner):
            result = jmo_runner(["scan", "--help"])
            assert result.returncode == 0
            assert "scan" in result.stdout

    Returns:
        Callable that runs JMo commands
    """

    def _run(
        args: list[str], timeout: int = 120, **kwargs
    ) -> subprocess.CompletedProcess:
        defaults = {"capture_output": True, "text": True, "timeout": timeout}
        defaults.update(kwargs)
        return run_jmo_command(args, **defaults)

    return _run


# ============================================================================
# Cross-Platform Error Message Patterns
# ============================================================================

# Pattern matching for "command not found" errors across platforms
# Windows: "cannot find the file specified", "is not recognized"
# Unix: "not found", "No such file or directory"
COMMAND_NOT_FOUND_PATTERNS = [
    "not found",
    "no such file",
    "cannot find",
    "is not recognized",
]


def is_command_not_found_error(stderr: str) -> bool:
    """
    Check if stderr indicates a command-not-found error (cross-platform).

    Args:
        stderr: The stderr output from subprocess

    Returns:
        True if stderr indicates the command was not found
    """
    stderr_lower = stderr.lower()
    return any(pattern in stderr_lower for pattern in COMMAND_NOT_FOUND_PATTERNS)


# ============================================================================
# Integration Test Fixtures
# ============================================================================


@pytest.fixture
def docker_available() -> bool:
    """
    Check if Docker is available for testing.

    Returns:
        True if Docker is available, False otherwise
    """
    try:
        result = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ---------------------------------------------------------------------------
# Guard: the test suite must never destroy the developer's real installation.
# ---------------------------------------------------------------------------
#
# `_uninstall_tools` ends with `shutil.rmtree(Path.home() / ".jmo" / "bin")`.
# A test that exercises it without redirecting `Path.home()` deletes the real
# tool directory and still passes - measured: a sentinel file placed in
# `~/.jmo/bin` was gone after a single green test run, taking every installed
# scanner with it. Recovering costs a full `jmo tools install`, and until the
# developer notices, every scan silently under-reports because the tools that
# vanished are the ones being tested.
#
# Detection rather than prevention: redirecting `Path.home()` for the whole
# suite would break tests that legitimately read real user config. This notices
# the damage and names it, which is enough to stop it reaching a second person.


@pytest.fixture(scope="session", autouse=True)
def _guard_real_jmo_install():
    """Fail the run if a test deleted the real ~/.jmo/bin."""
    from pathlib import Path

    jmo_bin = Path.home() / ".jmo" / "bin"
    existed = jmo_bin.exists()

    yield

    if existed and not jmo_bin.exists():
        pytest.fail(
            f"A test deleted the real tool directory {jmo_bin}.\n"
            "Something called an uninstall path without redirecting "
            "Path.home(). Use:\n"
            "    monkeypatch.setattr(Path, 'home', staticmethod(lambda: tmp_path))\n"
            "and NOT monkeypatch.setenv('HOME', ...), which does not affect "
            "Path.home() on Windows.\n"
            "Recover with: jmo tools install --profile fast --yes",
            pytrace=False,
        )


# ---------------------------------------------------------------------------
# Repo walking that prunes during traversal, not after.
# ---------------------------------------------------------------------------


def iter_repo_files(
    root: Path,
    skip_dir_names: set[str],
    suffixes: set[str] | None = None,
) -> list[Path]:
    """Walk `root`, skipping `skip_dir_names` **during** descent.

    The obvious formulation is wrong in a way that hides behind a platform:

        for path in root.rglob("*"):
            if not path.is_file():          # <- stats every vendored file
                continue
            if any(p in SKIP for p in path.parts):   # <- far too late

    `rglob` descends into `node_modules` regardless of any later filter, and
    `is_file()` stats each entry it yields. Measured symptoms of that single
    bug, one per platform:

    - **Windows**: `OSError: [WinError 1920]` on the pnpm symlink farm under
      `scripts/dashboard/node_modules/.pnpm/`.
    - **Linux over /mnt/c (WSL)**: no error at all - the suite simply **times
      out** in `os.stat`, because stat-ing tens of thousands of vendored files
      across the 9p mount is glacial.

    Neither symptom points at the cause on its own, which is how it survived:
    each platform reads as its own quirk. `os.walk` with in-place `dirs`
    pruning never enters those trees.
    """
    import os

    found: list[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # In-place mutation is what prunes the walk; rebinding does nothing.
        dirnames[:] = [d for d in dirnames if d not in skip_dir_names]
        base = Path(dirpath)
        for name in filenames:
            path = base / name
            if suffixes is not None and path.suffix not in suffixes:
                continue
            found.append(path)
    return found
