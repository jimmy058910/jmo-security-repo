#!/usr/bin/env python3
"""
Shared pytest fixtures and utilities for JMo Security tests.

This module provides:
- Cross-platform Python executable detection
- Platform-specific skip conditions
- Subprocess mocking helpers
- Common test utilities
"""

import subprocess
import sys
from pathlib import Path
from typing import List
from unittest.mock import MagicMock

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


def run_jmo_command(args: List[str], **kwargs) -> subprocess.CompletedProcess:
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

    def _run(args: List[str], **kwargs) -> subprocess.CompletedProcess:
        defaults = {"capture_output": True, "text": True}
        defaults.update(kwargs)
        return run_jmo_command(args, **defaults)

    return _run


# ============================================================================
# Subprocess Mocking Helpers
# ============================================================================


def mock_subprocess_success(returncode: int = 0, stdout: str = "", stderr: str = ""):
    """
    Create a MagicMock configured as a successful subprocess.run result.

    Usage:
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = mock_subprocess_success()
            # ... test code ...

    Args:
        returncode: Exit code (0 = success)
        stdout: Standard output
        stderr: Standard error

    Returns:
        MagicMock configured as CompletedProcess
    """
    mock = MagicMock()
    mock.returncode = returncode
    mock.stdout = stdout
    mock.stderr = stderr
    return mock


def mock_subprocess_failure(
    returncode: int = 1, stdout: str = "", stderr: str = "Error"
):
    """Create a MagicMock configured as a failed subprocess.run result."""
    return mock_subprocess_success(returncode=returncode, stdout=stdout, stderr=stderr)


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
# Path Normalization Utilities
# ============================================================================


def normalize_path(path: str | Path) -> str:
    """
    Normalize a path for cross-platform comparison.

    Converts backslashes to forward slashes and normalizes case on Windows.

    Args:
        path: Path string or Path object

    Returns:
        Normalized path string
    """
    normalized = str(path).replace("\\", "/")
    if IS_WINDOWS:
        normalized = normalized.lower()
    return normalized
