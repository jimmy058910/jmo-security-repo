#!/usr/bin/env python3
"""
Shared pytest fixtures and utilities for JMo Security tests.

This module provides:
- Cross-platform Python executable detection
- Common test utilities
"""

import subprocess
import sys
from typing import List

import pytest


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
