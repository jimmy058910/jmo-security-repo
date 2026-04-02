"""Base installer protocol and common types.

This module defines the Strategy pattern infrastructure for tool installation.
Each concrete installer class handles one installation method (pip, brew, npm, etc.)
and implements the BaseInstaller interface.

The pattern enables:
- Easy addition of new installation methods without modifying existing code
- Dependency injection of subprocess/download operations for testing
- Type-safe installation method selection via InstallMethod enum
"""

from __future__ import annotations

import subprocess
from abc import ABC, abstractmethod
from enum import Enum
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

if TYPE_CHECKING:
    from scripts.core.tool_registry import ToolInfo
    from scripts.cli.installers.models import InstallResult


class InstallMethod(Enum):
    """Installation method enumeration (replaces string primitives).

    Using an enum instead of strings provides:
    - Compile-time type checking
    - IDE autocomplete support
    - Centralized list of valid methods
    - Protection against typos in method names
    """

    PIP = "pip"
    BREW = "brew"
    APT = "apt"
    NPM = "npm"
    BINARY = "binary"
    SCRIPT = "script"
    GIT_CLONE = "git_clone"
    EXTRACT_APP = "extract_app"
    DOCKER = "docker"
    MANUAL = "manual"


class SubprocessRunner(Protocol):
    """Protocol for subprocess operations (enables testing).

    This protocol allows dependency injection of subprocess behavior.
    In production, DefaultSubprocessRunner calls subprocess.run().
    In tests, a mock implementation can return controlled responses.
    """

    def run(
        self,
        cmd: list[str],
        timeout: int = 120,
        capture_output: bool = True,
        text: bool = True,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Run a subprocess command.

        Args:
            cmd: Command and arguments as list (never use shell=True)
            timeout: Maximum seconds to wait for command completion
            capture_output: If True, capture stdout and stderr
            text: If True, decode output as text instead of bytes
            **kwargs: Additional arguments passed to subprocess.run

        Returns:
            CompletedProcess with returncode, stdout, stderr
        """
        ...


class DefaultSubprocessRunner:
    """Default subprocess runner using subprocess.run().

    This is the production implementation that actually executes commands.
    SECURITY: Always uses shell=False (the default) to prevent command injection.
    """

    def run(
        self,
        cmd: list[str],
        timeout: int = 120,
        capture_output: bool = True,
        text: bool = True,
        **kwargs,
    ) -> subprocess.CompletedProcess:
        """Execute command via subprocess.run with security defaults."""
        return subprocess.run(
            cmd,
            timeout=timeout,
            capture_output=capture_output,
            text=text,
            **kwargs,
        )


class Downloader(Protocol):
    """Protocol for download operations (enables testing).

    Abstracts HTTP download functionality to enable:
    - Testing without network access
    - Custom download implementations (e.g., with progress bars)
    - Retry logic and error handling in one place
    """

    def download(self, url: str, dest: Path, timeout: int = 300) -> bool:
        """Download file from URL to destination path.

        Args:
            url: URL to download from
            dest: Local path to save the downloaded file
            timeout: Maximum seconds to wait for download

        Returns:
            True if download succeeded, False otherwise
        """
        ...


class BaseInstaller(ABC):
    """Abstract base class for installation strategies.

    Implements Strategy pattern for tool installation.
    Each concrete installer handles one installation method.

    Subclasses must implement:
    - method: Property returning the InstallMethod this installer handles
    - can_install: Check if this installer can handle a given tool
    - install: Perform the actual installation

    The verify() method has a default implementation that returns (False, None)
    but can be overridden for installers that have custom verification logic.

    Example usage:
        class PipInstaller(BaseInstaller):
            @property
            def method(self) -> InstallMethod:
                return InstallMethod.PIP

            def can_install(self, tool_info: ToolInfo) -> bool:
                return bool(tool_info.pypi_package)

            def install(self, tool_name: str, tool_info: ToolInfo) -> InstallResult:
                # ... perform pip install ...
    """

    @property
    @abstractmethod
    def method(self) -> InstallMethod:
        """Return the installation method this installer handles."""
        ...

    @abstractmethod
    def can_install(self, tool_info: ToolInfo) -> bool:
        """Check if this installer can handle the given tool.

        Args:
            tool_info: Tool metadata from registry

        Returns:
            True if this installer can install the tool
        """
        ...

    @abstractmethod
    def install(self, tool_name: str, tool_info: ToolInfo) -> InstallResult:
        """Perform the installation. Returns result with success/failure.

        Args:
            tool_name: Name of the tool to install
            tool_info: Tool metadata from registry

        Returns:
            InstallResult with success status, method used, and details
        """
        ...

    def verify(self, tool_name: str) -> tuple[bool, str | None]:
        """Verify tool was installed correctly.

        Default implementation returns (False, None). Override in subclasses
        that need custom verification logic (e.g., checking specific paths
        or running version commands).

        Args:
            tool_name: Name of the tool to verify

        Returns:
            Tuple of (is_installed, version_string or None)
        """
        # Default implementation - subclasses can override
        return (False, None)
