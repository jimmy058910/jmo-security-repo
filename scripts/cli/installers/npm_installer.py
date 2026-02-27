"""Npm-based installation strategy.

This module provides NpmInstaller for tools distributed as npm packages.
Uses global npm installation (-g flag) which makes tools available system-wide.

Key features:
- Node.js version validation for packages requiring newer versions (e.g., cdxgen needs 18+)
- Batch installation for efficiency with single-install fallback
- Integration with ToolManager for post-install verification
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import time
from typing import TYPE_CHECKING

from scripts.cli.installers.base import (
    BaseInstaller,
    DefaultSubprocessRunner,
    InstallMethod,
    SubprocessRunner,
)
from scripts.cli.installers.models import InstallResult
from scripts.core.install_config import NPM_INSTALL_TIMEOUT_SECONDS
from scripts.core.validation import sanitize_subprocess_output

if TYPE_CHECKING:
    from scripts.core.tool_registry import ToolInfo
    from scripts.cli.tool_manager import ToolManager
    from scripts.cli.ui.progress import ParallelInstallProgress

logger = logging.getLogger(__name__)


class NpmInstaller(BaseInstaller):
    """Installer for npm packages (global installation).

    Handles tools distributed as npm packages that are installed globally
    via `npm install -g <package>`. Examples include:
    - cdxgen (SBOM generator)
    - snyk (vulnerability scanner)
    - retire (JS dependency checker)

    Features:
    - Node.js version validation for packages with minimum requirements
    - Batch installation for multiple packages in single command
    - Automatic fallback to individual installs on batch failure
    """

    def __init__(
        self,
        subprocess_runner: SubprocessRunner | None = None,
        tool_manager: ToolManager | None = None,
    ):
        """Initialize NpmInstaller.

        Args:
            subprocess_runner: Custom subprocess runner (for testing)
            tool_manager: ToolManager for verification (optional)
        """
        self._runner = subprocess_runner or DefaultSubprocessRunner()
        self._manager = tool_manager

    @property
    def method(self) -> InstallMethod:
        """Return NPM as the installation method."""
        return InstallMethod.NPM

    def can_install(self, tool_info: ToolInfo) -> bool:
        """Check if tool has npm_package defined.

        Args:
            tool_info: Tool metadata from registry

        Returns:
            True if tool can be installed via npm
        """
        return bool(tool_info.npm_package)

    def install(self, tool_name: str, tool_info: ToolInfo) -> InstallResult:
        """Install tool via npm.

        Extracted from ToolInstaller._install_npm() (lines 1673-1766).

        Args:
            tool_name: Name of the tool to install
            tool_info: Tool metadata from registry

        Returns:
            InstallResult with success status and details
        """
        start_time = time.time()

        # Check npm availability
        npm_cmd = shutil.which("npm")
        if not npm_cmd:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="npm",
                message="npm not installed",
            )

        # Node.js version check for packages with minimum requirements
        # cdxgen requires Node.js 18+ (fails silently on older versions)
        version_check = self._check_node_version(tool_name)
        if version_check is not None:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="npm",
                message=version_check,
            )

        package = tool_info.npm_package
        if not package:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="npm",
                message="No npm package defined",
            )

        try:
            cmd = [npm_cmd, "install", "-g", package]
            result = self._runner.run(
                cmd,
                timeout=NPM_INSTALL_TIMEOUT_SECONDS,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                version_installed = None
                if self._manager:
                    status = self._manager.check_tool(tool_name)
                    version_installed = status.installed_version

                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="npm",
                    message=f"Installed via npm: {package}",
                    version_installed=version_installed,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="npm",
                    message=f"npm install failed: {sanitize_subprocess_output(result.stderr, max_length=200)}",
                    duration_seconds=time.time() - start_time,
                )
        except subprocess.TimeoutExpired:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="npm",
                message="Installation timed out",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="npm",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def batch_install(
        self,
        tools: list[tuple[str, ToolInfo]],
        progress: ParallelInstallProgress | None = None,
    ) -> list[InstallResult]:
        """Batch install npm packages in single command.

        More efficient than individual npm install commands because:
        1. Single npm resolution pass
        2. Shared network connections
        3. Reduced subprocess overhead

        Falls back to individual installs if batch fails.

        Args:
            tools: List of (tool_name, tool_info) tuples to install
            progress: Optional progress tracker for status updates

        Returns:
            List of InstallResult for each tool
        """
        results: list[InstallResult] = []
        start_time = time.time()

        # Check npm availability first
        npm_cmd = shutil.which("npm")
        if not npm_cmd:
            for tool_name, _ in tools:
                results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="npm",
                        message="npm not installed",
                    )
                )
            return results

        # Build package list, filtering tools with Node.js version issues
        packages: list[str] = []
        tool_to_package: dict[str, str] = {}
        npm_tools: list[str] = []
        skipped_results: list[InstallResult] = []

        for tool_name, tool_info in tools:
            # Check Node.js version requirements
            version_issue = self._check_node_version(tool_name)
            if version_issue is not None:
                skipped_results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="npm",
                        message=version_issue,
                    )
                )
                continue

            if tool_info and tool_info.npm_package:
                package = tool_info.npm_package
                packages.append(package)
                tool_to_package[tool_name] = package
                npm_tools.append(tool_name)

        # Add skipped results to output
        results.extend(skipped_results)

        if not packages:
            return results

        # Signal start for all npm tools
        if progress:
            for tool_name in npm_tools:
                progress.on_start(tool_name)

        # Try batch install
        cmd = [npm_cmd, "install", "-g"] + packages

        try:
            result = self._runner.run(
                cmd,
                timeout=NPM_INSTALL_TIMEOUT_SECONDS,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                # All succeeded - verify each tool
                duration = time.time() - start_time
                for tool_name in npm_tools:
                    version_installed = None
                    if self._manager:
                        status = self._manager.check_tool(tool_name)
                        version_installed = status.installed_version

                    results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=True,
                            method="npm_batch",
                            message=f"Installed via npm batch: {tool_to_package.get(tool_name, '')}",
                            version_installed=version_installed,
                            duration_seconds=duration / len(npm_tools),
                        )
                    )
            else:
                # Batch failed - fall back to individual installs
                logger.warning(
                    f"Batch npm install failed, falling back to individual: "
                    f"{result.stderr[:200] if result.stderr else 'unknown error'}"
                )
                results.extend(self._fallback_individual_install(tools, progress))

        except subprocess.TimeoutExpired:
            logger.error("Batch npm install timed out")
            results.extend(self._fallback_individual_install(tools, progress))

        except Exception as e:
            logger.error(f"Batch npm install error: {e}")
            for tool_name, _ in tools:
                if tool_name in npm_tools:
                    results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=False,
                            method="npm",
                            message=str(e),
                        )
                    )

        return results

    def _check_node_version(self, tool_name: str) -> str | None:
        """Check if Node.js version meets tool requirements.

        Some npm packages require specific Node.js versions to function correctly.
        For example, cdxgen requires Node.js 18+ (silently fails on older versions).

        Args:
            tool_name: Name of the tool to check

        Returns:
            Error message if version requirement not met, None if OK
        """
        # Define Node.js version requirements per tool
        node_requirements = {
            "cdxgen": 18,  # cdxgen requires Node.js 18+
        }

        min_version = node_requirements.get(tool_name)
        if min_version is None:
            return None

        node_cmd = shutil.which("node")
        if not node_cmd:
            # Let the install proceed and fail naturally
            return None

        try:
            # Bypass our SubprocessRunner for version check (quick operation)
            ver_result = subprocess.run(
                [node_cmd, "--version"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if ver_result.returncode == 0:
                # Parse version: v20.10.0 -> 20
                ver_str = ver_result.stdout.strip().lstrip("v")
                major_ver = int(ver_str.split(".")[0])
                if major_ver < min_version:
                    return (
                        f"{tool_name} requires Node.js {min_version}+, found v{ver_str}. "
                        f"Install Node.js 20 LTS: https://nodejs.org/"
                    )
        except (subprocess.TimeoutExpired, ValueError, IndexError):
            pass  # Proceed with install, let it fail naturally if needed

        return None

    def _fallback_individual_install(
        self,
        tools: list[tuple[str, ToolInfo]],
        progress: ParallelInstallProgress | None,
    ) -> list[InstallResult]:
        """Fall back to installing tools individually when batch fails.

        Args:
            tools: List of (tool_name, tool_info) tuples
            progress: Optional progress tracker

        Returns:
            List of InstallResult for each tool
        """
        results: list[InstallResult] = []

        for tool_name, tool_info in tools:
            if progress and progress.is_cancelled():
                results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="npm",
                        message="Installation cancelled",
                    )
                )
            else:
                individual_result = self.install(tool_name, tool_info)
                results.append(individual_result)

        return results
