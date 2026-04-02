"""Pip-based installation strategies.

This module provides two concrete installer implementations:
- PipInstaller: For standard pip packages installed globally
- IsolatedPipInstaller: For packages with dependency conflicts that need isolated venvs

The isolation strategy is critical for tools like semgrep/prowler that have
conflicting pydantic version requirements (v2 vs v1).
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

from scripts.cli.installers.base import (
    BaseInstaller,
    DefaultSubprocessRunner,
    InstallMethod,
    SubprocessRunner,
)
from scripts.cli.installers.models import InstallResult
from scripts.core.install_config import (
    ISOLATED_TOOLS,
    PIP_INSTALL_TIMEOUT_SECONDS,
)
from scripts.core.paths import get_isolated_venv_path, get_isolated_tool_path
from scripts.core.validation import validate_version, sanitize_subprocess_output

if TYPE_CHECKING:
    from scripts.core.tool_registry import ToolInfo, ToolRegistry
    from scripts.cli.tool_manager import ToolManager
    from scripts.cli.ui.progress import ParallelInstallProgress

logger = logging.getLogger(__name__)


class PipInstaller(BaseInstaller):
    """Installer for pip packages (global installation).

    Handles standard pip package installation for tools that don't have
    dependency conflicts. Tools with conflicts are handled by IsolatedPipInstaller.

    Features:
    - Version pinning for reproducible installs
    - Version validation to prevent injection attacks
    - Post-install verification via ToolManager
    - Batch installation support for efficiency
    """

    def __init__(
        self,
        subprocess_runner: SubprocessRunner | None = None,
        tool_manager: ToolManager | None = None,
        registry: ToolRegistry | None = None,
    ):
        """Initialize PipInstaller.

        Args:
            subprocess_runner: Custom subprocess runner (for testing)
            tool_manager: ToolManager for verification (optional)
            registry: ToolRegistry for batch installs (optional)
        """
        self._runner = subprocess_runner or DefaultSubprocessRunner()
        self._manager = tool_manager
        self._registry = registry

    @property
    def method(self) -> InstallMethod:
        """Return PIP as the installation method."""
        return InstallMethod.PIP

    def can_install(self, tool_info: ToolInfo) -> bool:
        """Check if tool has pypi_package and is not isolated.

        Args:
            tool_info: Tool metadata from registry

        Returns:
            True if tool can be installed via standard pip
        """
        if not tool_info.pypi_package:
            return False
        # Isolated tools use IsolatedPipInstaller
        return tool_info.name not in ISOLATED_TOOLS

    def install(self, tool_name: str, tool_info: ToolInfo) -> InstallResult:
        """Install tool via pip.

        Extracted from ToolInstaller._install_pip() (lines 1453-1523).

        Args:
            tool_name: Name of the tool to install
            tool_info: Tool metadata from registry

        Returns:
            InstallResult with success status and details
        """
        start_time = time.time()

        package = tool_info.pypi_package
        if not package:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="pip",
                message="No PyPI package defined",
            )

        # Security: Validate version string before command construction
        if not validate_version(tool_info.version, tool_name):
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="pip",
                message=f"Invalid version format: '{tool_info.version}'",
                duration_seconds=time.time() - start_time,
            )

        try:
            # Pin to specific version from versions.yaml for reproducibility
            pinned_package = f"{package}=={tool_info.version}"
            cmd = [sys.executable, "-m", "pip", "install", "--quiet", pinned_package]
            result = self._runner.run(
                cmd,
                timeout=PIP_INSTALL_TIMEOUT_SECONDS,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                # Verify installation
                version_installed = None
                if self._manager:
                    status = self._manager.check_tool(tool_name)
                    version_installed = status.installed_version

                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="pip",
                    message=f"Installed via pip: {pinned_package}",
                    version_installed=version_installed,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="pip",
                    message=f"pip install failed: {sanitize_subprocess_output(result.stderr, max_length=200)}",
                    duration_seconds=time.time() - start_time,
                )
        except subprocess.TimeoutExpired:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="pip",
                message="Installation timed out",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="pip",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def batch_install(
        self,
        tools: list[tuple[str, ToolInfo]],
        progress: ParallelInstallProgress | None = None,
        fallback_installer: BaseInstaller | None = None,
    ) -> list[InstallResult]:
        """Batch install multiple pip packages in single command.

        Extracted from ToolInstaller._batch_pip_install() (lines 1110-1224).

        More efficient than individual pip install commands because:
        1. Single dependency resolution pass
        2. Shared network connections
        3. Reduced subprocess overhead

        Falls back to individual installs if batch fails.

        Args:
            tools: List of (tool_name, tool_info) tuples to install
            progress: Optional progress tracker for status updates
            fallback_installer: Installer to use for individual fallback installs

        Returns:
            List of InstallResult for each tool
        """
        results: list[InstallResult] = []
        start_time = time.time()

        # Build package list
        packages: list[str] = []
        tool_to_package: dict[str, str] = {}
        pip_tools: list[str] = []

        for tool_name, tool_info in tools:
            if tool_info and tool_info.pypi_package:
                package_spec = f"{tool_info.pypi_package}=={tool_info.version}"
                packages.append(package_spec)
                tool_to_package[tool_name] = package_spec
                pip_tools.append(tool_name)

        if not packages:
            return results

        # Signal start for all pip tools
        if progress:
            for tool_name in pip_tools:
                progress.on_start(tool_name)

        # Try batch install
        cmd = [sys.executable, "-m", "pip", "install", "--quiet"] + packages

        try:
            result = self._runner.run(
                cmd,
                timeout=PIP_INSTALL_TIMEOUT_SECONDS,
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                # All succeeded - verify each tool
                duration = time.time() - start_time
                for tool_name in pip_tools:
                    version_installed = None
                    if self._manager:
                        status = self._manager.check_tool(tool_name)
                        version_installed = status.installed_version

                    results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=True,
                            method="pip_batch",
                            message=f"Installed via pip batch: {tool_to_package.get(tool_name, '')}",
                            version_installed=version_installed,
                            duration_seconds=duration / len(pip_tools),
                        )
                    )
            else:
                # Batch failed - fall back to individual installs
                logger.warning(
                    f"Batch pip install failed, falling back to individual: "
                    f"{result.stderr[:200] if result.stderr else 'unknown error'}"
                )
                results = self._fallback_individual_install(
                    tools, progress, fallback_installer
                )

        except subprocess.TimeoutExpired:
            logger.error("Batch pip install timed out after 10 minutes")
            results = self._fallback_individual_install(
                tools, progress, fallback_installer
            )

        except Exception as e:
            logger.error(f"Batch pip install error: {e}")
            for tool_name, _ in tools:
                results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="pip",
                        message=str(e),
                    )
                )

        return results

    def _fallback_individual_install(
        self,
        tools: list[tuple[str, ToolInfo]],
        progress: ParallelInstallProgress | None,
        fallback_installer: BaseInstaller | None,
    ) -> list[InstallResult]:
        """Fall back to installing tools individually when batch fails.

        Args:
            tools: List of (tool_name, tool_info) tuples
            progress: Optional progress tracker
            fallback_installer: Installer to use (defaults to self)

        Returns:
            List of InstallResult for each tool
        """
        results: list[InstallResult] = []
        installer = fallback_installer or self

        for tool_name, tool_info in tools:
            if progress and progress.is_cancelled():
                results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="pip",
                        message="Installation cancelled",
                    )
                )
            else:
                individual_result = installer.install(tool_name, tool_info)
                results.append(individual_result)

        return results


class IsolatedPipInstaller(BaseInstaller):
    """Installer for pip packages in isolated venvs.

    Used for tools with dependency conflicts that cannot coexist in the same
    Python environment:
    - prowler (needs pydantic<2)
    - semgrep (needs pydantic>=2)
    - checkov (needs pydantic>=2)

    Each tool gets its own venv at ~/.jmo/tools/venvs/<tool_name>/ to prevent
    conflicts. The tool executable is found via get_isolated_tool_path().
    """

    def __init__(
        self,
        subprocess_runner: SubprocessRunner | None = None,
        tool_manager: ToolManager | None = None,
    ):
        """Initialize IsolatedPipInstaller.

        Args:
            subprocess_runner: Custom subprocess runner (for testing)
            tool_manager: ToolManager for verification (optional)
        """
        self._runner = subprocess_runner or DefaultSubprocessRunner()
        self._manager = tool_manager

    @property
    def method(self) -> InstallMethod:
        """Return PIP as the installation method (isolated variant)."""
        return InstallMethod.PIP

    def can_install(self, tool_info: ToolInfo) -> bool:
        """Check if tool requires isolated venv.

        Args:
            tool_info: Tool metadata from registry

        Returns:
            True if tool is in ISOLATED_TOOLS config
        """
        return tool_info.name in ISOLATED_TOOLS

    def install(self, tool_name: str, tool_info: ToolInfo) -> InstallResult:
        """Install tool in isolated venv.

        Extracted from ToolInstaller._isolated_pip_install() (lines 947-1108).

        Creates venv at ~/.jmo/tools/venvs/<tool_name>/ and installs the
        package there with its own dependencies, isolated from other tools.

        Args:
            tool_name: Name of the tool to install
            tool_info: Tool metadata from registry

        Returns:
            InstallResult with success status and details
        """
        # Get package spec from ISOLATED_TOOLS config or tool_info
        isolated_config = ISOLATED_TOOLS.get(tool_name, {})
        package_name = isolated_config.get("package", tool_info.pypi_package)

        if not package_name:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="isolated_venv",
                message="No package defined for isolated install",
            )

        # Build versioned package spec
        package_spec = f"{package_name}=={tool_info.version}"

        return self._install_in_venv(tool_name, package_spec)

    def _install_in_venv(
        self,
        tool_name: str,
        package_spec: str,
    ) -> InstallResult:
        """Install a tool in an isolated virtual environment.

        Used for tools with known dependency conflicts (e.g., prowler/checkov
        pydantic conflict) that cannot be installed in the same environment.

        The isolated venv is created at ~/.jmo/tools/venvs/<tool_name>/

        Args:
            tool_name: Name of the tool
            package_spec: Pip package specification (e.g., "prowler==5.16.0")

        Returns:
            InstallResult with success status and details
        """
        venv_dir = get_isolated_venv_path(tool_name)
        start_time = time.time()

        try:
            # Step 1: Create venv if it doesn't exist
            if not venv_dir.exists():
                logger.info(f"Creating isolated venv for {tool_name} at {venv_dir}")
                venv_dir.parent.mkdir(parents=True, exist_ok=True)

                # Use --copies on Windows to create actual copies instead of symlinks
                # This ensures the venv's Python is truly isolated
                venv_cmd = [sys.executable, "-m", "venv", str(venv_dir)]
                if sys.platform == "win32":
                    venv_cmd.append("--copies")

                result = self._runner.run(
                    venv_cmd,
                    timeout=120,
                    capture_output=True,
                    text=True,
                )
                if result.returncode != 0:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="isolated_venv",
                        message=f"Failed to create venv: {result.stderr[:200]}",
                        duration_seconds=time.time() - start_time,
                    )

            # Step 2: Get Python and pip paths in venv (platform-specific)
            if sys.platform == "win32":
                bin_dir = venv_dir / "Scripts"
                python_path = bin_dir / "python.exe"
                pip_path = bin_dir / "pip.exe"
            else:
                bin_dir = venv_dir / "bin"
                python_path = bin_dir / "python"
                pip_path = bin_dir / "pip"

            if not pip_path.exists():
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="isolated_venv",
                    message=f"pip not found in venv at {pip_path}",
                    duration_seconds=time.time() - start_time,
                )

            # Step 3: Upgrade pip in venv (helps with dependency resolution)
            # Use explicit Python to ensure we're using venv's Python
            self._runner.run(
                [str(python_path), "-m", "pip", "install", "--upgrade", "pip"],
                timeout=120,
                capture_output=True,
            )

            # Step 4: Install the package using venv's Python explicitly
            logger.info(f"Installing {package_spec} in isolated venv")
            result = self._runner.run(
                [str(python_path), "-m", "pip", "install", "--quiet", package_spec],
                timeout=PIP_INSTALL_TIMEOUT_SECONDS,
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="isolated_venv",
                    message=f"pip install failed: {result.stderr[:200]}",
                    duration_seconds=time.time() - start_time,
                )

            # Step 5: Verify installation by checking if executable exists
            # get_isolated_tool_path already handles alternate names
            tool_path = get_isolated_tool_path(tool_name)
            if tool_path and tool_path.exists():
                # Try to get version using console script with clean environment
                # Clean PATH ensures the script uses venv's Python
                version = self._get_tool_version(tool_path, bin_dir)

                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="isolated_venv",
                    message=f"Installed in isolated venv at {venv_dir}",
                    version_installed=version,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="isolated_venv",
                    message=f"Package installed but {tool_name} executable not found",
                    duration_seconds=time.time() - start_time,
                )

        except subprocess.TimeoutExpired:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="isolated_venv",
                message="Installation timed out (10 minutes)",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="isolated_venv",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _get_tool_version(self, tool_path: Path, bin_dir: Path) -> str | None:
        """Try to get tool version from --version output.

        Creates clean environment with venv's bin dir first in PATH to ensure
        the script uses venv's Python.

        Args:
            tool_path: Path to tool executable
            bin_dir: Path to venv bin directory

        Returns:
            Version string if found, None otherwise
        """
        try:
            # Create clean env with venv's bin dir first in PATH
            clean_env = os.environ.copy()
            clean_env["PATH"] = str(bin_dir) + os.pathsep + clean_env.get("PATH", "")
            clean_env.pop("PYTHONPATH", None)
            clean_env.pop("PYTHONHOME", None)

            version_result = self._runner.run(
                [str(tool_path), "--version"],
                timeout=30,
                capture_output=True,
                text=True,
                env=clean_env,
            )
            if version_result.returncode == 0:
                output = version_result.stdout + version_result.stderr
                match = re.search(r"(\d+\.\d+\.\d+)", output)
                if match:
                    return match.group(1)
        except Exception:
            pass  # Version detection is best-effort

        return None
