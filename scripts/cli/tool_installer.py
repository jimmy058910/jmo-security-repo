"""
Tool Installer for JMo Security.

Handles cross-platform installation of security tools with progress
tracking, error handling, and retry logic.

Security: Uses centralized validation from scripts.core.validation for
version string and tool name validation to prevent URL/path injection.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from scripts.core.tool_registry import (
    Platform,
    ToolInfo,
    ToolRegistry,
    TOOL_VARIANTS,
    detect_platform,
)
from scripts.cli.tool_manager import ToolManager
from scripts.core.validation import (
    validate_version,
    validate_tool_name,
    sanitize_subprocess_output,
)

logger = logging.getLogger(__name__)


# Installation method priorities per platform
# "install_script" uses official install scripts from tool maintainers (most reliable)
# "binary" downloads pre-built binaries from GitHub releases
INSTALL_PRIORITIES: dict[Platform, list[str]] = {
    "linux": ["apt", "pip", "npm", "install_script", "binary", "brew"],
    "macos": ["brew", "pip", "npm", "install_script", "binary"],
    "windows": ["pip", "npm", "binary", "manual"],
}

# Tools that require special installation handling
# NOTE: kubescape moved to BINARY_URLS (v1.0.0) - direct binary download is more reliable
SPECIAL_INSTALL: dict[str, str] = {
    "zap": "extract_app",  # Extract tar.gz to directory
    "dependency-check": "extract_app",  # Extract zip to directory (Java CLI)
    "falco": "manual",  # Kernel module
    "afl++": "manual",  # Build from source
    "mobsf": "docker",  # Docker-only
    "akto": "docker",  # Docker-only
    "lynis": "clone",  # Git clone
}

# App archives that extract to a directory (not single binary)
# These are downloaded, extracted, and the main script is linked/used
EXTRACT_APP_URLS: dict[str, str] = {
    "zap": "https://github.com/zaproxy/zaproxy/releases/download/v{version}/ZAP_{version}_Linux.tar.gz",
    "dependency-check": "https://github.com/jeremylong/DependencyCheck/releases/download/v{version}/dependency-check-{version}-release.zip",
}

# Binary download URLs (GitHub releases)
# v1.0.0: Changed from /latest/download/ to /download/v{version}/ for reproducible installs
# v1.0.1: Fixed asset naming to match actual GitHub release filenames
#
# IMPORTANT: Asset naming varies significantly by tool:
# - trivy: Uses "Linux-64bit" / "Linux-ARM64" (unique format)
# - Most Go tools: Use "linux_amd64" / "linux_arm64" (lowercase)
# - noseyparker: Uses Rust target triple "x86_64-unknown-linux-gnu"
# - hadolint: Uses "Linux-x86_64" (capital L, underscore)
# - shellcheck: Uses "linux.x86_64" (lowercase, dots)
#
# Available placeholders:
#   {version}    - Tool version from versions.yaml
#   {os}         - "Linux", "Darwin", "Windows"
#   {os_lower}   - "linux", "darwin", "windows"
#   {arch}       - "x86_64", "arm64"
#   {arch_amd}   - "amd64", "arm64" (for Go tools)
#   {arch_aarch} - "x86_64", "aarch64" (for shellcheck)
#   {rust_arch}  - "x86_64-unknown-linux-gnu", "aarch64-unknown-linux-gnu" (for Rust tools)
#   {trivy_arch} - "64bit", "ARM64" (trivy's unique format)
BINARY_URLS: dict[str, str] = {
    # trivy: unique format "Linux-64bit" / "Linux-ARM64"
    "trivy": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os}-{trivy_arch}.tar.gz",
    # Anchore tools: lowercase "linux_amd64"
    "grype": "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_{os_lower}_{arch_amd}.tar.gz",
    "syft": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_{os_lower}_{arch_amd}.tar.gz",
    # hadolint: "Linux-x86_64" (capital L, hyphen, lowercase arch)
    "hadolint": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-{os}-{arch}",
    # shellcheck: lowercase "linux.x86_64" with dots
    "shellcheck": "https://github.com/koalaman/shellcheck/releases/download/v{version}/shellcheck-v{version}.{os_lower}.{arch_aarch}.tar.xz",
    # Go tools using lowercase "linux_amd64" format
    "trufflehog": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_{os_lower}_{arch_amd}.tar.gz",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{os_lower}_{arch_amd}.zip",
    "gosec": "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_{os_lower}_{arch_amd}.tar.gz",
    "bearer": "https://github.com/Bearer/bearer/releases/download/v{version}/bearer_{version}_{os_lower}_{arch_amd}.tar.gz",
    # horusec: lowercase "linux_amd64" (no version in filename)
    "horusec": "https://github.com/ZupIT/horusec/releases/download/v{version}/horusec_{os_lower}_{arch_amd}",
    # noseyparker: Rust target triple format with 'v' prefix
    "noseyparker": "https://github.com/praetorian-inc/noseyparker/releases/download/v{version}/noseyparker-v{version}-{rust_arch}.tar.gz",
    # kubescape: "kubescape_{version}_linux_amd64" (underscores, version in filename)
    "kubescape": "https://github.com/kubescape/kubescape/releases/download/v{version}/kubescape_{version}_{os_lower}_{arch_amd}",
}

# Official install scripts (preferred over direct binary downloads)
# These are maintained by tool authors and handle platform detection correctly
INSTALL_SCRIPTS: dict[str, str] = {
    "trivy": "https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh",
    "grype": "https://raw.githubusercontent.com/anchore/grype/main/install.sh",
    "syft": "https://raw.githubusercontent.com/anchore/syft/main/install.sh",
    "kubescape": "https://raw.githubusercontent.com/kubescape/kubescape/master/install.sh",
}


@dataclass
class InstallResult:
    """Result of a tool installation attempt."""

    tool_name: str
    success: bool
    method: str = ""
    message: str = ""
    version_installed: str | None = None
    version_expected: str | None = None
    version_mismatch: bool = False
    duration_seconds: float = 0.0


@dataclass
class InstallProgress:
    """Progress tracking for batch installations."""

    total: int = 0
    completed: int = 0
    successful: int = 0
    failed: int = 0
    skipped: int = 0
    results: list[InstallResult] = field(default_factory=list)

    @property
    def current(self) -> int:
        return self.completed

    def add_result(self, result: InstallResult) -> None:
        self.results.append(result)
        self.completed += 1
        if result.success:
            self.successful += 1
        else:
            self.failed += 1


class ToolInstaller:
    """Cross-platform tool installation manager."""

    def __init__(
        self,
        registry: ToolRegistry | None = None,
        manager: ToolManager | None = None,
        install_dir: Path | None = None,
    ):
        """
        Initialize tool installer.

        Args:
            registry: ToolRegistry instance
            manager: ToolManager instance
            install_dir: Directory for local tool installations
        """
        self._registry = registry
        self._manager = manager
        self.platform = detect_platform()
        self.install_dir = install_dir or Path.home() / ".jmo" / "bin"
        self._progress_callback: Callable[[str, int, int], None] | None = None

    @property
    def registry(self) -> ToolRegistry:
        if self._registry is None:
            self._registry = ToolRegistry()
        return self._registry

    @property
    def manager(self) -> ToolManager:
        if self._manager is None:
            self._manager = ToolManager(self.registry)
        return self._manager

    def set_progress_callback(self, callback: Callable[[str, int, int], None]) -> None:
        """Set callback for progress updates: (tool_name, current, total)."""
        self._progress_callback = callback

    def _validate_installed_version(
        self, result: InstallResult, expected_version: str
    ) -> InstallResult:
        """
        Validate installed version matches expected and log warning if not.

        Args:
            result: The InstallResult to validate
            expected_version: Expected version from versions.yaml

        Returns:
            Updated InstallResult with version validation info
        """
        result.version_expected = expected_version

        if result.success and result.version_installed:
            # Normalize versions for comparison (strip leading 'v')
            installed = result.version_installed.lstrip("v")
            expected = expected_version.lstrip("v")

            if installed != expected:
                result.version_mismatch = True
                logger.warning(
                    f"Version mismatch for {result.tool_name}: "
                    f"installed={result.version_installed}, expected={expected_version}"
                )

        return result

    def install_tool(
        self,
        tool_name: str,
        method: str | None = None,
        force: bool = False,
    ) -> InstallResult:
        """
        Install a single tool.

        Args:
            tool_name: Name of the tool to install
            method: Force specific install method (pip, brew, apt, npm, binary)
            force: Reinstall even if already installed

        Returns:
            InstallResult with success/failure details
        """
        import time

        start_time = time.time()

        # Security: Validate tool name format
        if not validate_tool_name(tool_name):
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message=f"Invalid tool name format: '{tool_name}'",
                duration_seconds=time.time() - start_time,
            )

        # Check if already installed
        if not force:
            status = self.manager.check_tool(tool_name)
            if status.installed:
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="existing",
                    message=f"Already installed (v{status.installed_version})",
                    version_installed=status.installed_version,
                )

        # Get tool info
        tool_info = self.registry.get_tool(tool_name)
        if not tool_info:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message=f"Unknown tool: {tool_name}",
            )

        # Check for tool variants (share binary with base tool)
        if tool_name in TOOL_VARIANTS:
            base_tool = TOOL_VARIANTS[tool_name]
            base_status = self.manager.check_tool(base_tool)
            if base_status.installed:
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="variant",
                    message=f"Uses {base_tool} binary (v{base_status.installed_version})",
                    version_installed=base_status.installed_version,
                    duration_seconds=time.time() - start_time,
                )
            else:
                # Base tool not installed - install it instead
                logger.info(f"{tool_name} requires {base_tool}, installing base tool")
                return self.install_tool(base_tool, method, force)

        # Check for special installation requirements
        if tool_name in SPECIAL_INSTALL:
            result = self._install_special(tool_name, tool_info, start_time)
            return self._validate_installed_version(result, tool_info.version)

        # Try installation methods in priority order
        methods = [method] if method else INSTALL_PRIORITIES.get(self.platform, [])
        attempted_methods = []
        last_error = ""

        for install_method in methods:
            logger.debug(f"Trying {install_method} for {tool_name}")
            result = self._try_install_method(
                tool_name, tool_info, install_method, start_time
            )
            if result.success:
                # Validate version after successful install
                return self._validate_installed_version(result, tool_info.version)
            elif result.message and "not available" not in result.message:
                # Method was attempted but failed
                attempted_methods.append(install_method)
                last_error = result.message
                logger.debug(
                    f"{install_method} failed for {tool_name}: {result.message}"
                )

        # All methods failed - provide helpful error message
        duration = time.time() - start_time
        if attempted_methods:
            error_msg = (
                f"Tried {', '.join(attempted_methods)}. Last error: {last_error}"
            )
        else:
            error_msg = (
                f"No installation methods available (tried: {', '.join(methods)})"
            )

        return InstallResult(
            tool_name=tool_name,
            success=False,
            message=error_msg,
            duration_seconds=duration,
        )

    def install_profile(
        self,
        profile: str,
        skip_installed: bool = True,
        parallel: bool = False,
    ) -> InstallProgress:
        """
        Install all tools for a scan profile.

        Args:
            profile: Profile name (fast, slim, balanced, deep)
            skip_installed: Skip tools that are already installed
            parallel: Install tools in parallel (not implemented yet)

        Returns:
            InstallProgress with results for all tools
        """
        from scripts.core.tool_registry import PROFILE_TOOLS

        tools = PROFILE_TOOLS.get(profile, [])
        progress = InstallProgress(total=len(tools))

        for i, tool_name in enumerate(tools):
            if self._progress_callback:
                self._progress_callback(tool_name, i + 1, len(tools))

            # Check if should skip
            if skip_installed:
                status = self.manager.check_tool(tool_name)
                if status.installed:
                    progress.skipped += 1
                    progress.completed += 1
                    progress.results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=True,
                            method="skipped",
                            message=f"Already installed (v{status.installed_version})",
                            version_installed=status.installed_version,
                        )
                    )
                    continue

            # Install
            result = self.install_tool(tool_name)
            progress.add_result(result)

        return progress

    def install_missing(self, profile: str) -> InstallProgress:
        """Install only missing tools for a profile."""
        return self.install_profile(profile, skip_installed=True)

    def _try_install_method(
        self,
        tool_name: str,
        tool_info: ToolInfo,
        method: str,
        start_time: float,
    ) -> InstallResult:
        """Try a specific installation method."""
        import time

        try:
            if method == "pip" and tool_info.pypi_package:
                return self._install_pip(tool_name, tool_info, start_time)
            elif method == "brew" and tool_info.brew_package:
                return self._install_brew(tool_name, tool_info, start_time)
            elif method == "apt" and tool_info.apt_package:
                return self._install_apt(tool_name, tool_info, start_time)
            elif method == "npm" and tool_info.npm_package:
                return self._install_npm(tool_name, tool_info, start_time)
            elif method == "install_script" and tool_name in INSTALL_SCRIPTS:
                return self._install_via_script(tool_name, tool_info, start_time)
            elif method == "binary" and tool_name in BINARY_URLS:
                return self._install_binary(tool_name, tool_info, start_time)
        except Exception as e:
            logger.debug(f"Install method {method} failed for {tool_name}: {e}")

        return InstallResult(
            tool_name=tool_name,
            success=False,
            method=method,
            message=f"Method {method} not available or failed",
            duration_seconds=time.time() - start_time,
        )

    def _install_pip(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install via pip."""
        import time

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
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                # Verify installation
                status = self.manager.check_tool(tool_name)
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="pip",
                    message=f"Installed via pip: {pinned_package}",
                    version_installed=status.installed_version,
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

    def _install_brew(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install via Homebrew."""
        import time

        if not shutil.which("brew"):
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="brew",
                message="Homebrew not installed",
            )

        package = tool_info.brew_package
        if not package:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="brew",
                message="No brew package defined",
            )

        try:
            cmd = ["brew", "install", package]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode == 0:
                status = self.manager.check_tool(tool_name)
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="brew",
                    message=f"Installed via brew: {package}",
                    version_installed=status.installed_version,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="brew",
                    message=f"brew install failed: {sanitize_subprocess_output(result.stderr, max_length=200)}",
                    duration_seconds=time.time() - start_time,
                )
        except subprocess.TimeoutExpired:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="brew",
                message="Installation timed out",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="brew",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _install_apt(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install via apt (requires sudo)."""
        import time

        if not shutil.which("apt-get"):
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="apt",
                message="apt-get not available",
            )

        package = tool_info.apt_package
        if not package:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="apt",
                message="No apt package defined",
            )

        try:
            # Check if we can use sudo
            sudo_check = subprocess.run(
                ["sudo", "-n", "true"],
                capture_output=True,
                timeout=5,
            )
            if sudo_check.returncode != 0:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="apt",
                    message="sudo access required - run: sudo apt install " + package,
                )

            cmd = ["sudo", "apt-get", "install", "-y", package]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                status = self.manager.check_tool(tool_name)
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="apt",
                    message=f"Installed via apt: {package}",
                    version_installed=status.installed_version,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="apt",
                    message=f"apt install failed: {sanitize_subprocess_output(result.stderr, max_length=200)}",
                    duration_seconds=time.time() - start_time,
                )
        except subprocess.TimeoutExpired:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="apt",
                message="Installation timed out",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="apt",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _install_npm(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install via npm."""
        import time

        npm_cmd = shutil.which("npm")
        if not npm_cmd:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="npm",
                message="npm not installed",
            )

        # Check Node.js version for packages that require newer versions
        # cdxgen requires Node.js 18+ (fails silently on older versions)
        if tool_name == "cdxgen":
            node_cmd = shutil.which("node")
            if node_cmd:
                try:
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
                        if major_ver < 18:
                            return InstallResult(
                                tool_name=tool_name,
                                success=False,
                                method="npm",
                                message=f"cdxgen requires Node.js 18+, found v{ver_str}. "
                                "Install Node.js 20 LTS: https://nodejs.org/",
                            )
                except (subprocess.TimeoutExpired, ValueError, IndexError):
                    pass  # Proceed with install, let it fail naturally if needed

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
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=300,
            )

            if result.returncode == 0:
                status = self.manager.check_tool(tool_name)
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="npm",
                    message=f"Installed via npm: {package}",
                    version_installed=status.installed_version,
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

    def _install_binary(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install by downloading binary release."""
        import time

        # Security: Validate version string before URL construction
        if not validate_version(tool_info.version, tool_name):
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="binary",
                message=f"Invalid version format: '{tool_info.version}'",
                duration_seconds=time.time() - start_time,
            )

        if tool_name not in BINARY_URLS:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="binary",
                message="No binary download URL defined",
            )

        # Ensure install directory exists
        self.install_dir.mkdir(parents=True, exist_ok=True)

        # Determine OS and arch for URL
        os_name = self._get_os_name()
        arch = self._get_arch()

        url_template = BINARY_URLS[tool_name]

        # Compute all architecture variants for URL formatting
        # Different tools use different naming conventions:
        #
        # | Placeholder   | x86_64 value                    | arm64 value                     |
        # |---------------|--------------------------------|--------------------------------|
        # | {arch}        | "x86_64"                        | "arm64"                         |
        # | {arch_amd}    | "amd64"                         | "arm64"                         |
        # | {arch_aarch}  | "x86_64"                        | "aarch64"                       |
        # | {trivy_arch}  | "64bit"                         | "ARM64"                         |
        # | {rust_arch}   | "x86_64-unknown-linux-gnu"      | "aarch64-unknown-linux-gnu"     |

        # Go-style architecture (most common): x86_64 -> amd64
        arch_amd = "amd64" if arch == "x86_64" else "arm64" if arch == "arm64" else arch

        # GNU/Linux style: arm64 -> aarch64
        arch_aarch = (
            "x86_64" if arch == "x86_64" else "aarch64" if arch == "arm64" else arch
        )

        # Trivy's unique format: x86_64 -> "64bit", arm64 -> "ARM64"
        trivy_arch = (
            "64bit" if arch == "x86_64" else "ARM64" if arch == "arm64" else arch
        )

        # Rust target triple (for noseyparker)
        if os_name.lower() == "linux":
            rust_arch = f"{arch_aarch}-unknown-linux-gnu"
        elif os_name.lower() == "darwin":
            rust_arch = f"{arch_aarch}-apple-darwin"
        else:
            rust_arch = f"{arch_aarch}-pc-windows-msvc"

        url = url_template.format(
            version=tool_info.version,
            os=os_name,
            arch=arch,
            os_lower=os_name.lower(),
            arch_lower=arch_amd,  # deprecated alias for arch_amd
            arch_amd=arch_amd,
            arch_aarch=arch_aarch,
            trivy_arch=trivy_arch,
            rust_arch=rust_arch,
        )

        # Log URL for debugging (helps users report issues with specific asset names)
        logger.debug(f"Downloading {tool_name} from: {url}")

        try:
            # Download to temp file (preserve extension for archive detection)
            with tempfile.TemporaryDirectory() as tmpdir:
                tmppath = Path(tmpdir)

                # Extract filename from URL to preserve extension (.tar.gz, .zip, etc.)
                url_filename = url.split("/")[-1].split("?")[0]  # Remove query params
                download_file = tmppath / url_filename

                # Use curl or wget
                download_cmd = self._get_download_command(url, download_file)
                if not download_cmd:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="binary",
                        message="No download tool available (curl/wget). Install curl or wget.",
                    )

                result = subprocess.run(
                    download_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if result.returncode != 0:
                    # Provide actionable error message
                    # Sanitize stderr to prevent leaking paths/credentials in logs
                    stderr_raw = (
                        result.stderr.strip() if result.stderr else "Unknown error"
                    )
                    stderr = sanitize_subprocess_output(stderr_raw, max_length=200)
                    if "404" in stderr or "Not Found" in stderr.lower():
                        error_msg = (
                            f"Asset not found at {url}. "
                            f"This may be a version mismatch - check if v{tool_info.version} exists."
                        )
                    elif "403" in stderr or "Forbidden" in stderr:
                        error_msg = f"Access denied. URL: {url}"
                    elif "curl: (22)" in stderr:
                        # curl -f returns exit 22 on HTTP errors
                        error_msg = (
                            f"HTTP error downloading {url}. "
                            f"Check that the release exists at https://github.com/"
                        )
                    else:
                        error_msg = f"Download failed: {stderr}"

                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="binary",
                        message=error_msg,
                        duration_seconds=time.time() - start_time,
                    )

                # Extract if archive (download_file already has correct extension)
                binary_path = self._extract_and_find_binary(
                    download_file, tool_name, tmppath
                )

                if not binary_path:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="binary",
                        message="Could not find binary in downloaded archive",
                        duration_seconds=time.time() - start_time,
                    )

                # Move to install directory
                dest = self.install_dir / tool_name
                shutil.copy2(binary_path, dest)
                dest.chmod(0o755)

                # Verify
                status = self.manager.check_tool(tool_name)
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="binary",
                    message=f"Installed binary to {dest}",
                    version_installed=status.installed_version,
                    duration_seconds=time.time() - start_time,
                )

        except subprocess.TimeoutExpired:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="binary",
                message="Download timed out",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="binary",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _install_via_script(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install using official install script from tool maintainers.

        These scripts are maintained by the tool authors and handle
        platform detection, version selection, and installation correctly.
        More reliable than manual binary URL construction.
        """
        import time

        if tool_name not in INSTALL_SCRIPTS:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="install_script",
                message="No install script available",
            )

        script_url = INSTALL_SCRIPTS[tool_name]
        logger.debug(f"Running official install script for {tool_name}: {script_url}")

        try:
            # Create install directory (scripts typically install to ~/.local/bin)
            self.install_dir.mkdir(parents=True, exist_ok=True)

            # Download and run the install script
            # Most official scripts support: curl ... | sh -s -- -b <install_dir>
            # We pass the install directory to ensure it goes to our managed location
            with tempfile.TemporaryDirectory() as tmpdir:
                script_path = Path(tmpdir) / "install.sh"

                # Download the script
                download_cmd = self._get_download_command(script_url, script_path)
                if not download_cmd:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="install_script",
                        message="No download tool available (curl/wget)",
                    )

                dl_result = subprocess.run(
                    download_cmd,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )

                if dl_result.returncode != 0:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="install_script",
                        message=f"Failed to download install script: {sanitize_subprocess_output(dl_result.stderr, max_length=200)}",
                        duration_seconds=time.time() - start_time,
                    )

                # Make script executable
                script_path.chmod(0o755)

                # Run the install script with version and install directory
                # Common flags used by Anchore/Aqua scripts:
                # -b <dir>: Install to directory
                # -d: Debug mode (we don't use this)
                # Version is typically passed as first argument
                install_cmd = [
                    "sh",
                    str(script_path),
                    "-b",
                    str(self.install_dir),
                    f"v{tool_info.version}",
                ]

                result = subprocess.run(
                    install_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                    env={**os.environ, "INSTALL_DIR": str(self.install_dir)},
                )

                if result.returncode != 0:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="install_script",
                        message=f"Install script failed: {sanitize_subprocess_output(result.stderr, max_length=200)}",
                        duration_seconds=time.time() - start_time,
                    )

                # Verify installation
                status = self.manager.check_tool(tool_name)
                if not status.installed:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="install_script",
                        message="Install script ran but binary not found in PATH",
                        duration_seconds=time.time() - start_time,
                    )

                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="install_script",
                    message=f"Installed via official script to {self.install_dir}",
                    version_installed=status.installed_version,
                    duration_seconds=time.time() - start_time,
                )

        except subprocess.TimeoutExpired:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="install_script",
                message="Install script timed out",
                duration_seconds=time.time() - start_time,
            )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="install_script",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _install_special(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Handle special installation cases."""
        import time

        special_type = SPECIAL_INSTALL.get(tool_name)

        if special_type == "docker":
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="docker",
                message=f"{tool_name} requires Docker. Run via: docker run ...",
                duration_seconds=time.time() - start_time,
            )
        elif special_type == "manual":
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="manual",
                message=f"{tool_name} requires manual installation. See JMo docs.",
                duration_seconds=time.time() - start_time,
            )
        elif special_type == "extract_app":
            return self._install_extract_app(tool_name, tool_info, start_time)
        elif special_type == "clone":
            return self._install_git_clone(tool_name, tool_info, start_time)

        return InstallResult(
            tool_name=tool_name,
            success=False,
            method="special",
            message=f"Unknown special install type: {special_type}",
            duration_seconds=time.time() - start_time,
        )

    def _install_git_clone(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install by cloning git repository at specific version tag."""
        import time

        if not tool_info.github_repo:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="clone",
                message="No GitHub repository defined",
            )

        clone_dir = self.install_dir / tool_name
        repo_url = f"https://github.com/{tool_info.github_repo}.git"

        # Determine tag format - some tools use 'v' prefix, some don't
        # Tools without 'v' prefix: lynis
        no_v_prefix_tools = {"lynis"}
        if tool_name in no_v_prefix_tools:
            version_tag = tool_info.version
        else:
            version_tag = f"v{tool_info.version}"

        try:
            if clone_dir.exists():
                # Check current version - if it matches, no action needed
                current_tag_result = subprocess.run(
                    [
                        "git",
                        "-C",
                        str(clone_dir),
                        "describe",
                        "--tags",
                        "--exact-match",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=30,
                )
                current_tag = (
                    current_tag_result.stdout.strip()
                    if current_tag_result.returncode == 0
                    else ""
                )

                if current_tag == version_tag:
                    # Already at correct version
                    status = self.manager.check_tool(tool_name)
                    return InstallResult(
                        tool_name=tool_name,
                        success=True,
                        method="clone",
                        message=f"Already at {version_tag}",
                        version_installed=status.installed_version,
                        duration_seconds=time.time() - start_time,
                    )

                # Different version - remove and re-clone at correct tag
                # (Shallow clones can't easily switch tags)
                logger.info(
                    f"Updating {tool_name} from {current_tag or 'unknown'} to {version_tag}"
                )
                shutil.rmtree(clone_dir)

            # Fresh clone at specific tag
            result = subprocess.run(
                [
                    "git",
                    "clone",
                    "--depth",
                    "1",
                    "--branch",
                    version_tag,
                    repo_url,
                    str(clone_dir),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )

            if result.returncode == 0:
                status = self.manager.check_tool(tool_name)
                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="clone",
                    message=f"Cloned {version_tag} to {clone_dir}",
                    version_installed=status.installed_version,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="clone",
                    message=f"Git clone failed: {sanitize_subprocess_output(result.stderr, max_length=200)}",
                    duration_seconds=time.time() - start_time,
                )
        except Exception as e:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="clone",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _install_extract_app(
        self, tool_name: str, tool_info: ToolInfo, start_time: float
    ) -> InstallResult:
        """Install app that extracts to a directory (e.g., ZAP).

        Downloads archive, extracts to ~/.jmo/{tool_name}/, and verifies.
        """
        import tarfile
        import time

        # Security: Validate version string before URL construction
        if not validate_version(tool_info.version, tool_name):
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="extract_app",
                message=f"Invalid version format: '{tool_info.version}'",
                duration_seconds=time.time() - start_time,
            )

        if tool_name not in EXTRACT_APP_URLS:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="extract_app",
                message=f"No extract app URL defined for {tool_name}",
                duration_seconds=time.time() - start_time,
            )

        url_template = EXTRACT_APP_URLS[tool_name]
        url = url_template.format(version=tool_info.version)
        app_dir = self.install_dir / tool_name

        logger.debug(f"Downloading {tool_name} from: {url}")

        try:
            with tempfile.TemporaryDirectory() as tmpdir:
                tmppath = Path(tmpdir)
                url_filename = url.split("/")[-1]
                download_file = tmppath / url_filename

                # Download
                download_cmd = self._get_download_command(url, download_file)
                if not download_cmd:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="extract_app",
                        message="No download tool available (curl/wget)",
                        duration_seconds=time.time() - start_time,
                    )

                result = subprocess.run(
                    download_cmd,
                    capture_output=True,
                    text=True,
                    timeout=600,  # Larger timeout for bigger apps
                )

                if result.returncode != 0:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="extract_app",
                        message=f"Download failed: {sanitize_subprocess_output(result.stderr, max_length=200)}",
                        duration_seconds=time.time() - start_time,
                    )

                # Remove old installation if exists
                if app_dir.exists():
                    shutil.rmtree(app_dir)

                # Extract
                extract_dir = tmppath / "extracted"
                extract_dir.mkdir()

                if str(download_file).endswith(".tar.gz"):
                    with tarfile.open(download_file, "r:gz") as tar:
                        tar.extractall(extract_dir)
                elif str(download_file).endswith(".zip"):
                    import zipfile

                    with zipfile.ZipFile(download_file, "r") as zip_ref:
                        zip_ref.extractall(extract_dir)
                else:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="extract_app",
                        message=f"Unknown archive format: {download_file}",
                        duration_seconds=time.time() - start_time,
                    )

                # Find the extracted directory (usually ZAP_X.Y.Z/)
                extracted_dirs = list(extract_dir.iterdir())
                if len(extracted_dirs) == 1 and extracted_dirs[0].is_dir():
                    # Single directory extracted - move its contents
                    src_dir = extracted_dirs[0]
                else:
                    src_dir = extract_dir

                # Move to install location
                shutil.move(str(src_dir), str(app_dir))

                # Make shell scripts and binaries executable
                # (ZIP extraction doesn't preserve Unix permissions)
                for script in app_dir.rglob("*.sh"):
                    script.chmod(0o755)
                for script in app_dir.rglob("*.py"):
                    if script.is_file():
                        script.chmod(0o755)
                # Also make bin/ directory contents executable
                bin_dir = app_dir / "bin"
                if bin_dir.exists():
                    for exe in bin_dir.iterdir():
                        if exe.is_file():
                            exe.chmod(0o755)

                # Verify installation
                status = self.manager.check_tool(tool_name)
                if status.installed:
                    return InstallResult(
                        tool_name=tool_name,
                        success=True,
                        method="extract_app",
                        message=f"Installed to {app_dir}",
                        version_installed=status.installed_version,
                        duration_seconds=time.time() - start_time,
                    )
                else:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="extract_app",
                        message="Extraction succeeded but tool not detected",
                        duration_seconds=time.time() - start_time,
                    )

        except Exception as e:
            logger.debug(f"Extract app install failed: {e}")
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="extract_app",
                message=str(e),
                duration_seconds=time.time() - start_time,
            )

    def _get_os_name(self) -> str:
        """Get OS name for binary downloads."""
        if self.platform == "macos":
            return "Darwin"
        elif self.platform == "windows":
            return "Windows"
        return "Linux"

    def _get_arch(self) -> str:
        """Get architecture for binary downloads."""
        import platform

        machine = platform.machine().lower()
        if machine in ("x86_64", "amd64"):
            return "x86_64"
        elif machine in ("aarch64", "arm64"):
            return "arm64"
        elif machine.startswith("arm"):
            return "arm"
        return machine

    def _get_download_command(self, url: str, output_path: Path) -> list[str] | None:
        """Get download command (curl or wget).

        Uses -f flag for curl to fail on HTTP errors (404, 500, etc.)
        rather than saving error pages as the output file.
        """
        if shutil.which("curl"):
            # -f: Fail silently on server errors (exit non-zero on 4xx/5xx)
            # -S: Show errors even with -s
            # -L: Follow redirects
            return ["curl", "-fsSL", "-o", str(output_path), url]
        elif shutil.which("wget"):
            # wget already fails on HTTP errors by default
            return ["wget", "-q", "-O", str(output_path), url]
        return None

    def _extract_and_find_binary(
        self, archive_path: Path, tool_name: str, extract_dir: Path
    ) -> Path | None:
        """Extract archive and find binary."""
        import tarfile
        import zipfile

        archive_str = str(archive_path)

        # Define archive extensions to skip when searching for binaries
        archive_extensions = (
            ".tar.gz",
            ".tgz",
            ".tar.xz",
            ".tar.bz2",
            ".zip",
            ".gz",
            ".xz",
        )

        try:
            # Determine archive type and extract
            if archive_str.endswith(".tar.gz") or archive_str.endswith(".tgz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    tar.extractall(extract_dir)
            elif archive_str.endswith(".tar.xz"):
                with tarfile.open(archive_path, "r:xz") as tar:
                    tar.extractall(extract_dir)
            elif archive_str.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zip_ref:
                    zip_ref.extractall(extract_dir)
            else:
                # Assume it's a standalone binary
                return archive_path

            # Find the binary - skip archive files to avoid returning the archive itself
            for candidate in extract_dir.rglob("*"):
                # Skip archive files (don't return the archive we just extracted from!)
                if any(str(candidate).endswith(ext) for ext in archive_extensions):
                    continue
                if candidate.is_file() and candidate.name == tool_name:
                    return candidate

            # Second pass: look for files containing the tool name (but not archives)
            for candidate in extract_dir.rglob("*"):
                if any(str(candidate).endswith(ext) for ext in archive_extensions):
                    continue
                if candidate.is_file() and tool_name in candidate.name:
                    return candidate

            # Fallback: find any executable (but not archives)
            for candidate in extract_dir.rglob("*"):
                if any(str(candidate).endswith(ext) for ext in archive_extensions):
                    continue
                if candidate.is_file() and os.access(candidate, os.X_OK):
                    return candidate

            return None
        except Exception as e:
            logger.debug(f"Extract failed: {e}")
            return None


def print_install_progress(
    progress: InstallProgress,
    colorize: Callable[[str, str], str] | None = None,
) -> None:
    """Print installation progress summary."""
    if colorize is None:
        colorize = lambda text, color: text  # noqa: E731

    print("\nInstallation Summary:")
    print("-" * 50)

    for result in progress.results:
        if result.success:
            if result.method == "skipped":
                icon = colorize("[SKIP]", "cyan")
            else:
                icon = colorize("[OK]", "green")
            version = (
                f" (v{result.version_installed})" if result.version_installed else ""
            )
            print(f"  {icon} {result.tool_name}{version} - {result.method}")
        else:
            icon = colorize("[FAIL]", "red")
            print(f"  {icon} {result.tool_name} - {result.message[:50]}")

    print("-" * 50)
    summary_parts = [f"Total: {progress.total}"]
    if progress.successful:
        summary_parts.append(colorize(f"Installed: {progress.successful}", "green"))
    if progress.skipped:
        summary_parts.append(colorize(f"Skipped: {progress.skipped}", "cyan"))
    if progress.failed:
        summary_parts.append(colorize(f"Failed: {progress.failed}", "red"))
    print("  " + ", ".join(summary_parts))
