"""
Tool Installer for JMo Security.

Handles cross-platform installation of security tools with progress
tracking, error handling, and retry logic.
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
    detect_platform,
)
from scripts.cli.tool_manager import ToolManager, ToolStatus

logger = logging.getLogger(__name__)

# Installation method priorities per platform
INSTALL_PRIORITIES: dict[Platform, list[str]] = {
    "linux": ["apt", "pip", "npm", "binary", "brew"],
    "macos": ["brew", "pip", "npm", "binary"],
    "windows": ["pip", "npm", "binary", "manual"],
}

# Tools that require special installation handling
# NOTE: kubescape moved to BINARY_URLS (v1.0.0) - direct binary download is more reliable
SPECIAL_INSTALL: dict[str, str] = {
    "zap": "manual",  # Requires manual download
    "falco": "manual",  # Kernel module
    "afl++": "manual",  # Build from source
    "mobsf": "docker",  # Docker-only
    "akto": "docker",  # Docker-only
    "lynis": "clone",  # Git clone
}

# Binary download URLs (GitHub releases)
# NOTE: {os} uses _get_os_name() output: Linux, Darwin, Windows
# Some tools need lowercase - use {os_lower} pattern and handle in _install_binary
BINARY_URLS: dict[str, str] = {
    "trivy": "https://github.com/aquasecurity/trivy/releases/latest/download/trivy_{version}_{os}_{arch}.tar.gz",
    "grype": "https://github.com/anchore/grype/releases/latest/download/grype_{version}_{os}_{arch}.tar.gz",
    "syft": "https://github.com/anchore/syft/releases/latest/download/syft_{version}_{os}_{arch}.tar.gz",
    "hadolint": "https://github.com/hadolint/hadolint/releases/latest/download/hadolint-{os}-{arch}",
    "shellcheck": "https://github.com/koalaman/shellcheck/releases/latest/download/shellcheck-{version}.{os}.{arch}.tar.xz",
    "trufflehog": "https://github.com/trufflesecurity/trufflehog/releases/latest/download/trufflehog_{version}_{os}_{arch}.tar.gz",
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_{version}_{os}_{arch}.zip",
    "gosec": "https://github.com/securego/gosec/releases/latest/download/gosec_{version}_{os}_{arch}.tar.gz",
    "bearer": "https://github.com/Bearer/bearer/releases/latest/download/bearer_{version}_{os}_{arch}.tar.gz",
    "horusec": "https://github.com/ZupIT/horusec/releases/latest/download/horusec_{os}_{arch}",
    "noseyparker": "https://github.com/praetorian-inc/noseyparker/releases/latest/download/noseyparker-{version}-{os}-{arch}.tar.gz",
    # Kubescape: v1.0.0 - Direct binary download (was using install.sh script)
    # NOTE: Uses lowercase linux/darwin and amd64/arm64
    "kubescape": "https://github.com/kubescape/kubescape/releases/download/v{version}/kubescape_{version}_{os_lower}_{arch_lower}",
}


@dataclass
class InstallResult:
    """Result of a tool installation attempt."""

    tool_name: str
    success: bool
    method: str = ""
    message: str = ""
    version_installed: str | None = None
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

    def set_progress_callback(
        self, callback: Callable[[str, int, int], None]
    ) -> None:
        """Set callback for progress updates: (tool_name, current, total)."""
        self._progress_callback = callback

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

        # Check for special installation requirements
        if tool_name in SPECIAL_INSTALL:
            return self._install_special(tool_name, tool_info, start_time)

        # Try installation methods in priority order
        methods = [method] if method else INSTALL_PRIORITIES.get(self.platform, [])

        for install_method in methods:
            result = self._try_install_method(
                tool_name, tool_info, install_method, start_time
            )
            if result.success:
                return result

        # All methods failed
        duration = time.time() - start_time
        return InstallResult(
            tool_name=tool_name,
            success=False,
            message="All installation methods failed",
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

        try:
            cmd = [sys.executable, "-m", "pip", "install", "--quiet", package]
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
                    message=f"Installed via pip: {package}",
                    version_installed=status.installed_version,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="pip",
                    message=f"pip install failed: {result.stderr[:200]}",
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
                    message=f"brew install failed: {result.stderr[:200]}",
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
                    message=f"apt install failed: {result.stderr[:200]}",
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
                    message=f"npm install failed: {result.stderr[:200]}",
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
        # Map architecture to common formats
        # x86_64 -> amd64 for lowercase variant (kubescape uses amd64)
        arch_lower = "amd64" if arch == "x86_64" else arch.lower()
        url = url_template.format(
            version=tool_info.version,
            os=os_name,
            arch=arch,
            os_lower=os_name.lower(),  # linux, darwin, windows
            arch_lower=arch_lower,  # amd64, arm64
        )

        try:
            # Download to temp file
            with tempfile.TemporaryDirectory() as tmpdir:
                tmppath = Path(tmpdir)

                # Use curl or wget
                download_cmd = self._get_download_command(url, tmppath / "download")
                if not download_cmd:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="binary",
                        message="No download tool available (curl/wget)",
                    )

                result = subprocess.run(
                    download_cmd,
                    capture_output=True,
                    text=True,
                    timeout=300,
                )

                if result.returncode != 0:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="binary",
                        message=f"Download failed: {result.stderr[:200]}",
                        duration_seconds=time.time() - start_time,
                    )

                # Extract if archive
                download_file = tmppath / "download"
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
        """Install by cloning git repository."""
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

        try:
            if clone_dir.exists():
                # Update existing
                result = subprocess.run(
                    ["git", "-C", str(clone_dir), "pull"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                )
            else:
                # Fresh clone
                result = subprocess.run(
                    ["git", "clone", "--depth", "1", repo_url, str(clone_dir)],
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
                    message=f"Cloned to {clone_dir}",
                    version_installed=status.installed_version,
                    duration_seconds=time.time() - start_time,
                )
            else:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="clone",
                    message=f"Git clone failed: {result.stderr[:200]}",
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

    def _get_download_command(
        self, url: str, output_path: Path
    ) -> list[str] | None:
        """Get download command (curl or wget)."""
        if shutil.which("curl"):
            return ["curl", "-sSL", "-o", str(output_path), url]
        elif shutil.which("wget"):
            return ["wget", "-q", "-O", str(output_path), url]
        return None

    def _extract_and_find_binary(
        self, archive_path: Path, tool_name: str, extract_dir: Path
    ) -> Path | None:
        """Extract archive and find binary."""
        import tarfile
        import zipfile

        archive_str = str(archive_path)

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

            # Find the binary
            for candidate in extract_dir.rglob("*"):
                if candidate.is_file() and candidate.name == tool_name:
                    return candidate
                if candidate.is_file() and tool_name in candidate.name:
                    return candidate

            # Fallback: find any executable
            for candidate in extract_dir.rglob("*"):
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
            version = f" (v{result.version_installed})" if result.version_installed else ""
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
