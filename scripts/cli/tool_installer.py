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
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import requests
import tarfile
import zipfile

from rich.console import Console
from rich.progress import (
    Progress,
    SpinnerColumn,
    TextColumn,
    BarColumn,
    TaskProgressColumn,
    TimeElapsedColumn,
    TaskID,
)

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


def _is_safe_path(base_dir: Path, member_path: str) -> bool:
    """Check if extracted path stays within base directory.

    Prevents path traversal attacks (CWE-22, Zip Slip) by ensuring
    the resolved path doesn't escape the extraction directory.

    Args:
        base_dir: The target extraction directory
        member_path: Path from the archive member

    Returns:
        True if path is safe, False if it would escape base_dir
    """
    # Resolve the full path (handles .., symlinks, etc.)
    target_path = (base_dir / member_path).resolve()

    # Ensure it's still under base_dir
    try:
        target_path.relative_to(base_dir.resolve())
        return True
    except ValueError:
        return False


def safe_tar_extract(tar: tarfile.TarFile, extract_dir: Path) -> None:
    """Safely extract tarfile, filtering dangerous members.

    Security: Validates each member path to prevent:
    - Path traversal via ../ sequences (CWE-22)
    - Absolute paths escaping extraction directory
    - Symlink attacks

    Args:
        tar: Open tarfile object
        extract_dir: Directory to extract to

    Raises:
        ValueError: If archive contains malicious paths
    """
    for member in tar.getmembers():
        # Skip dangerous member types
        if member.islnk() or member.issym():
            # Check symlink target is safe
            if member.linkname and not _is_safe_path(extract_dir, member.linkname):
                logger.warning(
                    f"Skipping potentially unsafe symlink: {member.name} -> {member.linkname}"
                )
                continue

        # Check the member path itself
        if not _is_safe_path(extract_dir, member.name):
            raise ValueError(f"Archive contains path traversal attempt: {member.name}")

    # All members validated above, extract using filter (Python 3.12+) or manual extraction
    # Security: All member paths validated above via _is_safe_path()
    try:
        # Python 3.12+ supports data filter which is the safest option
        tar.extractall(extract_dir, filter="data")  # nosec B202 - paths validated above
    except TypeError:
        # Python < 3.12 doesn't support filter parameter
        # Extract members one by one after validation (already done above)
        for member in tar.getmembers():
            if member.islnk() or member.issym():
                if member.linkname and not _is_safe_path(extract_dir, member.linkname):
                    continue
            tar.extract(member, extract_dir)  # nosec B202 - paths validated above


def safe_zip_extract(zip_ref: zipfile.ZipFile, extract_dir: Path) -> None:
    """Safely extract zipfile, filtering dangerous members.

    Security: Validates each member path to prevent:
    - Path traversal via ../ sequences (CWE-22, Zip Slip)
    - Absolute paths escaping extraction directory

    Args:
        zip_ref: Open ZipFile object
        extract_dir: Directory to extract to

    Raises:
        ValueError: If archive contains malicious paths
    """
    for member in zip_ref.namelist():
        if not _is_safe_path(extract_dir, member):
            raise ValueError(f"Archive contains path traversal attempt: {member}")

    # All members validated, safe to extract
    # Security: All member paths validated above via _is_safe_path()
    zip_ref.extractall(extract_dir)  # nosec B202 - paths validated above


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
    "zap": "extract_app",  # Extract zip to directory (cross-platform)
    "dependency-check": "extract_app",  # Extract zip to directory (Java CLI)
    "scancode": "extract_app",  # Platform-specific pre-built releases (bypasses pip bug)
    "falco": "manual",  # Kernel module
    "afl++": "manual",  # Build from source
    "mobsf": "docker",  # Docker-only
    "akto": "docker",  # Docker-only
    "lynis": "clone",  # Git clone
}

# App archives that extract to a directory (not single binary)
# These are downloaded, extracted, and the main script is linked/used
#
# Type can be str (universal) or dict (platform-specific)
# For platform-specific URLs, use keys: "windows", "linux", "macos", "default"
#
# Available placeholders:
#   {version}    - Tool version from versions.yaml
#   {py_version} - Python version (e.g., "3.11") for tools requiring specific Python builds
EXTRACT_APP_URLS: dict[str, str | dict[str, str]] = {
    # ZAP: Use cross-platform release that works on all platforms
    # Changed from Linux-only tarball to universal Crossplatform.zip
    "zap": "https://github.com/zaproxy/zaproxy/releases/download/v{version}/ZAP_{version}_Crossplatform.zip",
    # Dependency-check: Universal zip works on all platforms (Java-based)
    "dependency-check": "https://github.com/jeremylong/DependencyCheck/releases/download/v{version}/dependency-check-{version}-release.zip",
    # ScanCode: Platform-specific pre-built releases (bypasses pip upstream bug)
    # The pip install fails due to invalid PEP 440 specifier in extractcode dependency
    # See: https://github.com/aboutcode-org/scancode-toolkit/issues/3944
    "scancode": {
        "windows": "https://github.com/nexB/scancode-toolkit/releases/download/v{version}/scancode-toolkit-v{version}_py{py_version}-windows.zip",
        "linux": "https://github.com/nexB/scancode-toolkit/releases/download/v{version}/scancode-toolkit-v{version}_py{py_version}-linux.tar.gz",
        "macos": "https://github.com/nexB/scancode-toolkit/releases/download/v{version}/scancode-toolkit-v{version}_py{py_version}-macos.tar.gz",
    },
}

# Binary download URLs (GitHub releases)
# v1.0.0: Changed from /latest/download/ to /download/v{version}/ for reproducible installs
# v1.0.1: Fixed asset naming to match actual GitHub release filenames
# v1.0.2: Added platform-specific URL support (dict format) for Windows compatibility
#
# Type can be str (universal) or dict (platform-specific)
# For platform-specific URLs, use keys: "windows", "linux", "macos", "default"
#
# IMPORTANT: Asset naming varies significantly by tool AND platform:
# - Windows typically uses .zip extension, Linux uses .tar.gz
# - Windows uses "windows" (lowercase), Linux uses "Linux" or "linux"
#
# Available placeholders:
#   {version}    - Tool version from versions.yaml
#   {os}         - "Linux", "Darwin", "Windows"
#   {os_lower}   - "linux", "darwin", "windows"
#   {arch}       - "x86_64", "arm64"
#   {arch_amd}   - "amd64", "arm64" (for Go tools)
#   {arch_aarch} - "x86_64", "aarch64" (for shellcheck)
#   {rust_arch}  - "x86_64-unknown-linux-gnu", "x86_64-pc-windows-msvc", etc.
#   {trivy_arch} - "64bit", "ARM64" (trivy's unique format)
BINARY_URLS: dict[str, str | dict[str, str]] = {
    # trivy: Windows uses lowercase "windows-64bit.zip", Linux uses "Linux-64bit.tar.gz"
    "trivy": {
        "windows": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_windows-{trivy_arch}.zip",
        "default": "https://github.com/aquasecurity/trivy/releases/download/v{version}/trivy_{version}_{os}-{trivy_arch}.tar.gz",
    },
    # Anchore grype: Windows uses .zip, Linux uses .tar.gz
    "grype": {
        "windows": "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/anchore/grype/releases/download/v{version}/grype_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    # Anchore syft: Windows uses .zip, Linux uses .tar.gz
    "syft": {
        "windows": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/anchore/syft/releases/download/v{version}/syft_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    # hadolint: "Linux-x86_64" (capital L, hyphen, lowercase arch)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    "hadolint": {
        "windows": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-Windows-x86_64.exe",
        "default": "https://github.com/hadolint/hadolint/releases/download/v{version}/hadolint-{os}-{arch}",
    },
    # shellcheck: lowercase "linux.x86_64" with dots
    "shellcheck": "https://github.com/koalaman/shellcheck/releases/download/v{version}/shellcheck-v{version}.{os_lower}.{arch_aarch}.tar.xz",
    # Go tools using lowercase "linux_amd64" format
    # trufflehog: Windows uses .zip, Linux/macOS use .tar.gz
    "trufflehog": {
        "windows": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/trufflesecurity/trufflehog/releases/download/v{version}/trufflehog_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    "nuclei": "https://github.com/projectdiscovery/nuclei/releases/download/v{version}/nuclei_{version}_{os_lower}_{arch_amd}.zip",
    "gosec": "https://github.com/securego/gosec/releases/download/v{version}/gosec_{version}_{os_lower}_{arch_amd}.tar.gz",
    # bearer: Windows uses .zip, Linux/macOS use .tar.gz
    "bearer": {
        "windows": "https://github.com/Bearer/bearer/releases/download/v{version}/bearer_{version}_windows_{arch_amd}.zip",
        "default": "https://github.com/Bearer/bearer/releases/download/v{version}/bearer_{version}_{os_lower}_{arch_amd}.tar.gz",
    },
    # horusec: lowercase "linux_amd64" (no version in filename)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    "horusec": {
        "windows": "https://github.com/ZupIT/horusec/releases/download/v{version}/horusec_windows_{arch_amd}.exe",
        "default": "https://github.com/ZupIT/horusec/releases/download/v{version}/horusec_{os_lower}_{arch_amd}",
    },
    # noseyparker: Rust target triple format with 'v' prefix
    "noseyparker": "https://github.com/praetorian-inc/noseyparker/releases/download/v{version}/noseyparker-v{version}-{rust_arch}.tar.gz",
    # kubescape: "kubescape_{version}_linux_amd64" (underscores, version in filename)
    # Windows provides .exe directly, Linux/macOS provide binary without extension
    "kubescape": {
        "windows": "https://github.com/kubescape/kubescape/releases/download/v{version}/kubescape_{version}_windows_{arch_amd}.exe",
        "default": "https://github.com/kubescape/kubescape/releases/download/v{version}/kubescape_{version}_{os_lower}_{arch_amd}",
    },
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


@dataclass
class ParallelInstallProgress:
    """Thread-safe progress tracking for parallel installations.

    Uses threading.Lock to protect shared state from race conditions
    when multiple threads update progress concurrently.

    Attributes:
        total: Total number of tools to install
        completed: Number of successfully installed tools
        failed: Number of failed installations
        skipped: Number of skipped (already installed) tools
        current_tools: List of tools currently being installed
        results: List of InstallResult objects
    """

    total: int
    completed: int = 0
    failed: int = 0
    skipped: int = 0
    current_tools: list[str] = field(default_factory=list)
    results: list[InstallResult] = field(default_factory=list)
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)
    _cancelled: threading.Event = field(default_factory=threading.Event, repr=False)

    def on_start(self, tool_name: str) -> None:
        """Called when a tool installation begins (thread-safe)."""
        with self._lock:
            self.current_tools.append(tool_name)

    def on_complete(self, tool_name: str, result: InstallResult) -> None:
        """Called when a tool installation completes (thread-safe)."""
        with self._lock:
            if tool_name in self.current_tools:
                self.current_tools.remove(tool_name)
            self.results.append(result)
            if result.success:
                if result.method == "skipped":
                    self.skipped += 1
                else:
                    self.completed += 1
            else:
                self.failed += 1

    def get_status_line(self) -> str:
        """Get current progress status for display (thread-safe)."""
        with self._lock:
            done = self.completed + self.failed + self.skipped
            running = ", ".join(self.current_tools[:3])
            if len(self.current_tools) > 3:
                running += f" +{len(self.current_tools) - 3}"
            return f"[{done}/{self.total}] Installing: {running}"

    def is_cancelled(self) -> bool:
        """Check if installation has been cancelled."""
        return self._cancelled.is_set()

    def cancel(self) -> None:
        """Signal cancellation to all worker threads."""
        self._cancelled.set()

    def to_install_progress(self) -> InstallProgress:
        """Convert to legacy InstallProgress for compatibility."""
        with self._lock:
            progress = InstallProgress(
                total=self.total,
                completed=self.completed + self.skipped,
                successful=self.completed,
                failed=self.failed,
                skipped=self.skipped,
                results=list(self.results),
            )
            return progress


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

    def install_profile_parallel(
        self,
        profile: str,
        skip_installed: bool = True,
        max_workers: int = 4,
        show_progress: bool = True,
    ) -> InstallProgress:
        """
        Install tools for a profile in parallel with Rich progress display.

        Uses a three-stage strategy for optimal performance:
        1. Batch pip installs (single subprocess for all Python packages)
        2. Batch npm installs (single subprocess for all Node packages)
        3. Parallel binary downloads (ThreadPoolExecutor)

        Args:
            profile: Profile name ('fast', 'slim', 'balanced', 'deep')
            skip_installed: Skip already-installed tools (default: True)
            max_workers: Maximum concurrent installations (default: 4, max: 8)
            show_progress: Show Rich progress bars (default: True)

        Returns:
            InstallProgress with results for all tools
        """
        from scripts.core.tool_registry import PROFILE_TOOLS

        # Cap max_workers at 8 to avoid resource exhaustion
        max_workers = min(max_workers, 8)

        tools = PROFILE_TOOLS.get(profile, [])
        if not tools:
            logger.warning(f"Unknown profile '{profile}' or no tools defined")
            return InstallProgress(total=0)

        # Pre-flight deduplication to prevent race conditions
        tools = list(dict.fromkeys(tools))

        # Categorize tools by installation method
        pip_tools: list[str] = []
        npm_tools: list[str] = []
        other_tools: list[str] = []
        skipped_results: list[InstallResult] = []

        for tool_name in tools:
            # Check if should skip
            if skip_installed:
                status = self.manager.check_tool(tool_name)
                if status.installed:
                    skipped_results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=True,
                            method="skipped",
                            message=f"Already installed (v{status.installed_version})",
                            version_installed=status.installed_version,
                        )
                    )
                    continue

            # Categorize by install method
            tool_info = self.registry.get_tool(tool_name)
            if tool_info:
                if tool_info.pypi_package:
                    pip_tools.append(tool_name)
                elif tool_info.npm_package:
                    npm_tools.append(tool_name)
                else:
                    other_tools.append(tool_name)
            else:
                other_tools.append(tool_name)

        # Create progress tracker
        total_to_install = len(pip_tools) + len(npm_tools) + len(other_tools)
        progress = ParallelInstallProgress(total=len(tools))

        # Add skipped results
        for result in skipped_results:
            progress.on_complete(result.tool_name, result)

        if total_to_install == 0:
            return progress.to_install_progress()

        # Set up signal handler for graceful Ctrl+C
        original_handler = signal.getsignal(signal.SIGINT)

        def signal_handler(signum, frame):
            logger.info("Installation cancelled by user")
            progress.cancel()
            raise KeyboardInterrupt

        try:
            signal.signal(signal.SIGINT, signal_handler)
        except ValueError:
            # Can't set signal handler in non-main thread
            pass

        try:
            if show_progress:
                self._install_with_rich_progress(
                    pip_tools, npm_tools, other_tools, progress, max_workers
                )
            else:
                self._install_without_progress(
                    pip_tools, npm_tools, other_tools, progress, max_workers
                )
        except KeyboardInterrupt:
            logger.info("Installation cancelled")
        finally:
            try:
                signal.signal(signal.SIGINT, original_handler)
            except ValueError:
                pass

        return progress.to_install_progress()

    def _install_with_rich_progress(
        self,
        pip_tools: list[str],
        npm_tools: list[str],
        other_tools: list[str],
        progress: ParallelInstallProgress,
        max_workers: int,
    ) -> None:
        """Run parallel installation with Rich progress display."""
        console = Console()

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            TimeElapsedColumn(),
            console=console,
            transient=False,
        ) as rich_progress:
            total_tools = len(pip_tools) + len(npm_tools) + len(other_tools)
            main_task = rich_progress.add_task(
                f"[cyan]Installing {total_tools} tools...", total=total_tools
            )

            # Stage 1: Batch pip installs
            if pip_tools and not progress.is_cancelled():
                pip_task = rich_progress.add_task(
                    f"[dim]pip batch ({len(pip_tools)} packages)...", total=None
                )
                pip_results = self._batch_pip_install(pip_tools, progress)
                for result in pip_results:
                    progress.on_complete(result.tool_name, result)
                    rich_progress.advance(main_task)
                    status = "[green]✓[/]" if result.success else "[red]✗[/]"
                    console.print(f"  {status} {result.tool_name} (pip)")
                rich_progress.remove_task(pip_task)

            # Stage 2: Batch npm installs
            if npm_tools and not progress.is_cancelled():
                npm_task = rich_progress.add_task(
                    f"[dim]npm batch ({len(npm_tools)} packages)...", total=None
                )
                npm_results = self._batch_npm_install(npm_tools, progress)
                for result in npm_results:
                    progress.on_complete(result.tool_name, result)
                    rich_progress.advance(main_task)
                    status = "[green]✓[/]" if result.success else "[red]✗[/]"
                    console.print(f"  {status} {result.tool_name} (npm)")
                rich_progress.remove_task(npm_task)

            # Stage 3: Parallel binary downloads
            if other_tools and not progress.is_cancelled():
                # Track active downloads
                active_tasks: dict[str, TaskID] = {}

                with ThreadPoolExecutor(max_workers=max_workers) as executor:
                    futures = {}
                    for tool_name in other_tools:
                        if progress.is_cancelled():
                            break
                        future = executor.submit(
                            self._install_tool_threadsafe, tool_name, progress
                        )
                        futures[future] = tool_name
                        # Add task for this tool
                        task_id = rich_progress.add_task(
                            f"[dim]  {tool_name}...", total=None
                        )
                        active_tasks[tool_name] = task_id

                    for future in as_completed(futures):
                        if progress.is_cancelled():
                            for f in futures:
                                f.cancel()
                            break

                        tool_name = futures[future]
                        try:
                            result = future.result(timeout=600)
                        except TimeoutError:
                            result = InstallResult(
                                tool_name=tool_name,
                                success=False,
                                message="Installation timed out after 10 minutes",
                            )
                        except Exception as e:
                            logger.error(f"Installation failed for {tool_name}: {e}")
                            result = InstallResult(
                                tool_name=tool_name,
                                success=False,
                                message=str(e),
                            )

                        progress.on_complete(tool_name, result)
                        rich_progress.advance(main_task)

                        # Remove task and print status
                        if tool_name in active_tasks:
                            rich_progress.remove_task(active_tasks[tool_name])
                        status = "[green]✓[/]" if result.success else "[red]✗[/]"
                        method = result.method or "binary"
                        console.print(f"  {status} {tool_name} ({method})")

    def _install_without_progress(
        self,
        pip_tools: list[str],
        npm_tools: list[str],
        other_tools: list[str],
        progress: ParallelInstallProgress,
        max_workers: int,
    ) -> None:
        """Run parallel installation without Rich progress (for non-TTY)."""
        # Stage 1: Batch pip installs
        if pip_tools and not progress.is_cancelled():
            logger.info(f"Installing {len(pip_tools)} pip packages in batch...")
            pip_results = self._batch_pip_install(pip_tools, progress)
            for result in pip_results:
                progress.on_complete(result.tool_name, result)

        # Stage 2: Batch npm installs
        if npm_tools and not progress.is_cancelled():
            logger.info(f"Installing {len(npm_tools)} npm packages in batch...")
            npm_results = self._batch_npm_install(npm_tools, progress)
            for result in npm_results:
                progress.on_complete(result.tool_name, result)

        # Stage 3: Parallel binary downloads
        if other_tools and not progress.is_cancelled():
            logger.info(
                f"Installing {len(other_tools)} tools in parallel "
                f"(max {max_workers} workers)..."
            )
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(self._install_tool_threadsafe, tool, progress): tool
                    for tool in other_tools
                }

                for future in as_completed(futures):
                    if progress.is_cancelled():
                        for f in futures:
                            f.cancel()
                        break

                    tool_name = futures[future]
                    try:
                        result = future.result(timeout=600)
                    except Exception as e:
                        result = InstallResult(
                            tool_name=tool_name,
                            success=False,
                            message=str(e),
                        )
                    progress.on_complete(tool_name, result)

    def _batch_pip_install(
        self,
        pip_tools: list[str],
        progress: ParallelInstallProgress,
    ) -> list[InstallResult]:
        """
        Install multiple pip packages in a single subprocess call.

        More efficient than individual pip install commands because:
        1. Single dependency resolution pass
        2. Shared network connections
        3. Reduced subprocess overhead

        Falls back to individual installs if batch fails.
        """
        results: list[InstallResult] = []
        start_time = time.time()

        # Get package specs from tool registry
        packages: list[str] = []
        tool_to_package: dict[str, str] = {}

        for tool_name in pip_tools:
            tool_info = self.registry.get_tool(tool_name)
            if tool_info and tool_info.pypi_package:
                package_spec = f"{tool_info.pypi_package}=={tool_info.version}"
                packages.append(package_spec)
                tool_to_package[tool_name] = package_spec

        if not packages:
            return results

        # Signal start for all pip tools
        for tool_name in pip_tools:
            progress.on_start(tool_name)

        # Try batch install
        cmd = [sys.executable, "-m", "pip", "install", "--quiet"] + packages

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode == 0:
                # All succeeded - verify each tool
                duration = time.time() - start_time
                for tool_name in pip_tools:
                    status = self.manager.check_tool(tool_name)
                    results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=True,
                            method="pip_batch",
                            message=f"Installed via pip batch: {tool_to_package.get(tool_name, '')}",
                            version_installed=status.installed_version,
                            duration_seconds=duration / len(pip_tools),
                        )
                    )
            else:
                # Batch failed - fall back to individual installs
                logger.warning(
                    f"Batch pip install failed, falling back to individual: "
                    f"{result.stderr[:200] if result.stderr else 'unknown error'}"
                )
                for tool_name in pip_tools:
                    if progress.is_cancelled():
                        results.append(
                            InstallResult(
                                tool_name=tool_name,
                                success=False,
                                method="pip",
                                message="Installation cancelled",
                            )
                        )
                    else:
                        individual_result = self.install_tool(tool_name)
                        results.append(individual_result)

        except subprocess.TimeoutExpired:
            logger.error("Batch pip install timed out after 10 minutes")
            # Fall back to individual installs
            for tool_name in pip_tools:
                if progress.is_cancelled():
                    results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=False,
                            method="pip",
                            message="Installation cancelled",
                        )
                    )
                else:
                    individual_result = self.install_tool(tool_name)
                    results.append(individual_result)

        except Exception as e:
            logger.error(f"Batch pip install error: {e}")
            for tool_name in pip_tools:
                results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="pip",
                        message=str(e),
                    )
                )

        return results

    def _batch_npm_install(
        self,
        npm_tools: list[str],
        progress: ParallelInstallProgress,
    ) -> list[InstallResult]:
        """
        Install multiple npm packages in a single subprocess call.

        Similar benefits to batch pip install.
        Falls back to individual installs if batch fails.
        """
        results: list[InstallResult] = []
        start_time = time.time()

        # Check if npm is available
        npm_cmd = shutil.which("npm")
        if not npm_cmd:
            for tool_name in npm_tools:
                results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="npm",
                        message="npm not installed",
                    )
                )
            return results

        # Get package names from tool registry
        packages: list[str] = []
        tool_to_package: dict[str, str] = {}

        for tool_name in npm_tools:
            tool_info = self.registry.get_tool(tool_name)
            if tool_info and tool_info.npm_package:
                packages.append(tool_info.npm_package)
                tool_to_package[tool_name] = tool_info.npm_package

        if not packages:
            return results

        # Signal start for all npm tools
        for tool_name in npm_tools:
            progress.on_start(tool_name)

        # Try batch install
        cmd = [npm_cmd, "install", "-g"] + packages

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=600,
            )

            if result.returncode == 0:
                # All succeeded - verify each tool
                duration = time.time() - start_time
                for tool_name in npm_tools:
                    status = self.manager.check_tool(tool_name)
                    results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=True,
                            method="npm_batch",
                            message=f"Installed via npm batch: {tool_to_package.get(tool_name, '')}",
                            version_installed=status.installed_version,
                            duration_seconds=duration / len(npm_tools),
                        )
                    )
            else:
                # Batch failed - fall back to individual installs
                logger.warning(
                    f"Batch npm install failed, falling back to individual: "
                    f"{result.stderr[:200] if result.stderr else 'unknown error'}"
                )
                for tool_name in npm_tools:
                    if progress.is_cancelled():
                        results.append(
                            InstallResult(
                                tool_name=tool_name,
                                success=False,
                                method="npm",
                                message="Installation cancelled",
                            )
                        )
                    else:
                        individual_result = self.install_tool(tool_name)
                        results.append(individual_result)

        except subprocess.TimeoutExpired:
            logger.error("Batch npm install timed out after 10 minutes")
            for tool_name in npm_tools:
                if progress.is_cancelled():
                    results.append(
                        InstallResult(
                            tool_name=tool_name,
                            success=False,
                            method="npm",
                            message="Installation cancelled",
                        )
                    )
                else:
                    individual_result = self.install_tool(tool_name)
                    results.append(individual_result)

        except Exception as e:
            logger.error(f"Batch npm install error: {e}")
            for tool_name in npm_tools:
                results.append(
                    InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="npm",
                        message=str(e),
                    )
                )

        return results

    def _install_tool_threadsafe(
        self,
        tool_name: str,
        progress: ParallelInstallProgress,
    ) -> InstallResult:
        """
        Thread-safe wrapper around install_tool().

        Handles progress tracking and cancellation checking.
        """
        if progress.is_cancelled():
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message="Installation cancelled",
            )

        progress.on_start(tool_name)

        try:
            result = self.install_tool(tool_name)
            return result
        except Exception as e:
            logger.error(f"Thread-safe install failed for {tool_name}: {e}")
            return InstallResult(
                tool_name=tool_name,
                success=False,
                message=str(e),
            )

    def _download_with_requests(
        self,
        url: str,
        output_path: Path,
        timeout: int = 300,
    ) -> bool:
        """
        Download a file using the requests library (cross-platform).

        Avoids Windows curl alias issues by using pure Python.

        Args:
            url: URL to download from
            output_path: Path to save the downloaded file
            timeout: Request timeout in seconds

        Returns:
            True if download succeeded, False otherwise
        """
        try:
            response = requests.get(url, stream=True, timeout=timeout)
            response.raise_for_status()

            with open(output_path, "wb") as f:
                for chunk in response.iter_content(chunk_size=8192):
                    f.write(chunk)

            return True

        except requests.exceptions.Timeout:
            logger.error(f"Download timed out after {timeout}s: {url}")
            return False
        except requests.exceptions.HTTPError as e:
            logger.error(f"HTTP error downloading {url}: {e}")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"Request error downloading {url}: {e}")
            return False
        except OSError as e:
            logger.error(f"File error saving download: {e}")
            return False

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

        url_config = BINARY_URLS[tool_name]

        # Handle platform-specific URLs (dict) vs universal URLs (str)
        if isinstance(url_config, dict):
            url_template = url_config.get(self.platform)
            if not url_template:
                url_template = url_config.get("default")
            if not url_template:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="binary",
                    message=f"No {self.platform} binary URL defined for {tool_name}",
                    duration_seconds=time.time() - start_time,
                )
        else:
            url_template = url_config

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
                # On Windows, ensure .exe extension for executable binaries
                if self.platform == "windows" and url.endswith(".exe"):
                    dest = self.install_dir / f"{tool_name}.exe"
                else:
                    dest = self.install_dir / tool_name
                shutil.copy2(binary_path, dest)
                dest.chmod(0o755)  # No-op on Windows, but harmless

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
        """Install app that extracts to a directory (e.g., ZAP, scancode).

        Downloads archive, extracts to ~/.jmo/{tool_name}/, and verifies.
        Supports platform-specific URLs for tools like scancode.
        Security: Uses safe_tar_extract/safe_zip_extract to prevent path traversal.
        """
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

        url_config = EXTRACT_APP_URLS[tool_name]

        # Handle platform-specific URLs (dict) vs universal URLs (str)
        if isinstance(url_config, dict):
            # Get URL for current platform
            url_template = url_config.get(self.platform)
            if not url_template:
                # Try "default" fallback
                url_template = url_config.get("default")
            if not url_template:
                return InstallResult(
                    tool_name=tool_name,
                    success=False,
                    method="extract_app",
                    message=f"No {self.platform} URL defined for {tool_name}",
                    duration_seconds=time.time() - start_time,
                )
        else:
            url_template = url_config

        # Get Python version for tools that need it (e.g., scancode pre-built releases)
        py_version = f"{sys.version_info.major}.{sys.version_info.minor}"

        # Format URL with version and optional py_version
        url = url_template.format(version=tool_info.version, py_version=py_version)
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
                        safe_tar_extract(tar, extract_dir)
                elif str(download_file).endswith(".zip"):
                    with zipfile.ZipFile(download_file, "r") as zip_ref:
                        safe_zip_extract(zip_ref, extract_dir)
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
        """Extract archive and find binary.

        Security: Uses safe_tar_extract/safe_zip_extract to prevent
        path traversal attacks (CWE-22, Zip Slip vulnerability).
        """
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
            # Determine archive type and extract using safe extraction
            if archive_str.endswith(".tar.gz") or archive_str.endswith(".tgz"):
                with tarfile.open(archive_path, "r:gz") as tar:
                    safe_tar_extract(tar, extract_dir)
            elif archive_str.endswith(".tar.xz"):
                with tarfile.open(archive_path, "r:xz") as tar:
                    safe_tar_extract(tar, extract_dir)
            elif archive_str.endswith(".zip"):
                with zipfile.ZipFile(archive_path, "r") as zip_ref:
                    safe_zip_extract(zip_ref, extract_dir)
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
