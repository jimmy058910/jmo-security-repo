"""Binary download installation strategy.

This module provides BinaryInstaller for tools distributed as pre-compiled
binaries from GitHub releases. Handles platform detection, URL template
resolution, archive extraction, and binary discovery.

Key features:
- Cached platform/architecture detection via PlatformInfo dataclass
- URL template resolution with multiple arch naming conventions
- Safe archive extraction (prevents path traversal attacks)
- Optimized single-pass binary search
- Windows-safe temp directory cleanup with retry logic
"""

from __future__ import annotations

import functools
import logging
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import time
import zipfile
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Iterator

from scripts.cli.installers.base import (
    BaseInstaller,
    DefaultSubprocessRunner,
    InstallMethod,
    SubprocessRunner,
)
from scripts.cli.installers.models import InstallResult
from scripts.core.archive_security import safe_tar_extract, safe_zip_extract
from scripts.core.install_config import (
    BINARY_URLS,
    DOWNLOAD_TIMEOUT_SECONDS,
    CLEANUP_RETRY_BACKOFF_FACTOR,
    MAX_CLEANUP_RETRIES,
)
from scripts.core.validation import validate_version, sanitize_subprocess_output

if TYPE_CHECKING:
    from scripts.core.tool_registry import ToolInfo
    from scripts.cli.tool_manager import ToolManager

logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class PlatformInfo:
    """Cached platform/architecture information.

    Pre-computes all architecture naming variants used by different tools:
    - Go tools: amd64, arm64
    - GNU/Linux tools: x86_64, aarch64
    - Trivy: 64bit, ARM64
    - Rust tools: x86_64-unknown-linux-gnu, etc.

    Using frozen=True makes this hashable and ensures values don't change
    after computation.
    """

    os_name: str  # "Linux", "Darwin", "Windows"
    os_lower: str  # "linux", "darwin", "windows"
    arch: str  # "x86_64", "arm64", "aarch64"
    arch_amd: str  # "amd64", "arm64" (Go style)
    arch_aarch: str  # "x86_64", "aarch64" (GNU style)
    trivy_arch: str  # "64bit", "ARM64" (Trivy's unique format)
    rust_arch: str  # "x86_64-unknown-linux-gnu", etc.
    platform_key: str  # "linux", "macos", "windows" (for URL config lookup)


@functools.lru_cache(maxsize=1)
def get_platform_info() -> PlatformInfo:
    """Compute platform/arch info once, cache for session.

    Uses functools.lru_cache to avoid repeated system calls for platform
    detection. Since platform doesn't change during a session, we can
    compute this once and reuse.

    Returns:
        PlatformInfo with all architecture variants pre-computed
    """
    os_name = platform.system()  # "Linux", "Darwin", "Windows"
    os_lower = os_name.lower()
    arch = platform.machine()  # "x86_64", "AMD64", "arm64", "aarch64"

    # Normalize architecture names for consistent comparison
    # Windows reports "AMD64", Linux/Mac report "x86_64"
    if arch in ("x86_64", "AMD64"):
        normalized_arch = "x86_64"
    elif arch in ("arm64", "aarch64"):
        normalized_arch = "arm64"
    else:
        normalized_arch = arch

    # Go-style architecture (most common): x86_64 -> amd64
    arch_amd = "amd64" if normalized_arch == "x86_64" else "arm64"

    # GNU/Linux style: arm64 -> aarch64
    arch_aarch = "x86_64" if normalized_arch == "x86_64" else "aarch64"

    # Trivy's unique format: x86_64 -> "64bit", arm64 -> "ARM64"
    trivy_arch = "64bit" if normalized_arch == "x86_64" else "ARM64"

    # Rust target triple (for noseyparker and similar)
    if os_lower == "linux":
        rust_arch = f"{arch_aarch}-unknown-linux-gnu"
    elif os_lower == "darwin":
        rust_arch = f"{arch_aarch}-apple-darwin"
    else:
        rust_arch = f"{arch_aarch}-pc-windows-msvc"

    # Platform key for URL config lookup
    if os_lower == "darwin":
        platform_key = "macos"
    else:
        platform_key = os_lower  # "linux" or "windows"

    return PlatformInfo(
        os_name=os_name,
        os_lower=os_lower,
        arch=normalized_arch,
        arch_amd=arch_amd,
        arch_aarch=arch_aarch,
        trivy_arch=trivy_arch,
        rust_arch=rust_arch,
        platform_key=platform_key,
    )


class BinaryInstaller(BaseInstaller):
    """Installer for binary downloads from GitHub releases.

    Handles pre-compiled binary tools that are distributed as:
    - Direct binaries (e.g., hadolint-Linux-x86_64)
    - Archives containing binaries (e.g., trivy_0.50.0_Linux-64bit.tar.gz)

    Features:
    - Platform-specific URL resolution with multiple arch naming conventions
    - Safe archive extraction preventing path traversal attacks
    - Single-pass binary discovery (optimized from triple rglob)
    - Windows-safe temp directory cleanup with retry on file locking
    """

    # Archive extensions to skip when searching for binaries
    ARCHIVE_EXTENSIONS = (
        ".tar.gz",
        ".tgz",
        ".tar.xz",
        ".tar.bz2",
        ".zip",
        ".gz",
        ".xz",
    )

    def __init__(
        self,
        subprocess_runner: SubprocessRunner | None = None,
        tool_manager: ToolManager | None = None,
        install_dir: Path | None = None,
    ):
        """Initialize BinaryInstaller.

        Args:
            subprocess_runner: Custom subprocess runner (for testing)
            tool_manager: ToolManager for verification (optional)
            install_dir: Directory for binary installation (defaults to ~/.local/bin)
        """
        self._runner = subprocess_runner or DefaultSubprocessRunner()
        self._manager = tool_manager
        self._install_dir = install_dir or Path.home() / ".local" / "bin"
        self._platform = get_platform_info()

    @property
    def method(self) -> InstallMethod:
        """Return BINARY as the installation method."""
        return InstallMethod.BINARY

    def can_install(self, tool_info: ToolInfo) -> bool:
        """Check if tool has binary download URL defined.

        Args:
            tool_info: Tool metadata from registry

        Returns:
            True if tool has entry in BINARY_URLS config
        """
        return tool_info.name in BINARY_URLS

    def install(self, tool_name: str, tool_info: ToolInfo) -> InstallResult:
        """Download and install binary.

        Extracted from ToolInstaller._install_binary() (lines 1768-1969).

        Args:
            tool_name: Name of the tool to install
            tool_info: Tool metadata from registry

        Returns:
            InstallResult with success status and details
        """
        start_time = time.time()

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
        self._install_dir.mkdir(parents=True, exist_ok=True)

        # Get URL template and resolve platform-specific URL
        url = self._resolve_download_url(tool_name, tool_info.version)
        if url is None:
            return InstallResult(
                tool_name=tool_name,
                success=False,
                method="binary",
                message=f"No {self._platform.platform_key} binary URL defined for {tool_name}",
                duration_seconds=time.time() - start_time,
            )

        logger.debug(f"Downloading {tool_name} from: {url}")

        try:
            with self._safe_tempdir() as tmppath:
                # Extract filename from URL to preserve extension
                url_filename = url.split("/")[-1].split("?")[0]  # Remove query params
                download_file = tmppath / url_filename

                # Download the file
                success, error_msg = self._download(url, download_file, tool_info.version)
                if not success:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="binary",
                        message=error_msg or "Download failed",
                        duration_seconds=time.time() - start_time,
                    )

                # Extract if archive and find the binary
                binary_path = self._extract_and_find_binary(
                    download_file, tmppath, tool_name
                )

                if not binary_path:
                    return InstallResult(
                        tool_name=tool_name,
                        success=False,
                        method="binary",
                        message="Could not find binary in downloaded archive",
                        duration_seconds=time.time() - start_time,
                    )

                # Move to install directory with proper naming
                dest = self._get_destination_path(tool_name, url)
                shutil.copy2(binary_path, dest)
                dest.chmod(0o755)  # No-op on Windows, but harmless

                # Verify installation
                version_installed = None
                if self._manager:
                    status = self._manager.check_tool(tool_name)
                    version_installed = status.installed_version

                return InstallResult(
                    tool_name=tool_name,
                    success=True,
                    method="binary",
                    message=f"Installed binary to {dest}",
                    version_installed=version_installed,
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

    def _resolve_download_url(self, tool_name: str, version: str) -> str | None:
        """Resolve platform-specific download URL from template.

        Handles both universal URLs (str) and platform-specific URLs (dict).
        Substitutes placeholders like {version}, {os}, {arch}, etc.

        Args:
            tool_name: Name of the tool
            version: Version string from versions.yaml

        Returns:
            Resolved URL or None if no URL for current platform
        """
        url_config = BINARY_URLS[tool_name]

        # Handle platform-specific URLs (dict) vs universal URLs (str)
        if isinstance(url_config, dict):
            url_template = url_config.get(self._platform.platform_key)
            if not url_template:
                url_template = url_config.get("default")
            if not url_template:
                return None
        else:
            url_template = url_config

        # Resolve all placeholders
        return url_template.format(
            version=version,
            os=self._platform.os_name,
            os_lower=self._platform.os_lower,
            arch=self._platform.arch,
            arch_lower=self._platform.arch_amd,  # deprecated alias
            arch_amd=self._platform.arch_amd,
            arch_aarch=self._platform.arch_aarch,
            trivy_arch=self._platform.trivy_arch,
            rust_arch=self._platform.rust_arch,
        )

    def _download(
        self, url: str, dest: Path, version: str, timeout: int = DOWNLOAD_TIMEOUT_SECONDS
    ) -> tuple[bool, str | None]:
        """Download file from URL using curl or wget.

        Uses -f flag for curl to fail on HTTP errors (404, 500, etc.)
        rather than saving error pages as the output file.

        Args:
            url: URL to download from
            dest: Local path to save the downloaded file
            version: Version string (for error messages)
            timeout: Maximum seconds to wait for download

        Returns:
            Tuple of (success, error_message or None)
        """
        download_cmd = self._get_download_command(url, dest)
        if not download_cmd:
            return False, "No download tool available (curl/wget). Install curl or wget."

        result = self._runner.run(
            download_cmd,
            timeout=timeout,
            capture_output=True,
            text=True,
        )

        if result.returncode != 0:
            # Provide actionable error message
            stderr_raw = result.stderr.strip() if result.stderr else "Unknown error"
            stderr = sanitize_subprocess_output(stderr_raw, max_length=200)

            if "404" in stderr or "Not Found" in stderr.lower():
                error_msg = (
                    f"Asset not found at {url}. "
                    f"This may be a version mismatch - check if v{version} exists."
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

            return False, error_msg

        return True, None

    def _get_download_command(self, url: str, output_path: Path) -> list[str] | None:
        """Get download command (curl or wget).

        Uses -f flag for curl to fail on HTTP errors (404, 500, etc.)
        rather than saving error pages as the output file.

        Args:
            url: URL to download from
            output_path: Path to save downloaded file

        Returns:
            Command as list of strings, or None if no download tool available
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

    def _get_destination_path(self, tool_name: str, url: str) -> Path:
        """Determine destination path with proper extension.

        On Windows, ensures .exe extension for executables.

        Args:
            tool_name: Name of the tool
            url: Download URL (used to check if source is .exe)

        Returns:
            Full path for installed binary
        """
        if self._platform.platform_key == "windows" and url.endswith(".exe"):
            return self._install_dir / f"{tool_name}.exe"
        return self._install_dir / tool_name

    def _extract_and_find_binary(
        self, archive_path: Path, extract_dir: Path, tool_name: str
    ) -> Path | None:
        """Extract archive and find binary.

        Security: Uses safe_tar_extract/safe_zip_extract to prevent
        path traversal attacks (CWE-22, Zip Slip vulnerability).

        Args:
            archive_path: Path to downloaded archive
            extract_dir: Directory to extract to
            tool_name: Name of the tool to find

        Returns:
            Path to found binary, or None if not found
        """
        archive_str = str(archive_path)

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

            # Find binary using optimized single-pass search
            return self._find_binary_single_pass(extract_dir, tool_name)

        except Exception as e:
            logger.debug(f"Extract failed: {e}")
            return None

    def _find_binary_single_pass(
        self, extract_dir: Path, tool_name: str
    ) -> Path | None:
        """Find binary in extracted directory with single pass.

        Optimized from original triple rglob to single directory traversal.
        Uses priority scoring to select best match:
        1. Exact name match (highest priority)
        2. Name contains tool name
        3. Any executable file (fallback)

        Args:
            extract_dir: Directory containing extracted files
            tool_name: Name of the tool to find

        Returns:
            Path to best matching binary, or None if not found
        """
        exact_match: Path | None = None
        contains_match: Path | None = None
        executable_match: Path | None = None

        # Single traversal with priority categorization
        for candidate in extract_dir.rglob("*"):
            # Skip directories and archives
            if not candidate.is_file():
                continue
            if any(str(candidate).endswith(ext) for ext in self.ARCHIVE_EXTENSIONS):
                continue

            # Check for exact name match (highest priority)
            if candidate.name == tool_name or candidate.name == f"{tool_name}.exe":
                exact_match = candidate
                break  # Best possible match, exit early

            # Check for name containing tool name
            if tool_name in candidate.name and contains_match is None:
                contains_match = candidate

            # Check for any executable (lowest priority fallback)
            if executable_match is None and os.access(candidate, os.X_OK):
                executable_match = candidate

        # Return best match by priority
        return exact_match or contains_match or executable_match

    @contextmanager
    def _safe_tempdir(self) -> Iterator[Path]:
        """Context manager for temp directories with Windows-safe cleanup.

        On Windows, temp directory cleanup can fail with WinError 32 when
        antivirus or file indexer holds locks on recently-accessed files.
        This wrapper catches cleanup exceptions and retries with backoff.

        Yields:
            Path to the temporary directory
        """
        tmpdir = tempfile.mkdtemp()
        tmppath = Path(tmpdir)
        try:
            yield tmppath
        finally:
            # Use safe cleanup with retry on Windows
            self._safe_cleanup_tempdir(tmppath)
            # Final cleanup attempt (ignore errors on Windows)
            if tmppath.exists():
                shutil.rmtree(tmppath, ignore_errors=True)

    def _safe_cleanup_tempdir(self, tmpdir: Path) -> None:
        """Safely clean up temp directory with retry for Windows file locking.

        On Windows, antivirus/indexer can hold file locks momentarily.
        This method retries cleanup with exponential backoff to handle
        transient WinError 32 (file in use) errors.

        Args:
            tmpdir: Path to temporary directory to clean up
        """
        if self._platform.platform_key != "windows":
            # On non-Windows, let normal cleanup handle it
            return

        for attempt in range(MAX_CLEANUP_RETRIES):
            try:
                if tmpdir.exists():
                    shutil.rmtree(tmpdir, ignore_errors=True)
                break
            except OSError as e:
                # WinError 32: The process cannot access the file
                if attempt < MAX_CLEANUP_RETRIES - 1:
                    time.sleep(CLEANUP_RETRY_BACKOFF_FACTOR * (attempt + 1))
                    logger.debug(f"Retry {attempt + 1}/{MAX_CLEANUP_RETRIES} cleaning temp dir due to: {e}")
                else:
                    # Final attempt failed, log but don't raise
                    logger.debug(f"Could not fully clean temp dir: {e}")
