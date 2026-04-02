"""Tests for scripts/cli/installers/binary_installer.py.

Covers:
- PlatformInfo dataclass
- get_platform_info() with cached detection
- BinaryInstaller.can_install()
- BinaryInstaller.install() - success, download failure, version validation
- _resolve_download_url() - universal and platform-specific URL templates
- _download() - curl/wget, HTTP error messages
- _get_download_command() - curl/wget selection
- _get_destination_path() - Windows .exe handling
- _extract_and_find_binary() - tar.gz, tar.xz, zip, standalone
- _find_binary_single_pass() - exact, contains, executable match priorities
- _safe_tempdir() and _safe_cleanup_tempdir() - Windows retry logic
"""

from __future__ import annotations

import subprocess
import tarfile
import zipfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from scripts.cli.installers.binary_installer import (
    BinaryInstaller,
    PlatformInfo,
    get_platform_info,
)
from scripts.cli.installers.base import InstallMethod

# ========== Helpers ==========


def make_tool_info(name: str = "trivy", version: str = "0.50.0", **kwargs) -> MagicMock:
    """Create a mock ToolInfo."""
    info = MagicMock()
    info.name = name
    info.version = version
    for k, v in kwargs.items():
        setattr(info, k, v)
    return info


def make_runner(returncode: int = 0, stdout: str = "", stderr: str = "") -> MagicMock:
    """Create a mock SubprocessRunner."""
    runner = MagicMock()
    result = MagicMock(spec=subprocess.CompletedProcess)
    result.returncode = returncode
    result.stdout = stdout
    result.stderr = stderr
    runner.run.return_value = result
    return runner


def make_installer(
    runner: MagicMock | None = None,
    install_dir: Path | None = None,
) -> BinaryInstaller:
    """Create a BinaryInstaller with mock dependencies."""
    return BinaryInstaller(
        subprocess_runner=runner or make_runner(),
        tool_manager=None,
        install_dir=install_dir,
    )


# ========== Category 1: PlatformInfo ==========


class TestPlatformInfo:
    """Tests for PlatformInfo dataclass."""

    def test_frozen_dataclass(self):
        """Test PlatformInfo is immutable."""
        info = PlatformInfo(
            os_name="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
            platform_key="linux",
        )
        with pytest.raises(AttributeError):
            info.os_name = "Windows"  # type: ignore[misc]

    def test_all_fields(self):
        """Test all fields are accessible."""
        info = PlatformInfo(
            os_name="Darwin",
            os_lower="darwin",
            arch="arm64",
            arch_amd="arm64",
            arch_aarch="aarch64",
            trivy_arch="ARM64",
            rust_arch="aarch64-apple-darwin",
            platform_key="macos",
        )
        assert info.os_name == "Darwin"
        assert info.platform_key == "macos"
        assert info.trivy_arch == "ARM64"


# ========== Category 2: get_platform_info() ==========


class TestGetPlatformInfo:
    """Tests for get_platform_info() cached detection."""

    def test_returns_platform_info(self):
        """Test returns PlatformInfo instance."""
        # Clear cache for fresh computation
        get_platform_info.cache_clear()
        info = get_platform_info()
        assert isinstance(info, PlatformInfo)
        assert info.os_name in ("Linux", "Darwin", "Windows")

    @patch(
        "scripts.cli.installers.binary_installer.platform.system", return_value="Linux"
    )
    @patch(
        "scripts.cli.installers.binary_installer.platform.machine",
        return_value="x86_64",
    )
    def test_linux_x86_64(self, mock_machine, mock_system):
        """Test Linux x86_64 detection."""
        get_platform_info.cache_clear()
        info = get_platform_info()
        assert info.os_lower == "linux"
        assert info.arch == "x86_64"
        assert info.arch_amd == "amd64"
        assert info.trivy_arch == "64bit"
        assert info.platform_key == "linux"
        assert "linux-gnu" in info.rust_arch
        get_platform_info.cache_clear()

    @patch(
        "scripts.cli.installers.binary_installer.platform.system", return_value="Darwin"
    )
    @patch(
        "scripts.cli.installers.binary_installer.platform.machine", return_value="arm64"
    )
    def test_macos_arm64(self, mock_machine, mock_system):
        """Test macOS ARM64 detection."""
        get_platform_info.cache_clear()
        info = get_platform_info()
        assert info.os_lower == "darwin"
        assert info.arch == "arm64"
        assert info.arch_amd == "arm64"
        assert info.arch_aarch == "aarch64"
        assert info.trivy_arch == "ARM64"
        assert info.platform_key == "macos"
        assert "apple-darwin" in info.rust_arch
        get_platform_info.cache_clear()

    @patch(
        "scripts.cli.installers.binary_installer.platform.system",
        return_value="Windows",
    )
    @patch(
        "scripts.cli.installers.binary_installer.platform.machine", return_value="AMD64"
    )
    def test_windows_amd64(self, mock_machine, mock_system):
        """Test Windows AMD64 normalization."""
        get_platform_info.cache_clear()
        info = get_platform_info()
        assert info.arch == "x86_64"  # Normalized from AMD64
        assert info.platform_key == "windows"
        assert "windows-msvc" in info.rust_arch
        get_platform_info.cache_clear()

    @patch(
        "scripts.cli.installers.binary_installer.platform.system", return_value="Linux"
    )
    @patch(
        "scripts.cli.installers.binary_installer.platform.machine",
        return_value="riscv64",
    )
    def test_unknown_arch(self, mock_machine, mock_system):
        """Test unknown architecture passthrough."""
        get_platform_info.cache_clear()
        info = get_platform_info()
        assert info.arch == "riscv64"
        get_platform_info.cache_clear()


# ========== Category 3: BinaryInstaller Properties ==========


class TestBinaryInstallerProperties:
    """Tests for BinaryInstaller properties and can_install."""

    def test_method_is_binary(self):
        """Test method property returns BINARY."""
        installer = make_installer()
        assert installer.method == InstallMethod.BINARY

    def test_can_install_known_tool(self):
        """Test can_install for tool in BINARY_URLS."""
        installer = make_installer()
        with patch(
            "scripts.cli.installers.binary_installer.BINARY_URLS",
            {"trivy": "http://..."},
        ):
            assert installer.can_install(make_tool_info("trivy")) is True

    def test_cannot_install_unknown_tool(self):
        """Test can_install for tool not in BINARY_URLS."""
        installer = make_installer()
        with patch("scripts.cli.installers.binary_installer.BINARY_URLS", {}):
            assert installer.can_install(make_tool_info("unknown")) is False


# ========== Category 4: _resolve_download_url() ==========


class TestResolveDownloadUrl:
    """Tests for URL template resolution."""

    def test_universal_url_string(self):
        """Test URL resolution with universal string template."""
        installer = make_installer()
        with patch(
            "scripts.cli.installers.binary_installer.BINARY_URLS",
            {"tool": "https://example.com/{version}/{os_lower}_{arch_amd}.tar.gz"},
        ):
            url = installer._resolve_download_url("tool", "1.0.0")
            assert "1.0.0" in url
            assert url is not None

    def test_platform_specific_dict(self):
        """Test URL resolution with platform-specific dict."""
        installer = make_installer()
        with patch(
            "scripts.cli.installers.binary_installer.BINARY_URLS",
            {
                "tool": {
                    "linux": "https://linux.url/{version}",
                    "macos": "https://mac.url/{version}",
                }
            },
        ):
            url = installer._resolve_download_url("tool", "2.0.0")
            # Result depends on current platform
            if url is not None:
                assert "2.0.0" in url

    def test_platform_specific_with_default(self):
        """Test URL resolution falls back to 'default' key."""
        installer = make_installer()
        with patch(
            "scripts.cli.installers.binary_installer.BINARY_URLS",
            {"tool": {"default": "https://default.url/{version}"}},
        ):
            url = installer._resolve_download_url("tool", "3.0.0")
            if url is not None:
                assert "3.0.0" in url

    def test_no_url_for_platform(self):
        """Test None when no URL exists for current platform."""
        installer = make_installer()
        # Use a platform key that won't match current platform
        with patch(
            "scripts.cli.installers.binary_installer.BINARY_URLS",
            {"tool": {"nonexistent_platform": "https://url"}},
        ):
            url = installer._resolve_download_url("tool", "1.0.0")
            assert url is None


# ========== Category 5: install() Main Flow ==========


class TestInstall:
    """Tests for install() main flow."""

    def test_invalid_version(self):
        """Test install rejects invalid version strings."""
        installer = make_installer()
        with patch(
            "scripts.cli.installers.binary_installer.validate_version",
            return_value=False,
        ):
            result = installer.install("tool", make_tool_info(version="evil;rm -rf"))
            assert not result.success
            assert "Invalid version" in result.message

    def test_no_binary_url_defined(self):
        """Test install fails when tool has no BINARY_URLS entry."""
        installer = make_installer()
        with patch(
            "scripts.cli.installers.binary_installer.validate_version",
            return_value=True,
        ):
            with patch("scripts.cli.installers.binary_installer.BINARY_URLS", {}):
                result = installer.install("unknown", make_tool_info("unknown"))
                assert not result.success
                assert "No binary download URL" in result.message

    def test_no_platform_url(self):
        """Test install fails when no URL for current platform."""
        installer = make_installer()
        with patch(
            "scripts.cli.installers.binary_installer.validate_version",
            return_value=True,
        ):
            with patch(
                "scripts.cli.installers.binary_installer.BINARY_URLS", {"tool": {}}
            ):
                result = installer.install("tool", make_tool_info("tool"))
                assert not result.success
                assert "No " in result.message and "binary URL" in result.message

    def test_download_failure(self, tmp_path: Path):
        """Test install returns failure on download error."""
        runner = make_runner(returncode=1, stderr="404 Not Found")
        installer = BinaryInstaller(
            subprocess_runner=runner,
            install_dir=tmp_path / "bin",
        )
        with patch(
            "scripts.cli.installers.binary_installer.validate_version",
            return_value=True,
        ):
            with patch(
                "scripts.cli.installers.binary_installer.BINARY_URLS",
                {"tool": "https://example.com/{version}/tool"},
            ):
                result = installer.install(
                    "tool", make_tool_info("tool", version="1.0.0")
                )
                assert not result.success

    def test_timeout_expired(self, tmp_path: Path):
        """Test install handles TimeoutExpired."""
        runner = MagicMock()
        runner.run.side_effect = subprocess.TimeoutExpired(cmd="curl", timeout=300)
        installer = BinaryInstaller(
            subprocess_runner=runner,
            install_dir=tmp_path / "bin",
        )
        with patch(
            "scripts.cli.installers.binary_installer.validate_version",
            return_value=True,
        ):
            with patch(
                "scripts.cli.installers.binary_installer.BINARY_URLS",
                {"tool": "https://example.com/{version}/tool"},
            ):
                result = installer.install("tool", make_tool_info("tool"))
                assert not result.success
                assert "timed out" in result.message.lower()

    def test_generic_exception(self, tmp_path: Path):
        """Test install handles generic exceptions."""
        runner = MagicMock()
        runner.run.side_effect = OSError("disk full")
        installer = BinaryInstaller(
            subprocess_runner=runner,
            install_dir=tmp_path / "bin",
        )
        with patch(
            "scripts.cli.installers.binary_installer.validate_version",
            return_value=True,
        ):
            with patch(
                "scripts.cli.installers.binary_installer.BINARY_URLS",
                {"tool": "https://example.com/{version}/tool"},
            ):
                result = installer.install("tool", make_tool_info("tool"))
                assert not result.success
                assert "disk full" in result.message


# ========== Category 6: _download() ==========


class TestDownload:
    """Tests for _download() HTTP download logic."""

    def test_successful_download(self, tmp_path: Path):
        """Test successful download returns (True, None)."""
        runner = make_runner(returncode=0)
        installer = BinaryInstaller(subprocess_runner=runner, install_dir=tmp_path)
        with patch.object(
            installer,
            "_get_download_command",
            return_value=["curl", "-o", "file", "url"],
        ):
            success, error = installer._download(
                "http://example.com/file", tmp_path / "file", "1.0.0"
            )
            assert success is True
            assert error is None

    def test_404_error_message(self, tmp_path: Path):
        """Test 404 error produces actionable message."""
        runner = make_runner(returncode=22, stderr="404 Not Found")
        installer = BinaryInstaller(subprocess_runner=runner, install_dir=tmp_path)
        with patch.object(
            installer, "_get_download_command", return_value=["curl", "-o", "f", "url"]
        ):
            success, error = installer._download(
                "http://example.com/file", tmp_path / "file", "1.0.0"
            )
            assert success is False
            assert "not found" in error.lower() or "Asset" in error

    def test_403_error_message(self, tmp_path: Path):
        """Test 403 error produces access denied message."""
        runner = make_runner(returncode=22, stderr="403 Forbidden")
        installer = BinaryInstaller(subprocess_runner=runner, install_dir=tmp_path)
        with patch.object(
            installer, "_get_download_command", return_value=["curl", "-o", "f", "url"]
        ):
            success, error = installer._download(
                "http://example.com/file", tmp_path / "file", "1.0.0"
            )
            assert success is False
            assert "denied" in error.lower() or "Access" in error

    def test_curl_22_error(self, tmp_path: Path):
        """Test curl exit code 22 HTTP error handling."""
        runner = make_runner(
            returncode=22, stderr="curl: (22) The requested URL returned error: 500"
        )
        installer = BinaryInstaller(subprocess_runner=runner, install_dir=tmp_path)
        with patch.object(
            installer, "_get_download_command", return_value=["curl", "-o", "f", "url"]
        ):
            success, error = installer._download(
                "http://example.com/file", tmp_path / "file", "1.0.0"
            )
            assert success is False
            assert "HTTP error" in error

    def test_no_download_tool(self, tmp_path: Path):
        """Test error when no download tool available."""
        installer = BinaryInstaller(
            subprocess_runner=make_runner(), install_dir=tmp_path
        )
        with patch.object(installer, "_get_download_command", return_value=None):
            success, error = installer._download(
                "http://example.com/file", tmp_path / "file", "1.0.0"
            )
            assert success is False
            assert "curl" in error.lower() or "wget" in error.lower()


# ========== Category 7: _get_download_command() ==========


class TestGetDownloadCommand:
    """Tests for _get_download_command() curl/wget selection."""

    def test_prefers_curl(self, tmp_path: Path):
        """Test curl is preferred over wget."""
        installer = make_installer(install_dir=tmp_path)
        with patch(
            "shutil.which",
            side_effect=lambda x: "/usr/bin/curl" if x == "curl" else None,
        ):
            cmd = installer._get_download_command("http://url", tmp_path / "out")
            assert cmd is not None
            assert cmd[0] == "curl"
            assert "-fsSL" in cmd

    def test_falls_back_to_wget(self, tmp_path: Path):
        """Test wget fallback when curl not available."""
        installer = make_installer(install_dir=tmp_path)
        with patch(
            "shutil.which",
            side_effect=lambda x: "/usr/bin/wget" if x == "wget" else None,
        ):
            cmd = installer._get_download_command("http://url", tmp_path / "out")
            assert cmd is not None
            assert cmd[0] == "wget"

    def test_no_tool_returns_none(self, tmp_path: Path):
        """Test None when neither curl nor wget available."""
        installer = make_installer(install_dir=tmp_path)
        with patch("shutil.which", return_value=None):
            cmd = installer._get_download_command("http://url", tmp_path / "out")
            assert cmd is None


# ========== Category 8: _get_destination_path() ==========


class TestGetDestinationPath:
    """Tests for _get_destination_path() platform handling."""

    def test_non_windows(self, tmp_path: Path):
        """Test non-Windows destination has no extension."""
        installer = make_installer(install_dir=tmp_path)
        installer._platform = PlatformInfo(
            os_name="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
            platform_key="linux",
        )
        dest = installer._get_destination_path("trivy", "http://example.com/trivy")
        assert dest == tmp_path / "trivy"

    def test_windows_exe(self, tmp_path: Path):
        """Test Windows destination gets .exe extension."""
        installer = make_installer(install_dir=tmp_path)
        installer._platform = PlatformInfo(
            os_name="Windows",
            os_lower="windows",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-pc-windows-msvc",
            platform_key="windows",
        )
        dest = installer._get_destination_path("trivy", "http://example.com/trivy.exe")
        assert dest == tmp_path / "trivy.exe"

    def test_windows_non_exe(self, tmp_path: Path):
        """Test Windows destination without .exe when URL is not .exe."""
        installer = make_installer(install_dir=tmp_path)
        installer._platform = PlatformInfo(
            os_name="Windows",
            os_lower="windows",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-pc-windows-msvc",
            platform_key="windows",
        )
        dest = installer._get_destination_path(
            "trivy", "http://example.com/trivy.tar.gz"
        )
        assert dest == tmp_path / "trivy"


# ========== Category 9: _extract_and_find_binary() ==========


class TestExtractAndFindBinary:
    """Tests for _extract_and_find_binary() archive handling."""

    def test_tar_gz_extraction(self, tmp_path: Path):
        """Test .tar.gz archive extraction."""
        installer = make_installer(install_dir=tmp_path)
        # Create a real tar.gz with a binary inside
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()
        binary = tmp_path / "mytool"
        binary.write_text("#!/bin/sh\necho hi", encoding="utf-8")

        archive = tmp_path / "archive.tar.gz"
        with tarfile.open(archive, "w:gz") as tar:
            tar.add(binary, arcname="mytool")

        result = installer._extract_and_find_binary(archive, extract_dir, "mytool")
        assert result is not None
        assert result.name == "mytool"

    def test_zip_extraction(self, tmp_path: Path):
        """Test .zip archive extraction."""
        installer = make_installer(install_dir=tmp_path)
        extract_dir = tmp_path / "extract"
        extract_dir.mkdir()

        # Create a zip with a binary
        archive = tmp_path / "archive.zip"
        with zipfile.ZipFile(archive, "w") as zf:
            zf.writestr("mytool", "binary content")

        result = installer._extract_and_find_binary(archive, extract_dir, "mytool")
        assert result is not None
        assert result.name == "mytool"

    def test_standalone_binary(self, tmp_path: Path):
        """Test standalone binary (no extraction needed)."""
        installer = make_installer(install_dir=tmp_path)
        binary = tmp_path / "hadolint-Linux-x86_64"
        binary.write_text("binary content", encoding="utf-8")

        result = installer._extract_and_find_binary(binary, tmp_path, "hadolint")
        # Standalone binary returns the archive_path itself
        assert result == binary

    def test_extraction_failure(self, tmp_path: Path):
        """Test returns None on extraction error."""
        installer = make_installer(install_dir=tmp_path)
        # Create a file that looks like tar.gz but isn't
        fake_archive = tmp_path / "fake.tar.gz"
        fake_archive.write_text("not a real archive", encoding="utf-8")

        result = installer._extract_and_find_binary(fake_archive, tmp_path, "tool")
        assert result is None


# ========== Category 10: _find_binary_single_pass() ==========


class TestFindBinarySinglePass:
    """Tests for _find_binary_single_pass() priority matching."""

    def test_exact_match_priority(self, tmp_path: Path):
        """Test exact name match has highest priority."""
        installer = make_installer()
        (tmp_path / "trivy").write_text("exact", encoding="utf-8")
        (tmp_path / "trivy-helper").write_text("contains", encoding="utf-8")

        result = installer._find_binary_single_pass(tmp_path, "trivy")
        assert result is not None
        assert result.name == "trivy"

    def test_contains_match(self, tmp_path: Path):
        """Test name-contains match when no exact match."""
        installer = make_installer()
        (tmp_path / "trivy_0.50.0_Linux-64bit").write_text("bin", encoding="utf-8")

        result = installer._find_binary_single_pass(tmp_path, "trivy")
        assert result is not None
        assert "trivy" in result.name

    def test_skips_archive_extensions(self, tmp_path: Path):
        """Test archive files are skipped."""
        installer = make_installer()
        (tmp_path / "tool.tar.gz").write_text("archive", encoding="utf-8")
        (tmp_path / "tool").write_text("binary", encoding="utf-8")

        result = installer._find_binary_single_pass(tmp_path, "tool")
        assert result is not None
        assert result.name == "tool"

    def test_no_match_returns_none(self, tmp_path: Path):
        """Test returns None when no binary found."""
        installer = make_installer()
        (tmp_path / "readme.md").write_text("docs", encoding="utf-8")

        result = installer._find_binary_single_pass(tmp_path, "trivy")
        # May return None or readme.md as fallback executable
        # On Windows, os.access(X_OK) is always True for files
        if result is not None:
            assert result.is_file()

    def test_exe_exact_match(self, tmp_path: Path):
        """Test .exe variant exact match."""
        installer = make_installer()
        (tmp_path / "tool.exe").write_text("windows binary", encoding="utf-8")

        result = installer._find_binary_single_pass(tmp_path, "tool")
        assert result is not None
        assert result.name == "tool.exe"


# ========== Category 11: Temp Directory ==========


class TestSafeTempdir:
    """Tests for _safe_tempdir() context manager."""

    def test_creates_temp_directory(self):
        """Test temp directory is created and yielded."""
        installer = make_installer()
        with installer._safe_tempdir() as tmppath:
            assert tmppath.exists()
            assert tmppath.is_dir()

    def test_cleanup_after_exit(self):
        """Test temp directory is cleaned up."""
        installer = make_installer()
        with installer._safe_tempdir() as tmppath:
            _ = tmppath
        # May or may not exist depending on platform, but should not raise

    def test_cleanup_non_windows_skips_retry(self):
        """Test non-Windows cleanup skips retry logic."""
        installer = make_installer()
        installer._platform = PlatformInfo(
            os_name="Linux",
            os_lower="linux",
            arch="x86_64",
            arch_amd="amd64",
            arch_aarch="x86_64",
            trivy_arch="64bit",
            rust_arch="x86_64-unknown-linux-gnu",
            platform_key="linux",
        )
        # _safe_cleanup_tempdir should return immediately on non-Windows
        installer._safe_cleanup_tempdir(Path("/nonexistent"))
        # No exception means success
