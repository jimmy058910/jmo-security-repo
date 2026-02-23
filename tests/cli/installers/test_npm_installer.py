"""Tests for scripts/cli/installers/npm_installer.py.

Covers:
- NpmInstaller: can_install, method, install, batch_install
- _check_node_version(): Version requirement validation
- _fallback_individual_install(): Cancellation and individual fallback
- Error handling: npm missing, timeout, generic exceptions
"""

from __future__ import annotations

import subprocess
from unittest.mock import MagicMock, patch


from scripts.cli.installers.npm_installer import NpmInstaller
from scripts.cli.installers.base import InstallMethod
from scripts.cli.installers.models import InstallResult


# ========== Helpers ==========


def make_tool_info(
    name: str = "cdxgen",
    version: str = "10.0.0",
    npm_package: str | None = "@cyclonedx/cdxgen",
    **kwargs,
) -> MagicMock:
    """Create a mock ToolInfo."""
    info = MagicMock()
    info.name = name
    info.version = version
    info.npm_package = npm_package
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


# ========== Category 1: Properties ==========


class TestNpmInstallerProperties:
    """Tests for NpmInstaller basic properties."""

    def test_method_is_npm(self):
        """Test method property returns NPM."""
        installer = NpmInstaller()
        assert installer.method == InstallMethod.NPM

    def test_can_install_with_npm_package(self):
        """Test can_install when tool has npm_package."""
        installer = NpmInstaller()
        assert installer.can_install(make_tool_info(npm_package="@pkg/tool")) is True

    def test_cannot_install_without_npm_package(self):
        """Test can_install when tool has no npm_package."""
        installer = NpmInstaller()
        assert installer.can_install(make_tool_info(npm_package=None)) is False

    def test_cannot_install_empty_npm_package(self):
        """Test can_install when npm_package is empty string."""
        installer = NpmInstaller()
        assert installer.can_install(make_tool_info(npm_package="")) is False


# ========== Category 2: install() ==========


class TestNpmInstallerInstall:
    """Tests for NpmInstaller.install()."""

    def test_successful_install(self):
        """Test successful npm install."""
        runner = make_runner(returncode=0)
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                result = installer.install("cdxgen", make_tool_info())
                assert result.success is True
                assert result.method == "npm"
                assert "cdxgen" in result.message or "@cyclonedx" in result.message

    def test_npm_not_installed(self):
        """Test install fails when npm is not available."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        with patch("shutil.which", return_value=None):
            result = installer.install("cdxgen", make_tool_info())
            assert result.success is False
            assert "npm not installed" in result.message

    def test_node_version_check_failure(self):
        """Test install fails when Node.js version too old."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(
                installer,
                "_check_node_version",
                return_value="cdxgen requires Node.js 18+",
            ):
                result = installer.install("cdxgen", make_tool_info())
                assert result.success is False
                assert "Node.js 18" in result.message

    def test_no_npm_package_defined(self):
        """Test install fails when no npm package defined."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                result = installer.install("tool", make_tool_info(npm_package=None))
                assert result.success is False
                assert "No npm package" in result.message

    def test_npm_install_failure(self):
        """Test install handles npm failure."""
        runner = make_runner(returncode=1, stderr="ERR! 404 not found")
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                result = installer.install("cdxgen", make_tool_info())
                assert result.success is False
                assert "npm install failed" in result.message

    def test_timeout(self):
        """Test install handles timeout."""
        runner = MagicMock()
        runner.run.side_effect = subprocess.TimeoutExpired(cmd="npm", timeout=300)
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                result = installer.install("cdxgen", make_tool_info())
                assert result.success is False
                assert "timed out" in result.message.lower()

    def test_generic_exception(self):
        """Test install handles generic exceptions."""
        runner = MagicMock()
        runner.run.side_effect = OSError("network error")
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                result = installer.install("cdxgen", make_tool_info())
                assert result.success is False
                assert "network error" in result.message

    def test_verification_with_tool_manager(self):
        """Test post-install verification via ToolManager."""
        runner = make_runner(returncode=0)
        manager = MagicMock()
        status = MagicMock()
        status.installed_version = "10.0.0"
        manager.check_tool.return_value = status
        installer = NpmInstaller(subprocess_runner=runner, tool_manager=manager)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                result = installer.install("cdxgen", make_tool_info())
                assert result.version_installed == "10.0.0"

    def test_duration_tracked(self):
        """Test duration is tracked."""
        runner = make_runner(returncode=0)
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                result = installer.install("cdxgen", make_tool_info())
                assert result.duration_seconds >= 0


# ========== Category 3: _check_node_version() ==========


class TestCheckNodeVersion:
    """Tests for _check_node_version() Node.js validation."""

    def test_no_requirement(self):
        """Test tools without Node.js requirement return None."""
        installer = NpmInstaller()
        assert installer._check_node_version("retire") is None

    def test_cdxgen_requires_18(self):
        """Test cdxgen requirement for Node.js 18+."""
        installer = NpmInstaller()
        with patch("shutil.which", return_value="/usr/bin/node"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0, stdout="v16.14.0\n", stderr=""
                )
                result = installer._check_node_version("cdxgen")
                assert result is not None
                assert "18+" in result

    def test_node_version_sufficient(self):
        """Test no error when Node.js version is sufficient."""
        installer = NpmInstaller()
        with patch("shutil.which", return_value="/usr/bin/node"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0, stdout="v20.10.0\n", stderr=""
                )
                result = installer._check_node_version("cdxgen")
                assert result is None

    def test_node_not_found(self):
        """Test proceeds when node command not found."""
        installer = NpmInstaller()
        with patch("shutil.which", return_value=None):
            result = installer._check_node_version("cdxgen")
            assert result is None  # Let install proceed naturally

    def test_version_command_failure(self):
        """Test proceeds on version command failure."""
        installer = NpmInstaller()
        with patch("shutil.which", return_value="/usr/bin/node"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=1, stdout="", stderr="error"
                )
                result = installer._check_node_version("cdxgen")
                assert result is None

    def test_version_parse_error(self):
        """Test proceeds on version parse error."""
        installer = NpmInstaller()
        with patch("shutil.which", return_value="/usr/bin/node"):
            with patch("subprocess.run") as mock_run:
                mock_run.return_value = MagicMock(
                    returncode=0, stdout="not-a-version\n", stderr=""
                )
                result = installer._check_node_version("cdxgen")
                assert result is None

    def test_timeout_during_version_check(self):
        """Test proceeds on timeout."""
        installer = NpmInstaller()
        with patch("shutil.which", return_value="/usr/bin/node"):
            with patch(
                "subprocess.run", side_effect=subprocess.TimeoutExpired("node", 10)
            ):
                result = installer._check_node_version("cdxgen")
                assert result is None


# ========== Category 4: batch_install() ==========


class TestNpmInstallerBatchInstall:
    """Tests for NpmInstaller.batch_install()."""

    def test_batch_success(self):
        """Test successful batch install."""
        runner = make_runner(returncode=0)
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                tools = [
                    ("cdxgen", make_tool_info("cdxgen")),
                    ("retire", make_tool_info("retire", npm_package="retire")),
                ]
                results = installer.batch_install(tools)
                success_results = [r for r in results if r.success]
                assert len(success_results) == 2
                assert all(r.method == "npm_batch" for r in success_results)

    def test_batch_npm_not_installed(self):
        """Test batch returns failures when npm missing."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        with patch("shutil.which", return_value=None):
            tools = [("cdxgen", make_tool_info())]
            results = installer.batch_install(tools)
            assert len(results) == 1
            assert not results[0].success
            assert "npm not installed" in results[0].message

    def test_batch_skips_version_failed_tools(self):
        """Test batch skips tools failing Node.js version check."""
        runner = make_runner(returncode=0)
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(
                installer, "_check_node_version", return_value="Node.js 18+ required"
            ):
                tools = [("cdxgen", make_tool_info())]
                results = installer.batch_install(tools)
                assert len(results) >= 1
                assert not results[0].success
                assert "Node.js" in results[0].message

    def test_batch_empty_packages(self):
        """Test batch with no valid packages."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                tools = [("tool", make_tool_info(npm_package=None))]
                results = installer.batch_install(tools)
                assert results == []

    def test_batch_fallback_on_failure(self):
        """Test batch falls back to individual on failure."""
        runner = make_runner(returncode=1, stderr="ERR! conflict")
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                tools = [("cdxgen", make_tool_info())]
                results = installer.batch_install(tools)
                assert len(results) >= 1

    def test_batch_timeout(self):
        """Test batch handles timeout with fallback."""
        runner = MagicMock()
        runner.run.side_effect = subprocess.TimeoutExpired(cmd="npm", timeout=300)
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                tools = [("cdxgen", make_tool_info())]
                results = installer.batch_install(tools)
                assert len(results) >= 1

    def test_batch_generic_exception(self):
        """Test batch handles generic exception."""
        runner = MagicMock()
        runner.run.side_effect = RuntimeError("unexpected")
        installer = NpmInstaller(subprocess_runner=runner)
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                tools = [("cdxgen", make_tool_info())]
                results = installer.batch_install(tools)
                assert len(results) == 1
                assert not results[0].success

    def test_batch_with_progress(self):
        """Test batch calls progress callbacks."""
        runner = make_runner(returncode=0)
        installer = NpmInstaller(subprocess_runner=runner)
        progress = MagicMock()
        with patch("shutil.which", return_value="/usr/bin/npm"):
            with patch.object(installer, "_check_node_version", return_value=None):
                tools = [("cdxgen", make_tool_info())]
                installer.batch_install(tools, progress=progress)
                progress.on_start.assert_called_with("cdxgen")


# ========== Category 5: _fallback_individual_install() ==========


class TestFallbackIndividualInstall:
    """Tests for _fallback_individual_install()."""

    def test_cancellation(self):
        """Test cancelled progress stops installation."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        progress = MagicMock()
        progress.is_cancelled.return_value = True
        tools = [("cdxgen", make_tool_info())]
        results = installer._fallback_individual_install(tools, progress)
        assert len(results) == 1
        assert not results[0].success
        assert "cancelled" in results[0].message.lower()

    def test_individual_install_called(self):
        """Test falls back to individual install calls."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        with patch.object(installer, "install") as mock_install:
            mock_install.return_value = InstallResult(
                tool_name="t", success=True, method="npm"
            )
            tools = [("t", make_tool_info("t"))]
            results = installer._fallback_individual_install(tools, None)
            mock_install.assert_called_once()
            assert len(results) == 1

    def test_no_progress_tracker(self):
        """Test works without progress tracker."""
        installer = NpmInstaller(subprocess_runner=make_runner())
        with patch.object(installer, "install") as mock_install:
            mock_install.return_value = InstallResult(
                tool_name="t", success=True, method="npm"
            )
            tools = [("t", make_tool_info("t"))]
            results = installer._fallback_individual_install(tools, None)
            assert len(results) == 1
