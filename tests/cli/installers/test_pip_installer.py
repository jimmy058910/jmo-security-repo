"""Tests for scripts/cli/installers/pip_installer.py.

Covers:
- PipInstaller: can_install, install, batch_install, _fallback_individual_install
- IsolatedPipInstaller: can_install, install, _install_in_venv, _get_tool_version
- Version validation, timeout handling, error paths
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch


from scripts.cli.installers.pip_installer import PipInstaller, IsolatedPipInstaller
from scripts.cli.installers.base import InstallMethod
from scripts.cli.installers.models import InstallResult

# ========== Helpers ==========


def make_tool_info(
    name: str = "bandit",
    version: str = "1.7.5",
    pypi_package: str | None = "bandit",
    **kwargs,
) -> MagicMock:
    """Create a mock ToolInfo."""
    info = MagicMock()
    info.name = name
    info.version = version
    info.pypi_package = pypi_package
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


# ========== PipInstaller: Properties ==========


class TestPipInstallerProperties:
    """Tests for PipInstaller basic properties."""

    def test_method_is_pip(self):
        """Test method property returns PIP."""
        installer = PipInstaller()
        assert installer.method == InstallMethod.PIP

    def test_can_install_with_pypi_package(self):
        """Test can_install when tool has pypi_package."""
        installer = PipInstaller()
        with patch("scripts.cli.installers.pip_installer.ISOLATED_TOOLS", {}):
            assert (
                installer.can_install(make_tool_info("bandit", pypi_package="bandit"))
                is True
            )

    def test_cannot_install_without_pypi_package(self):
        """Test can_install when tool has no pypi_package."""
        installer = PipInstaller()
        assert installer.can_install(make_tool_info(pypi_package=None)) is False

    def test_cannot_install_isolated_tool(self):
        """Test can_install rejects isolated tools (handled by IsolatedPipInstaller)."""
        installer = PipInstaller()
        with patch(
            "scripts.cli.installers.pip_installer.ISOLATED_TOOLS", {"semgrep": {}}
        ):
            assert installer.can_install(make_tool_info("semgrep")) is False


# ========== PipInstaller: install() ==========


class TestPipInstallerInstall:
    """Tests for PipInstaller.install()."""

    def test_successful_install(self):
        """Test successful pip install."""
        runner = make_runner(returncode=0)
        installer = PipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            result = installer.install("bandit", make_tool_info())
            assert result.success is True
            assert result.method == "pip"
            assert "bandit==" in result.message

    def test_no_pypi_package(self):
        """Test install fails when no pypi_package defined."""
        installer = PipInstaller(subprocess_runner=make_runner())
        result = installer.install("tool", make_tool_info(pypi_package=None))
        assert result.success is False
        assert "No PyPI package" in result.message

    def test_invalid_version(self):
        """Test install rejects invalid version."""
        installer = PipInstaller(subprocess_runner=make_runner())
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=False
        ):
            result = installer.install("bandit", make_tool_info(version="evil;cmd"))
            assert result.success is False
            assert "Invalid version" in result.message

    def test_pip_failure(self):
        """Test install handles pip failure."""
        runner = make_runner(returncode=1, stderr="Could not find version")
        installer = PipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            result = installer.install("bandit", make_tool_info())
            assert result.success is False
            assert "pip install failed" in result.message

    def test_timeout(self):
        """Test install handles timeout."""
        runner = MagicMock()
        runner.run.side_effect = subprocess.TimeoutExpired(cmd="pip", timeout=600)
        installer = PipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            result = installer.install("bandit", make_tool_info())
            assert result.success is False
            assert "timed out" in result.message.lower()

    def test_generic_exception(self):
        """Test install handles generic exceptions."""
        runner = MagicMock()
        runner.run.side_effect = OSError("permission denied")
        installer = PipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            result = installer.install("bandit", make_tool_info())
            assert result.success is False
            assert "permission denied" in result.message

    def test_verification_with_tool_manager(self):
        """Test post-install verification via ToolManager."""
        runner = make_runner(returncode=0)
        manager = MagicMock()
        status = MagicMock()
        status.installed_version = "1.7.5"
        manager.check_tool.return_value = status
        installer = PipInstaller(subprocess_runner=runner, tool_manager=manager)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            result = installer.install("bandit", make_tool_info())
            assert result.success is True
            assert result.version_installed == "1.7.5"
            manager.check_tool.assert_called_once_with("bandit")

    def test_duration_tracked(self):
        """Test duration_seconds is tracked."""
        runner = make_runner(returncode=0)
        installer = PipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            result = installer.install("bandit", make_tool_info())
            assert result.duration_seconds >= 0


# ========== PipInstaller: batch_install() ==========


class TestPipInstallerBatchInstall:
    """Tests for PipInstaller.batch_install()."""

    def test_batch_success(self):
        """Test successful batch install."""
        runner = make_runner(returncode=0)
        installer = PipInstaller(subprocess_runner=runner)
        tools = [
            ("bandit", make_tool_info("bandit")),
            ("safety", make_tool_info("safety", pypi_package="safety")),
        ]
        results = installer.batch_install(tools)
        assert len(results) == 2
        assert all(r.success for r in results)
        assert all(r.method == "pip_batch" for r in results)

    def test_batch_fallback_on_failure(self):
        """Test batch falls back to individual on failure."""
        runner = make_runner(returncode=1, stderr="conflict error")
        installer = PipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            tools = [("bandit", make_tool_info("bandit"))]
            results = installer.batch_install(tools)
            # Fallback runs individual installs (which also fail)
            assert len(results) >= 1

    def test_batch_empty_packages(self):
        """Test batch with no valid packages returns empty."""
        installer = PipInstaller(subprocess_runner=make_runner())
        tools = [("tool", make_tool_info(pypi_package=None))]
        results = installer.batch_install(tools)
        assert results == []

    def test_batch_timeout(self):
        """Test batch handles timeout with fallback."""
        runner = MagicMock()
        runner.run.side_effect = subprocess.TimeoutExpired(cmd="pip", timeout=600)
        installer = PipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.validate_version", return_value=True
        ):
            tools = [("bandit", make_tool_info("bandit"))]
            results = installer.batch_install(tools)
            assert len(results) >= 1

    def test_batch_generic_exception(self):
        """Test batch handles generic exception."""
        runner = MagicMock()
        runner.run.side_effect = RuntimeError("unexpected")
        installer = PipInstaller(subprocess_runner=runner)
        tools = [("bandit", make_tool_info("bandit"))]
        results = installer.batch_install(tools)
        assert len(results) == 1
        assert not results[0].success

    def test_batch_with_progress(self):
        """Test batch calls progress callbacks."""
        runner = make_runner(returncode=0)
        installer = PipInstaller(subprocess_runner=runner)
        progress = MagicMock()
        tools = [("bandit", make_tool_info("bandit"))]
        installer.batch_install(tools, progress=progress)
        progress.on_start.assert_called_with("bandit")


# ========== PipInstaller: _fallback_individual_install() ==========


class TestFallbackIndividualInstall:
    """Tests for _fallback_individual_install()."""

    def test_cancellation_check(self):
        """Test cancelled progress stops installation."""
        installer = PipInstaller(subprocess_runner=make_runner())
        progress = MagicMock()
        progress.is_cancelled.return_value = True
        tools = [("bandit", make_tool_info())]
        results = installer._fallback_individual_install(tools, progress, None)
        assert len(results) == 1
        assert not results[0].success
        assert "cancelled" in results[0].message.lower()

    def test_uses_fallback_installer(self):
        """Test uses fallback installer when provided."""
        installer = PipInstaller(subprocess_runner=make_runner())
        fallback = MagicMock()
        fallback.install.return_value = InstallResult(
            tool_name="t", success=True, method="pip"
        )
        tools = [("t", make_tool_info())]
        installer._fallback_individual_install(tools, None, fallback)
        fallback.install.assert_called_once()


# ========== IsolatedPipInstaller: Properties ==========


class TestIsolatedPipInstallerProperties:
    """Tests for IsolatedPipInstaller basic properties."""

    def test_method_is_pip(self):
        """Test method property returns PIP."""
        installer = IsolatedPipInstaller()
        assert installer.method == InstallMethod.PIP

    def test_can_install_isolated_tool(self):
        """Test can_install for tools in ISOLATED_TOOLS."""
        installer = IsolatedPipInstaller()
        with patch(
            "scripts.cli.installers.pip_installer.ISOLATED_TOOLS", {"semgrep": {}}
        ):
            assert installer.can_install(make_tool_info("semgrep")) is True

    def test_cannot_install_non_isolated(self):
        """Test can_install rejects non-isolated tools."""
        installer = IsolatedPipInstaller()
        with patch("scripts.cli.installers.pip_installer.ISOLATED_TOOLS", {}):
            assert installer.can_install(make_tool_info("bandit")) is False


# ========== IsolatedPipInstaller: install() ==========


class TestIsolatedPipInstallerInstall:
    """Tests for IsolatedPipInstaller.install()."""

    def test_no_package_defined(self):
        """Test install fails when no package defined."""
        installer = IsolatedPipInstaller(subprocess_runner=make_runner())
        with patch("scripts.cli.installers.pip_installer.ISOLATED_TOOLS", {"tool": {}}):
            result = installer.install("tool", make_tool_info(pypi_package=None))
            assert result.success is False
            assert "No package" in result.message

    def test_uses_isolated_config_package(self):
        """Test install uses package from ISOLATED_TOOLS config."""
        runner = make_runner(returncode=0)
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.ISOLATED_TOOLS",
            {"semgrep": {"package": "semgrep"}},
        ):
            with patch.object(installer, "_install_in_venv") as mock_venv:
                mock_venv.return_value = InstallResult(
                    tool_name="semgrep", success=True
                )
                installer.install("semgrep", make_tool_info("semgrep"))
                # Verify package spec was passed
                mock_venv.assert_called_once()
                assert "semgrep==" in mock_venv.call_args[0][1]


# ========== IsolatedPipInstaller: _install_in_venv() ==========


class TestInstallInVenv:
    """Tests for IsolatedPipInstaller._install_in_venv()."""

    def test_venv_creation_failure(self, tmp_path: Path):
        """Test handles venv creation failure."""
        runner = make_runner(returncode=1, stderr="venv error")
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.get_isolated_venv_path",
            return_value=tmp_path / "venv",
        ):
            result = installer._install_in_venv("tool", "tool==1.0.0")
            assert result.success is False
            assert "venv" in result.message.lower()

    def test_pip_not_found_in_venv(self, tmp_path: Path):
        """Test handles missing pip in venv."""
        runner = make_runner(returncode=0)
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        venv_dir = tmp_path / "venv"
        venv_dir.mkdir(parents=True)

        with patch(
            "scripts.cli.installers.pip_installer.get_isolated_venv_path",
            return_value=venv_dir,
        ):
            result = installer._install_in_venv("tool", "tool==1.0.0")
            assert result.success is False
            assert "pip not found" in result.message

    def test_timeout_during_install(self, tmp_path: Path):
        """Test handles timeout during installation."""
        runner = MagicMock()
        runner.run.side_effect = subprocess.TimeoutExpired(cmd="pip", timeout=600)
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        venv_dir = tmp_path / "venv"

        with patch(
            "scripts.cli.installers.pip_installer.get_isolated_venv_path",
            return_value=venv_dir,
        ):
            result = installer._install_in_venv("tool", "tool==1.0.0")
            assert result.success is False
            assert "timed out" in result.message.lower()

    def test_generic_exception(self, tmp_path: Path):
        """Test handles generic exception."""
        runner = MagicMock()
        runner.run.side_effect = OSError("disk full")
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        with patch(
            "scripts.cli.installers.pip_installer.get_isolated_venv_path",
            return_value=tmp_path / "venv",
        ):
            result = installer._install_in_venv("tool", "tool==1.0.0")
            assert result.success is False
            assert "disk full" in result.message


# ========== IsolatedPipInstaller: _get_tool_version() ==========


class TestGetToolVersion:
    """Tests for IsolatedPipInstaller._get_tool_version()."""

    def test_parses_version_from_output(self, tmp_path: Path):
        """Test version parsing from --version output."""
        runner = make_runner(returncode=0, stdout="semgrep 1.50.0")
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        version = installer._get_tool_version(tmp_path / "tool", tmp_path / "bin")
        assert version == "1.50.0"

    def test_version_from_stderr(self, tmp_path: Path):
        """Test version parsing from stderr output."""
        runner = make_runner(returncode=0, stdout="", stderr="tool version 2.3.4")
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        version = installer._get_tool_version(tmp_path / "tool", tmp_path / "bin")
        assert version == "2.3.4"

    def test_no_version_match(self, tmp_path: Path):
        """Test returns None when no version pattern found."""
        runner = make_runner(returncode=0, stdout="tool is ready")
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        version = installer._get_tool_version(tmp_path / "tool", tmp_path / "bin")
        assert version is None

    def test_command_failure(self, tmp_path: Path):
        """Test returns None on command failure."""
        runner = make_runner(returncode=1)
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        version = installer._get_tool_version(tmp_path / "tool", tmp_path / "bin")
        assert version is None

    def test_exception_returns_none(self, tmp_path: Path):
        """Test returns None on exception (best-effort)."""
        runner = MagicMock()
        runner.run.side_effect = OSError("command not found")
        installer = IsolatedPipInstaller(subprocess_runner=runner)
        version = installer._get_tool_version(tmp_path / "tool", tmp_path / "bin")
        assert version is None
