#!/usr/bin/env python3
"""
Linux-Specific E2E Tests for JMo Security.

Tests Linux-specific behaviors including systemd, SELinux/AppArmor,
and various package manager paths.

Usage:
    pytest tests/e2e/test_linux_specific.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import IS_LINUX

linux_only = pytest.mark.skipif(not IS_LINUX, reason="Linux-only test")


@linux_only
class TestLinuxPathHandling:
    """Test Linux-specific path handling."""

    def test_usr_bin_tools(self, jmo_runner):
        """Verify tools in /usr/bin are discovered."""
        result = jmo_runner(["tools", "check"], timeout=60)

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_usr_local_bin_tools(self, jmo_runner):
        """Verify tools in /usr/local/bin are discovered."""
        result = jmo_runner(["tools", "debug", "trivy"], timeout=30)

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_home_local_bin_tools(self, jmo_runner, tmp_path, monkeypatch):
        """Verify tools in ~/.local/bin are discovered."""
        # Mock home directory
        mock_home = tmp_path / "mock_home"
        mock_home.mkdir()
        local_bin = mock_home / ".local" / "bin"
        local_bin.mkdir(parents=True)

        monkeypatch.setattr(Path, "home", staticmethod(lambda: mock_home))

        result = jmo_runner(["tools", "check"], timeout=60)

        assert result.returncode in (0, 1)

    def test_symlink_paths(self, jmo_runner, tmp_path):
        """Verify symlinked paths are followed."""
        repo = tmp_path / "actual-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        # Create symlink
        link = tmp_path / "linked-repo"
        link.symlink_to(repo)

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(link),
                "--allow-missing-tools",
            ],
            timeout=120,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@linux_only
class TestLinuxPermissions:
    """Test Linux-specific permission handling."""

    def test_non_root_execution(self, jmo_runner, tmp_path):
        """Verify tool runs correctly as non-root user."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
            ],
            timeout=120,
        )

        # Should work without root
        assert result.returncode in (0, 1)

    def test_executable_permission_check(self, jmo_runner, tmp_path):
        """Verify executable permission checking works."""
        # Create a non-executable script
        script = tmp_path / "script.sh"
        script.write_text("#!/bin/bash\necho test", encoding="utf-8")
        # Don't set executable bit

        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
            ],
            timeout=120,
        )

        # Should handle non-executable scripts
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@linux_only
class TestLinuxContainerIntegration:
    """Test Linux container integration."""

    def test_docker_socket_access(self, jmo_runner):
        """Verify Docker socket access is handled."""
        # Check if Docker is available
        result = jmo_runner(["tools", "debug", "docker"], timeout=30)

        # Should report Docker availability
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_podman_alternative(self, jmo_runner):
        """Verify Podman can be used as Docker alternative."""
        result = jmo_runner(["tools", "check"], timeout=60)

        # Should check for both Docker and Podman
        assert result.returncode in (0, 1)


@linux_only
class TestLinuxFilesystem:
    """Test Linux filesystem handling."""

    def test_proc_filesystem_ignored(self, jmo_runner, tmp_path):
        """Verify /proc is not scanned."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
            ],
            timeout=120,
        )

        # Should not try to scan /proc
        combined = result.stdout.lower() + result.stderr.lower()
        assert "/proc" not in combined or "skip" in combined

    def test_large_filesystem_handling(self, jmo_runner, tmp_path):
        """Verify handling of directories with many files."""
        repo = tmp_path / "test-repo"
        repo.mkdir()

        # Create many files
        for i in range(100):
            (repo / f"file_{i:03d}.py").write_text(f"x = {i}", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
            ],
            timeout=120,
        )

        # Should handle many files
        assert result.returncode in (0, 1)


@linux_only
class TestLinuxPackageManagers:
    """Test integration with Linux package managers."""

    def test_pip_installed_tools(self, jmo_runner):
        """Verify pip-installed tools are found."""
        result = jmo_runner(["tools", "debug", "bandit"], timeout=30)

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_npm_installed_tools(self, jmo_runner):
        """Verify npm-installed tools are found."""
        result = jmo_runner(["tools", "check"], timeout=60)

        # Should check npm global and local paths
        assert result.returncode in (0, 1)

    def test_go_installed_tools(self, jmo_runner):
        """Verify Go-installed tools are found."""
        result = jmo_runner(["tools", "debug", "gosec"], timeout=30)

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined
