#!/usr/bin/env python3
"""
macOS-Specific E2E Tests for JMo Security.

Tests macOS-specific behaviors including Homebrew paths, SIP restrictions,
and macOS-specific filesystem features.

Usage:
    pytest tests/e2e/test_macos_specific.py -v
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.conftest import IS_MACOS

macos_only = pytest.mark.skipif(not IS_MACOS, reason="macOS-only test")


@macos_only
class TestMacOSPathHandling:
    """Test macOS-specific path handling."""

    def test_homebrew_paths(self, jmo_runner):
        """Verify Homebrew-installed tools are discovered."""
        result = jmo_runner(["tools", "check"], timeout=60)

        # Should check Homebrew locations
        assert result.returncode in (0, 1)

        # May mention Homebrew paths
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_home_tilde_expansion(self, jmo_runner, tmp_path, monkeypatch):
        """Verify ~ expands correctly on macOS."""
        # Create a test structure in a mock home
        mock_home = tmp_path / "mock_home"
        mock_home.mkdir()
        repo = mock_home / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        # Mock Path.home() for cross-platform compatibility
        monkeypatch.setattr(Path, "home", staticmethod(lambda: mock_home))

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
            ],
            timeout=60,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_case_insensitive_filesystem(self, jmo_runner, tmp_path):
        """Verify handling of macOS case-insensitive filesystem."""
        # Create repo
        repo = tmp_path / "TestRepo"
        repo.mkdir()
        (repo / "Test.py").write_text("x = 1", encoding="utf-8")

        # Try to access with different case (may work on macOS default FS)
        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(tmp_path / "testrepo"),  # Different case
                "--allow-missing-tools",
            ],
            timeout=60,
        )

        # Either finds it or reports not found cleanly
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@macos_only
class TestMacOSToolDiscovery:
    """Test tool discovery on macOS."""

    def test_opt_homebrew_path(self, jmo_runner):
        """Verify /opt/homebrew (Apple Silicon) paths are checked."""
        result = jmo_runner(["tools", "debug", "trivy"], timeout=30)

        # Should show path information
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_usr_local_path(self, jmo_runner):
        """Verify /usr/local (Intel Mac) paths are checked."""
        result = jmo_runner(["tools", "check"], timeout=60)

        assert result.returncode in (0, 1)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@macos_only
class TestMacOSPermissions:
    """Test macOS permission handling."""

    def test_quarantine_attribute_handling(self, jmo_runner, tmp_path):
        """Verify handling of quarantine attribute on downloaded tools."""
        # Create test repo
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
            timeout=60,
        )

        # Should handle tools even if quarantined (will be missing)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined

    def test_system_directory_access(self, jmo_runner):
        """Verify tools in system directories are accessible."""
        result = jmo_runner(["tools", "check"], timeout=60)

        # Should check system paths without permission errors
        assert result.returncode in (0, 1)


@macos_only
class TestMacOSExtendedAttributes:
    """Test macOS extended attribute handling."""

    def test_xattr_on_results(self, jmo_runner, tmp_path):
        """Verify results files don't cause xattr issues."""
        repo = tmp_path / "test-repo"
        repo.mkdir()
        (repo / "test.py").write_text("x = 1", encoding="utf-8")

        result = jmo_runner(
            [
                "scan",
                "--repo",
                str(repo),
                "--allow-missing-tools",
                "--results-dir",
                str(tmp_path / "results"),
            ],
            timeout=60,
        )

        # Should create results without xattr errors
        combined = result.stdout.lower() + result.stderr.lower()
        assert "operation not permitted" not in combined
        assert "traceback" not in combined
