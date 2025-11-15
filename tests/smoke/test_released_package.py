"""
Smoke tests for released JMo Security package.

These tests verify the PyPI package and Docker images are correctly published
and functional. Run after release to catch deployment issues early.

Usage:
    pytest tests/smoke/test_released_package.py -v
"""

import json
import subprocess
import tempfile
from pathlib import Path

import pytest


class TestPyPIPackage:
    """Smoke tests for PyPI package."""

    def test_install_from_pypi(self):
        """Test installing from PyPI works."""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create virtual environment
            venv_path = Path(tmpdir) / "venv"
            result = subprocess.run(
                ["python3", "-m", "venv", str(venv_path)],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, f"Failed to create venv: {result.stderr}"

            # Determine pip path (OS-specific)
            pip = venv_path / "bin" / "pip"
            if not pip.exists():
                pip = venv_path / "Scripts" / "pip.exe"  # Windows

            # Install from PyPI
            result = subprocess.run(
                [str(pip), "install", "jmo-security", "--no-cache-dir"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            assert result.returncode == 0, f"Failed to install: {result.stderr}"

    def test_cli_help_works(self):
        """Test CLI --help command works."""
        result = subprocess.run(
            ["jmo", "--help"], capture_output=True, text=True, timeout=10
        )

        # Should succeed
        assert result.returncode == 0, f"jmo --help failed: {result.stderr}"

        # Should contain expected help text
        assert "JMo Security" in result.stdout or "usage" in result.stdout.lower()
        assert "scan" in result.stdout.lower()
        assert "report" in result.stdout.lower()

    def test_cli_version_command(self):
        """Test CLI version can be retrieved."""
        # jmo doesn't have --version, so we use help to verify it works
        result = subprocess.run(
            ["jmo", "scan", "--help"], capture_output=True, text=True, timeout=10
        )

        assert result.returncode == 0, f"jmo scan --help failed: {result.stderr}"
        assert "usage" in result.stdout.lower()

    def test_basic_scan_command(self, tmp_path):
        """Test basic scan command executes (dry-run mode)."""
        # Create minimal test repository
        test_repo = tmp_path / "test-repo"
        test_repo.mkdir()
        (test_repo / "test.py").write_text("print('hello')\n")

        # Initialize git (required for some tools)
        subprocess.run(
            ["git", "init"],
            cwd=test_repo,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=test_repo,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "config", "user.name", "Test User"],
            cwd=test_repo,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "add", "."],
            cwd=test_repo,
            capture_output=True,
            check=True,
        )
        subprocess.run(
            ["git", "commit", "-m", "initial"],
            cwd=test_repo,
            capture_output=True,
            check=True,
        )

        # Run scan with minimal profile (allow missing tools)
        results_dir = tmp_path / "results"
        result = subprocess.run(
            [
                "jmo",
                "scan",
                "--repo",
                str(test_repo),
                "--results-dir",
                str(results_dir),
                "--tools",
                "trufflehog",  # Single tool to minimize dependencies
                "--allow-missing-tools",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should complete (exit 0 or 1 if findings detected)
        assert result.returncode in (
            0,
            1,
        ), f"Scan failed with exit {result.returncode}: {result.stderr}"

        # Results directory should exist
        assert results_dir.exists(), "Results directory not created"


class TestDockerImages:
    """Smoke tests for Docker images."""

    @pytest.mark.skipif(
        subprocess.run(["docker", "--version"], capture_output=True).returncode != 0,
        reason="Docker not available",
    )
    def test_docker_image_available(self):
        """Test Docker image can be pulled."""
        result = subprocess.run(
            ["docker", "pull", "ghcr.io/jimmy058910/jmo-security:latest"],
            capture_output=True,
            text=True,
            timeout=300,  # 5 minutes for image pull
        )

        assert (
            result.returncode == 0
        ), f"Failed to pull Docker image: {result.stderr}"

    @pytest.mark.skipif(
        subprocess.run(["docker", "--version"], capture_output=True).returncode != 0,
        reason="Docker not available",
    )
    def test_docker_image_help_works(self):
        """Test Docker image runs and --help works."""
        result = subprocess.run(
            ["docker", "run", "--rm", "ghcr.io/jimmy058910/jmo-security:latest", "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # Should succeed
        assert result.returncode == 0, f"Docker --help failed: {result.stderr}"

        # Should contain expected help text
        assert "JMo Security" in result.stdout or "usage" in result.stdout.lower()

    @pytest.mark.skipif(
        subprocess.run(["docker", "--version"], capture_output=True).returncode != 0,
        reason="Docker not available",
    )
    def test_docker_scan_help_works(self):
        """Test Docker image scan --help works."""
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "ghcr.io/jimmy058910/jmo-security:latest",
                "scan",
                "--help",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"Docker scan --help failed: {result.stderr}"
        assert "usage" in result.stdout.lower()


class TestDocumentation:
    """Smoke tests for documentation availability."""

    def test_readme_accessible_on_github(self):
        """Test README.md is accessible on GitHub."""
        # Use curl to check if README renders on GitHub
        result = subprocess.run(
            [
                "curl",
                "-sf",
                "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/README.md",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, "README.md not accessible on GitHub"
        assert len(result.stdout) > 1000, "README.md too short (likely missing content)"

    def test_user_guide_accessible(self):
        """Test USER_GUIDE.md is accessible on GitHub."""
        result = subprocess.run(
            [
                "curl",
                "-sf",
                "https://raw.githubusercontent.com/jimmy058910/jmo-security-repo/main/docs/USER_GUIDE.md",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, "USER_GUIDE.md not accessible"
        assert len(result.stdout) > 2000, "USER_GUIDE.md too short"


class TestPyPIMetadata:
    """Smoke tests for PyPI metadata."""

    def test_pypi_package_exists(self):
        """Test package exists on PyPI."""
        result = subprocess.run(
            [
                "curl",
                "-sf",
                "https://pypi.org/pypi/jmo-security/json",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, "Package not found on PyPI"

        # Parse JSON metadata
        metadata = json.loads(result.stdout)
        assert "info" in metadata
        assert metadata["info"]["name"] == "jmo-security"

    def test_pypi_readme_renders(self):
        """Test README renders correctly on PyPI page."""
        result = subprocess.run(
            [
                "curl",
                "-sf",
                "https://pypi.org/project/jmo-security/",
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, "PyPI project page not accessible"

        # Check for key content markers
        assert "jmo" in result.stdout.lower() or "security" in result.stdout.lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
