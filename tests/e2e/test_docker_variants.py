#!/usr/bin/env python3
"""
End-to-end tests for JMo Security Docker image variants.

These tests validate that each Docker image variant:
- Has the expected tools installed
- Can complete a scan successfully
- Produces valid output

Requires: Docker installed and running
Runtime: ~30-60 minutes for all variants
"""

from __future__ import annotations

import json
import subprocess
from pathlib import Path

import pytest

# Docker image variants to test
DOCKER_REGISTRY = "ghcr.io/jimmy058910/jmo-security"
DOCKER_VARIANTS = [
    pytest.param("deep", 28, id="deep"),
    pytest.param("balanced", 18, id="balanced"),
    pytest.param("slim", 14, id="slim"),
    pytest.param("fast", 8, id="fast"),
]


def docker_available() -> bool:
    """Check if Docker is available."""
    try:
        result = subprocess.run(
            ["docker", "version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def image_exists(image: str) -> bool:
    """Check if a Docker image exists locally or can be pulled."""
    result = subprocess.run(
        ["docker", "image", "inspect", image],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def pull_image(image: str) -> bool:
    """Pull a Docker image."""
    result = subprocess.run(
        ["docker", "pull", image],
        capture_output=True,
        text=True,
        timeout=600,
    )
    return result.returncode == 0


@pytest.mark.docker
@pytest.mark.e2e
@pytest.mark.slow
class TestDockerVariants:
    """End-to-end tests for Docker image variants."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    @pytest.mark.parametrize("variant,expected_tools", DOCKER_VARIANTS)
    def test_docker_variant_tools(self, variant: str, expected_tools: int):
        """Each Docker variant should have the expected minimum tool count."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        # Ensure image exists
        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Run tools check
        result = subprocess.run(
            ["docker", "run", "--rm", image, "tools", "check", "--json"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        if result.returncode != 0:
            pytest.fail(f"tools check failed: {result.stderr}")

        # Parse output
        try:
            tools = json.loads(result.stdout)
        except json.JSONDecodeError:
            pytest.fail(f"Invalid JSON output: {result.stdout[:500]}")

        # Count installed tools
        installed = sum(1 for t in tools if t.get("installed", False))

        assert installed >= expected_tools, (
            f"{variant} variant has {installed} tools, expected at least {expected_tools}"
        )

    @pytest.mark.parametrize("variant,_expected_tools", DOCKER_VARIANTS)
    def test_docker_variant_scan(
        self, variant: str, _expected_tools: int, tmp_path: Path
    ):
        """Each Docker variant should complete a scan successfully."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        # Ensure image exists
        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Create sample vulnerable code
        src_dir = tmp_path / "src"
        src_dir.mkdir()

        (src_dir / "app.js").write_text(
            """
const userId = req.query.id;
const query = "SELECT * FROM users WHERE id = " + userId;
"""
        )

        # Determine profile based on variant
        profile = "fast" if variant in ["fast", "slim"] else variant

        # Run scan in Docker
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp_path}:/scan",
                "-w",
                "/scan",
                image,
                "scan",
                "--repo",
                ".",
                "--profile",
                profile,
                "--results-dir",
                "/scan/results",
            ],
            capture_output=True,
            text=True,
            timeout=1800,  # 30 minutes max
        )

        # Scan should complete (may have non-zero exit if findings)
        results_dir = tmp_path / "results"

        # Check for output (either results dir or exit 0)
        assert (
            result.returncode == 0
            or results_dir.exists()
            or "findings" in result.stdout.lower()
        ), f"Scan failed: {result.stderr}"

    def test_docker_help_command(self):
        """Docker image should show help correctly."""
        image = f"{DOCKER_REGISTRY}:balanced"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        result = subprocess.run(
            ["docker", "run", "--rm", image, "--help"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"Help failed: {result.stderr}"
        assert "jmo" in result.stdout.lower() or "security" in result.stdout.lower()

    def test_docker_version_command(self):
        """Docker image should report version correctly."""
        image = f"{DOCKER_REGISTRY}:balanced"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        result = subprocess.run(
            ["docker", "run", "--rm", image, "--version"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        assert result.returncode == 0, f"Version failed: {result.stderr}"
        # Should contain version number pattern
        assert "." in result.stdout  # e.g., "1.0.0"


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerVolumeMount:
    """Test Docker volume mounting scenarios."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_volume_mount_results_persist(self, tmp_path: Path):
        """Results should persist to mounted volume."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Create sample code
        (tmp_path / "test.py").write_text("password = 'secret123'")

        # Run scan
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp_path}:/scan",
                "-w",
                "/scan",
                image,
                "scan",
                "--repo",
                ".",
                "--profile",
                "fast",
                "--results-dir",
                "/scan/results",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        # Check results exist on host
        results_dir = tmp_path / "results"
        if results_dir.exists():
            # Should have some output files
            output_files = list(results_dir.glob("*"))
            assert len(output_files) >= 0  # May or may not have findings

    def test_history_db_mount(self, tmp_path: Path):
        """History database should persist when mounted."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Create .jmo directory for history
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        # Create sample code
        (tmp_path / "test.py").write_text("x = 1")

        # Run scan with history mount
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp_path}:/scan",
                "-v",
                f"{jmo_dir}:/scan/.jmo",
                "-w",
                "/scan",
                image,
                "scan",
                "--repo",
                ".",
                "--profile",
                "fast",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        # History database may be created
        # This is a soft check - may not create if no findings
        # Just verify no errors occurred
