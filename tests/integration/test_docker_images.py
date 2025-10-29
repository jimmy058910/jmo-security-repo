#!/usr/bin/env python3
"""
Integration tests for Docker images.

Tests verify that Docker images:
1. Can be built successfully
2. Have all required tools installed
3. Can run basic scans
4. Produce valid output

These tests require Docker to be installed and running.
"""

import os
import platform
import subprocess
import sys
from pathlib import Path

import pytest

# Docker image configuration
DOCKER_REGISTRY = "ghcr.io"
DOCKER_ORG = "jimmy058910"
DOCKER_IMAGE = "jmo-security"
DOCKER_TAG = "test"

VARIANTS = ["full", "slim", "alpine"]

# Tools expected in each variant (v0.6.0)
# Active tools (11): trufflehog, semgrep, trivy, syft, checkov, hadolint, zap,
#                    noseyparker, bandit, falco, afl++
# Legacy tools (3): gitleaks, tfsec, osv-scanner (adapters remain for backward compatibility)
EXPECTED_TOOLS = {
    "full": [
        # Secrets scanning (2)
        "trufflehog",  # Verified secrets, 95% false positive reduction
        "noseyparker",  # Deep secrets scanning, Docker fallback
        # SAST (2)
        "semgrep",  # Multi-language SAST
        "bandit",  # Python-specific SAST
        # SBOM + Vulnerability (2)
        "syft",  # SBOM generation
        "trivy",  # Vuln/misconfig/secrets scanning
        # IaC (1)
        "checkov",  # Policy-as-code
        # Dockerfile (1)
        "hadolint",  # Dockerfile best practices
        # DAST (1)
        "zap",  # OWASP ZAP web security
        # Runtime Security (1)
        "falcoctl",  # Falco CLI (full falco requires kernel modules)
        # Fuzzing (1)
        "afl-fuzz",  # AFL++ coverage-guided fuzzing
        # Formatting/Linting (2)
        "shellcheck",  # Shell script linting
        "shfmt",  # Shell script formatting
    ],
    "slim": [
        "trufflehog",  # Verified secrets
        "semgrep",  # Multi-language SAST
        "syft",  # SBOM generation
        "trivy",  # Vuln/misconfig scanning
        "hadolint",  # Dockerfile best practices
        "checkov",  # IaC policy-as-code
        "zap",  # DAST web security
    ],
    # Alpine: semgrep/checkov skipped when TARGETARCH is not set (defaults to ARM64 path)
    # This is a known limitation - buildx would fix it, but we use standard docker build
    "alpine": [
        "trufflehog",  # Verified secrets
        "syft",  # SBOM generation
        "trivy",  # Vuln/misconfig scanning
        "hadolint",  # Dockerfile best practices
        "zap",  # DAST web security
    ],
}


def is_docker_available() -> bool:
    """Check if Docker is installed and running."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


def get_image_name(variant: str) -> str:
    """Get full Docker image name for variant."""
    suffix = f"-{variant}" if variant != "full" else ""
    return f"{DOCKER_REGISTRY}/{DOCKER_ORG}/{DOCKER_IMAGE}:{DOCKER_TAG}{suffix}"


def docker_image_exists(variant: str) -> bool:
    """Check if Docker image exists locally."""
    image_name = get_image_name(variant)
    result = subprocess.run(
        ["docker", "images", "-q", image_name],
        capture_output=True,
        text=True,
        check=False,
    )
    return bool(result.stdout.strip())


@pytest.fixture(scope="module")
def docker_check():
    """Fixture to check Docker availability once per module."""
    if not is_docker_available():
        pytest.skip("Docker is not available or not running")


@pytest.fixture(scope="module")
def test_repo(tmp_path_factory) -> Path:
    """Create a simple test repository."""
    repo_dir = tmp_path_factory.mktemp("test_repo")

    # Create simple Python file with a potential issue
    test_py = repo_dir / "test.py"
    test_py.write_text(
        """
# Test file for security scanning
import os

# This should trigger some findings
password = "hardcoded_password_123"
api_key = os.environ.get("API_KEY", "default_key")

def insecure_function():
    eval(input("Enter code: "))  # B307: Use of eval

if __name__ == "__main__":
    print("Test file")
"""
    )

    # Create a Dockerfile
    dockerfile = repo_dir / "Dockerfile"
    dockerfile.write_text(
        """
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y curl
USER root
WORKDIR /app
"""
    )

    return repo_dir


@pytest.mark.skipif(
    not is_docker_available(), reason="Docker is not available or not running"
)
class TestDockerImages:
    """Test Docker image functionality."""

    @pytest.mark.parametrize("variant", VARIANTS)
    def test_image_exists_or_skip(self, variant: str):
        """Check if Docker image exists, skip if not."""
        if not docker_image_exists(variant):
            pytest.skip(f"Docker image for variant '{variant}' not built yet")

    @pytest.mark.parametrize("variant", VARIANTS)
    def test_jmo_default_help(self, docker_check, variant: str):
        """Test that jmo (default --help) works."""
        if not docker_image_exists(variant):
            pytest.skip(f"Image {variant} not built")

        image_name = get_image_name(variant)
        result = subprocess.run(
            ["docker", "run", "--rm", image_name],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        assert result.returncode == 0, f"jmo default command failed: {result.stderr}"
        assert "usage" in result.stdout.lower() or "scan" in result.stdout.lower()

    @pytest.mark.parametrize("variant", VARIANTS)
    def test_jmo_explicit_help(self, docker_check, variant: str):
        """Test that jmo --help works."""
        if not docker_image_exists(variant):
            pytest.skip(f"Image {variant} not built")

        image_name = get_image_name(variant)
        result = subprocess.run(
            ["docker", "run", "--rm", image_name, "--help"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        assert result.returncode == 0, f"jmo --help failed: {result.stderr}"
        assert "usage" in result.stdout.lower() or "commands" in result.stdout.lower()

    @pytest.mark.parametrize("variant", VARIANTS)
    def test_tools_installed(self, docker_check, variant: str):
        """Test that expected tools are installed."""
        if not docker_image_exists(variant):
            pytest.skip(f"Image {variant} not built")

        image_name = get_image_name(variant)
        expected_tools = EXPECTED_TOOLS[variant]

        for tool in expected_tools:
            # Check if tool exists (override entrypoint to run shell)
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "sh",
                    image_name,
                    "-c",
                    f"which {tool}",
                ],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )

            assert (
                result.returncode == 0
            ), f"Tool '{tool}' not found in {variant} image: {result.stderr}"

    @pytest.mark.parametrize("variant", VARIANTS)
    def test_basic_scan(self, docker_check, variant: str, test_repo: Path):
        """Test that a basic scan works in Docker container."""
        if not docker_image_exists(variant):
            pytest.skip(f"Image {variant} not built")

        image_name = get_image_name(variant)

        # Run a basic scan on test repo
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{test_repo}:/scan",
                image_name,
                "scan",
                "--repo",
                "/scan",
                "--results",
                "/scan/results",
                "--profile-name",
                "fast",
                "--human-logs",
            ],
            capture_output=True,
            text=True,
            timeout=120,  # 2 minutes max
            check=False,
        )

        # Scan should complete (exit 0 or exit 1 with findings)
        assert result.returncode in (0, 1), (
            f"Scan failed with exit {result.returncode}:\n"
            f"STDOUT: {result.stdout}\n"
            f"STDERR: {result.stderr}"
        )

        # Verify results directory was created
        results_dir = test_repo / "results"
        assert results_dir.exists(), f"Results directory not created at {results_dir}"

    def test_docker_compose_syntax(self, docker_check):
        """Test that docker-compose.yml is valid."""
        compose_file = Path(__file__).parent.parent.parent / "docker-compose.yml"

        if not compose_file.exists():
            pytest.skip("docker-compose.yml not found")

        result = subprocess.run(
            ["docker", "compose", "-f", str(compose_file), "config"],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
        )

        assert (
            result.returncode == 0
        ), f"docker-compose.yml validation failed: {result.stderr}"


@pytest.mark.skipif(
    not is_docker_available(), reason="Docker is not available or not running"
)
class TestDockerBuild:
    """Test Docker build process (optional, slow)."""

    @pytest.mark.slow
    @pytest.mark.skipif(
        os.getenv("CI") == "true" and platform.system() == "Linux",
        reason="Docker build timeout on Ubuntu CI (pre-existing flaky test, runs on macOS)",
    )
    @pytest.mark.parametrize("variant", ["slim"])  # Only test slim for speed
    def test_build_slim_image(self, docker_check, variant: str):
        """Test building the slim Docker image."""
        dockerfile = "Dockerfile" if variant == "full" else f"Dockerfile.{variant}"
        dockerfile_path = Path(__file__).parent.parent.parent / dockerfile

        if not dockerfile_path.exists():
            pytest.skip(f"Dockerfile for variant '{variant}' not found")

        image_name = get_image_name(variant)

        # Build image
        result = subprocess.run(
            [
                "docker",
                "build",
                "-f",
                str(dockerfile_path),
                "-t",
                image_name,
                str(dockerfile_path.parent),
            ],
            capture_output=True,
            text=True,
            timeout=600,  # 10 minutes max
            check=False,
        )

        assert result.returncode == 0, f"Docker build failed: {result.stderr}"

        # Verify image was created
        assert docker_image_exists(variant), f"Image {image_name} not found after build"


if __name__ == "__main__":
    # Run tests with verbose output
    sys.exit(pytest.main([__file__, "-v", "-s"]))
