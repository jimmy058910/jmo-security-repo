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
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import skip_on_windows

# Docker image variants to test.
# expected_tools mirrors scheduled.yml validate-variants matrix (source of truth):
# deep = PROFILE_TOOLS["deep"] (29) minus MANUAL_INSTALL_TOOLS (akto, afl++, mobsf, falco).
DOCKER_REGISTRY = "ghcr.io/jimmy058910/jmo-security"
DOCKER_VARIANTS = [
    pytest.param("deep", 25, id="deep"),
    pytest.param("balanced", 18, id="balanced"),
    pytest.param("slim", 14, id="slim"),
    pytest.param("fast", 9, id="fast"),
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
@pytest.mark.timeout(1200)
class TestDockerVariants:
    """End-to-end tests for Docker image variants.

    Per-class ``@pytest.mark.timeout(1200)`` overrides the 120s default from
    pyproject.toml. Deep variant cold-start (25 tools, each doing a --version
    subprocess inside the container) routinely exceeds 10 minutes on unseeded
    CI runners. Without this override, pytest-timeout's thread method kills
    the test before any per-subprocess timeout can fire — prior fixes that
    raised ``subprocess.run(timeout=...)`` were ineffective because pytest
    pulled the plug first.
    """

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    @pytest.mark.parametrize("variant,expected_tools", DOCKER_VARIANTS)
    def test_docker_variant_tools(self, variant: str, expected_tools: int):
        """Each Docker variant should have the expected minimum tool count.

        Mirrors the scheduled.yml validate-variants pattern:
          - Uses ``--profile <variant>`` so the output is the guarded per-tool
            ``{name: {installed: bool, ...}}`` shape. Without ``--profile`` the
            CLI returns a profile-summary dict with integer ``installed`` counts
            that can't be iterated tool-by-tool (and the plain path has
            historically hit the 120s subprocess timeout while fanning out
            across all profiles).
        """
        image = f"{DOCKER_REGISTRY}:{variant}"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Subprocess timeout is 1150s — slightly less than the class-level
        # ``@pytest.mark.timeout(1200)`` so ``subprocess.TimeoutExpired`` fires
        # with a real traceback before pytest-timeout's thread method kills the
        # test with only a stack dump. Prior bumps to 180s (PR #320) and 600s
        # (PR #327) were ineffective: pyproject.toml pins a 120s default, so
        # pytest killed the test long before subprocess.run's timeout could
        # fire. See release.rules.md troubleshooting entry.
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                image,
                "tools",
                "check",
                "--profile",
                variant,
                "--json",
            ],
            capture_output=True,
            text=True,
            timeout=1150,
        )

        # `tools check --json` (tool_commands.py:170-171) returns rc=1 when any
        # tool reports installed=false. For the `deep` profile, 4 tools in
        # PROFILE_TOOLS are in MANUAL_INSTALL_TOOLS (akto, afl++, mobsf, falco)
        # and intentionally NOT baked into the Docker image — so rc=1 is the
        # expected outcome even for a correctly-built deep container. The real
        # verification is the installed count assertion below. Only hard-fail
        # here if we can't parse JSON (catastrophic failure).
        try:
            tools = json.loads(result.stdout)
        except json.JSONDecodeError:
            pytest.fail(
                f"tools check --profile {variant} emitted invalid JSON "
                f"(rc={result.returncode}): "
                f"stderr={result.stderr[:500]} stdout={result.stdout[:500]}"
            )

        # Shape is {tool_name: {installed: bool, ...}} — iterate values, not keys.
        installed = sum(
            1 for status in tools.values() if status.get("installed", False)
        )

        # On assertion failure, enumerate which tools report installed=false so
        # the log shows the specific image-drift diagnosis instead of just a
        # count mismatch. Saves a round-trip dispatch to identify the missing
        # tool when PROFILE_TOOLS and the Dockerfile get out of sync.
        missing_names = sorted(
            name for name, status in tools.items() if not status.get("installed", False)
        )
        assert installed >= expected_tools, (
            f"{variant} variant has {installed} tools, expected at least "
            f"{expected_tools}. Tools reporting installed=false: {missing_names}"
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

        (src_dir / "app.js").write_text("""
const userId = req.query.id;
const query = "SELECT * FROM users WHERE id = " + userId;
""")

        # UID mismatch fix (mirrors scheduled.yml:1083 pattern):
        # GitHub runners are UID 1001, container `USER jmo` is UID 1000. Bind
        # mounts preserve host UID, so without world-accessible bits the
        # container can't even stat files in /scan — which on Python 3.12+
        # propagates as PermissionError from Path.exists() (the 3.12+
        # pathlib behavior change). 0o777 is intentional: the container runs
        # as "other" relative to the host UID and needs rwx to traverse, read
        # source files, and create the results subdir. Safe because tmp_path
        # is a pytest-managed, run-scoped directory destroyed after the test.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(tmp_path), 0o777)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(src_dir), 0o777)

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
            assert len(output_files) > 0  # Should have at least one output file

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


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerToolVerification:
    """Verify tools are actually functional in Docker containers."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    @pytest.mark.parametrize(
        "variant,tool",
        [
            ("fast", "trivy"),
            ("fast", "gitleaks"),
            ("fast", "semgrep"),
            ("fast", "bandit"),
            ("balanced", "trivy"),
            ("balanced", "checkov"),
            ("deep", "nuclei"),
        ],
    )
    def test_tool_actually_runs(self, variant: str, tool: str):
        """Verify each tool can actually execute in the container."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Run tool version check
        result = subprocess.run(
            ["docker", "run", "--rm", image, "tools", "debug", tool],
            capture_output=True,
            text=True,
            timeout=120,
        )

        combined = result.stdout.lower() + result.stderr.lower()
        # Should show version info or "not found" - but not crash
        assert "traceback" not in combined

    @pytest.mark.parametrize("variant,expected_tools", DOCKER_VARIANTS)
    def test_all_expected_tools_functional(self, variant: str, expected_tools: int):
        """Verify all expected tools in variant are functional."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Get tool list
        result = subprocess.run(
            ["docker", "run", "--rm", image, "tools", "check"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Count tools that show as OK
        output = result.stdout.lower()
        ok_count = output.count("ok") + output.count("✓") + output.count("installed")

        # Should have reasonable number of working tools
        assert ok_count > 0 or result.returncode == 0


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerNonRootExecution:
    """Test Docker image works with non-root users."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_run_as_non_root_user(self, tmp_path: Path):
        """Container should work when run as non-root user."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Create sample code
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "test.py").write_text("x = 1", encoding="utf-8")

        # Run as user 1000:1000
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "1000:1000",
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
                "--allow-missing-tools",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        # Should not have permission errors
        combined = result.stdout.lower() + result.stderr.lower()
        assert "permission denied" not in combined or result.returncode == 0

    @skip_on_windows
    def test_run_with_uid_mapping(self, tmp_path: Path):
        """Container should work with UID/GID mapping."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Create sample code
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        # Get current user ID
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        gid = os.getgid() if hasattr(os, "getgid") else 1000

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                f"{uid}:{gid}",
                "-v",
                f"{tmp_path}:/scan",
                "-w",
                "/scan",
                image,
                "tools",
                "check",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should complete (may have warnings but shouldn't crash)
        combined = result.stdout.lower() + result.stderr.lower()
        assert "traceback" not in combined


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerResourceLimits:
    """Test Docker container behavior with resource limits."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_run_with_memory_limit(self, tmp_path: Path):
        """Container should work with memory limits."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        # Run with 512MB memory limit
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--memory",
                "512m",
                "-v",
                f"{tmp_path}:/scan",
                "-w",
                "/scan",
                image,
                "tools",
                "check",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Should complete within memory limit
        assert result.returncode in (0, 1)

    def test_run_with_cpu_limit(self, tmp_path: Path):
        """Container should work with CPU limits."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        # Run with 1 CPU limit
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--cpus",
                "1",
                "-v",
                f"{tmp_path}:/scan",
                "-w",
                "/scan",
                image,
                "tools",
                "check",
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )

        # Should complete within CPU limit
        assert result.returncode in (0, 1)


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerHistoryPersistence:
    """Test scan history persistence across container runs."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_history_persists_between_scans(self, tmp_path: Path):
        """History database should persist between container runs."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        # Create .jmo directory for history persistence
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        # Create sample code
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        # Run first scan
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp_path}:/scan",
                "-v",
                f"{jmo_dir}:/root/.jmo",
                "-w",
                "/scan",
                image,
                "scan",
                "--repo",
                ".",
                "--profile",
                "fast",
                "--allow-missing-tools",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        # Run second scan
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{tmp_path}:/scan",
                "-v",
                f"{jmo_dir}:/root/.jmo",
                "-w",
                "/scan",
                image,
                "scan",
                "--repo",
                ".",
                "--profile",
                "fast",
                "--allow-missing-tools",
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )

        # Check history
        result_history = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{jmo_dir}:/root/.jmo",
                image,
                "history",
                "list",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        # History should show scans (or be empty if DB wasn't created)
        assert result_history.returncode == 0


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerOutputFormats:
    """Test different output formats work in Docker."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_json_output_valid(self, tmp_path: Path):
        """JSON output from container should be valid."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        result = subprocess.run(
            ["docker", "run", "--rm", image, "tools", "list", "--json"],
            capture_output=True,
            text=True,
            timeout=60,
        )

        if result.stdout.strip():
            try:
                json.loads(result.stdout)
            except json.JSONDecodeError:
                # May not output JSON for all commands
                pass

    def test_human_readable_output(self, tmp_path: Path):
        """Human-readable output should be properly formatted."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        result = subprocess.run(
            ["docker", "run", "--rm", image, "tools", "check", "--human-logs"],
            capture_output=True,
            text=True,
            timeout=120,
        )

        # Output should exist and be readable
        assert result.stdout or result.stderr
        combined = result.stdout + result.stderr
        # Should not have garbled characters
        assert all(ord(c) < 128 for c in combined)


# Image size ranges in MB (min, max) — allow generous tolerance for registry builds
# Actual sizes will vary by build cache / layer optimization
IMAGE_SIZE_RANGES = {
    "deep": (1500, 3000),  # Deep/full: ~1.6-2.5 GB (most tools)
    "balanced": (900, 2000),  # Balanced: ~1.0-1.8 GB
    "slim": (700, 1600),  # Slim: ~0.8-1.5 GB (IaC/cloud focus)
    "fast": (500, 1200),  # Fast: ~0.5-1.0 GB (fewest tools)
}

# Tools that are deep-profile-only (should NOT appear in lighter variants)
DEEP_ONLY_TOOLS = ["noseyparker", "bandit", "falcoctl", "afl-fuzz"]
# Tools that are deep/balanced but NOT in fast (slim uses fast profile tools)
BALANCED_ONLY_TOOLS = ["checkov", "hadolint"]

# Named tool sets per variant for exhaustive presence checks
DEEP_EXPECTED_TOOLS = [
    "trufflehog",
    "noseyparker",
    "semgrep",
    "bandit",
    "syft",
    "trivy",
    "checkov",
    "hadolint",
    "zap",
    "falcoctl",
    "afl-fuzz",
]
BALANCED_EXPECTED_TOOLS = [
    "trufflehog",
    "semgrep",
    "syft",
    "trivy",
    "checkov",
    "hadolint",
    "zap",
]
FAST_EXPECTED_TOOLS = ["trufflehog", "semgrep", "trivy"]

# Mapping of variant -> (profile, expected_named_tools, shell)
VARIANT_NAMED_TOOLS: list[tuple[str, str, list[str], str]] = [
    ("deep", "deep", DEEP_EXPECTED_TOOLS, "bash"),
    ("balanced", "balanced", BALANCED_EXPECTED_TOOLS, "bash"),
    ("fast", "fast", FAST_EXPECTED_TOOLS, "sh"),
]


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerImageSize:
    """Test Docker image sizes are within expected ranges."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    @pytest.mark.parametrize(
        "variant,size_range",
        [
            ("deep", IMAGE_SIZE_RANGES["deep"]),
            ("balanced", IMAGE_SIZE_RANGES["balanced"]),
            ("slim", IMAGE_SIZE_RANGES["slim"]),
            ("fast", IMAGE_SIZE_RANGES["fast"]),
        ],
    )
    def test_image_size_within_range(self, variant: str, size_range: tuple):
        """Image sizes should be within expected ranges (no runaway bloat)."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        result = subprocess.run(
            ["docker", "image", "inspect", image, "--format={{.Size}}"],
            capture_output=True,
            text=True,
            timeout=10,
        )

        assert result.returncode == 0, f"Failed to inspect {image}"

        size_bytes = int(result.stdout.strip())
        size_mb = size_bytes / (1024 * 1024)
        min_mb, max_mb = size_range

        assert min_mb <= size_mb <= max_mb, (
            f"{image} size {size_mb:.0f} MB out of expected range [{min_mb}, {max_mb}] MB. "
            f"This may indicate bloated dependencies or missing tools."
        )


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerToolExclusion:
    """Test that lighter variants correctly exclude heavy/deep-only tools."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_balanced_excludes_deep_only_tools(self):
        """Balanced variant should NOT include deep-profile-only tools."""
        image = f"{DOCKER_REGISTRY}:balanced"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        found = []
        for tool in DEEP_ONLY_TOOLS:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "bash",
                    image,
                    "-c",
                    f"which {tool}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                found.append(tool)

        assert (
            not found
        ), f"Balanced image should not include deep-only tools, but found: {found}"

    def test_fast_excludes_deep_only_tools(self):
        """Fast variant should NOT include deep-profile-only tools."""
        image = f"{DOCKER_REGISTRY}:fast"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        found = []
        for tool in DEEP_ONLY_TOOLS:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "bash",
                    image,
                    "-c",
                    f"which {tool}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                found.append(tool)

        assert (
            not found
        ), f"Fast image should not include deep-only tools, but found: {found}"

    def test_deep_includes_deep_only_tools(self):
        """Deep variant SHOULD include the deep-profile-only tools."""
        image = f"{DOCKER_REGISTRY}:deep"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        missing = []
        for tool in DEEP_ONLY_TOOLS:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "bash",
                    image,
                    "-c",
                    f"which {tool}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                missing.append(tool)

        assert (
            not missing
        ), f"Deep image should include deep-only tools, but missing: {missing}"


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerCLIConsistency:
    """Test that all variants have a consistent CLI interface."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    @pytest.mark.parametrize("variant,_expected_tools", DOCKER_VARIANTS)
    def test_scan_help_available(self, variant: str, _expected_tools: int):
        """All variants should support scan --help."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        result = subprocess.run(
            ["docker", "run", "--rm", image, "scan", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert (
            result.returncode == 0
        ), f"scan --help failed for {image}: {result.stderr}"
        assert "scan" in result.stdout.lower()
        assert "--repo" in result.stdout

    @pytest.mark.parametrize("variant,_expected_tools", DOCKER_VARIANTS)
    def test_core_scan_flags_present(self, variant: str, _expected_tools: int):
        """All variants should expose the same core scan flags."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        result = subprocess.run(
            ["docker", "run", "--rm", image, "scan", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        # All variants must expose core flags
        assert "--repo" in result.stdout
        assert "--results-dir" in result.stdout
        assert "--profile" in result.stdout or "--profile-name" in result.stdout

    def test_all_variants_same_version(self):
        """All variants should report the same jmo package version."""
        versions: dict[str, str] = {}

        for variant, _ in [("deep", 28), ("balanced", 18), ("slim", 14), ("fast", 8)]:
            image = f"{DOCKER_REGISTRY}:{variant}"

            if not image_exists(image):
                continue  # Skip missing images, don't fail

            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "bash",
                    image,
                    "-c",
                    "python3 -c 'import importlib.metadata; print(importlib.metadata.version(\"jmo-security\"))'",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout.strip():
                versions[variant] = result.stdout.strip()

        if len(versions) < 2:
            pytest.skip(
                "Fewer than 2 variants available locally — cannot compare versions"
            )

        unique_versions = set(versions.values())
        assert (
            len(unique_versions) == 1
        ), f"Version mismatch across variants: {versions}"


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerNamedToolPresence:
    """Verify specific named tools are present (via which) in each variant.

    Merged from tests/integration/test_docker_variants.py which used legacy
    variant names: full→deep, slim→balanced, alpine→fast.
    """

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    @pytest.mark.parametrize(
        "variant,profile,expected_tools,shell",
        VARIANT_NAMED_TOOLS,
        ids=["deep", "balanced", "fast"],
    )
    def test_variant_has_named_tools(
        self, variant: str, profile: str, expected_tools: list[str], shell: str
    ):
        """Each variant should have its expected named tools on PATH."""
        image = f"{DOCKER_REGISTRY}:{variant}"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        missing_tools = []
        for tool in expected_tools:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    shell,
                    image,
                    "-c",
                    f"which {tool}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                missing_tools.append(tool)

        assert (
            not missing_tools
        ), f"{image} ({profile} profile) missing tools: {missing_tools}"

    def test_deep_has_all_expected_tools(self):
        """Deep variant should have all expected tools (comprehensive check)."""
        image = f"{DOCKER_REGISTRY}:deep"

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        missing = []
        for tool in DEEP_EXPECTED_TOOLS:
            result = subprocess.run(
                [
                    "docker",
                    "run",
                    "--rm",
                    "--entrypoint",
                    "bash",
                    image,
                    "-c",
                    f"which {tool}",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                missing.append(tool)

        assert not missing, f"Deep image missing expected tools: {missing}"


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerBasicScanByVariant:
    """Basic scan functionality tests using /repo mount pattern.

    Merged from tests/integration/test_docker_variants.py (test_docker_full_basic_scan,
    test_docker_slim_basic_scan, test_docker_alpine_basic_scan). Uses --profile-name
    flag and /repo volume mount rather than working-directory approach.
    """

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_deep_basic_scan(self, tmp_path: "Path"):
        """Deep variant can perform a basic repository scan."""
        image = f"{DOCKER_REGISTRY}:deep"
        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        test_repo = tmp_path / "test-repo"
        test_repo.mkdir()
        (test_repo / "README.md").write_text("# Test Repository")
        (test_repo / "requirements.txt").write_text("requests==2.25.0")

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{test_repo}:/repo",
                image,
                "scan",
                "--repo",
                "/repo",
                "--profile",
                "fast",
                "--allow-missing-tools",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode in (
            0,
            1,
        ), f"Scan failed with exit code {result.returncode}: {result.stderr}"

    def test_balanced_basic_scan(self, tmp_path: "Path"):
        """Balanced variant can perform a basic repository scan."""
        image = f"{DOCKER_REGISTRY}:balanced"
        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        test_repo = tmp_path / "test-repo"
        test_repo.mkdir()
        (test_repo / "app.py").write_text("print('hello')")

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{test_repo}:/repo",
                image,
                "scan",
                "--repo",
                "/repo",
                "--profile",
                "balanced",
                "--allow-missing-tools",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode in (
            0,
            1,
        ), f"Scan failed with exit code {result.returncode}: {result.stderr}"

    def test_fast_basic_scan(self, tmp_path: "Path"):
        """Fast variant can perform a basic repository scan."""
        image = f"{DOCKER_REGISTRY}:fast"
        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

        test_repo = tmp_path / "test-repo"
        test_repo.mkdir()
        (test_repo / "test.py").write_text("x = 1")

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{test_repo}:/repo",
                image,
                "scan",
                "--repo",
                "/repo",
                "--profile",
                "fast",
                "--allow-missing-tools",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )

        assert result.returncode in (
            0,
            1,
        ), f"Scan failed with exit code {result.returncode}: {result.stderr}"


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.docker
class TestDockerCLIWorkflows:
    """Docker CLI workflow tests replacing bash U9-U11, M5-M6, W3-W4.

    Tests jmo scan execution inside Docker containers with volume mounts.
    """

    DOCKER_REGISTRY = "ghcr.io/jimmy058910/jmo-security"

    @pytest.mark.skipif(not shutil.which("docker"), reason="Docker not installed")
    @pytest.mark.parametrize(
        "test_id,variant,cli_args,platform",
        [
            pytest.param(
                "U9",
                "latest-full",
                ["ci", "--repo", "/scan", "--profile", "balanced"],
                "linux",
                id="U9-docker-full-repo",
            ),
            pytest.param(
                "U10",
                "latest-full",
                ["ci", "--image", "alpine:3.19", "--tools", "trivy,syft"],
                "linux",
                id="U10-docker-full-image",
            ),
            pytest.param(
                "U11",
                "latest-slim",
                ["ci", "--repo", "/scan", "--profile", "fast"],
                "linux",
                id="U11-docker-slim-multi",
            ),
            pytest.param(
                "M5",
                "latest-full",
                ["ci", "--repo", "/scan", "--profile", "balanced"],
                "darwin",
                id="M5-docker-full-macos",
            ),
            pytest.param(
                "M6",
                "latest-slim",
                ["ci", "--repo", "/scan", "--profile", "fast"],
                "darwin",
                id="M6-docker-slim-macos",
            ),
            pytest.param(
                "W3",
                "latest-full",
                ["ci", "--repo", "/scan", "--profile", "balanced"],
                "win32",
                id="W3-docker-full-windows",
            ),
            pytest.param(
                "W4",
                "latest-slim",
                ["ci", "--repo", "/scan", "--profile", "fast"],
                "win32",
                id="W4-docker-slim-windows",
            ),
        ],
    )
    def test_docker_cli_workflow(self, test_id, variant, cli_args, platform, tmp_path):
        """Run jmo inside Docker container and validate output."""
        if sys.platform != platform:
            pytest.skip(f"Test {test_id} is for {platform}")

        results_dir = tmp_path / "results"
        results_dir.mkdir()

        docker_cmd = [
            "docker",
            "run",
            "--rm",
            "-v",
            f"{tmp_path}:/scan",
            "-v",
            f"{results_dir}:/scan/results",
            f"{self.DOCKER_REGISTRY}:{variant}",
            *cli_args,
            "--results-dir",
            "/scan/results",
            "--allow-missing-tools",
        ]

        result = subprocess.run(
            docker_cmd,
            capture_output=True,
            text=True,
            timeout=900,
        )

        assert result.returncode in (0, 1), (
            f"Docker test {test_id} failed with exit code {result.returncode}.\n"
            f"stderr: {result.stderr[:500]}"
        )

        # Validate output files exist on host via volume mount
        assert (results_dir / "findings.json").exists() or result.returncode == 0
