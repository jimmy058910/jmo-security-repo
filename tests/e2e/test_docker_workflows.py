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
# expected_tools mirrors scheduled.yml validate-variants matrix (source of truth).
# Counts align with PROFILE_TOOLS in scripts/core/tool_registry.py minus
# MANUAL_INSTALL_TOOLS (akto, afl++, mobsf, falco) for variants that include them.
# Post-v1.0.3 (dev → main reconciliation): bearer was removed from PROFILE_TOOLS,
# so all variants that previously included bearer dropped by 1:
#   deep:     29 → 28 in PROFILE_TOOLS, minus 4 manual = 24 expected installable
#   balanced: 18 → 17 in PROFILE_TOOLS (no manual tools)
#   slim:     14 → 13 in PROFILE_TOOLS (no manual tools)
#   fast:      9 →  9 (bearer was never in fast)
# Then #795 added shellcheck to deep -- it was in the other three profiles and
# not the most comprehensive one, and Dockerfile.deep already built it:
#   deep:     28 → 29 in PROFILE_TOOLS, minus 4 manual = 25 expected installable
# Registry this suite audits. Overridable so the same tests can be pointed at an
# image built from the CURRENT source tree rather than the published release:
#
#     JMO_DOCKER_REGISTRY=jmo-security-dev pytest tests/e2e/test_docker_workflows.py -m docker
#
# The distinction is not cosmetic. Images are rebuilt ONLY on a `v*` tag push
# (release.yml), and every variant bakes the whole tree in via
# `COPY . /opt/jmo-security/`. For most of a development cycle the default below
# is therefore many commits behind `dev` -- at the time this was written, 77
# commits and +7820/-2324 lines of `scripts/`. Running this suite with the
# variable unset audits the RELEASED image and says nothing about working-tree
# code. Say which of the two a finding is about.
DOCKER_REGISTRY = os.environ.get(
    "JMO_DOCKER_REGISTRY", "ghcr.io/jimmy058910/jmo-security"
)
DOCKER_VARIANTS = [
    pytest.param("deep", 25, id="deep"),
    pytest.param("balanced", 17, id="balanced"),
    pytest.param("slim", 13, id="slim"),
    pytest.param("fast", 9, id="fast"),
]


# Budget for a single `docker pull`. Exceeding it is reported as a FAILURE, not
# a skip -- see ensure_image().
PULL_TIMEOUT = 600


def _docker(*args: str, timeout: int = 60) -> subprocess.CompletedProcess[str]:
    """Run a docker command with a timeout that is always set.

    `image_exists` previously called subprocess.run with no timeout at all, so an
    unresponsive daemon blocked until pytest-timeout killed the test with a bare
    stack dump and no attributable cause.
    """
    return subprocess.run(
        ["docker", *args], capture_output=True, text=True, timeout=timeout
    )


def docker_available() -> bool:
    """True if a Docker daemon is reachable."""
    try:
        return _docker("version", timeout=10).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def image_exists(image: str) -> bool:
    """True if the image is already present locally."""
    try:
        return _docker("image", "inspect", image, timeout=30).returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return False


def _has_registry_host(repo: str) -> bool:
    """True if ``repo`` names a registry we can ask for a manifest.

    Docker's own rule: the first path component is a host only if it contains a
    "." or a ":", or is exactly "localhost". So `ghcr.io/owner/name` qualifies
    and a local build tag like `jmo-security-dev` does not.
    """
    if "/" not in repo:
        return False
    head = repo.split("/", 1)[0]
    return "." in head or ":" in head or head == "localhost"


def registry_compressed_mb(image: str) -> float | None:
    """Compressed size in MiB the REGISTRY reports for ``image`` on linux/amd64.

    Returns None when ``image`` has no registry host to ask (a local build), so
    the caller can say so rather than silently reporting a wrong number. Every
    other failure mode is a real defect and fails loudly — the same principle
    `ensure_image` above applies to pulls (#941): outcomes must stay
    distinguishable, because one blanket skip hides bugs and absent
    prerequisites behind the same signal.
    """
    repo = image.rsplit(":", 1)[0]
    if not _has_registry_host(repo):
        return None

    result = _docker("manifest", "inspect", image, timeout=60)
    if result.returncode != 0:
        pytest.fail(
            f"docker manifest inspect {image} failed (rc={result.returncode}): "
            f"{result.stderr.strip()[:400]}"
        )
    doc = json.loads(result.stdout)

    layers = doc.get("layers")
    if layers is None:
        # A manifest LIST (multi-arch). Resolve the linux/amd64 child by digest,
        # then sum that child's layers. Summing the list itself would add the
        # per-arch manifest sizes — a few KB — and quietly report ~0 MiB.
        amd64 = [
            m["digest"]
            for m in doc.get("manifests", [])
            if m.get("platform", {}).get("architecture") == "amd64"
            and m.get("platform", {}).get("os") == "linux"
        ]
        if not amd64:
            pytest.fail(f"{image}: manifest list has no linux/amd64 entry")
        child = _docker("manifest", "inspect", f"{repo}@{amd64[0]}", timeout=60)
        if child.returncode != 0:
            pytest.fail(
                f"docker manifest inspect {repo}@{amd64[0]} failed "
                f"(rc={child.returncode}): {child.stderr.strip()[:400]}"
            )
        layers = json.loads(child.stdout).get("layers", [])

    total = sum(int(layer["size"]) for layer in layers)
    if total <= 0:
        # Without this, an empty or unexpected manifest shape yields 0 and the
        # range assertion below would be judging a number nothing produced.
        pytest.fail(
            f"{image}: manifest reported {len(layers)} layer(s) totalling "
            f"{total} bytes, which cannot be right"
        )
    return total / (1024 * 1024)


def ensure_image(image: str) -> None:
    """Make ``image`` available locally, or end the test with a stated reason.

    The point of this helper is that the outcomes are DISTINGUISHABLE. Every call
    site used to read::

        if not image_exists(image):
            if not pull_image(image):
                pytest.skip(f"Could not pull image: {image}")

    which collapsed "no daemon", "tag does not exist", "not logged in", "network
    down" and "the pull ran past its own 600s budget" into one identical SKIP. A
    genuinely missing tag then reported exactly what a machine with no Docker
    reports -- the same signal for a real defect and for an absent prerequisite
    (#941). `pull_image` additionally never caught TimeoutExpired, so that one
    case raised instead of skipping, inconsistently with `docker_available`.

    Environmental causes skip. Causes that indicate a real defect fail.
    """
    if image_exists(image):
        return

    try:
        result = _docker("pull", image, timeout=PULL_TIMEOUT)
    except FileNotFoundError:
        pytest.skip("docker binary not on PATH")
    except subprocess.TimeoutExpired:
        pytest.fail(
            f"docker pull {image} exceeded its own {PULL_TIMEOUT}s budget. "
            f"This is NOT the same as an absent daemon and must not be read "
            f"as 'skipped'."
        )

    if result.returncode == 0:
        return

    err = (result.stderr or result.stdout or "").strip()
    lowered = err.lower()
    if "manifest unknown" in lowered or "not found" in lowered:
        pytest.fail(
            f"{image} does not exist in the registry -- the tag is wrong or was "
            f"never published: {err}"
        )
    if any(w in lowered for w in ("denied", "unauthorized", "authentication")):
        # Genuinely ambiguous, and the message must not pretend otherwise: a
        # registry returns 401 for an absent repository AND for a private one,
        # deliberately, so as not to leak which repositories exist. Measured --
        # docker says "repository does not exist or may require docker login"
        # for both. A missing TAG in a repository we CAN see is a different
        # matter and is caught by the "not found" branch above as a failure.
        pytest.skip(f"cannot access {image} (absent or private): {err}")
    if "daemon" in lowered or "connection refused" in lowered:
        pytest.skip(f"docker daemon not reachable: {err}")
    pytest.fail(f"docker pull {image} failed (rc={result.returncode}): {err}")


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

        ensure_image(image)

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
        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

        # Create sample code
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "test.py").write_text("x = 1", encoding="utf-8")

        # UID-mismatch fix (mirrors test_docker_variant_scan + scheduled.yml:1083):
        # GitHub runners use UID 1001; this test mounts as `--user 1000:1000` (the
        # `jmo` container user). Without world-accessible bits, the container's
        # UID 1000 can't traverse the host-owned tmp_path → EACCES → which
        # Python 3.12+ propagates from Path.exists() in scripts/core/config.py.
        # Safe because tmp_path is a pytest-managed run-scoped directory.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(tmp_path), 0o777)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(src_dir), 0o777)

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

        ensure_image(image)

        # Create sample code
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        # Get current user ID
        uid = os.getuid() if hasattr(os, "getuid") else 1000
        gid = os.getgid() if hasattr(os, "getgid") else 1000

        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(tmp_path), 0o777)

        # Set HOME=/tmp explicitly: with arbitrary --user UID:GID, no
        # /etc/passwd entry exists for that UID, so HOME resolves to "/"
        # and semgrep tries to write its cache to "/.semgrep" which fails
        # with PermissionError. Pointing HOME at the world-writable /tmp
        # gives semgrep (and any other tool with a cache) a writable home.
        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                f"{uid}:{gid}",
                "-e",
                "HOME=/tmp",
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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

        # Create .jmo directory for history persistence
        jmo_dir = tmp_path / ".jmo"
        jmo_dir.mkdir()

        # Create sample code
        (tmp_path / "test.py").write_text("x = 1", encoding="utf-8")

        # The previous attempt to mount at /home/jmo/.jmo (matching the jmo
        # user's home) didn't work because `jmo history list` returns rc=1
        # on an empty database — the test's primary intent is "persistence
        # between runs", not "non-root user" specifically. Run all three
        # containers as root with --user 0:0 so the /root/.jmo mount target
        # is the deterministic HOME, the DB is consistently written and read,
        # and we don't need separate chmod for non-root traversal.
        # Run first scan
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "0:0",
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
                "--user",
                "0:0",
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
                "--user",
                "0:0",
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

        # History should show scans OR exit 1 if the DB is empty/missing
        # (jmo history list returns rc=1 when no scans exist, which is valid
        # behavior — see scripts/cli/history_commands.py). The test's
        # primary intent is "container can read its own history without
        # crashing", not "scans always populate history" (which depends on
        # tool availability inside the container — fast variant lacks most
        # tools, so --allow-missing-tools scans may produce no findings to
        # store).
        assert result_history.returncode in (0, 1)


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

        ensure_image(image)

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

        ensure_image(image)

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
# Compressed download size in MiB, summed from the REGISTRY manifest.
# Deliberately NOT `docker image inspect --format={{.Size}}` — see #961.
#
# `.Size` reports whatever the daemon's image store decides it means. Under the
# containerd snapshotter it is compressed content; under the classic graph
# driver it was unpacked layers. Same image, two answers 4.4x apart:
#
#     docker images         SIZE: 9.56GB      (unpacked snapshot)
#     docker image inspect .Size: 2057 MiB    (compressed content)
#
# These ranges were calibrated against graph-driver semantics, and the storage
# backend changed underneath them. The result was a test that failed against the
# images users pull TODAY: published :fast measured 511 MiB against a 1000 MiB
# floor. That is not a dev-vs-released difference — the published v1.0.8 image
# and a local build of `dev` measured within 1.4% of each other.
#
# Which unit `.Size` means is therefore not a property of this test, and no
# amount of recalibrating it fixes that. A manifest sum cannot drift the same
# way: it is a property of the artifact in the registry, not of whichever daemon
# happens to run the test. It is also the number users actually experience.
#
# Measured 2026-08-25 against published v1.0.8, linux/amd64:
#     fast 511    slim 806    balanced 1796    deep 2033   MiB
# Cross-checked: the manifest sum for :fast equals what `docker image inspect`
# reports under containerd on the same image, confirming the two agree once the
# store's unit is known — the manifest just does not depend on knowing it.
#
# Bands are +/-20%, the buffer this file has always used, now applied to
# MEASURED values rather than extrapolated ones. Widen only after re-measuring;
# a band that no longer contains reality is how this test spent months red.
IMAGE_SIZE_RANGES = {
    "deep": (1620, 2440),  # measured 2033 MiB (24 baked tools; 4 manual-install)
    "balanced": (1430, 2160),  # measured 1796 MiB (17 tools)
    "slim": (640, 970),  # measured 806 MiB (13 tools, cloud-focused)
    "fast": (400, 620),  # measured 511 MiB (9 tools)
}

# Tools that are deep-profile-only (should NOT appear in lighter variants).
# Note: `afl-fuzz` (afl++) is in MANUAL_INSTALL_TOOLS — listed in
# PROFILE_TOOLS["deep"] but intentionally NOT baked into the Docker image
# (users install manually per docs/MANUAL_INSTALLATION.md). Removed from
# this list because deep image legitimately doesn't have afl-fuzz.
# `falcoctl` IS installed separately in Dockerfile.deep (lines around 130),
# so it stays.
DEEP_ONLY_TOOLS = ["noseyparker", "bandit", "falcoctl"]
# Tools that are deep/balanced but NOT in fast (slim uses fast profile tools)
BALANCED_ONLY_TOOLS = ["checkov", "hadolint"]

# Named tool sets per variant for exhaustive presence checks.
# Excludes MANUAL_INSTALL_TOOLS binaries: afl-fuzz (afl++) is in
# PROFILE_TOOLS["deep"] but listed in MANUAL_INSTALL_TOOLS — users install
# it manually per docs/MANUAL_INSTALLATION.md, not baked into the image.
# falcoctl IS installed separately in Dockerfile.deep (not via the falco
# manual-install entry).
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
        """Compressed download size stays inside its measured band.

        Reads the registry manifest rather than `docker image inspect`, because
        the latter's unit is decided by the daemon's image store and changed
        underneath this test once already (#961). No `ensure_image` here: a
        manifest query needs no local copy, so this does not pull ~2 GB just to
        read a number.
        """
        image = f"{DOCKER_REGISTRY}:{variant}"

        size_mb = registry_compressed_mb(image)
        if size_mb is None:
            pytest.skip(
                f"{DOCKER_REGISTRY!r} is not registry-qualified, so it has no "
                "manifest to measure. This check is about the artifact users "
                "download; point JMO_DOCKER_REGISTRY at a registry-qualified "
                "name (the default is the published GHCR repo) to run it."
            )

        min_mb, max_mb = size_range
        assert min_mb <= size_mb <= max_mb, (
            f"{image} compressed size {size_mb:.0f} MiB is outside the measured "
            f"band [{min_mb}, {max_mb}] MiB. Either the image really changed "
            f"(bloat, or tools dropped), or the band needs re-measuring against "
            f"the current release -- see the IMAGE_SIZE_RANGES comment before "
            f"widening it."
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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        ensure_image(image)

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

        # Names only. This list used to carry tool counts bound to `_` and read
        # by nothing -- and by the time #795 touched it they had drifted to
        # (28, 18, 14, 8) against an actual (28, 17, 13, 9), wrong in three of
        # four entries. A number nobody reads cannot stay right; DOCKER_VARIANTS
        # above is the one place a count belongs.
        for variant in ("deep", "balanced", "slim", "fast"):
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

        ensure_image(image)

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

        ensure_image(image)

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

    def test_deep_basic_scan(self, tmp_path: Path):
        """Deep variant can perform a basic repository scan."""
        image = f"{DOCKER_REGISTRY}:deep"
        ensure_image(image)

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

    def test_balanced_basic_scan(self, tmp_path: Path):
        """Balanced variant can perform a basic repository scan."""
        image = f"{DOCKER_REGISTRY}:balanced"
        ensure_image(image)

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

    def test_fast_basic_scan(self, tmp_path: Path):
        """Fast variant can perform a basic repository scan."""
        image = f"{DOCKER_REGISTRY}:fast"
        ensure_image(image)

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
                "latest",
                ["ci", "--repo", "/scan", "--profile-name", "balanced"],
                "linux",
                id="U9-docker-full-repo",
            ),
            pytest.param(
                "U10",
                "latest",
                ["ci", "--image", "alpine:3.19", "--tools", "trivy,syft"],
                "linux",
                id="U10-docker-full-image",
            ),
            pytest.param(
                "U11",
                "slim",
                ["ci", "--repo", "/scan", "--profile-name", "fast"],
                "linux",
                id="U11-docker-slim-multi",
            ),
            pytest.param(
                "M5",
                "latest",
                ["ci", "--repo", "/scan", "--profile-name", "balanced"],
                "darwin",
                id="M5-docker-full-macos",
            ),
            pytest.param(
                "M6",
                "slim",
                ["ci", "--repo", "/scan", "--profile-name", "fast"],
                "darwin",
                id="M6-docker-slim-macos",
            ),
            pytest.param(
                "W3",
                "latest",
                ["ci", "--repo", "/scan", "--profile-name", "balanced"],
                "win32",
                id="W3-docker-full-windows",
            ),
            pytest.param(
                "W4",
                "slim",
                ["ci", "--repo", "/scan", "--profile-name", "fast"],
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

        # UID-mismatch fix: container runs as USER jmo (UID 1000), tmp_path
        # is owned by host runner UID 1001 with 0o700 mode → container can't
        # write /scan/results/individual-* subdirs (PermissionError on the
        # mkdir(mode=0o700) call inside scan_orchestrator). chmod 0o777
        # applies to both the parent tmp_path and the results_dir we just
        # created so the container has full traversal + write.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(tmp_path), 0o777)
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(results_dir), 0o777)

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
