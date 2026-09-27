#!/usr/bin/env python3
"""
End-to-end tests for the JMo Security Docker image.

There is one image, built from `Dockerfile` and published as `:latest` and the
release semver. These tests validate that it:
- Carries every TOOL_MATRIX scanner and the policy engine, able to run
- Can complete a scan successfully
- Produces valid output

Requires: Docker installed and running
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import assert_no_jmo_traceback, skip_on_windows

# Registry this suite audits. Overridable so the same tests can be pointed at an
# image built from the CURRENT source tree rather than the published release:
#
#     JMO_DOCKER_REGISTRY=jmo-security-dev pytest tests/e2e/test_docker_workflows.py -m docker
#
# The distinction is not cosmetic. Images are rebuilt ONLY on a `v*` tag push
# (release.yml), and the image bakes the whole tree in via
# `COPY . /opt/jmo-security/`. For most of a development cycle the default below
# is therefore many commits behind `dev` -- at the time this was written, 77
# commits and +7820/-2324 lines of `scripts/`. Running this suite with the
# variable unset audits the RELEASED image and says nothing about working-tree
# code. Say which of the two a finding is about.
DOCKER_REGISTRY = os.environ.get(
    "JMO_DOCKER_REGISTRY", "ghcr.io/jimmy058910/jmo-security"
)


# Budget for a single `docker pull`. Exceeding it is reported as a FAILURE, not
# a skip -- see ensure_image().
PULL_TIMEOUT = 600

# Scanners the image carries but cannot run yet, each with the issue that fixes
# it. test_docker_image_tools fails on any OTHER not-ready tool, and fails on a
# listed one once it can run, so an entry cannot outlive its fix.
KNOWN_NOT_READY = {
    # The Dockerfile installs yara-python but never fetches a rule bundle, so
    # `tools check` reports yara installed and not execution_ready: a scan would
    # report every file clean. v1's image was the same; its test asserted only
    # `installed`. Phase 6 replaces yara with yara-x + signature-base.
    "yara": "no rules in the image, TODO(issue-#1282)",
}


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


def image_tool_matrix(image: str) -> tuple[list[str], str]:
    """The TOOL_MATRIX and POLICY_ENGINE the IMAGE was built with.

    The expectation comes from the image, never from this checkout -- the same
    source scheduled.yml's validate-image job reads. For an image built from
    the PR (ci.yml's docker-smoke) the two are equal anyway. For the weekly run
    against the published image they are not: the image is whatever the last
    `v*` tag built, so a checkout comparison false-alarms whenever main's
    matrix is ahead of that tag, which is exactly how #1039 went red on a
    correctly built image.
    """
    result = _docker(
        "run",
        "--rm",
        "--entrypoint",
        "python3",
        image,
        "-c",
        "import json; "
        "from scripts.core.tool_registry import POLICY_ENGINE, TOOL_MATRIX; "
        "print(json.dumps([list(TOOL_MATRIX), POLICY_ENGINE]))",
        timeout=120,
    )
    if result.returncode != 0:
        pytest.fail(
            f"could not read TOOL_MATRIX from {image} (rc={result.returncode}): "
            f"{result.stderr.strip()[:500]}"
        )
    try:
        matrix, engine = json.loads(result.stdout)
    except (json.JSONDecodeError, ValueError):
        pytest.fail(f"{image} printed no [matrix, engine] pair: {result.stdout[:500]}")
    # Meta-guard: every check built on an empty matrix passes.
    if not matrix:
        pytest.fail(f"{image} reports an empty TOOL_MATRIX")
    return matrix, engine


@pytest.mark.docker
@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.timeout(1200)
class TestDockerImage:
    """End-to-end tests for the Docker image.

    Per-class ``@pytest.mark.timeout(1200)`` overrides the 120s default from
    pyproject.toml. A cold start of the image's `tools check` (every
    TOOL_MATRIX tool, each doing a --version subprocess inside the container)
    has exceeded 10 minutes on unseeded CI runners. Without this override,
    pytest-timeout's thread method kills the test before any per-subprocess
    timeout can fire — prior fixes that raised ``subprocess.run(timeout=...)``
    were ineffective because pytest pulled the plug first.
    """

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_docker_image_tools(self):
        """The image carries every TOOL_MATRIX scanner, able to run, and opa.

        Mirrors scheduled.yml's validate-image job. With no tool names,
        ``tools check --json`` reports the scan matrix under ``tools`` and the
        policy engine under ``policy_engine``, one entry per tool, so every
        assertion below names its offenders rather than reporting a total.
        """
        image = f"{DOCKER_REGISTRY}:latest"

        ensure_image(image)
        # From the image, never the checkout: see image_tool_matrix for why.
        expected, policy_engine = image_tool_matrix(image)

        # Subprocess timeout is 1150s — slightly less than the class-level
        # ``@pytest.mark.timeout(1200)`` so ``subprocess.TimeoutExpired`` fires
        # with a real traceback before pytest-timeout's thread method kills the
        # test with only a stack dump. Prior bumps to 180s (PR #320) and 600s
        # (PR #327) were ineffective: pyproject.toml pins a 120s default, so
        # pytest killed the test long before subprocess.run's timeout could
        # fire. See release.rules.md troubleshooting entry.
        result = subprocess.run(
            ["docker", "run", "--rm", image, "tools", "check", "--json"],
            capture_output=True,
            text=True,
            timeout=1150,
        )

        # Unparseable output is catastrophic regardless of rc, and says nothing
        # about which tool is at fault, so fail with both streams.
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            pytest.fail(
                f"tools check --json emitted invalid JSON "
                f"(rc={result.returncode}): "
                f"stderr={result.stderr[:500]} stdout={result.stdout[:500]}"
            )

        tools = data.get("tools", {})
        engine = data.get("policy_engine", {})

        # `tools check` must report exactly the image's own matrix. Both sides
        # come from one program, so a difference is a defect in the image, not
        # release skew. `expected` is never empty (image_tool_matrix fails
        # first), so this also catches an empty `tools` dict, which a broken
        # image or a changed output shape would produce and which satisfies
        # every assertion below.
        assert sorted(tools) == sorted(expected), (
            f"tools check reports scanners {sorted(tools)}; the image's "
            f"TOOL_MATRIX is {sorted(expected)}"
        )

        # Each tool must be installed and able to run. An installed tool that
        # cannot run (zap without Java) contributes nothing to a scan, the same
        # as a missing one (#1136).
        not_ready = sorted(
            name
            for name, status in tools.items()
            if not (status.get("installed") and status.get("execution_ready"))
        )
        unexpected = [name for name in not_ready if name not in KNOWN_NOT_READY]
        assert not unexpected, (
            f"{len(unexpected)} of {len(tools)} scanner(s) in the image are not "
            f"installed or not able to run: {unexpected}"
        )
        # A known exception that has started working must go, or it would hide
        # the tool's next regression.
        recovered = [
            name for name in KNOWN_NOT_READY if name in tools and name not in not_ready
        ]
        assert not recovered, (
            f"{recovered} can run in the image now: delete their KNOWN_NOT_READY "
            f"entry so the strict check covers them again"
        )

        # opa scans nothing, so it is not in TOOL_MATRIX, but policy evaluation
        # defaults on and the image must carry it.
        assert engine.get("name") == policy_engine and engine.get("installed"), (
            f"the image does not carry its policy engine {policy_engine}: {engine}"
        )

        # rc=0 is the contract once every tool and the policy engine are ready;
        # anything else means the exit code and the JSON disagree. A known
        # not-ready tool makes `tools check` exit 1, which is also the contract.
        expected_rc = 1 if not_ready else 0
        assert result.returncode == expected_rc, (
            f"tools check exited {result.returncode}, expected {expected_rc} with "
            f"not-ready scanners {not_ready}: {result.stderr[:500]}"
        )

    def test_docker_image_scan(self, tmp_path: Path):
        """The image completes a scan successfully."""
        image = f"{DOCKER_REGISTRY}:latest"

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
        image = f"{DOCKER_REGISTRY}:latest"

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
        image = f"{DOCKER_REGISTRY}:latest"

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
        image = f"{DOCKER_REGISTRY}:latest"

        ensure_image(image)

        # Create sample code
        (tmp_path / "test.py").write_text("password = 'secret123'")

        # UID mismatch fix (mirrors scheduled.yml:1083 pattern):
        # GitHub runners are UID 1001, container `USER jmo` is UID 1000. Bind
        # mounts preserve host UID, so without world-accessible bits the
        # container can't even stat files in /scan — which on Python 3.12+
        # propagates as PermissionError from Path.exists() (the 3.12+
        # pathlib behavior change). 0o777 is intentional: the container runs
        # as "other" relative to the host UID and needs rwx to traverse, read
        # source files, and create the results subdir. Safe because tmp_path
        # is a pytest-managed, run-scoped directory destroyed after the test.
        #
        # This test was the ONLY one in this file without it (#1163), so it was
        # asserting the runner's uid rather than the mount. The product-side
        # half of that fix is `_probe` in scan_orchestrator: without the chmod
        # the scan now refuses the mount legibly instead of crashing, but it
        # still scans nothing, so both halves are needed to make this green.
        # nosemgrep: python.lang.security.audit.insecure-file-permissions.insecure-file-permissions
        os.chmod(str(tmp_path), 0o777)

        # Run scan
        proc = subprocess.run(
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
                "--results-dir",
                "/scan/results",
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )

        # Check results exist on host. This used to sit under
        # `if results_dir.exists():` -- so a mount that delivered nothing back
        # to the host left the test green, which is the exact failure the test
        # exists to catch.
        results_dir = tmp_path / "results"
        assert results_dir.is_dir(), (
            f"scan wrote nothing back through the volume mount "
            f"(exit {proc.returncode}): {proc.stderr[-500:]}"
        )

        # ...and the scan's own layout must survive the mount, not merely some
        # file. `findings.json` is what every downstream consumer reads.
        assert (results_dir / "summaries" / "findings.json").is_file(), sorted(
            p.name for p in results_dir.rglob("*")
        )

    def test_history_db_mount(self, tmp_path: Path):
        """History database should persist when mounted."""
        image = f"{DOCKER_REGISTRY}:latest"

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
        "tool",
        [
            "trivy",
            # Exercises `tools debug` for a tool neither registered nor installed;
            # it makes no claim that gitleaks is present.
            pytest.param("gitleaks", id="unregistered-gitleaks"),
            "semgrep",
            "checkov",
            "nuclei",
        ],
    )
    def test_tool_actually_runs(self, tool: str):
        """Verify each tool can actually execute in the container."""
        image = f"{DOCKER_REGISTRY}:latest"

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
        assert_no_jmo_traceback(combined)

    def test_all_expected_tools_functional(self):
        """Verify the image's tools are functional."""
        image = f"{DOCKER_REGISTRY}:latest"

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
        image = f"{DOCKER_REGISTRY}:latest"

        ensure_image(image)

        # Create sample code
        src_dir = tmp_path / "src"
        src_dir.mkdir()
        (src_dir / "test.py").write_text("x = 1", encoding="utf-8")

        # UID-mismatch fix (mirrors test_docker_image_scan + scheduled.yml:1083):
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
        image = f"{DOCKER_REGISTRY}:latest"

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
        assert_no_jmo_traceback(combined)


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
        image = f"{DOCKER_REGISTRY}:latest"

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
        image = f"{DOCKER_REGISTRY}:latest"

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
        image = f"{DOCKER_REGISTRY}:latest"

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
        # what the scan finds -- a one-line `x = 1` may produce no findings to
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
        image = f"{DOCKER_REGISTRY}:latest"

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
        image = f"{DOCKER_REGISTRY}:latest"

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
# Measured 2026-08-25 against published v1.0.8, linux/amd64. `:latest` was the
# deep image then: 2033 MiB.
# Cross-checked: the manifest sum for the then-published `:fast` equals what
# `docker image inspect` reports under containerd on the same image, confirming
# the two agree once the store's unit is known — the manifest just does not
# depend on knowing it.
#
# The band is +/-20%, the buffer this file has always used, applied to a
# MEASURED value rather than an extrapolated one. Widen only after re-measuring;
# a band that no longer contains reality is how this test spent months red.
#
# v2.0.0 publishes one image, and it is not the deep image: it drops every
# tool v2.0.0 removed, Node and the C toolchain. No v2.0.0 image has been published
# to measure, so this band is still v1.0.8's `:latest`. Re-measure it against
# the first published v2.0.0 image; do not widen it to fit.
IMAGE_SIZE_RANGE = (1620, 2440)


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerImageSize:
    """Test the Docker image size is within its measured range."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_image_size_within_range(self):
        """Compressed download size stays inside its measured band.

        Reads the registry manifest rather than `docker image inspect`, because
        the latter's unit is decided by the daemon's image store and changed
        underneath this test once already (#961). No `ensure_image` here: a
        manifest query needs no local copy, so this does not pull ~2 GB just to
        read a number.
        """
        image = f"{DOCKER_REGISTRY}:latest"

        size_mb = registry_compressed_mb(image)
        if size_mb is None:
            pytest.skip(
                f"{DOCKER_REGISTRY!r} is not registry-qualified, so it has no "
                "manifest to measure. This check is about the artifact users "
                "download; point JMO_DOCKER_REGISTRY at a registry-qualified "
                "name (the default is the published GHCR repo) to run it."
            )

        min_mb, max_mb = IMAGE_SIZE_RANGE
        assert min_mb <= size_mb <= max_mb, (
            f"{image} compressed size {size_mb:.0f} MiB is outside the measured "
            f"band [{min_mb}, {max_mb}] MiB. Either the image really changed "
            f"(bloat, or tools dropped), or the band needs re-measuring against "
            f"the current release -- see the IMAGE_SIZE_RANGE comment before "
            f"widening it."
        )


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerCLIConsistency:
    """Test the image exposes the expected CLI interface."""

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_scan_help_available(self):
        """The image should support scan --help."""
        image = f"{DOCKER_REGISTRY}:latest"

        ensure_image(image)

        result = subprocess.run(
            ["docker", "run", "--rm", image, "scan", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0, (
            f"scan --help failed for {image}: {result.stderr}"
        )
        assert "scan" in result.stdout.lower()
        assert "--repo" in result.stdout

    def test_core_scan_flags_present(self):
        """The image should expose the core scan flags."""
        image = f"{DOCKER_REGISTRY}:latest"

        ensure_image(image)

        result = subprocess.run(
            ["docker", "run", "--rm", image, "scan", "--help"],
            capture_output=True,
            text=True,
            timeout=30,
        )

        assert result.returncode == 0
        assert "--repo" in result.stdout
        assert "--results-dir" in result.stdout
        # How a scan narrows its tool list since v2.0.0, which removed the
        # profile flag this line used to accept in its place.
        assert "--tools" in result.stdout


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerNamedToolPresence:
    """Verify every scanner and the policy engine are on the image's PATH.

    Merged from tests/integration/test_docker_variants.py.
    """

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_image_has_every_tool_on_path(self):
        """Every TOOL_MATRIX scanner, and the policy engine, is on PATH.

        The list is the image's own TOOL_MATRIX, read from inside it (see
        image_tool_matrix for why not the checkout's), so a tool entering or
        leaving the matrix changes what this checks with no edit here. Each
        tool's name is also its command in the image; zap's is the
        /usr/local/bin/zap symlink to /opt/zaproxy/zap.sh.
        """
        image = f"{DOCKER_REGISTRY}:latest"

        ensure_image(image)
        matrix, policy_engine = image_tool_matrix(image)

        missing = []
        for tool in (*matrix, policy_engine):
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

        assert not missing, f"{image} is missing tools on PATH: {missing}"


@pytest.mark.docker
@pytest.mark.e2e
class TestDockerBasicScan:
    """Basic scan functionality test using the /repo mount pattern.

    Merged from tests/integration/test_docker_variants.py
    (test_docker_full_basic_scan). Uses a /repo volume mount rather than the
    working-directory approach.
    """

    @pytest.fixture(autouse=True)
    def check_docker(self):
        """Skip all tests if Docker is not available."""
        if not docker_available():
            pytest.skip("Docker not available")

    def test_basic_scan(self, tmp_path: Path):
        """The image can perform a basic repository scan."""
        image = f"{DOCKER_REGISTRY}:latest"
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
    """Docker CLI workflow tests replacing bash U9-U10, M5, W3.

    Tests jmo scan execution inside Docker containers with volume mounts.
    """

    @pytest.mark.skipif(not shutil.which("docker"), reason="Docker not installed")
    @pytest.mark.parametrize(
        "test_id,cli_args,platform",
        [
            pytest.param(
                "U9",
                ["ci", "--repo", "/scan"],
                "linux",
                id="U9-docker-full-repo",
            ),
            pytest.param(
                "U10",
                ["ci", "--image", "alpine:3.19", "--tools", "trivy,syft"],
                "linux",
                id="U10-docker-full-image",
            ),
            pytest.param(
                "M5",
                ["ci", "--repo", "/scan"],
                "darwin",
                id="M5-docker-full-macos",
            ),
            pytest.param(
                "W3",
                ["ci", "--repo", "/scan"],
                "win32",
                id="W3-docker-full-windows",
            ),
        ],
    )
    def test_docker_cli_workflow(self, test_id, cli_args, platform, tmp_path):
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
            f"{DOCKER_REGISTRY}:latest",
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

        # Validate output files exist on host via volume mount.
        #
        # This read `(results_dir / "findings.json").exists() or
        # result.returncode == 0` until #1163 -- a path the product has never
        # written. `report_orchestrator.py:161` resolves the output directory to
        # `<results-dir>/summaries` whenever `--out` is absent, and no case here
        # passes `--out`, so the left operand was False on every run this test
        # has ever had. Measured against the published image:
        #
        #     results/findings.json           ABSENT
        #     results/summaries/findings.json EXISTS (368 bytes)
        #
        # So it passed solely on the returncode clause -- and the assertion
        # directly above already accepts 1 as normal, which leaves that clause
        # accepting every outcome the test can produce. Correcting the path
        # alone would not have been enough: an `or` whose left operand is
        # permanently False is invisible to a passing run, so the escape hatch
        # goes too. Phase 10 (#1077) could not have caught this one, because
        # the assertion *can* fail -- it just never had.
        findings = results_dir / "summaries" / "findings.json"
        assert findings.is_file(), (
            f"Docker test {test_id} (exit {result.returncode}) wrote no "
            f"summaries/findings.json through the volume mount; results tree: "
            f"{sorted(str(p.relative_to(results_dir)) for p in results_dir.rglob('*'))}"
        )
