"""
Integration tests for Docker image variants (full, slim, alpine).

This test suite validates that all 3 Docker image variants:
- Provide working --help and scan --help commands
- Include expected tools for their profile
- Have correct image sizes (within tolerance)
- Can perform basic scanning operations

Coverage:
- Matrix 2.1-2.6: Docker (slim) and Docker (alpine) columns
- Matrix 3.1: Docker (slim) and Docker (alpine) for all tools

Related:
- TESTING_MATRIX.md Matrix 2, Matrix 3
- COVERAGE_GAP_ANALYSIS.md Gap #1
"""

import shutil
import subprocess

import pytest


# ========== Docker Availability Check ==========

# Skip all tests in this module if Docker is not available
pytestmark = pytest.mark.skipif(
    not shutil.which("docker"), reason="Docker not installed"
)


def _docker_image_exists(image: str) -> bool:
    """Check if a Docker image exists locally."""
    if not shutil.which("docker"):
        return False
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True,
            timeout=10,
        )
        return result.returncode == 0
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return False


# ========== Configuration ==========

DOCKER_VARIANTS: list[tuple[str, str, list[str]]] = [
    # (image_tag, profile, expected_tools)
    (
        "jmo-security:latest",
        "deep",
        [
            "trufflehog",
            "noseyparker",
            "semgrep",
            "bandit",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
            "falcoctl",  # Falco CLI tool (not 'falco' binary)
            "afl-fuzz",
        ],
    ),
    (
        "jmo-security:slim",
        "balanced",
        [
            "trufflehog",
            "semgrep",
            "syft",
            "trivy",
            "checkov",
            "hadolint",
            "zap",
        ],
    ),
    (
        "jmo-security:alpine",
        "fast",
        ["trufflehog", "semgrep", "trivy"],
    ),  # Note: semgrep installed on amd64 when TARGETARCH set
]

IMAGE_SIZE_RANGES = {
    # (min_mb, max_mb) — Actual observed sizes with tolerance
    "jmo-security:latest": (1500, 2500),  # Full: ~1.6 GB (optimized from v0.6.1)
    "jmo-security:slim": (1000, 1800),  # Slim: ~1.5 GB
    "jmo-security:alpine": (
        900,
        1300,
    ),  # Alpine: ~1.0 GB (includes semgrep+checkov on amd64)
}


# ========== Category 1: Basic Functionality Tests ==========


@pytest.mark.parametrize(
    "image,_,__",
    DOCKER_VARIANTS,
    ids=lambda x: x[0] if isinstance(x, tuple) else str(x),
)
def test_docker_variant_help(image: str, _: str, __: list[str]):
    """Test all variants support --help command."""
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    cmd = ["docker", "run", "--rm", image, "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    assert result.returncode == 0, f"--help failed for {image}"
    assert "jmo" in result.stdout.lower(), f"Output missing 'jmo' for {image}"
    assert "scan" in result.stdout.lower(), f"Output missing 'scan' command for {image}"


@pytest.mark.parametrize(
    "image,_,__",
    DOCKER_VARIANTS,
    ids=lambda x: x[0] if isinstance(x, tuple) else str(x),
)
def test_docker_variant_scan_help(image: str, _: str, __: list[str]):
    """Test all variants support scan --help command."""
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    cmd = ["docker", "run", "--rm", image, "scan", "--help"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

    assert result.returncode == 0, f"scan --help failed for {image}"
    assert "scan" in result.stdout.lower()
    assert "--repo" in result.stdout or "--repos-dir" in result.stdout


# ========== Category 2: Tool Availability Tests ==========


@pytest.mark.parametrize(
    "image,profile,expected_tools",
    DOCKER_VARIANTS,
    ids=lambda x: x[0] if isinstance(x, tuple) else str(x),
)
def test_docker_variant_tools_present(
    image: str, profile: str, expected_tools: list[str]
):
    """Test each variant has tools for its profile."""
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    # Alpine uses sh, others use bash
    shell = "sh" if "alpine" in image else "bash"

    # Check each tool individually for better error messages
    # Override entrypoint since Docker images have jmo CLI as ENTRYPOINT
    missing_tools = []
    for tool in expected_tools:
        check_cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            shell,
            image,
            "-c",
            f"which {tool}",
        ]
        check_result = subprocess.run(
            check_cmd, capture_output=True, text=True, timeout=10
        )
        if check_result.returncode != 0:
            missing_tools.append(tool)

    assert (
        not missing_tools
    ), f"{image} ({profile} profile) missing tools: {missing_tools}"


def test_docker_full_has_all_tools():
    """Test full variant has all 11 tools (comprehensive check)."""
    image = "jmo-security:latest"
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    all_tools = [
        "trufflehog",
        "noseyparker",
        "semgrep",
        "bandit",
        "syft",
        "trivy",
        "checkov",
        "hadolint",
        "zap",
        "falcoctl",  # Falco CLI tool
        "afl-fuzz",
    ]

    missing = []

    for tool in all_tools:
        # Override entrypoint since Docker images have jmo CLI as ENTRYPOINT
        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "bash",
            image,
            "-c",
            f"which {tool}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode != 0:
            missing.append(tool)

    assert not missing, f"Full image missing tools: {missing}"


def test_docker_slim_excludes_deep_tools():
    """Test slim variant does NOT include deep-profile-only tools."""
    image = "jmo-security:slim"
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    deep_only_tools = ["noseyparker", "bandit", "falcoctl", "afl-fuzz"]

    found = []

    for tool in deep_only_tools:
        # Override entrypoint since Docker images have jmo CLI as ENTRYPOINT
        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "bash",
            image,
            "-c",
            f"which {tool}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            found.append(tool)

    assert (
        not found
    ), f"Slim image should not include deep-only tools, but found: {found}"


def test_docker_alpine_excludes_deep_only_tools():
    """Test alpine variant does NOT include deep-profile-only tools."""
    image = "jmo-security:alpine"
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    # Alpine (fast profile) excludes: noseyparker, bandit, falcoctl, afl-fuzz
    # Note: With TARGETARCH=amd64, alpine now includes semgrep+checkov
    deep_only_tools = ["noseyparker", "bandit", "falcoctl", "afl-fuzz"]

    found = []

    for tool in deep_only_tools:
        # Override entrypoint since Docker images have jmo CLI as ENTRYPOINT
        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            "sh",
            image,
            "-c",
            f"which {tool}",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        if result.returncode == 0:
            found.append(tool)

    assert (
        not found
    ), f"Alpine image should not include deep-only tools, but found: {found}"


# ========== Category 3: Image Size Validation Tests ==========


@pytest.mark.parametrize(
    "image,size_range",
    [
        ("jmo-security:latest", IMAGE_SIZE_RANGES["jmo-security:latest"]),
        ("jmo-security:slim", IMAGE_SIZE_RANGES["jmo-security:slim"]),
        ("jmo-security:alpine", IMAGE_SIZE_RANGES["jmo-security:alpine"]),
    ],
)
def test_docker_variant_size(image: str, size_range: tuple[int, int]):
    """Test image sizes are within expected ranges."""
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    min_mb, max_mb = size_range

    cmd = ["docker", "image", "inspect", image, "--format={{.Size}}"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

    assert result.returncode == 0, f"Failed to inspect {image}"

    size_bytes = int(result.stdout.strip())
    size_mb = size_bytes / (1024 * 1024)

    assert min_mb <= size_mb <= max_mb, (
        f"{image} size {size_mb:.0f} MB out of range [{min_mb}, {max_mb}] MB. "
        f"This may indicate bloated dependencies or missing tools."
    )


# ========== Category 4: Basic Scan Functionality Tests ==========


def test_docker_full_basic_scan(tmp_path):
    """Test full variant can perform basic repository scan."""
    image = "jmo-security:latest"
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    # Create minimal test repo
    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "README.md").write_text("# Test Repository")
    (test_repo / "requirements.txt").write_text("requests==2.25.0")  # Known CVE

    # Run scan with fast profile (quick validation)
    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{test_repo}:/repo",
        image,
        "scan",
        "--repo",
        "/repo",
        "--profile-name",
        "fast",
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    # Should complete without crashes (exit code 0 or 1 for findings)
    assert result.returncode in [
        0,
        1,
    ], f"Scan failed with exit code {result.returncode}"


def test_docker_slim_basic_scan(tmp_path):
    """Test slim variant can perform basic repository scan."""
    image = "jmo-security:slim"
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "app.py").write_text("print('hello')")

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{test_repo}:/repo",
        image,
        "scan",
        "--repo",
        "/repo",
        "--profile-name",
        "balanced",
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    assert result.returncode in [0, 1]


def test_docker_alpine_basic_scan(tmp_path):
    """Test alpine variant can perform basic repository scan."""
    image = "jmo-security:alpine"
    if not _docker_image_exists(image):
        pytest.skip(f"Docker image {image} not available locally")

    test_repo = tmp_path / "test-repo"
    test_repo.mkdir()
    (test_repo / "test.py").write_text("x = 1")

    cmd = [
        "docker",
        "run",
        "--rm",
        "-v",
        f"{test_repo}:/repo",
        image,
        "scan",
        "--repo",
        "/repo",
        "--profile-name",
        "fast",
        "--allow-missing-tools",
    ]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)

    assert result.returncode in [0, 1]


# ========== Category 5: Cross-Variant Consistency Tests ==========


def test_docker_variants_same_cli_interface():
    """Test all variants have consistent CLI interface."""
    for image, _, _ in DOCKER_VARIANTS:
        if not _docker_image_exists(image):
            pytest.skip(f"Docker image {image} not available locally")

        # Check scan command accepts same flags
        cmd = ["docker", "run", "--rm", image, "scan", "--help"]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        assert result.returncode == 0
        # All variants should support core flags
        assert "--repo" in result.stdout
        assert "--results-dir" in result.stdout
        assert "--profile-name" in result.stdout


def test_docker_variants_version_consistency():
    """Test all variants report same jmo version."""
    versions = {}

    for image, _, _ in DOCKER_VARIANTS:
        if not _docker_image_exists(image):
            pytest.skip(f"Docker image {image} not available locally")

        shell = "sh" if "alpine" in image else "bash"
        # Override entrypoint since Docker images have jmo CLI as ENTRYPOINT
        cmd = [
            "docker",
            "run",
            "--rm",
            "--entrypoint",
            shell,
            image,
            "-c",
            "python3 -c 'import importlib.metadata; print(importlib.metadata.version(\"jmo-security\"))'",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)

        if result.returncode == 0:
            versions[image] = result.stdout.strip()

    # All variants should have same version
    unique_versions = set(versions.values())
    assert len(unique_versions) == 1, f"Version mismatch across variants: {versions}"
