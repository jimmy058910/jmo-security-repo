"""Parametrized e2e scan workflow tests.

Replaces bash tests U1-U6 (Ubuntu), M1-M3 (macOS), W1 (Windows).
Each test runs jmo CLI with specific arguments and validates output.

Uses jmo_runner fixture from conftest.py.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    current_platform,
    validate_basic_scan,
    validate_multi_target,
)

# Test fixture paths
E2E_FIXTURES = Path(__file__).parent / "fixtures"
IAC_FIXTURE = E2E_FIXTURES / "iac" / "aws-s3-public.tf"

# Default test targets (can be overridden via environment variables)
DEFAULT_REPO = "https://github.com/juice-shop/juice-shop.git"
DEFAULT_IMAGE = "alpine:3.19"


def _get_test_repo():
    """Get test repo URL from environment or use default."""
    import os

    return os.environ.get("TEST_REPO", DEFAULT_REPO)


def _get_test_image():
    """Get test image from environment or use default."""
    import os

    return os.environ.get("TEST_IMAGE", DEFAULT_IMAGE)


requires_docker = pytest.mark.skipif(
    not shutil.which("docker"),
    reason="Docker not installed",
)


SCAN_WORKFLOWS = [
    # Ubuntu tests
    pytest.param(
        "U1",
        "Single repo - native CLI",
        lambda: [
            "ci",
            "--repo",
            _get_test_repo(),
            "--profile",
            "fast",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        id="U1-repo-native",
    ),
    pytest.param(
        "U2",
        "Single image - native CLI",
        lambda: [
            "ci",
            "--image",
            _get_test_image(),
            "--tools",
            "trivy,syft",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        marks=[requires_docker],
        id="U2-image-native",
    ),
    pytest.param(
        "U3",
        "IaC file - native CLI",
        lambda: [
            "ci",
            "--terraform-state",
            str(IAC_FIXTURE),
            "--tools",
            "checkov,trivy",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        id="U3-iac-native",
    ),
    pytest.param(
        "U4",
        "URL DAST - native CLI",
        lambda: [
            "ci",
            "--url",
            "http://testphp.vulnweb.com",
            "--tools",
            "zap",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        id="U4-url-dast",
    ),
    pytest.param(
        "U5",
        "Multi-target - native CLI",
        lambda: [
            "ci",
            "--repo",
            _get_test_repo(),
            "--image",
            _get_test_image(),
            "--terraform-state",
            str(IAC_FIXTURE),
            "--allow-missing-tools",
        ],
        validate_multi_target,
        "linux",
        marks=[requires_docker],
        id="U5-multi-target",
    ),
    # macOS tests (same commands, different platform)
    pytest.param(
        "M1",
        "Single repo - native CLI (macOS)",
        lambda: [
            "ci",
            "--repo",
            _get_test_repo(),
            "--profile",
            "fast",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "darwin",
        id="M1-repo-native-macos",
    ),
    pytest.param(
        "M2",
        "Single image - native CLI (macOS)",
        lambda: [
            "ci",
            "--image",
            _get_test_image(),
            "--tools",
            "trivy,syft",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "darwin",
        marks=[requires_docker],
        id="M2-image-native-macos",
    ),
    pytest.param(
        "M3",
        "IaC file - native CLI (macOS)",
        lambda: [
            "ci",
            "--terraform-state",
            str(IAC_FIXTURE),
            "--tools",
            "checkov,trivy",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "darwin",
        id="M3-iac-native-macos",
    ),
    # Windows tests
    pytest.param(
        "W1",
        "Single repo - native CLI (Windows)",
        lambda: [
            "ci",
            "--repo",
            _get_test_repo(),
            "--profile",
            "fast",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "win32",
        id="W1-repo-native-windows",
    ),
]


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.parametrize("test_id,desc,args_fn,validator,platform", SCAN_WORKFLOWS)
def test_scan_workflow(test_id, desc, args_fn, validator, platform, jmo_runner):
    """Unified scan workflow test.

    Replaces bash tests U1-U6, M1-M3, W1.
    Each parametrized case runs jmo CLI and validates output.
    """
    if platform != current_platform():
        pytest.skip(
            f"Test {test_id} is for {platform}, running on {current_platform()}"
        )

    args = args_fn()
    rc, stdout, stderr, results_dir = jmo_runner(args)

    # Exit code 0 (no findings) or 1 (findings found) are success
    # Exit code 2+ means error
    assert rc in (0, 1), (
        f"Test {test_id} ({desc}) failed with exit code {rc}.\n"
        f"stderr: {stderr[:500]}"
    )

    validator(results_dir)


@pytest.mark.e2e
@pytest.mark.slow
@requires_docker
def test_batch_images_file(jmo_runner, tmp_path):
    """U6: Batch image scan using --images-file (replaces single-image duplicate)."""
    if current_platform() != "linux":
        pytest.skip("U6 is for linux")

    images_file = tmp_path / "batch-images.txt"
    images_file.write_text(f"{_get_test_image()}\n" "nginx:alpine\n" "redis:alpine\n")

    rc, stdout, stderr, results_dir = jmo_runner(
        [
            "ci",
            "--images-file",
            str(images_file),
            "--tools",
            "trivy,syft",
            "--allow-missing-tools",
        ]
    )

    assert rc in (0, 1), (
        f"U6 batch images failed with exit code {rc}.\n" f"stderr: {stderr[:500]}"
    )
    validate_basic_scan(results_dir)
