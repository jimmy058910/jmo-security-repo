"""Parametrized e2e scan workflow tests.

Replaces bash tests U1-U6 (Ubuntu), M1-M3 (macOS), W1 (Windows).
Each test runs jmo CLI with specific arguments and validates output.

Uses jmo_scan_runner fixture from conftest.py.

The repository cases (U1, U5, M1, W1) scan a clone of ``TEST_REPO`` at
``TEST_REPO_COMMIT`` (juice-shop at its pinned commit by default). ``jmo ci
--repo`` takes a path, not a URL, so the clone is made here; a URL that does not
clone fails the test instead of being scanned as nothing.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tests.e2e.conftest import (
    current_platform,
    validate_basic_scan,
    validate_multi_target,
)
from tests.integration.targets import (
    JUICE_SHOP_COMMIT,
    JUICE_SHOP_URL,
    clone_at_commit,
)

# Test fixture paths
E2E_FIXTURES = Path(__file__).parent / "fixtures"
IAC_FIXTURE = E2E_FIXTURES / "iac" / "aws-s3-public.tf"

# Default test image (can be overridden via TEST_IMAGE). The repository default
# is juice-shop's URL and pinned commit in tests/integration/targets.py.
DEFAULT_IMAGE = "alpine:3.19"


@pytest.fixture(scope="module")
def scan_repo(tmp_path_factory) -> str:
    """Clone the test repository once per module and return its path.

    ``TEST_REPO`` and ``TEST_REPO_COMMIT`` override the URL and the commit; set
    both, because a commit of one repository does not exist in another. A clone
    that fails or times out raises, which fails the test that asked for it.

    Not requested by name: ``test_scan_workflow`` asks for it through
    ``request.getfixturevalue`` only for the cases that scan a repository, after
    its platform skip, so the image and IaC cases never clone.
    """
    url = os.environ.get("TEST_REPO", JUICE_SHOP_URL)
    commit = os.environ.get("TEST_REPO_COMMIT", JUICE_SHOP_COMMIT)
    dest = tmp_path_factory.mktemp("test-repo")
    clone_at_commit(url, commit, dest)
    return str(dest)


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
        lambda repo: [
            "ci",
            "--repo",
            repo(),
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        id="U1-repo-native",
    ),
    pytest.param(
        "U2",
        "Single image - native CLI",
        lambda repo: [
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
        lambda repo: [
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
        lambda repo: [
            "ci",
            "--url",
            "http://testphp.vulnweb.com",
            "--tools",
            "zap",
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "linux",
        marks=[pytest.mark.requires_tools],
        id="U4-url-dast",
    ),
    pytest.param(
        "U5",
        "Multi-target - native CLI",
        lambda repo: [
            "ci",
            "--repo",
            repo(),
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
        lambda repo: [
            "ci",
            "--repo",
            repo(),
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "darwin",
        id="M1-repo-native-macos",
    ),
    pytest.param(
        "M2",
        "Single image - native CLI (macOS)",
        lambda repo: [
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
        lambda repo: [
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
        lambda repo: [
            "ci",
            "--repo",
            repo(),
            "--allow-missing-tools",
        ],
        validate_basic_scan,
        "win32",
        id="W1-repo-native-windows",
    ),
]


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.requires_tools
# Ceiling for a repository case: a clone (four git calls of up to CLONE_TIMEOUT)
# plus a scan (the runner's 900 s). The marker outranks the CI job's --timeout=300.
@pytest.mark.timeout(2400)
@pytest.mark.parametrize("test_id,desc,args_fn,validator,platform", SCAN_WORKFLOWS)
def test_scan_workflow(
    test_id, desc, args_fn, validator, platform, jmo_scan_runner, request
):
    """Unified scan workflow test.

    Replaces bash tests U1-U6, M1-M3, W1.
    Each parametrized case runs jmo CLI and validates output.
    """
    if platform != current_platform():
        pytest.skip(
            f"Test {test_id} is for {platform}, running on {current_platform()}"
        )

    # args_fn calls repo() only when its case scans a repository (see scan_repo)
    args = args_fn(lambda: request.getfixturevalue("scan_repo"))
    rc, stdout, stderr, results_dir = jmo_scan_runner(args)

    # Exit code 0 (no findings) or 1 (findings found) are success
    # Exit code 2+ means error. A scan that rejected every target also exits 1;
    # the validators catch it through meta.target_count.
    assert rc in (0, 1), (
        f"Test {test_id} ({desc}) failed with exit code {rc}.\nstderr: {stderr[:500]}"
    )

    validator(results_dir)


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.requires_tools
@requires_docker
def test_batch_images_file(jmo_scan_runner, tmp_path):
    """U6: Batch image scan using --images-file (replaces single-image duplicate)."""
    if current_platform() != "linux":
        pytest.skip("U6 is for linux")

    images_file = tmp_path / "batch-images.txt"
    images_file.write_text(f"{_get_test_image()}\nnginx:alpine\nredis:alpine\n")

    rc, stdout, stderr, results_dir = jmo_scan_runner(
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
        f"U6 batch images failed with exit code {rc}.\nstderr: {stderr[:500]}"
    )
    validate_basic_scan(results_dir)
