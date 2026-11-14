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

import json
import os
import shutil
from collections import Counter
from pathlib import Path

import pytest

from scripts.core.tool_descriptors import DESCRIPTORS
from scripts.core.tool_utils import find_tool
from tests.conftest import scanner_states
from tests.e2e.conftest import (
    current_platform,
    validate_basic_scan,
    validate_multi_target,
)
from tests.fixtures.samples.zap import fixture_server as fx
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
    # U4, the URL case, is test_url_dast_scan below: its target is a server the
    # test starts, on a port known only once it is running.
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

    # pytest shows this only if the validator fails: a scan that scanned nothing
    # says why in its log's tail, such as a tool it could not find (#1546).
    print(stderr[-4000:])
    validator(results_dir)


# What zap reports for the spider site's /search, which reflects `q` unescaped.
REFLECTED_XSS = "Cross Site Scripting (Reflected)"


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.requires_tools
@pytest.mark.timeout(1200)
def test_url_dast_scan(jmo_scan_runner, tmp_path):
    """U4: a URL scan with zap reaches its target and reports what it found.

    U4 scanned http://testphp.vulnweb.com, a third-party host that stopped
    answering, and passed while zap reached nothing: `validate_basic_scan` asks
    a URL target for a target count only, and the target's results directory
    exists when every tool failed (#1550). The target is now
    fixture_server.py's spider site, served from this process on 127.0.0.1,
    and the scan must show zap ran, reached the site and found its reflected
    XSS. zap's 15-30 s on the site, plus a fresh ZAP home, fit the budget.
    """
    if current_platform() != "linux":
        pytest.skip(f"U4 is for linux, running on {current_platform()}")
    zap = DESCRIPTORS["zap"]
    if not any(find_tool(name) for name in (zap.binary, zap.name) if name):
        pytest.skip("zap is not installed")

    log = tmp_path / "requests.jsonl"
    site = fx.start("spider", log)
    try:
        rc, _stdout, stderr, results_dir = jmo_scan_runner(
            ["ci", "--url", site.url, "--tools", "zap", "--allow-missing-tools"]
        )
    finally:
        site.close()

    assert rc in (0, 1), f"U4 exited {rc}.\nstderr: {stderr[-2000:]}"
    print(stderr[-4000:])
    validate_basic_scan(results_dir)
    states = scanner_states(results_dir)
    assert states.get("zap") == "ran", states
    attacked = Counter(r["op"] for r in fx.read_log(log) if r["payload"])
    assert attacked["search"], f"zap sent no attack to /search: {attacked}"
    summary = json.loads((results_dir / "summaries" / "findings.json").read_bytes())
    titles = {f.get("title") for f in summary["findings"]}
    assert REFLECTED_XSS in titles, sorted(titles)


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
