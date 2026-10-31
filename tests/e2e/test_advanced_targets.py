"""E2E tests for advanced scan targets.

Replaces bash tests A1 (GitLab), A2 (K8s), A3 (the full tool matrix).
These tests require specific infrastructure and are skipped if unavailable.
"""

from __future__ import annotations

import os
import re
import shutil
from pathlib import Path

import pytest

from tests.e2e.conftest import validate_basic_scan

E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
@pytest.mark.slow
@pytest.mark.requires_tools
class TestAdvancedTargets:
    """Advanced scan targets requiring specific infrastructure."""

    @pytest.mark.skipif(
        not os.environ.get("GITLAB_TOKEN"),
        reason="GITLAB_TOKEN not set",
    )
    # Clone, a default scan, and the images the repository names (pulled, then
    # scanned). juice-shop took 93 s with warm caches; gitlab-runner is larger,
    # and its images come over the network. The scan's own limit (1800 s) sits
    # under this one, so a hang is reported by the scan, not by the plugin
    # killing the test.
    @pytest.mark.timeout(2100)
    def test_gitlab_repo_scan(self, jmo_scan_runner):
        """A1: GitLab repository scan (requires GITLAB_TOKEN).

        Runs JMo's GitLab target, ``--gitlab-repo <group>/<repo>`` on
        ``TEST_GITLAB_URL``; ``--repo`` takes a path, so a URL there scans
        nothing. The scanner clones the default branch and has no ref option, so
        unlike U1 this test is not pinned to a commit. It scans the container
        images the repository names as targets too.
        """
        gitlab_url = os.environ.get("TEST_GITLAB_URL", "https://gitlab.com")
        gitlab_repo = os.environ.get("TEST_GITLAB_REPO", "gitlab-org/gitlab-runner")
        is_group_repo = re.fullmatch(r"[\w.-]+/[\w.-]+", gitlab_repo) is not None
        assert is_group_repo and not gitlab_repo.endswith(".git"), (
            "TEST_GITLAB_REPO must be <group>/<repo> (for example "
            f"gitlab-org/gitlab-runner), not a URL; read {gitlab_repo!r}"
        )
        rc, stdout, stderr, results_dir = jmo_scan_runner(
            [
                "ci",
                "--gitlab-url",
                gitlab_url,
                "--gitlab-repo",
                gitlab_repo,
                "--allow-missing-tools",
            ],
            timeout=1800,
        )
        assert rc in (0, 1), f"GitLab scan failed: {stderr[:500]}"
        validate_basic_scan(results_dir)

    @pytest.mark.skipif(
        not shutil.which("kubectl"),
        reason="kubectl not installed",
    )
    def test_k8s_cluster_scan(self, jmo_scan_runner):
        """A2: Kubernetes cluster scan (requires kubectl + running cluster)."""
        rc, stdout, stderr, results_dir = jmo_scan_runner(
            [
                "ci",
                "--k8s-context",
                "default",
                "--k8s-namespace",
                "default",
                "--tools",
                "trivy",
                "--allow-missing-tools",
            ]
        )
        assert rc in (0, 1), f"K8s scan failed: {stderr[:500]}"

    @pytest.mark.timeout(4500)
    def test_full_matrix_scan(self, jmo_scan_runner):
        """A3: A scan with the default tool list, which is all of TOOL_MATRIX."""
        rc, stdout, stderr, results_dir = jmo_scan_runner(
            [
                "ci",
                "--repo",
                str(E2E_FIXTURES / "python"),
                "--allow-missing-tools",
            ],
            timeout=4200,
        )  # 70 minutes
        assert rc in (0, 1), f"Full-matrix scan failed: {stderr[:500]}"
        validate_basic_scan(results_dir)
