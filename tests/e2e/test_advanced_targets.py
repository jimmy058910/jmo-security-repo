"""E2E tests for advanced scan targets.

Replaces bash tests A1 (GitLab), A2 (K8s), A3 (deep profile).
These tests require specific infrastructure and are skipped if unavailable.
"""

from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tests.e2e.conftest import validate_basic_scan

E2E_FIXTURES = Path(__file__).parent / "fixtures"


@pytest.mark.e2e
@pytest.mark.slow
class TestAdvancedTargets:
    """Advanced scan targets requiring specific infrastructure."""

    @pytest.mark.skipif(
        not os.environ.get("GITLAB_TOKEN"),
        reason="GITLAB_TOKEN not set",
    )
    def test_gitlab_repo_scan(self, jmo_scan_runner):
        """A1: GitLab repository scan (requires GITLAB_TOKEN)."""
        gitlab_repo = os.environ.get(
            "TEST_GITLAB_REPO",
            "https://gitlab.com/gitlab-org/gitlab-runner.git",
        )
        rc, stdout, stderr, results_dir = jmo_scan_runner(
            [
                "ci",
                "--repo",
                gitlab_repo,
                "--profile-name",
                "fast",
                "--allow-missing-tools",
            ]
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
                "trivy,falco",
                "--allow-missing-tools",
            ]
        )
        assert rc in (0, 1), f"K8s scan failed: {stderr[:500]}"

    @pytest.mark.timeout(4500)
    def test_deep_profile_scan(self, jmo_scan_runner):
        """A3: Deep profile scan (all tools, 40-70 min)."""
        rc, stdout, stderr, results_dir = jmo_scan_runner(
            [
                "ci",
                "--repo",
                str(E2E_FIXTURES / "python"),
                "--profile-name",
                "deep",
                "--allow-missing-tools",
            ],
            timeout=4200,
        )  # 70 minutes
        assert rc in (0, 1), f"Deep scan failed: {stderr[:500]}"
        validate_basic_scan(results_dir)
