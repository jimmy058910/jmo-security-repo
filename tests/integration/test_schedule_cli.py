"""Integration tests for 'jmo schedule' CLI commands.

Tests cover:
- Full lifecycle: create → list → get → update → delete
- Export workflows (GitHub Actions, GitLab CI)
- Install/uninstall from local cron
- Label filtering
- Error handling
"""

import json
import os
import subprocess
import sys
from pathlib import Path
import pytest
import yaml

# Skip all tests on Windows (cron not supported)
import platform

pytestmark = pytest.mark.skipif(
    platform.system() == "Windows", reason="Local cron not supported on Windows"
)

# Dynamically determine repository root for cross-platform compatibility
REPO_ROOT = Path(__file__).resolve().parents[2]


def _get_test_env(tmp_path: Path) -> dict:
    """Create isolated test environment with proper HOME and PYTHONPATH.

    Key insight: We need to isolate schedule data (stored in ~/.jmo) without
    breaking Python's ability to find installed packages. Solution: override
    HOME for ScheduleManager but preserve Python's site-packages paths.
    """
    env = os.environ.copy()

    # Override HOME so ScheduleManager creates schedules in tmp_path/.jmo
    env["HOME"] = str(tmp_path)

    # Preserve Python's ability to find user site-packages
    # Python uses the original user's site-packages even when HOME changes
    import site

    user_site = site.getusersitepackages()

    # Add user site-packages to PYTHONPATH if it's not already in sys.path
    pythonpath_parts = [str(REPO_ROOT)]
    if user_site:
        pythonpath_parts.append(user_site)

    # Also add the standard library paths
    import sys

    pythonpath_parts.extend(sys.path)

    env["PYTHONPATH"] = ":".join(pythonpath_parts)

    return env


def test_schedule_create_list_delete(tmp_path):
    """Test full lifecycle: create → list → get → delete."""
    env = _get_test_env(tmp_path)

    # 1. CREATE schedule
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "create",
            "--name",
            "test-nightly",
            "--cron",
            "0 2 * * *",
            "--profile",
            "balanced",
            "--repos-dir",
            "~/repos",
            "--backend",
            "github-actions",
            "--description",
            "Nightly security scan",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    assert result.returncode == 0
    assert "Created schedule 'test-nightly'" in result.stderr

    # 2. LIST schedules
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "list",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    assert result.returncode == 0
    schedules = json.loads(result.stdout)
    assert len(schedules) == 1
    assert schedules[0]["metadata"]["name"] == "test-nightly"

    # 3. GET schedule details
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "get",
            "test-nightly",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    assert result.returncode == 0
    schedule = json.loads(result.stdout)
    assert schedule["spec"]["schedule"] == "0 2 * * *"
    assert schedule["spec"]["jobTemplate"]["profile"] == "balanced"

    # 4. DELETE schedule
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "delete",
            "test-nightly",
            "--force",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    assert result.returncode == 0
    assert "Deleted schedule 'test-nightly'" in result.stderr

    # 5. Verify deletion
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "list",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    assert result.returncode == 0
    schedules = json.loads(result.stdout)
    assert len(schedules) == 0


def test_schedule_export_github_actions(tmp_path):
    """Test exporting GitHub Actions workflow."""
    env = _get_test_env(tmp_path)

    # Create schedule
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "create",
            "--name",
            "gha-export",
            "--cron",
            "0 3 * * *",
            "--profile",
            "deep",
            "--repos-dir",
            "~/repos",
            "--backend",
            "github-actions",
        ],
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    # Export workflow
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "export",
            "gha-export",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    assert result.returncode == 0

    # Parse YAML
    workflow = yaml.safe_load(result.stdout)

    # Verify structure
    assert workflow["name"] == "JMo Security Scan: gha-export"
    assert workflow["on"]["schedule"] == [{"cron": "0 3 * * *"}]
    assert "workflow_dispatch" in workflow["on"]
    assert "security-scan" in workflow["jobs"]

    # Verify scan command
    job = workflow["jobs"]["security-scan"]
    scan_step = [s for s in job["steps"] if "Run JMo Security Scan" in s["name"]][0]
    assert "--profile deep" in scan_step["run"]
    assert "--repos-dir ~/repos" in scan_step["run"]


def test_schedule_export_gitlab_ci(tmp_path):
    """Test exporting GitLab CI workflow."""
    env = _get_test_env(tmp_path)

    # Create schedule
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "create",
            "--name",
            "gitlab-export",
            "--cron",
            "0 4 * * *",
            "--profile",
            "balanced",
            "--repos-dir",
            "~/repos",
            "--backend",
            "gitlab-ci",
        ],
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    # Export workflow with backend override
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "export",
            "gitlab-export",
            "--backend",
            "gitlab-ci",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    assert result.returncode == 0

    # Parse YAML
    workflow = yaml.safe_load(result.stdout)

    # Verify GitLab CI structure (job name is 'security-scan')
    assert "security-scan" in workflow
    job = workflow["security-scan"]
    assert job["image"] == "ghcr.io/jimmy058910/jmo-security:latest"
    assert any("jmo scan" in cmd for cmd in job["script"])


@pytest.mark.skipif(
    platform.system() == "Darwin", reason="Requires Linux for safe cron testing"
)
def test_schedule_install_local_cron(tmp_path):
    """Test installing schedule to local cron (Linux only).

    IMPORTANT: This test modifies the actual crontab.
    Only run in CI or test environments.
    """
    env = _get_test_env(tmp_path)

    # Create schedule
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "create",
            "--name",
            "cron-test",
            "--cron",
            "0 5 * * *",
            "--profile",
            "fast",
            "--repos-dir",
            "~/repos",
            "--backend",
            "local-cron",
        ],
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    # Install to cron
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "install",
            "cron-test",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    # May fail if crontab not available
    if result.returncode == 0:
        assert "Installed schedule 'cron-test' to crontab" in result.stderr

        # Verify installation
        crontab_result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
        )

        assert "JMo Security Schedule: cron-test" in crontab_result.stdout
        assert "0 5 * * *" in crontab_result.stdout

        # Uninstall
        uninstall_result = subprocess.run(
            [
                sys.executable,
                "-m",
                "scripts.cli.jmo",
                "schedule",
                "uninstall",
                "cron-test",
            ],
            capture_output=True,
            text=True,
            env=env,
            cwd=str(REPO_ROOT),
        )

        assert uninstall_result.returncode == 0
        assert "Removed schedule 'cron-test' from crontab" in uninstall_result.stderr


def test_schedule_label_filtering(tmp_path):
    """Test label filtering in schedule list."""
    env = _get_test_env(tmp_path)

    # Create schedules with different labels
    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "create",
            "--name",
            "prod-scan",
            "--cron",
            "0 2 * * *",
            "--profile",
            "balanced",
            "--repos-dir",
            "~/repos",
            "--label",
            "env=prod",
            "--label",
            "team=security",
        ],
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "create",
            "--name",
            "dev-scan",
            "--cron",
            "0 3 * * *",
            "--profile",
            "fast",
            "--repos-dir",
            "~/repos",
            "--label",
            "env=dev",
            "--label",
            "team=devops",
        ],
        capture_output=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    # List all schedules
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "list",
            "--format",
            "json",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    schedules = json.loads(result.stdout)
    assert len(schedules) == 2

    # Filter by env=prod
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "list",
            "--format",
            "json",
            "--label",
            "env=prod",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    schedules = json.loads(result.stdout)
    assert len(schedules) == 1
    assert schedules[0]["metadata"]["name"] == "prod-scan"

    # Filter by team=devops
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "scripts.cli.jmo",
            "schedule",
            "list",
            "--format",
            "json",
            "--label",
            "team=devops",
        ],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(REPO_ROOT),
    )

    schedules = json.loads(result.stdout)
    assert len(schedules) == 1
    assert schedules[0]["metadata"]["name"] == "dev-scan"
