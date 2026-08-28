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

# Skip all tests on Windows (cron not supported)
import platform
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

# Only the cron test needs cron. This module-level skip used to cover all five
# tests with the reason "Local cron not supported on Windows", so the whole
# schedule round-trip -- create, list, get, delete, export to both backends,
# label filtering -- had **no** integration coverage on Windows, for a reason
# that applies to one of its tests. The narrow marker now sits on that one test.
requires_cron = pytest.mark.skipif(
    platform.system() == "Windows", reason="Local cron not supported on Windows"
)

# Dynamically determine repository root for cross-platform compatibility
REPO_ROOT = Path(__file__).resolve().parents[2]


def _get_test_env(tmp_path: Path) -> dict:
    """Create isolated test environment with proper home and PYTHONPATH.

    Schedule data lives under the user's home directory, so the child process
    must be pointed at tmp_path -- without breaking its ability to import
    installed packages.

    **Both** home variables are set. `HOME` alone is a POSIX-only isolation:
    `Path.home()` reads USERPROFILE on Windows and never consults HOME, which
    `.claude/rules/testing.cross-platform.rules.md` records as a standing trap.
    These tests only avoided writing into the developer's real ~/.jmo because
    the whole module was skipped on Windows. Un-skipping without this would
    have pointed them at real user state -- so the two changes belong together.
    `_assert_isolated` below is the check that this actually worked.
    """
    env = os.environ.copy()

    env["HOME"] = str(tmp_path)  # POSIX
    env["USERPROFILE"] = str(tmp_path)  # Windows

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

    # os.pathsep, not ":" -- Windows separates PYTHONPATH entries with ";" and
    # its entries contain a drive-letter colon, so a ":" join corrupted every
    # path on the list.
    env["PYTHONPATH"] = os.pathsep.join(pythonpath_parts)

    return env


def _assert_isolated(tmp_path: Path) -> Path:
    """Fail loudly if a test is about to touch the developer's real ~/.jmo.

    A scheduler test that silently escapes its sandbox looks exactly like a
    passing test. This asserts the sandbox exists where we put it before any
    assertion about its contents is trusted.
    """
    sandbox = tmp_path / ".jmo" / "schedules.json"
    real = Path.home() / ".jmo" / "schedules.json"
    assert sandbox.exists(), (
        f"schedule state was not created under {tmp_path} -- the subprocess "
        f"resolved a different home directory, and may have written to {real}"
    )
    assert sandbox.resolve() != real.resolve()
    return sandbox


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

    # The success message is not the evidence -- the persisted file is. Read it
    # back, from a path proven to be inside the sandbox, and check the write
    # actually happened. A schedule that was never persisted is indistinguishable
    # from one that was, if you only look at rc and stderr.
    sandbox = _assert_isolated(tmp_path)
    persisted = json.loads(sandbox.read_text(encoding="utf-8"))
    assert [s["metadata"]["name"] for s in persisted["schedules"]] == ["test-nightly"]
    stored = persisted["schedules"][0]
    assert stored["spec"]["schedule"] == "0 2 * * *"
    assert stored["spec"]["jobTemplate"]["profile"] == "balanced"
    assert stored["spec"]["jobTemplate"]["targets"]["repositories"]["repos_dir"] == (
        "~/repos"
    )

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
    # Without this the test passes whether or not the subprocess was isolated,
    # because it only ever asserts on exported YAML. Measured: with the
    # USERPROFILE line removed, this test still passed -- while writing its
    # schedule into the developer's real ~/.jmo/schedules.json.
    _assert_isolated(tmp_path)

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
    assert "--profile-name deep" in scan_step["run"]
    # Quoted, because every value interpolated into the `run:` shell line is now
    # shlex.quote()d -- the same treatment cron_installer.py:298 has always given
    # this exact field. Quoting does suppress shell tilde expansion, which is a
    # real trade-off and the right one here: the alternative is leaving `;` and
    # `$(...)` live in a workflow that runs with the job's permissions. `~` was
    # not usable in this position anyway -- the generated step runs the scan
    # inside a container where only $(pwd) is mounted, at /workspace -- and `jmo`
    # does not call expanduser() on --repos-dir (scan_orchestrator.py:379,
    # jmo.py:2073), so the tilde would not have resolved either. Tracked
    # separately, because it affects the cron path identically.
    assert "--repos-dir '~/repos'" in scan_step["run"]


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
    _assert_isolated(tmp_path)  # see test_schedule_export_github_actions

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
@requires_cron
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
    # Explicit, rather than relying on this test happening to notice extra
    # schedules leaking in from the developer's real file. See
    # test_schedule_export_github_actions.
    _assert_isolated(tmp_path)

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
