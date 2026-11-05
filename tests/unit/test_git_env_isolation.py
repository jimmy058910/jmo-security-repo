"""The suite's git helpers act on their own repositories, whatever git exported (#1575).

`git bisect run` in a linked worktree, and every git hook, export `GIT_DIR` to the
command they run. git honours it over `-C <dir>`, so `git_commit_all`'s
`git -C <tmp> init` and `config user.name ...` acted on the real repository: on
2026-11-04 a bisect of the suite re-initialised it as bare and wrote the fixture's
identity into its `.git/config`. The root conftest drops git's local environment
variables for the whole session, which covers every test that runs git without
touching each one.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from tests.conftest import scrub_git_environment

REPO_ROOT = Path(__file__).resolve().parents[2]
# A test that calls `git_commit_all`, which runs `git init` and `git config`.
GIT_FIXTURE_TEST = (
    "tests/unit/test_git_history_pieces.py::TestReadHistory::"
    "test_a_repository_with_its_history_is_read"
)

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args],
        cwd=cwd,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()


def test_the_scrub_drops_every_variable_git_names(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """`git rev-parse --local-env-vars` is git's own list: the variables it
    clears before running a command in another repository (a submodule)."""
    named = set(_git("rev-parse", "--local-env-vars", cwd=REPO_ROOT).split())
    assert "GIT_DIR" in named  # meta-guard: the listing was read
    for name in named:
        monkeypatch.setenv(name, str(REPO_ROOT / ".git"))

    scrub_git_environment()

    assert not named & set(os.environ)


def test_a_suite_run_under_git_dir_leaves_that_repository_alone(
    tmp_path: Path,
) -> None:
    """The incident, against a scratch repository: a child pytest with
    `GIT_DIR` set, as `git bisect run` sets it, runs a test that initialises
    and configures a repository of its own."""
    victim = tmp_path / "victim"
    victim.mkdir()
    _git("init", "-q", cwd=victim)
    config = victim / ".git" / "config"
    before = config.read_bytes()
    env = {k: v for k, v in os.environ.items() if k != "PYTEST_ADDOPTS"}
    env["GIT_DIR"] = str(victim / ".git")

    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            GIT_FIXTURE_TEST,
            "-q",
            "-p",
            "no:cacheprovider",
            "-p",
            "no:xdist",
            "--basetemp",
            str(tmp_path / "child"),
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        # Under the Windows shard's 60 s per-test limit, so a hung child is
        # killed here rather than orphaned.
        timeout=50,
    )

    assert config.read_bytes() == before
    assert _git("rev-parse", "--is-bare-repository", cwd=victim) == "false"
    assert result.returncode == 0, result.stdout + result.stderr
