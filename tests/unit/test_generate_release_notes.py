"""The release notes count contributors from the previous JMo version's tag.

Not every tag here is a version: BenchProctor's answer keys are assets of a
release tagged `answer-keys-benchproctor-2026.07.22` (#1722). Taken as the
previous release, a tag like that would drop from the notes everyone who
committed between the last version and it.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from scripts.dev import generate_release_notes as notes


def _git(repo: Path, *args: str, author: str = "t") -> None:
    subprocess.run(
        [
            "git",
            "-c",
            f"user.name={author}",
            "-c",
            "user.email=t@example.invalid",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "tag.gpgsign=false",
            *args,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


@pytest.fixture
def repo(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """An empty repository as the working directory. Nothing from the
    developer's git config, nor a GIT_DIR leaked from a parent process (a
    pre-commit hook sets one), reaches it or the code under test."""
    for name in [k for k in os.environ if k.startswith("GIT_")]:
        monkeypatch.delenv(name)
    empty = tmp_path / "empty.gitconfig"
    empty.touch()
    monkeypatch.setenv("GIT_CONFIG_GLOBAL", str(empty))
    monkeypatch.setenv("GIT_CONFIG_NOSYSTEM", "1")
    path = tmp_path / "repo"
    path.mkdir()
    _git(path, "init", "-q")
    monkeypatch.chdir(path)
    return path


def test_a_tag_that_is_not_a_version_is_not_the_previous_release(repo: Path) -> None:
    _git(repo, "commit", "-q", "--allow-empty", "-m", "a", author="Before")
    _git(repo, "tag", "-a", "v1.0.0", "-m", "v1.0.0")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "b", author="Since Version")
    _git(repo, "tag", "answer-keys-benchproctor-2026.07.22")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "c", author="Since Keys")
    _git(repo, "commit", "-q", "--allow-empty", "-m", "release", author="Since Keys")

    assert notes.get_contributors_since_last_release() == [
        "Since Keys",
        "Since Version",
    ]
