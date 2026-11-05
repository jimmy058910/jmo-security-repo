"""Reading the scanned repository's git context writes nothing in its `.git` (#1582).

`get_git_context` ran `git status --porcelain` in the target. When a file's stat
data no longer matches the index (a checkout, a `touch`, an editor's save of the
same content), status refreshes the index and writes it back through
`.git/index.lock`. Measured: the index got a new inode under plain `git status`
and kept its own under `--no-optional-locks`; and while JMo held the lock, a
`git commit` the user ran failed with "Unable to create ... index.lock: File
exists". A scan reads the repository; it has no business writing in it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

import pytest

from scripts.core.history_db import get_git_context

pytestmark = pytest.mark.skipif(shutil.which("git") is None, reason="needs git")


def _git(repo: Path, *args: str) -> None:
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@example.invalid", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        timeout=60,
        env={**os.environ, "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"},
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q", "-b", "main")
    (repo / "a.txt").write_bytes(b"a\n")
    _git(repo, "add", "a.txt")
    _git(repo, "commit", "-q", "-m", "a")
    return repo


def _stale(path: Path) -> None:
    """The same content with another mtime: the index's stat data is stale."""
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 10_000_000_000))


def _entries(git_dir: Path) -> dict[str, tuple[int, int, int]]:
    return {
        p.relative_to(git_dir).as_posix(): (
            p.lstat().st_ino,
            p.lstat().st_mtime_ns,
            p.lstat().st_size,
        )
        for p in sorted(git_dir.rglob("*"))
    }


def test_reading_the_context_writes_nothing_in_the_targets_git(repo: Path) -> None:
    _stale(repo / "a.txt")
    before = _entries(repo / ".git")

    context = get_git_context(repo)

    assert context["is_dirty"] == 0  # same content: not a change
    assert len(context["commit_hash"]) == 40
    assert _entries(repo / ".git") == before


def test_a_changed_file_still_reads_dirty(repo: Path) -> None:
    (repo / "a.txt").write_bytes(b"changed\n")

    assert get_git_context(repo)["is_dirty"] == 1
