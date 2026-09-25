"""Fixtures shared by the `jmo scan --tsv` tests."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

import pytest

REMOTE_URL = "https://example.invalid/owner/repo.git"
SCP_URL = "git@example.invalid:owner/repo.git"


def git(*args: str, cwd: Path | None = None) -> str:
    """Run git for fixture setup; any failure is the fixture's, so it raises."""
    cp = subprocess.run(
        ["git", *args],
        cwd=cwd,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        check=True,
        timeout=60,
    )
    return cp.stdout.strip()


def commit(work: Path, name: str, content: bytes) -> str:
    """Commit one file, immune to the caller's signing and hook settings."""
    (work / name).write_bytes(content)
    git("add", name, cwd=work)
    git(
        "-c",
        "user.name=jmo-test",
        "-c",
        "user.email=jmo-test@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "--no-verify",
        "-qm",
        name,
        cwd=work,
    )
    return git("rev-parse", "HEAD", cwd=work)


@dataclass
class GitRemote:
    work: Path
    bare: Path
    url: str = REMOTE_URL
    scp_url: str = SCP_URL

    def push_commit(self, name: str) -> str:
        """Add a commit upstream; returns its sha."""
        sha = commit(self.work, name, b"added upstream\n")
        git("push", "-q", str(self.bare), "HEAD", cwd=self.work)
        return sha

    def add_owner(self, owner: str) -> str:
        """The same repository under another owner; returns its URL."""
        git(
            "clone",
            "-q",
            "--bare",
            str(self.bare),
            str(self.bare.parent.parent / owner / "repo.git"),
        )
        return f"https://example.invalid/{owner}/repo.git"


@pytest.fixture
def git_remote(tmp_path, monkeypatch) -> GitRemote:
    """A local bare repository reachable at an allowed URL, with no network.

    `url.<base>.insteadOf`, set through `GIT_CONFIG_COUNT`, rewrites both URL
    forms the clone allowlist permits onto a local directory. Real git clones,
    fetches and fast-forwards, while the row still reads as a network URL and
    `remote.origin.url` keeps it. The host is `.invalid` (RFC 6761), so a
    rewrite that failed to apply cannot reach anything.
    """
    work = tmp_path / "upstream-work"
    work.mkdir()
    git("init", "-q", cwd=work)
    commit(work, "app.py", b"print('hello')\n")
    remotes = tmp_path / "remotes"
    bare = remotes / "owner" / "repo.git"
    git("clone", "-q", "--bare", str(work), str(bare))

    base = remotes.as_uri() + "/"
    monkeypatch.setenv("GIT_CONFIG_COUNT", "3")
    monkeypatch.setenv("GIT_CONFIG_KEY_0", f"url.{base}.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_0", "https://example.invalid/")
    monkeypatch.setenv("GIT_CONFIG_KEY_1", f"url.{base}.insteadOf")
    monkeypatch.setenv("GIT_CONFIG_VALUE_1", "git@example.invalid:")
    # A machine that hardens git with protocol.file.allow=never would refuse
    # the rewritten URL; the fixture's own remote is the one exception.
    monkeypatch.setenv("GIT_CONFIG_KEY_2", "protocol.file.allow")
    monkeypatch.setenv("GIT_CONFIG_VALUE_2", "always")
    return GitRemote(work=work, bare=bare)
