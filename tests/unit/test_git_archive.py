"""Git object ids read from an archive of one commit (#1573).

GitHub builds `/archive/<commit>.tar.gz` on request and does not promise its
bytes stay the same; its 2023 compression change broke every sha256 pin on
such archives until it was reverted. What a commit holds cannot change, so the
yara rules are pinned by git's own ids for it. These tests take git itself as
the oracle: an archive made by `git archive`, as GitHub makes them, must give
the ids `git rev-parse` reports, however it is repacked.
"""

from __future__ import annotations

import gzip
import io
import os
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from scripts.core.git_archive import object_ids


def _git(repo: Path, *args: str) -> str:
    # Nothing from the developer's or the runner's git config, nor a GIT_DIR
    # leaked from a parent process: a smudge or autocrlf there would change
    # the archive's bytes, and a GIT_DIR would point at another repository.
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    empty = repo.parent / "empty.gitconfig"
    empty.touch()
    env |= {"GIT_CONFIG_GLOBAL": str(empty), "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(
        [
            "git",
            "-c",
            "core.autocrlf=false",
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.invalid",
            *args,
        ],
        cwd=repo,
        env=env,
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    ).stdout.strip()


@pytest.fixture
def commit(tmp_path: Path) -> tuple[Path, Path]:
    """A repository shaped like signature-base, and its `git archive`."""
    repo = tmp_path / "repo"
    files = {
        "LICENSE": b"Detection Rule License 1.1\n",
        "yara/a.yar": b"rule A { condition: true }\n",
        "yara/crlf.yar": b"rule B {\r\n condition: true\r\n}\r\n",
        # git sorts a tree's entries as if a directory's name ended in "/":
        # "rules.yar" (".", 0x2e) before the directory "rules" ("/", 0x2f).
        "yara/rules.yar": b"rule C { condition: true }\n",
        "yara/rules/d.yar": b"rule D { condition: true }\n",
        "yara/run.sh": b"#!/bin/sh\n",
        "iocs/hashes.txt": b"deadbeef\n",
    }
    for rel, body in files.items():
        (repo / rel).parent.mkdir(parents=True, exist_ok=True)
        (repo / rel).write_bytes(body)
    _git(repo, "init", "-q")
    _git(repo, "add", ".")
    # An executable is a different tree entry (100755); set in the index so
    # the test means the same on Windows, where a file has no mode bits.
    _git(repo, "update-index", "--chmod=+x", "yara/run.sh")
    _git(repo, "commit", "-q", "-m", "rules")
    sha = _git(repo, "rev-parse", "HEAD")
    archive = tmp_path / "bundle.tar.gz"
    _git(
        repo,
        "archive",
        "--format=tar.gz",
        f"--prefix=signature-base-{sha}/",
        "-o",
        str(archive),
        "HEAD",
    )
    return repo, archive


def test_the_ids_are_gits(commit: tuple[Path, Path]) -> None:
    repo, archive = commit

    ids = object_ids(archive, ["yara", "LICENSE"])

    assert ids == {
        "yara": _git(repo, "rev-parse", "HEAD:yara"),
        "LICENSE": _git(repo, "rev-parse", "HEAD:LICENSE"),
    }


def test_a_repacked_archive_of_the_same_commit_has_the_same_ids(
    commit: tuple[Path, Path], tmp_path: Path
) -> None:
    """Members reordered, timestamps moved, compressed at another level: the
    bytes differ, and the ids do not."""
    _, archive = commit
    with tarfile.open(archive, "r:gz") as src:
        members = [
            (m, src.extractfile(m).read() if m.isfile() else None)
            for m in src.getmembers()
        ]
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as out:
        for member, data in reversed(members):
            member.mtime = 0
            out.addfile(member, io.BytesIO(data) if data is not None else None)
    repacked = tmp_path / "repacked.tar.gz"
    repacked.write_bytes(gzip.compress(buf.getvalue(), compresslevel=1))
    assert repacked.read_bytes() != archive.read_bytes()

    assert object_ids(repacked, ["yara", "LICENSE"]) == object_ids(
        archive, ["yara", "LICENSE"]
    )


def test_a_changed_rule_changes_the_tree_id(commit: tuple[Path, Path]) -> None:
    repo, archive = commit
    before = object_ids(archive, ["yara"])["yara"]
    (repo / "yara" / "a.yar").write_bytes(b"rule A { condition: false }\n")
    _git(repo, "commit", "-q", "-am", "edit")
    edited = archive.with_name("edited.tar.gz")
    _git(
        repo,
        "archive",
        "--format=tar.gz",
        "--prefix=signature-base-x/",
        "-o",
        str(edited),
        "HEAD",
    )

    assert object_ids(edited, ["yara"])["yara"] != before


def test_a_path_the_archive_lacks_has_no_id(commit: tuple[Path, Path]) -> None:
    _, archive = commit

    assert object_ids(archive, ["nope", "yara/nope.yar"]) == {}


@pytest.mark.skipif(
    sys.platform == "win32", reason="git symlinks need privileges on Windows"
)
def test_a_symlink_is_a_tree_entry_of_its_own(commit: tuple[Path, Path]) -> None:
    repo, _ = commit
    (repo / "yara" / "link.yar").symlink_to("a.yar")
    _git(repo, "add", "yara/link.yar")
    _git(repo, "commit", "-q", "-m", "link")
    archive = repo.parent / "linked.tar.gz"
    _git(repo, "archive", "--format=tar.gz", "--prefix=p/", "-o", str(archive), "HEAD")

    assert object_ids(archive, ["yara"])["yara"] == _git(repo, "rev-parse", "HEAD:yara")


def test_an_archive_not_under_one_root_is_refused(tmp_path: Path) -> None:
    archive = tmp_path / "flat.tar.gz"
    with tarfile.open(archive, "w:gz") as tar:
        for name in ("a/x", "b/y"):
            info = tarfile.TarInfo(name)
            tar.addfile(info, io.BytesIO(b""))

    with pytest.raises(ValueError, match="one top-level directory"):
        object_ids(archive, ["x"])
