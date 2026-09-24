"""scripts/dev/check_eol_flips.py: a line-ending conversion fails, renames included.

Every case runs real git in a throwaway repository, because the property under
test is git's own numstat arithmetic: a per-file check cannot pair a rename, and
the Phase 2 cut shipped a CRLF test file renamed and rewritten as LF that such a
check reported clean (+669/-1027 raw, +94/-452 ignoring CR).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.dev.check_eol_flips import main

LINES = [f"line {i}".encode() for i in range(10)]
CRLF = b"".join(line + b"\r\n" for line in LINES)
LF = b"".join(line + b"\n" for line in LINES)


def _git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-c", "user.email=t@example.com", "-c", "user.name=t", *args],
        cwd=repo,
        check=True,
        capture_output=True,
        timeout=60,
    )
    return proc.stdout.decode("utf-8", errors="replace")


@pytest.fixture
def repo(tmp_path, monkeypatch):
    """A repository holding one committed CRLF file, stored byte-for-byte."""
    root = tmp_path / "repo"
    root.mkdir()
    _git(root, "init", "-q")
    # This repository's own setting. A machine whose global autocrlf is true
    # would otherwise normalise on `git add`, and the test would pass or fail
    # by machine.
    _git(root, "config", "core.autocrlf", "false")
    (root / "a.py").write_bytes(CRLF)
    _git(root, "add", "a.py")
    _git(root, "commit", "-q", "-m", "init")
    monkeypatch.chdir(root)
    return root


def test_an_edit_that_keeps_the_endings_passes(repo):
    (repo / "a.py").write_bytes(CRLF.replace(b"line 3", b"line three"))
    _git(repo, "add", "a.py")
    assert main(["--cached"]) == 0


@pytest.mark.parametrize(
    ("before", "after"), [(CRLF, LF), (LF, CRLF)], ids=["crlf-to-lf", "lf-to-crlf"]
)
def test_a_whole_file_conversion_fails(repo, capsys, before, after):
    (repo / "a.py").write_bytes(before)
    _git(repo, "commit", "-q", "--allow-empty", "-am", "set the starting endings")
    (repo / "a.py").write_bytes(after)
    _git(repo, "add", "a.py")
    assert main(["--cached"]) == 1
    assert "a.py: +10/-10 raw, +0/-0 ignoring CR" in capsys.readouterr().out


def test_a_renamed_file_rewritten_with_other_endings_fails(repo, capsys):
    """The Phase 2 shape, and the reason the script diffs the whole tree."""
    _git(repo, "mv", "a.py", "b.py")
    (repo / "b.py").write_bytes(LF.replace(b"line 3", b"line three"))
    _git(repo, "add", "b.py")

    assert main(["--cached"]) == 1
    assert "a.py -> b.py: +10/-10 raw, +1/-1 ignoring CR" in capsys.readouterr().out

    # A per-file check, naming only the new path, sees an addition that agrees
    # with and without --ignore-cr-at-eol, so it would have passed this.
    per_file = [
        _git(repo, "diff", "--cached", "-M", "--numstat", *flag, "--", "b.py")
        for flag in ([], ["--ignore-cr-at-eol"])
    ]
    assert per_file[0] == per_file[1] == "10\t0\tb.py\n"


def test_allow_names_a_deliberate_conversion_by_its_new_path(repo):
    _git(repo, "mv", "a.py", "b.py")
    (repo / "b.py").write_bytes(LF)
    _git(repo, "add", "b.py")
    assert main(["--cached", "--allow", "b.py"]) == 0
    assert main(["--cached", "--allow", "a.py"]) == 1


def test_base_compares_the_tree_with_a_ref_as_ci_does(repo):
    (repo / "a.py").write_bytes(LF)
    _git(repo, "commit", "-q", "-am", "convert")
    assert main(["--base", "HEAD~1"]) == 1
    assert main(["--base", "HEAD"]) == 0


def test_a_git_failure_exits_2_rather_than_passing(repo):
    with pytest.raises(SystemExit) as exc:
        main(["--base", "no-such-ref"])
    assert exc.value.code == 2
