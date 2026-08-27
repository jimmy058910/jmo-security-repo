"""`~` in a path target must resolve to the home directory (#926).

A schedule created with ``--repos-dir ~/repos`` scanned a directory literally
named ``~`` relative to the cwd: ``Path("~/repos")`` is a *relative* path whose
first component is that one character. The scan found nothing, reported nothing
to scan, and raised no error.

The cron backend cannot fix it from its side. ``cron_installer`` emits the value
through ``shlex.quote``, and ``shlex.quote("~/repos")`` is ``'~/repos'`` -- a
quoted tilde, which the shell does not expand either. Un-quoting would
reintroduce the shell injection that quoting closed, so the expansion belongs in
the process that actually has a home directory.

Applied to every path-valued target flag, not just ``--repos-dir``: a user who
types ``~`` means their home directory whichever flag they typed it on.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from scripts.cli.scan_orchestrator import ScanConfig, ScanOrchestrator, _user_path


class _Args:
    """Only the attributes discovery reads; everything else defaults to None."""

    def __init__(self, **kw):
        defaults = {
            "repo": None,
            "repos_dir": None,
            "targets": None,
            "image": None,
            "images_file": None,
            "url": None,
            "urls_file": None,
            "api_spec": None,
            "terraform_state": None,
            "cloudformation": None,
            "k8s_manifest": None,
            "include": None,
            "exclude": None,
        }
        defaults.update(kw)
        for k, v in defaults.items():
            setattr(self, k, v)


@pytest.fixture
def fake_home(tmp_path, monkeypatch):
    """A home directory that is not the real one.

    `monkeypatch.setenv("HOME", ...)` is not enough on Windows, where HOME is
    not what `expanduser` consults -- patch `Path.home` and the environment
    both, per testing.cross-platform.rules.md.
    """
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.setattr(Path, "home", staticmethod(lambda: home))
    return home


@pytest.fixture
def orch(tmp_path):
    """ScanOrchestrator needs a ScanConfig; discovery does not read it."""
    return ScanOrchestrator(
        ScanConfig(tools=["trufflehog"], results_dir=tmp_path / "results")
    )


# --------------------------------------------------------------------------
# The helper
# --------------------------------------------------------------------------


def test_user_path_expands_a_leading_tilde(fake_home):
    assert _user_path("~/repos") == fake_home / "repos"


def test_user_path_leaves_other_paths_alone(tmp_path):
    assert _user_path(str(tmp_path / "x")) == tmp_path / "x"
    assert _user_path("relative/path") == Path("relative/path")


def test_a_literal_tilde_directory_is_no_longer_what_gets_scanned(fake_home):
    """States the defect as a property rather than a call.

    Before the fix this path was `Path("~/repos")`, whose first part is "~".
    """
    resolved = _user_path("~/repos")
    assert (
        resolved.parts[0] != "~"
    ), f"a tilde survived into the path that gets scanned: {resolved}"


# --------------------------------------------------------------------------
# Through the real discovery path
# --------------------------------------------------------------------------


def test_repos_dir_finds_repos_under_a_tilde_path(fake_home, orch):
    """The reproduction from the issue, end to end."""
    repos = fake_home / "repos"
    (repos / "alpha").mkdir(parents=True)
    (repos / "beta").mkdir()

    targets = orch.discover_targets(_Args(repos_dir="~/repos"))

    found = sorted(p.name for p in targets.repos)
    assert found == [
        "alpha",
        "beta",
    ], f"--repos-dir ~/repos discovered {found}; rejected={targets.rejected}"
    assert not targets.rejected


def test_repo_accepts_a_tilde_path(fake_home, orch):
    (fake_home / "one").mkdir()
    targets = orch.discover_targets(_Args(repo="~/one"))
    assert [p.name for p in targets.repos] == ["one"]


def test_targets_file_and_its_listed_paths_both_expand(fake_home, orch):
    """A targets file is user-authored on both ends: the path TO it, and the
    paths INSIDE it."""
    (fake_home / "gamma").mkdir()
    listing = fake_home / "targets.txt"
    listing.write_text("~/gamma\n# a comment\n", encoding="utf-8")

    targets = orch.discover_targets(_Args(targets="~/targets.txt"))
    assert [p.name for p in targets.repos] == ["gamma"], targets.rejected


def test_a_tilde_path_that_does_not_exist_is_still_rejected(fake_home, orch):
    """The negative control. Expanding must not turn a missing directory into
    a silent pass -- rejection is how a mistyped path stays distinguishable
    from asking for nothing."""
    targets = orch.discover_targets(_Args(repos_dir="~/nope"))
    assert targets.repos == []
    assert targets.rejected, "a non-existent ~ path was accepted without comment"


def test_every_path_valued_target_flag_goes_through_the_helper():
    """Guards the decision, not just today's call sites.

    #926 left open whether expansion should apply to one flag or all of them.
    The answer was all, so a new `Path(args.<something>)` added later to
    discovery is a regression -- this fails when one appears rather than
    waiting for a user to file the next tilde bug.
    """
    import ast
    import inspect

    import scripts.cli.scan_orchestrator as mod

    tree = ast.parse(inspect.getsource(mod))
    offenders: list[str] = []

    for node in ast.walk(tree):
        if not (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "Path"
            and node.args
        ):
            continue
        arg = node.args[0]
        # Path(args.foo) or Path(<local holding a user string>)
        reads_args = (
            isinstance(arg, ast.Attribute)
            and isinstance(arg.value, ast.Name)
            and arg.value.id == "args"
        )
        if reads_args:
            offenders.append(f"line {node.lineno}: Path(args.{arg.attr})")

    assert (
        not offenders
    ), "user-supplied paths must go through _user_path() so `~` expands: " + "; ".join(
        offenders
    )
