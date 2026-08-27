"""`jmo trends developers` can actually be given a repo and a team file (#974).

The handler read ``args.repo`` and ``args.team_file``, and no parser flag
created either. So ``repo_path`` was always ``Path.cwd()`` and the
``if team_file:`` team-aggregation branch was unreachable from any real
invocation -- while the machinery behind it (``aggregate_by_team``,
``load_team_mapping``, ``format_team_stats``, ``TeamStats``) was complete and
carried 24 references in ``tests/unit/test_developer_attribution.py``.

Closed by adding the flags rather than by deleting the branch. The command's own
error message already said *"Use --repo to specify the repository path"*, which
made the missing flag a user-facing instruction that could not be followed --
the same class as #790.

The existing stub tests in ``test_trend_commands.py`` set ``Args.repo`` and
``Args.team_file`` directly and so proved nothing about reachability: a
hand-built stub answers to any attribute the author thought to set. These drive
the **real parser** instead.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from scripts.cli import jmo
from scripts.cli.trend_commands import cmd_trends_developers


def _parse(argv: list[str]):
    """Parse through the real top-level parser, not a stub.

    `jmo.parse_args()` reads sys.argv and takes no arguments, so this goes one
    level down to the parser it builds -- still the production parser tree,
    which is the whole point: a hand-built `class Args` stub answers to any
    attribute name and so can never show that a flag is missing (#974).
    """
    return jmo.build_parser().parse_args(argv)


# --------------------------------------------------------------------------
# The flags exist and reach the handler's attribute names
# --------------------------------------------------------------------------


def test_repo_is_accepted_and_lands_on_the_dest_the_handler_reads():
    args = _parse(["trends", "developers", "--repo", "/some/path"])
    assert args.repo == "/some/path"


def test_team_file_is_accepted_and_lands_on_the_dest_the_handler_reads():
    args = _parse(["trends", "developers", "--team-file", "teams.json"])
    assert args.team_file == "teams.json"


def test_both_default_to_none_so_the_handler_falls_back_as_before():
    """Adding the flags must not change behaviour when they are omitted:
    `repo` falls back to cwd, and the team branch stays skipped."""
    args = _parse(["trends", "developers"])
    assert args.repo is None
    assert args.team_file is None


def test_the_existing_flags_still_work():
    """Negative control against a parser edit that clobbered its siblings."""
    args = _parse(["trends", "developers", "--last", "30", "--top", "5"])
    assert args.last == 30
    assert args.top == 5
    assert args.repo is None


# --------------------------------------------------------------------------
# The branch they gate is genuinely reachable now
# --------------------------------------------------------------------------


def test_repo_is_what_decides_the_not_a_git_repository_error(tmp_path, capsys):
    """The end-to-end consequence.

    `cmd_trends_developers` rejects a non-repo with "Use --repo to specify the
    repository path". Before the flag existed, following that advice was
    impossible -- argparse exited 2 on an unrecognised argument. Now the value
    reaches the check, which is observable: pointing --repo at a directory with
    no .git produces the error naming THAT directory.
    """
    not_a_repo = tmp_path / "not-a-repo"
    not_a_repo.mkdir()

    args = _parse(["trends", "developers", "--repo", str(not_a_repo)])
    rc = cmd_trends_developers(args)

    assert rc == 1
    err = capsys.readouterr().err
    assert "Not a git repository" in err
    assert (
        str(not_a_repo) in err
    ), f"--repo did not reach the git check; the error names something else: {err!r}"


def test_without_repo_the_check_still_uses_the_working_directory(
    tmp_path, capsys, monkeypatch
):
    """The fallback path, unchanged."""
    monkeypatch.chdir(tmp_path)
    args = _parse(["trends", "developers"])
    rc = cmd_trends_developers(args)

    assert rc == 1
    assert "Not a git repository" in capsys.readouterr().err


def test_a_team_file_is_readable_by_the_loader_the_branch_calls(tmp_path):
    """The team branch's first call, exercised on a file --team-file can now name.

    Kept at the loader rather than driving a whole attribution run: the branch
    needs two scans of real history and git blame output, which belongs in the
    integration tier. What #974 was about is that no CLI invocation could put a
    path here at all.
    """
    from scripts.core.developer_attribution import load_team_mapping

    teams = tmp_path / "teams.json"
    teams.write_text(
        json.dumps({"alice@example.com": "Backend", "bob@example.com": "Backend"}),
        encoding="utf-8",
    )

    args = _parse(["trends", "developers", "--team-file", str(teams)])
    mapping = load_team_mapping(Path(args.team_file))

    assert mapping == {"alice@example.com": "Backend", "bob@example.com": "Backend"}


def test_the_team_machinery_the_branch_gates_is_not_a_stub():
    """States why #974 was closed by adding rather than deleting.

    If these ever become stubs or disappear, the decision recorded in
    scripts/cli/jmo.py's `developers_parser` comment no longer holds and the
    flags should be revisited.
    """
    from scripts.core import developer_attribution as da

    assert callable(da.load_team_mapping)
    assert callable(da.format_team_stats)
    assert callable(da.DeveloperAttribution.aggregate_by_team)
    assert hasattr(da, "TeamStats")


@pytest.mark.parametrize("flag", ["--repo", "--team-file"])
def test_the_flag_was_genuinely_rejected_before(flag):
    """Positive control for this whole file.

    Proves argparse is strict here, so the acceptance tests above are measuring
    a real change rather than a parser that shrugs at anything.
    """
    with pytest.raises(SystemExit) as exc:
        _parse(["trends", "developers", f"{flag}-that-does-not-exist", "x"])
    assert exc.value.code == 2
