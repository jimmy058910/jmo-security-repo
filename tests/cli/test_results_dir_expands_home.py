"""A quoted `~` in a results or history path means the home directory (#1302).

A shell expands an unquoted `~`; a quoted one reaches `jmo` as typed, from a
`shlex.quote`d cron line, a generated script or a config value. `jmo scan
--results-dir '~/x'` then wrote its reports into a directory literally named
`~` under the working directory, and exited 0 (measured on Windows). Target
flags have been expanded since #926; these paths are expanded where the parser
reads them, so every command that reads one gets the expanded path.
"""

from __future__ import annotations

import argparse
import os

import pytest

from scripts.cli.jmo import build_parser

# Every option whose value is a path JMo reads or writes, other than the scan
# targets: `--repo`, `--targets`, `--tsv` and the rest are expanded where the
# scan reads them (`scan_orchestrator._user_path`, #926).
PATH_OPTIONS = {
    "--results-dir",
    "--history-db",
    "--db",
    "--out",
    "--output",
    "--config",
    "--baseline",
    "--current",
    "--target",
    "--emit-script",
    "--emit-make-target",
    "--emit-gha",
    "--attestation",
    "--findings-file",
    "--team-file",
    "--repo-root",
    "--export-json",
    "--export-html",
    "--export-csv",
    "--export-prometheus",
    "--export-grafana",
    "--export-dashboard",
}
# Positional paths, by dest: report's results directory, diff's two
# directories, adapters validate's file, attest's and verify's subject.
PATH_POSITIONALS = {"results_dir_pos", "directories", "file", "subject"}


@pytest.fixture
def home(tmp_path, monkeypatch):
    # expanduser reads HOME on POSIX and USERPROFILE on Windows.
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("USERPROFILE", str(tmp_path))
    return tmp_path


def _subparsers(parser: argparse.ArgumentParser, prefix: tuple[str, ...] = ()):
    for action in parser._actions:
        if isinstance(action, argparse._SubParsersAction):
            for name, sub in action.choices.items():
                yield (*prefix, name), sub
                yield from _subparsers(sub, (*prefix, name))


def _path_actions():
    found = []
    for command, sub in _subparsers(build_parser()):
        for action in sub._actions:
            named = set(action.option_strings) & PATH_OPTIONS
            if named or (not action.option_strings and action.dest in PATH_POSITIONALS):
                found.append((" ".join(command), min(named or {action.dest}), action))
    return found


def test_every_results_and_history_path_option_expands_home(home):
    """Derived from the parser, so a new subcommand's path option is covered."""
    actions = _path_actions()
    # Every listed name still exists somewhere: a list that outlives the parser
    # it describes checks nothing.
    seen = {o for _c, o, _a in actions}
    missing = (PATH_OPTIONS | PATH_POSITIONALS) - seen
    assert not missing, missing
    unexpanded = []
    for command, option, action in actions:
        value = action.type("~/probe") if action.type else "~/probe"
        if os.fspath(value) != os.path.join(str(home), "probe"):
            unexpanded.append(f"jmo {command} {option}")
    assert unexpanded == []


@pytest.mark.parametrize(
    "argv",
    [
        ["scan", "--repo", ".", "--results-dir", "~/out"],
        ["ci", "--repo", ".", "--results-dir", "~/out"],
        ["report", "~/out"],
        ["report", "--results-dir", "~/out"],
    ],
    ids=["scan", "ci", "report-positional", "report-option"],
)
def test_scan_ci_and_report_read_the_expanded_path(argv, home):
    args = build_parser().parse_args(argv)
    got = (
        getattr(args, "results_dir", None)
        or getattr(args, "results_dir_opt", None)
        or getattr(args, "results_dir_pos", None)
    )
    assert got == os.path.join(str(home), "out")
