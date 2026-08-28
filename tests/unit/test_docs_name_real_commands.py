#!/usr/bin/env python3
"""Guard: documentation may not tell a reader to run a command that does not exist.

Regression for #1012.

#790 fixed first-run output that pointed users at `jmo config` and
`jmo subscribe`, and left a guard behind --
``test_no_user_facing_string_names_a_nonexistent_subcommand`` in
``tests/unit/test_config_precedence.py``. That guard walks ``scripts/**/*.py``
and checks string literals against the real parser. **Documentation is outside
its scope**, so ``docs/CLI_REFERENCE.md`` advertised ``jmo slim`` -- a profile,
not a command -- in the file users are most likely to read.

## The matcher was already tight; only the file list needed widening

#790's matcher requires a backtick or a following flag, and its comment says why:
plain prose ("the .jmo directory", "jmo entry point failed") matches neither.
Measured over the 80 tracked Markdown files under ``docs/`` and the repository
root, it produced **16 references naming 7 non-existent commands and zero prose
false positives**. The issue predicted ~15 candidates "most of them prose false
positives"; the tightening it asked for had already been done, so widening the
walk was safe on its own.

Of those 7, three were real and four were deliberate.

## A rename would have shipped a still-broken command

`UPGRADE.md` carried a runnable example, ``jmo trend --branch main --scans 10``.
Renaming `trend` to `trends` is not enough, and neither is stopping there:

    jmo trend  --branch main --scans 10           invalid choice: 'trend'
    jmo trends --branch main --scans 10           invalid choice: 'main'
    jmo trends analyze --branch main --scans 10   unrecognized arguments: --scans
    jmo trends analyze --branch main --last 10    parses

``jmo trends`` dispatches to a subcommand, and the flag is ``--last``, not
``--scans``. Three of the four spellings fail, which is why the corrected line
was run through the parser rather than reasoned about.

## Naming a command in order to say it does not exist

Four references are correct precisely because the command is absent, and a guard
that cannot tell them apart would force the documentation to stop saying true
things. They are pinned below rather than pattern-matched, because "is this
sentence an instruction or a denial?" is not something a regex should be asked.
An unpinned one fails; a pinned one that stops being needed fails too, once the
reference goes.
"""

from __future__ import annotations

import argparse
import contextlib
import importlib.util
import io
import re
import sys
from pathlib import Path

import scripts.cli.jmo as jmo_mod

REPO_ROOT = Path(__file__).resolve().parents[2]
DOC_CHECKER = REPO_ROOT / "scripts" / "dev" / "check_doc_links.py"

# #790's matcher, deliberately identical. Two unambiguous ways of naming a
# command: backtick-quoted, or followed by a flag.
_COMMAND_REF = re.compile(r"`jmo\s+([a-z][a-z0-9-]+)|\bjmo\s+([a-z][a-z0-9-]+)\s+--")

# Dockerfiles carry the same references in comments -- three of them named
# `jmo trend` -- and a reader of a published image's build context is as much a
# reader as one of docs/. They cost one glob, so they are covered too.
_EXTRA_GLOBS = ("Dockerfile*",)

# (file, command) references that exist in order to say the command does not.
# Each is a true statement that a regex would have to be taught to recognise.
ALLOWED: dict[tuple[str, str], str] = {
    (
        "docs/CLI_REFERENCE.md",
        "slim",
    ): "states 'There is no `jmo slim` command' -- #870's correction",
    (
        "docs/KNOWN_LIMITATIONS.md",
        "config",
    ): "records #790: first-run output named a command that does not exist",
    ("docs/KNOWN_LIMITATIONS.md", "subscribe"): "records #790, same sentence",
    (
        "ROADMAP.md",
        "fix",
    ): "'`jmo fix` CLI (AI remediation) | Deferred from v1.0.0' -- unshipped by design",
    (
        "docs/USER_GUIDE.md",
        "triage",
    ): "'**Future:** CLI command `jmo triage`' -- explicitly future",
}


def _parser_subcommands() -> set[str]:
    """Derive the subcommand set from the parser, at every nesting level.

    Not a restated list: `cli_validator.MAIN_SUBCOMMANDS` was one of those and
    had drifted to 13 of 20 (#783).
    """
    captured: dict[str, argparse._SubParsersAction] = {}
    original = argparse.ArgumentParser.add_subparsers

    def _capture(self, *a, **kw):
        action = original(self, *a, **kw)
        captured.setdefault(kw.get("dest") or f"positional{len(captured)}", action)
        return action

    argv = sys.argv
    argparse.ArgumentParser.add_subparsers = _capture  # type: ignore[method-assign]
    try:
        sys.argv = ["jmo", "--help"]
        with (
            contextlib.redirect_stdout(io.StringIO()),
            contextlib.redirect_stderr(io.StringIO()),
            contextlib.suppress(SystemExit),
        ):
            jmo_mod.parse_args()
    finally:
        sys.argv = argv
        argparse.ArgumentParser.add_subparsers = original  # type: ignore[method-assign]

    names: set[str] = set()
    for action in captured.values():
        names |= set(action.choices)
    return names


def _checked_files() -> list[str]:
    spec = importlib.util.spec_from_file_location("check_doc_links", str(DOC_CHECKER))
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    tracked = mod.tracked_paths()
    docs = {
        p
        for p in tracked
        if p.endswith(".md") and not p.startswith(mod.ARCHIVAL_PREFIXES)
    }
    extra = {p for p in tracked for g in _EXTRA_GLOBS if Path(p).match(g)}
    return sorted(docs | extra)


def test_documentation_names_only_real_commands() -> None:
    """Regression for #1012: docs advertised `jmo slim`, which is a profile."""
    real = _parser_subcommands()
    assert len(real) >= 20, f"parser capture looks wrong: {sorted(real)}"
    assert {"trends", "report", "scan"} <= real, "parser capture missing known commands"

    files = _checked_files()
    assert len(files) >= 80, f"file discovery looks wrong: {len(files)}"

    offenders: list[str] = []
    seen: set[tuple[str, str]] = set()
    for rel in files:
        text = (REPO_ROOT / rel).read_text(encoding="utf-8", errors="replace")
        for lineno, line in enumerate(text.splitlines(), start=1):
            for match in _COMMAND_REF.finditer(line):
                name = match.group(1) or match.group(2)
                if name in real:
                    continue
                seen.add((rel, name))
                if (rel, name) in ALLOWED:
                    continue
                offenders.append(f"{rel}:{lineno}: jmo {name}")

    assert not offenders, (
        "documentation names a command the parser does not accept (#1012). "
        "Either fix the reference, or -- if it exists to say the command is "
        "absent -- add it to ALLOWED with the sentence that makes it true:\n"
        + "\n".join(offenders)
    )

    stale = sorted(k for k in ALLOWED if k not in seen)
    assert not stale, (
        "an ALLOWED entry no longer matches anything, so it is documenting a "
        f"sentence that has been removed: {stale}"
    )
