#!/usr/bin/env python3
"""Guard: user-facing text may not name a command-line flag that does not exist.

Regression for #1137.

`jmo history list --db <missing>` told the reader:

    Error: History database not found: ...
    Run a scan with --store-history first, or use 'jmo history store'

`jmo scan` has no `--store-history`. Storage is on by default and the flag that
exists is `--no-store-history`, so following the instruction exits 2 with
`unrecognized arguments`. The same class as #1104 (documentation naming
commands that do not exist) and #790 (first-run output naming
`jmo config` / `jmo subscribe`), one level down: those guard *commands*, and
nothing guarded *flags*.

## Scope, and why it is this scope

`scripts/` is full of other programs' flags - trivy's `--skip-dirs`, bandit's
`-x`, curl's `--retry`, docker's `--rm`. Measured over every string literal in
`scripts/**/*.py`:

    --flag tokens in string literals            1300
    not in jmo's parser                          288   <- a naive guard's noise

So the guard needs a scope, and the scope is measured rather than guessed:

    scoped to strings that also contain "jmo "    219 tokens, 8 unknown
    ...and are not docstrings                     219 tokens, 2 unknown

Both of the remaining two are the defect. **Zero false positives, and no
allowlist.** The six unknowns that docstring-exclusion removes are all real
references to *another program's* flags - `clone_from_tsv.py`'s own CLI
(`--tsv`, `--dest`, `--targets-out`, `--max`) and pip's `--python` - plus
`cmd_tools_outdated`'s docstring, which named `jmo tools check --outdated` and
was a genuine third instance fixed alongside the other two.

That last one is the honest cost of this scope: **a wrong flag inside a
docstring is out of scope here.** Including docstrings would need five pinned
exceptions, and a pinned exception is a maintenance claim. Docstrings are
developer-facing; the strings this guard covers are what a user is told to run.
"""

from __future__ import annotations

import argparse
import ast
import contextlib
import io
import re
import sys
from pathlib import Path

import scripts.cli.jmo as jmo_mod

REPO_ROOT = Path(__file__).resolve().parents[2]
SCRIPTS = REPO_ROOT / "scripts"

#: A long option. The lookbehind keeps `--foo` out of `x---foo` and out of the
#: tail of an em-dash-ish run, and stops `--no-store-history` matching twice.
_FLAG = re.compile(r"(?<![\w-])--[a-z][a-z0-9-]+")

#: Only strings that are talking about jmo. Without this the guard reports 288
#: other-tool flags; with it, 8.
_MENTIONS_JMO = "jmo "


def _parser_option_strings() -> set[str]:
    """Every long option any jmo parser accepts, derived from the parser itself.

    Captures the subparsers action on the way past, the same trick
    `tests/unit/test_config_precedence.py::_parser_subcommands` uses - a
    restated list is the thing this whole family of guards exists to avoid.

    `--version` and `--help` live on the **top-level** parser, which owns the
    subparsers action rather than appearing among its choices. A first draft of
    this function walked only the choices and reported both as non-existent, so
    they are added explicitly.
    """
    captured: dict[str, argparse._SubParsersAction] = {}
    original = argparse.ArgumentParser.add_subparsers

    def _capture(self, *a, **kw):
        action = original(self, *a, **kw)
        captured.setdefault(kw.get("dest") or "positional", action)
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
        argparse.ArgumentParser.add_subparsers = original  # type: ignore[method-assign]
        sys.argv = argv

    seen: set[str] = {"--version", "--help"}
    parsers: list[argparse.ArgumentParser] = []
    for action in captured.values():
        parsers.extend(action.choices.values())

    i = 0
    while i < len(parsers):
        parser = parsers[i]
        i += 1
        for action in parser._actions:
            seen.update(o for o in action.option_strings if o.startswith("--"))
            if isinstance(action, argparse._SubParsersAction):
                parsers.extend(action.choices.values())
    return seen


def _docstring_lines(tree: ast.AST) -> set[int]:
    """Line numbers of module/class/function docstrings in one tree."""
    lines: set[int] = set()
    for node in ast.walk(tree):
        if not isinstance(
            node, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)
        ):
            continue
        body = getattr(node, "body", [])
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            lines.add(body[0].value.lineno)
    return lines


def _candidate_flags() -> list[tuple[str, int, str, str]]:
    """(path, line, flag, text) for every flag in an in-scope string literal.

    Uses `ast` rather than reading lines, so a comment cannot trip it - the
    same approach as `tests/cross_platform/test_encoding_drift_guard.py`.
    """
    found: list[tuple[str, int, str, str]] = []
    for path in sorted(SCRIPTS.rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8", errors="replace"))
        except SyntaxError:  # pragma: no cover - would fail elsewhere first
            continue
        docstrings = _docstring_lines(tree)
        rel = path.relative_to(REPO_ROOT).as_posix()
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
                continue
            if node.lineno in docstrings:
                continue
            if _MENTIONS_JMO not in node.value:
                continue
            for match in _FLAG.finditer(node.value):
                found.append((rel, node.lineno, match.group(0), node.value))
    return found


def test_the_parser_capture_found_the_real_options():
    """Meta-guard: an empty capture would make every assertion below vacuous."""
    options = _parser_option_strings()

    assert len(options) >= 130, f"parser capture looks wrong: {len(options)}"
    for expected in ("--profile", "--no-store-history", "--fail-on", "--version"):
        assert expected in options, f"{expected} missing from the captured parser"


def test_the_extractor_found_strings_to_check():
    """Meta-guard: an extractor that silently finds nothing passes everything.

    219 candidate tokens were measured when this was written; the floor is set
    well below that so ordinary edits do not trip it, but a scope that collapses
    to nothing does.
    """
    candidates = _candidate_flags()

    assert len(candidates) >= 100, (
        f"only {len(candidates)} flag references found in scripts/ - the "
        "extractor or the scope is broken, and every other assertion here is "
        "vacuous"
    )


def test_no_user_facing_string_names_a_nonexistent_flag():
    """The guard itself."""
    real = _parser_option_strings()

    offenders = []
    for rel, line, flag, text in _candidate_flags():
        if flag not in real:
            snippet = " ".join(text.split())[:90]
            offenders.append(f"{rel}:{line}: {flag}\n      in: {snippet!r}")

    assert (
        not offenders
    ), "user-facing text names flags jmo's parser does not accept:\n" + "\n".join(
        offenders
    )


def test_the_guard_rejects_the_flag_this_issue_was_filed_for():
    """Negative control.

    Without this, "the parser accepts everything" and "no string is out of
    scope" both read as a pass. Rebuilds the exact string that shipped and
    checks the matcher would have flagged it.
    """
    real = _parser_option_strings()
    shipped = "Run a scan with --store-history first, or use 'jmo history store'\n"

    assert _MENTIONS_JMO in shipped
    flags = [m.group(0) for m in _FLAG.finditer(shipped)]

    assert flags == ["--store-history"]
    assert "--store-history" not in real, (
        "--store-history now exists, so this control no longer controls "
        "anything - replace it with a flag that does not"
    )
    # And the flag it should have named does exist.
    assert "--no-store-history" in real
