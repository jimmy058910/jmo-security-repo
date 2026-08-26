"""`jmo trends <sub>` must forward every flag its own subparser accepts.

#916: every one of the 52 tests in `test_trend_commands.py` drives its handler
through a hand-built `class Args` stub, never the real parser. That shape
cannot catch three classes of bug at once:

* a flag the parser defines that the handler never reads -- invisible,
  because the stub supplies a value nothing looks at;
* a flag the handler reads that the parser never defines -- invisible,
  because the stub supplies it too, and only a real `ArgumentParser` would
  raise `AttributeError` for a namespace that lacks it;
* a flag argparse itself sets to `None` when omitted -- invisible, because
  every stub sets a concrete value (`last = 30`), so a handler's own
  `getattr(args, "last", 30)` default, which can never fire against a real
  parsed namespace, is never exercised either way.

This file does not convert those 52 tests (issue #916 explicitly says not to;
they still give fast branch coverage). It adds a second, independent guard:
every dest a `trends` subparser defines, derived from the real
`_add_trends_args`, must be read by the handler `cmd_trends` actually routes
that subcommand to, derived from `cmd_trends`'s own source. Both sides are
extracted, never restated, so this file cannot become the same kind of mirror
it is checking for.

Two in-repo precedents, both reused here -- see
`.superpowers/sdd/2026-08-22-v1.1.0-pre-release-fix-program/task-10-report.md`
for the fuller writeup this file's design follows:

* `tests/unit/test_schedule_contract.py` -- derives a factory's written keys
  and three consumers' read keys independently, then asserts the one set is a
  subset of the other, with a floor-and-named-keys meta-guard so a broken
  extractor cannot pass by finding nothing.
* `tests/cli/test_schedule_cli_contract.py` (#930) -- the direct sibling of
  this file, one level up the CLI: `_schedule_subcommand_dests()` builds the
  real per-subcommand dest sets off `_add_schedule_args`, `_args_read_by()`
  AST-walks a handler for its own reads, and a two-direction property test
  (missing + extra) checks both. `_trend_subcommand_dests()` below is that
  same technique with no changes beyond the function name -- pure argparse
  introspection, not anything schedule-specific.

Two places needed real adjustment rather than a blind copy, because this
surface's shape genuinely differs from schedule's:

1. **The router compares a local variable, not `args.X` directly.**
   `cmd_schedule`'s if/elif chain reads `args.schedule_action == "create"`
   directly, so #930's `_schedule_routing_map()` matches an `ast.Attribute`.
   `cmd_trends` instead does `subcommand = getattr(args, "trends_command",
   None)` once, then dispatches on the local `subcommand` name -- so
   `_trend_routing_map()` below matches an `ast.Name`. Confirmed by reading
   `cmd_trends`'s source before writing this, per #930's own report: "confirm
   `cmd_trend`'s router has the same shape before reusing that function
   verbatim."
2. **The dominant read style is `getattr(args, "X", default)`, not bare
   `args.X`.** Measured: 41 `getattr(args, ...)` calls against 6 bare
   `args.X` reads in `trend_commands.py`, and the 6 are all one command's
   (`cmd_trends_analyze`'s `export_*` fields). #930's `_args_read_by()` only
   matches bare `ast.Attribute` reads, which on this file would find almost
   nothing and make every handler look like it ignores nearly every flag it
   defines -- noise with no relation to any real bug. This is not cosmetic:
   `getattr(args, "last", 30)` is the exact shape of the dead-default bug
   #916 opens with (argparse always creates `args.last`, set to `None` when
   `--last` is omitted, so the stub's implicit promise that `30` is a real
   fallback is false) -- an extractor blind to `getattr` calls could not even
   see the flag being read, let alone help catch that class of bug. So
   `_args_read_by()` below matches both forms. The floor below is chosen to
   exercise both matching branches in the same assertion, not just one.

One real, filed mismatch came out of running this against the live code
(`developers` reads `repo` and `team_file`; no `developers` subparser flag
defines either -- #974, filed while building this guard, distinct from #916
which only named `team_file`). Unlike #930's schedule guard, which found the
CLI already clean, this file cannot assert a blanket "no extra reads anywhere"
without either lying about a real, reproduced defect or going red on every
run. `KNOWN_UNDEFINED_READS` pins that one exception by name and exact
membership, so the property test still fails loudly on anything new or
different, and a dedicated test fails loudly if the pinned gap itself ever
changes shape (narrows because a flag was added, or widens because a new dead
read appeared) -- see its docstring for why an allowlist beats `xfail` here.
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

from scripts.cli import jmo, trend_commands

# Named rather than only counted, so a subcommand silently dropped from either
# the parser or the router is caught even if the total count coincidentally
# still clears the floor.
EXPECTED_SUBCOMMANDS = frozenset(
    {
        "analyze",
        "show",
        "regressions",
        "score",
        "compare",
        "insights",
        "explain",
        "developers",
    }
)

# The one filed, real exception (#974): `developers` reads `repo` and
# `team_file`, and no `developers` subparser flag defines either. Pinned
# exactly rather than silently swallowed -- see
# test_developers_974_gap_matches_exactly below.
KNOWN_UNDEFINED_READS: dict[str, frozenset[str]] = {
    "developers": frozenset({"repo", "team_file"}),
}

_SOURCE = Path(trend_commands.__file__)


def _trend_subcommand_dests() -> dict[str, set[str]]:
    """Every dest each `trends` subparser defines, read off the real parser.

    Builds a throwaway top-level parser purely to get a `subparsers` action to
    hand to `_add_trends_args` -- the same function `jmo.py` itself calls --
    then reads argparse's own dest resolution off the returned tree. Nothing
    here is hand-typed: `--validate-statistics` resolving to
    `validate_statistics`, `--fail-on-any` resolving to `fail_on_any`, and
    `explain`'s positional `metric` are all argparse's own doing, not this
    file's.
    """
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")
    trends_parser = jmo._add_trends_args(sub)

    action = next(
        a for a in trends_parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    return {
        name: {act.dest for act in subparser._actions if act.dest != "help"}
        for name, subparser in action.choices.items()
    }


def _trend_routing_map() -> dict[str, str]:
    """Which handler function `cmd_trends` calls for each `trends_command`.

    AST-walks the router's if/elif chain rather than restating it as a literal
    `{"analyze": "cmd_trends_analyze", ...}` dict -- a hand-written mapping
    here would be exactly the "mirror of a mirror" this file exists to avoid,
    one level higher than the dest check itself. If a subcommand's branch is
    renamed or re-routed, this walk sees the new target automatically.

    Matches `if subcommand == "<action>":`, not `if args.trends_command ==
    "<action>":` -- `cmd_trends` assigns `subcommand = getattr(args,
    "trends_command", None)` once at the top and dispatches on that local
    name, unlike `cmd_schedule`'s direct `args.schedule_action` comparisons.
    Both shapes are argparse-router idioms in this codebase; this one needed
    checking, not assuming, before reuse (see module docstring point 1).
    """
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    router = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "cmd_trends"
    )

    mapping: dict[str, str] = {}
    for node in ast.walk(router):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Name)
            and test.left.id == "subcommand"
            and len(test.ops) == 1
            and isinstance(test.ops[0], ast.Eq)
            and len(test.comparators) == 1
            and isinstance(test.comparators[0], ast.Constant)
            and isinstance(test.comparators[0].value, str)
        ):
            continue
        action = test.comparators[0].value
        for stmt in node.body:
            if (
                isinstance(stmt, ast.Return)
                and isinstance(stmt.value, ast.Call)
                and isinstance(stmt.value.func, ast.Name)
            ):
                mapping[action] = stmt.value.func.id
                break
    return mapping


def _args_read_by(func_name: str) -> set[str]:
    """Attributes `func_name` reads off its first parameter, either form.

    Static AST extraction, not driving the real handler with a spy namespace
    -- same reasoning `test_schedule_cli_contract.py` gives: most `cmd_trends_*`
    handlers return early on missing data or a bad git repo before reaching
    later reads, so live-driving every branch would need a bespoke valid
    `TrendAnalyzer`/git repo/database per branch and would still only prove
    what today's fixtures happen to exercise.

    Two independent forms count as "read", both walked in one pass:

    * bare ``args.X`` -- an ``ast.Attribute`` on the parameter name, the only
      form #930's version of this function needed;
    * ``getattr(args, "X", default)`` -- an ``ast.Call`` to the builtin
      ``getattr`` whose first argument is the parameter name and whose second
      is a string constant. This is the dominant style in `trend_commands.py`
      (41 of 47 total reads); see the module docstring for why treating it as
      unread would make the property test below noise rather than signal.
    """
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == func_name
    )
    param = func.args.args[0].arg  # "args" in every cmd_trends_* handler
    read: set[str] = set()
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == param
            and isinstance(node.ctx, ast.Load)
        ):
            read.add(node.attr)
            continue
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Name)
            and node.func.id == "getattr"
            and len(node.args) >= 2
            and isinstance(node.args[0], ast.Name)
            and node.args[0].id == param
            and isinstance(node.args[1], ast.Constant)
            and isinstance(node.args[1].value, str)
        ):
            read.add(node.args[1].value)
    return read


# ---------------------------------------------------------------------------
# Meta-guard: the extractors themselves must not silently find nothing
# ---------------------------------------------------------------------------


def test_extractors_actually_found_something():
    """An extractor that quietly returns empty makes every check below vacuous.

    This is the control the acceptance gate calls out by name: simulate the
    capture breaking (patch `_trend_subcommand_dests` to return `{}`) and
    confirm THIS test is what goes red, via the floor -- not the property
    test, which would see `set() - set() == set()` and pass.

    `analyze`'s own read-set is named explicitly (not just counted) because it
    is the one handler that mixes both read forms -- `export_json` etc. are
    bare `args.X`, `branch`/`last`/`db` are `getattr(args, ...)` -- so this
    one assertion proves both branches of `_args_read_by` are still firing,
    not just one of them.
    """
    dests = _trend_subcommand_dests()
    routing = _trend_routing_map()

    assert len(dests) >= 8, f"subcommand extractor looks wrong: {sorted(dests)}"
    missing_subs = EXPECTED_SUBCOMMANDS - set(dests)
    assert not missing_subs, f"parser lost subcommands: {sorted(missing_subs)}"
    for name in EXPECTED_SUBCOMMANDS:
        assert dests[name], f"'{name}' subparser produced no dests at all"

    total_dest_occurrences = sum(len(v) for v in dests.values())
    assert total_dest_occurrences >= 34, (
        f"only found {total_dest_occurrences} dest occurrences across all "
        f"subcommands: {dests}"
    )

    assert len(routing) >= 8, f"routing extractor looks wrong: {routing}"
    missing_routes = EXPECTED_SUBCOMMANDS - set(routing)
    assert not missing_routes, f"router lost subcommands: {sorted(missing_routes)}"

    analyze_reads = _args_read_by(routing["analyze"])
    assert (
        len(analyze_reads) >= 12
    ), f"handler-read extractor looks wrong: {analyze_reads}"
    # "export_json" only exists in the read-set if the bare-Attribute branch
    # fired; "branch" only exists if the getattr-Call branch fired.
    assert {"branch", "last", "db", "export_json"} <= analyze_reads


# ---------------------------------------------------------------------------
# The property: every dest a subparser defines is read by its own handler,
# and every dest a handler reads is defined by that same subparser -- except
# the one filed, tracked gap in KNOWN_UNDEFINED_READS.
# ---------------------------------------------------------------------------


def test_every_subcommand_dest_is_read_by_its_own_handler():
    """The bug, stated as a property, in both directions.

    A dest the parser defines that the handler never reads is #916's shape: a
    constraint nobody enforces, invisible to 52 green stub-driven tests. A
    dest the handler reads that the parser never defines is the sharper
    failure -- `AttributeError` against a real CLI invocation the first time a
    user reaches that branch, something a hand-built `class Args` stub cannot
    ever surface because it happily answers to any attribute name the test
    author thought to set.

    `KNOWN_UNDEFINED_READS` excludes exactly one real, filed exception (#974)
    from the "extra" direction -- not a blanket pass, a subtraction of a named
    set, so anything beyond that exact set on `developers`, or anything at all
    on any other subcommand, still fails here.
    """
    dests = _trend_subcommand_dests()
    routing = _trend_routing_map()

    unread: dict[str, list[str]] = {}
    undefined: dict[str, list[str]] = {}
    for action, dest_set in dests.items():
        handler = routing[action]
        read = _args_read_by(handler)
        missing = dest_set - read
        extra = read - dest_set - KNOWN_UNDEFINED_READS.get(action, frozenset())
        if missing:
            unread[action] = sorted(missing)
        if extra:
            undefined[action] = sorted(extra)

    assert not unread, (
        "these trends subcommands define a flag their own handler never "
        f"reads: {unread}"
    )
    assert not undefined, (
        "these trends subcommands' handlers read args.X for a dest their own "
        "parser never defines (AttributeError on real invocation), beyond "
        f"the filed exceptions in KNOWN_UNDEFINED_READS: {undefined}"
    )


def test_developers_974_gap_matches_exactly():
    """The one tracked exception, pinned so drift in either direction is caught.

    `test_every_subcommand_dest_is_read_by_its_own_handler` subtracts
    `KNOWN_UNDEFINED_READS` before asserting, so it cannot see #974 change
    shape -- a shrink (a flag added, the gap partly fixed) or a growth (a
    third dead read appears) both pass that test silently. This one recomputes
    the raw difference with nothing subtracted and asserts it against the
    pinned set exactly, so either direction of drift fails here and forces
    `KNOWN_UNDEFINED_READS` to be revisited -- including checking whether #974
    should be closed, if this ever goes red because the gap narrowed.
    """
    dests = _trend_subcommand_dests()
    routing = _trend_routing_map()
    # Assert membership rather than index directly: an extractor that broke
    # (returned {} or dropped this one subcommand) should fail with a message
    # naming that, not a bare KeyError -- test_extractors_actually_found_something
    # is the test responsible for that failure mode; this one only needs to
    # not obscure it with an unrelated traceback.
    assert "developers" in dests and "developers" in routing, (
        "extractor(s) did not produce a 'developers' entry -- see "
        f"test_extractors_actually_found_something: dests={sorted(dests)}, "
        f"routing={sorted(routing)}"
    )
    actual_extra = _args_read_by(routing["developers"]) - dests["developers"]
    assert (
        actual_extra == KNOWN_UNDEFINED_READS["developers"]
    ), f"the #974 gap on `developers` changed shape: {sorted(actual_extra)}"
