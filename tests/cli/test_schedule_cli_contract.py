"""`jmo schedule <action>` must forward every flag its own subparser accepts.

#930: every one of the 60 tests in `test_schedule_commands.py` drives its
handler through a hand-built `MagicMock(spec=[])` namespace
(`create_mock_args`), never the real parser. That shape cannot catch two
classes of bug at once:

* a flag the parser defines that the handler never reads -- invisible, because
  the mock supplies a value nothing looks at;
* a flag the handler reads that the parser never defines -- invisible, because
  the mock supplies it too, and only a real `ArgumentParser` would raise
  `AttributeError` for a namespace that lacks it.

Chunk 17 measured what that cost: `jmo schedule create` accepted
`"evil; rm -rf /"`, `"../../etc/passwd"`, `"has space"` and 65+-character
names that `jmo schedule install` rejects -- 60 mock-driven tests, all green,
because none of them drove the real parser's constraints.

This file does not convert those 60 tests (issue #930 explicitly says not to;
they still give fast branch coverage). It adds a second, independent guard:
every dest a `schedule` subparser defines, derived from the real
`_add_schedule_args`, must be read by the handler `cmd_schedule` actually
routes that subcommand to, derived from `cmd_schedule`'s own source. Both
sides are extracted, never restated, so this file cannot become the same kind
of mirror it is checking for.

Two in-repo precedents, both reused here:

* `tests/unit/test_schedule_contract.py` -- derives a factory's written keys
  and three consumers' read keys independently, then asserts the one set is a
  subset of the other, with a floor-and-named-keys meta-guard so a broken
  extractor cannot pass by finding nothing.
* `tests/cli/test_ci_arg_forwarding.py` -- `ci_parser_dests()` builds the real
  parser dest set by calling `_add_ci_args` on a throwaway
  `ArgumentParser().add_subparsers()`, and `unguarded_arg_reads()` AST-walks a
  handler for bare `args.X` reads. This file's `_schedule_subcommand_dests()`
  and `_args_read_by()` are the same two techniques, one level down: per
  *subcommand* dests rather than one flat pool, because `cmd_schedule` routes
  to nine independent handlers instead of forwarding one namespace into two
  phases (see the docstring on `_args_read_by` for why that shape rules out
  driving the real handlers instead of reading their source).
"""

from __future__ import annotations

import argparse
import ast
from pathlib import Path

from scripts.cli import jmo, schedule_commands

# Named rather than only counted, so a subcommand silently dropped from either
# the parser or the router is caught even if the total count coincidentally
# still clears the floor.
EXPECTED_SUBCOMMANDS = frozenset(
    {
        "create",
        "list",
        "get",
        "update",
        "export",
        "install",
        "uninstall",
        "delete",
        "validate",
    }
)

_SOURCE = Path(schedule_commands.__file__)


def _schedule_subcommand_dests() -> dict[str, set[str]]:
    """Every dest each `schedule` subparser defines, read off the real parser.

    Builds a throwaway top-level parser purely to get a `subparsers` action to
    hand to `_add_schedule_args` -- the same function `jmo.py` itself calls --
    then reads argparse's own dest resolution off the returned tree. Nothing
    here is hand-typed: `--repos-dir` resolving to `repos_dir`, `-o`/`--output`
    resolving to `output`, and the mutually-exclusive `--suspend`/`--resume`
    pair are all argparse's own doing, not this file's.
    """
    ap = argparse.ArgumentParser(prog="jmo")
    sub = ap.add_subparsers(dest="cmd")
    schedule_parser = jmo._add_schedule_args(sub)

    action = next(
        a for a in schedule_parser._actions if isinstance(a, argparse._SubParsersAction)
    )
    return {
        name: {act.dest for act in subparser._actions if act.dest != "help"}
        for name, subparser in action.choices.items()
    }


def _schedule_routing_map() -> dict[str, str]:
    """Which handler function `cmd_schedule` calls for each `schedule_action`.

    AST-walks the router's if/elif chain rather than restating it as a literal
    `{"create": "_cmd_schedule_create", ...}` dict -- a hand-written mapping
    here would be exactly the "mirror of a mirror" this file exists to avoid,
    one level higher than the dest check itself. If a subcommand's branch is
    renamed or re-routed, this walk sees the new target automatically.
    """
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    router = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "cmd_schedule"
    )

    mapping: dict[str, str] = {}
    for node in ast.walk(router):
        if not isinstance(node, ast.If):
            continue
        test = node.test
        if not (
            isinstance(test, ast.Compare)
            and isinstance(test.left, ast.Attribute)
            and test.left.attr == "schedule_action"
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
    """Attributes `func_name` reads off its first parameter as a bare `.X`.

    Static AST extraction, not driving the real handler with a spy namespace.
    `test_ci_arg_forwarding.py` can drive `cmd_ci` live because it forwards
    one shared namespace into exactly two downstream phases; `cmd_schedule`
    instead routes to nine independent handlers, most of which return early
    -- `manager.get() is None`, a declined delete confirmation, an
    unsupported-platform install -- before reaching later reads. Reaching
    every read live would need a bespoke valid `ScheduleManager`/
    `CronInstaller`/stdin per branch, and would still only prove what today's
    fixtures happen to exercise. Reading the source sees the whole function
    body regardless of which branch runs -- the same reasoning
    `test_schedule_contract.py` gives for parsing `from_simple_args` via
    `ast` rather than calling it.
    """
    tree = ast.parse(_SOURCE.read_text(encoding="utf-8"))
    func = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == func_name
    )
    param = func.args.args[0].arg  # "args" in every _cmd_schedule_* handler
    read: set[str] = set()
    for node in ast.walk(func):
        if (
            isinstance(node, ast.Attribute)
            and isinstance(node.value, ast.Name)
            and node.value.id == param
            and isinstance(node.ctx, ast.Load)
        ):
            read.add(node.attr)
    return read


# ---------------------------------------------------------------------------
# Meta-guard: the extractors themselves must not silently find nothing
# ---------------------------------------------------------------------------


def test_extractors_actually_found_something():
    """An extractor that quietly returns empty makes every check below vacuous.

    This is the control the acceptance gate calls out by name: simulate the
    capture breaking (patch `_schedule_subcommand_dests` to return `{}`) and
    confirm THIS test is what goes red, via the floor -- not the property test,
    which would see `set() - set() == set()` and pass.
    """
    dests = _schedule_subcommand_dests()
    routing = _schedule_routing_map()

    assert len(dests) >= 9, f"subcommand extractor looks wrong: {sorted(dests)}"
    missing_subs = EXPECTED_SUBCOMMANDS - set(dests)
    assert not missing_subs, f"parser lost subcommands: {sorted(missing_subs)}"
    for name in EXPECTED_SUBCOMMANDS:
        assert dests[name], f"'{name}' subparser produced no dests at all"

    total_dest_occurrences = sum(len(v) for v in dests.values())
    assert total_dest_occurrences >= 25, (
        f"only found {total_dest_occurrences} dest occurrences across all "
        f"subcommands: {dests}"
    )

    assert len(routing) >= 9, f"routing extractor looks wrong: {routing}"
    missing_routes = EXPECTED_SUBCOMMANDS - set(routing)
    assert not missing_routes, f"router lost subcommands: {sorted(missing_routes)}"

    create_reads = _args_read_by(routing["create"])
    assert len(create_reads) >= 8, f"handler-read extractor looks wrong: {create_reads}"
    assert {"name", "cron", "profile"} <= create_reads


# ---------------------------------------------------------------------------
# The property: every dest a subparser defines is read by its own handler,
# and every dest a handler reads is defined by that same subparser
# ---------------------------------------------------------------------------


def test_every_subcommand_dest_is_read_by_its_own_handler():
    """The bug, stated as a property, in both directions.

    A dest the parser defines that the handler never reads is Chunk 17's
    shape: a constraint nobody enforces, invisible to 60 green mock-driven
    tests. A dest the handler reads that the parser never defines is the
    sharper failure -- `AttributeError` against a real CLI invocation the
    first time a user reaches that branch, something `MagicMock(spec=[])`
    cannot ever surface because the mock happily answers to any attribute
    name the test author thought to set.
    """
    dests = _schedule_subcommand_dests()
    routing = _schedule_routing_map()

    unread: dict[str, list[str]] = {}
    undefined: dict[str, list[str]] = {}
    for action, dest_set in dests.items():
        handler = routing[action]
        read = _args_read_by(handler)
        missing = dest_set - read
        extra = read - dest_set
        if missing:
            unread[action] = sorted(missing)
        if extra:
            undefined[action] = sorted(extra)

    assert not unread, (
        "these schedule subcommands define a flag their own handler never "
        f"reads: {unread}"
    )
    assert not undefined, (
        "these schedule subcommands' handlers read args.X for a dest their "
        f"own parser never defines (AttributeError on real invocation): {undefined}"
    )
