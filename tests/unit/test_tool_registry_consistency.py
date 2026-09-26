"""Cross-table consistency of `scripts/core/tool_registry.py`.

The invariant: **every tool named anywhere in the registry must be one JMo
installs** -- a `TOOL_MATRIX` scanner or the `POLICY_ENGINE`. That pair is the
universe: a tool outside it is installed by nothing and invoked by no scan, so
an entry for it in any other table is dead weight that reads as working
configuration.

This is the guard for #782. `osv-scanner` sat in `TOOL_SCAN_TYPES` and in no
scan's tool list, plus a `Dockerfile.deep` download and a `versions.yaml` pin,
for long enough that `docs/superpowers/plans/2026-04-03-dead-code-cleanup.md:893`
filed it as "needs decision" in April 2026 and it was still there in August.
Nothing could detect it, because nothing compared the tables. (Before v2.0.0
the universe was a union of several named tool lists.)

Derived from the tables themselves -- see `test_every_registry_table_is_covered`,
which fails if someone adds a table this file does not know about, so the guard
cannot silently stop covering the registry.
"""

from __future__ import annotations

import pytest

import scripts.core.tool_registry as registry

# Which side of each table carries tool names. Stated explicitly rather than
# inferred: `TOOL_EXECUTION_COMMANDS`' *values* are executables (`java`,
# `zap.sh`), not tools, so a shape heuristic would assert the wrong thing and
# "pass" for the wrong reason.
TOOL_NAME_SIDES: dict[str, str] = {
    "DESCRIPTORS": "keys",  # tool -> its descriptor; every table below derives from it
    "TOOL_SCAN_TYPES": "values",  # scan type -> {tool, ...}
    "TOOL_BINARY_NAMES": "keys",  # tool -> binary name
    "TOOL_EXECUTION_COMMANDS": "keys",  # tool -> [executables it needs]
    "_REPO_TOOLS": "members",  # the repository target's tools
}

# The universe itself, which everything else is measured against.
UNIVERSE_TABLES = {"TOOL_MATRIX"}


def _universe() -> set[str]:
    return {*registry.TOOL_MATRIX, registry.POLICY_ENGINE}


def _tool_names(table_name: str) -> set[str]:
    table = getattr(registry, table_name)
    side = TOOL_NAME_SIDES[table_name]
    if side == "members":
        return set(table)
    if side == "keys":
        return set(table.keys())
    return {tool for group in table.values() for tool in group}  # "values"


def test_every_registry_table_is_covered():
    """A new table must be classified here, or the guard silently stops guarding.

    Tuples and frozensets count: the universe itself is a tuple and the repo
    set a frozenset, so a detector that only saw dict/set/list would miss the
    next table shaped like either.
    """
    exported = {
        name
        for name in dir(registry)
        if name.isupper()
        and isinstance(getattr(registry, name), (dict, set, frozenset, list, tuple))
    }
    unclassified = exported - set(TOOL_NAME_SIDES) - UNIVERSE_TABLES
    assert not unclassified, (
        "tool_registry gained table(s) this consistency guard does not check: "
        f"{sorted(unclassified)}. Add them to TOOL_NAME_SIDES."
    )
    # And the classification must not name tables that no longer exist.
    assert sorted(set(TOOL_NAME_SIDES) - exported) == []


@pytest.mark.parametrize("table_name", sorted(TOOL_NAME_SIDES))
def test_table_names_only_tools_jmo_installs(table_name: str):
    """Regression for #782: an entry for a tool outside the universe is unreachable."""
    orphans = sorted(_tool_names(table_name) - _universe())
    assert not orphans, (
        f"{table_name} names tool(s) outside TOOL_MATRIX and the policy engine, "
        f"so nothing installs or invokes them: {orphans}. Either add them to "
        f"TOOL_MATRIX or remove the entries -- half-wired is the state #782 was "
        f"filed for."
    )


def test_osv_scanner_is_gone():
    """Named explicitly so a revert is loud rather than merely a count change.

    Removed in #782, completing a removal the CHANGELOG recorded at the time as
    "Trivy superior for container/dependency scanning" -- with a documented user
    migration, `--tools osv-scanner` -> `--tools trivy`.
    """
    for table_name in TOOL_NAME_SIDES:
        assert "osv-scanner" not in _tool_names(table_name), (
            f"osv-scanner reappeared in {table_name}. It was removed deliberately;"
            " re-adding it needs an adapter, a binary name and an execution"
            " command, not just a registry entry."
        )


def test_every_matrix_tool_applies_to_some_target_type():
    """The other direction: a matrix tool on no target type can never run.

    `jmo scan` filters the tool list through TOOL_SCAN_TYPES per target, so a
    TOOL_MATRIX entry that no target type lists would be installed by `jmo
    tools install` and then skipped by every scan.
    """
    applicable = {tool for tools in registry.TOOL_SCAN_TYPES.values() for tool in tools}
    assert sorted(set(registry.TOOL_MATRIX) - applicable) == []
