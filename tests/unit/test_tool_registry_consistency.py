"""Cross-table consistency of `scripts/core/tool_registry.py`.

The invariant: **every tool named anywhere in the registry must be reachable by
some profile.** `PROFILE_TOOLS` is the universe — a tool absent from all four
profiles cannot be invoked by any scan, so an entry for it in any other table is
dead weight that reads as working configuration.

This is the guard for #782. `osv-scanner` sat in `TOOL_SCAN_TYPES` and in no
profile, plus a `Dockerfile.deep` download and a `versions.yaml` pin, for long
enough that `docs/superpowers/plans/2026-04-03-dead-code-cleanup.md:893` filed it
as "needs decision" in April 2026 and it was still there in August. Nothing could
detect it, because nothing compared the tables.

Derived from the tables themselves — see `test_every_registry_table_is_covered`,
which fails if someone adds a table this file does not know about, so the guard
cannot silently stop covering the registry.
"""

from __future__ import annotations

import pytest

import scripts.core.tool_registry as registry

# Which side of each table carries tool names. Stated explicitly rather than
# inferred: `TOOL_EXECUTION_COMMANDS`' *values* are executables (`java`, `node`,
# `zap.sh`), not tools, so a shape heuristic would assert the wrong thing and
# "pass" for the wrong reason.
TOOL_NAME_SIDES: dict[str, str] = {
    "TOOL_SCAN_TYPES": "values",  # scan type -> {tool, ...}
    "TOOL_BINARY_NAMES": "keys",  # tool -> binary name
    "TOOL_EXECUTION_COMMANDS": "keys",  # tool -> [executables it needs]
    "TOOL_VARIANTS": "both",  # variant -> parent tool; both are tools
    "CONTENT_TRIGGERED_TOOLS": "members",  # set of tools
    "MANUAL_INSTALL_TOOLS": "members",  # set of tools
    "TOOL_VERSION_REQUIREMENTS": "keys",  # tool -> {runtime: min version}
    "TOOL_PLATFORM_REQUIREMENTS": "keys",  # tool -> {platforms, ...}
}


def _profile_universe() -> set[str]:
    return {tool for tools in registry.PROFILE_TOOLS.values() for tool in tools}


def _tool_names(table_name: str) -> set[str]:
    table = getattr(registry, table_name)
    side = TOOL_NAME_SIDES[table_name]
    if side == "members":
        return set(table)
    if side == "keys":
        return set(table.keys())
    if side == "values":
        return {tool for group in table.values() for tool in group}
    return set(table.keys()) | set(table.values())  # "both"


def test_every_registry_table_is_covered():
    """A new table must be classified here, or the guard silently stops guarding.

    `PROFILE_TOOLS` is the universe everything else is measured against, so it is
    the one exclusion.
    """
    exported = {
        name
        for name in dir(registry)
        if name.isupper() and isinstance(getattr(registry, name), (dict, set, list))
    }
    unclassified = exported - set(TOOL_NAME_SIDES) - {"PROFILE_TOOLS"}
    assert not unclassified, (
        "tool_registry gained table(s) this consistency guard does not check: "
        f"{sorted(unclassified)}. Add them to TOOL_NAME_SIDES."
    )


@pytest.mark.parametrize("table_name", sorted(TOOL_NAME_SIDES))
def test_table_names_only_tools_some_profile_can_run(table_name: str):
    """Regression for #782: an entry for a tool no profile lists is unreachable."""
    universe = _profile_universe()
    orphans = sorted(_tool_names(table_name) - universe)
    assert not orphans, (
        f"{table_name} names tool(s) absent from every profile, so no scan can "
        f"invoke them: {orphans}. Either add them to a profile in PROFILE_TOOLS "
        f"or remove the entries -- half-wired is the state #782 was filed for."
    )


def test_variant_parents_are_real_tools():
    """`semgrep-secrets -> semgrep`: a variant is useless if its parent is gone."""
    universe = _profile_universe()
    dangling = sorted(
        f"{variant} -> {parent}"
        for variant, parent in registry.TOOL_VARIANTS.items()
        if parent not in universe
    )
    assert not dangling, f"variant(s) point at a tool no profile runs: {dangling}"


def test_manual_install_tools_are_a_subset_of_the_profiles():
    """A manual-install tool nothing lists is not 'manual', it is absent.

    These four are why `jmo tools check` exits 1 on a correctly-built deep image;
    that only makes sense while they are genuinely part of a profile.
    """
    assert _profile_universe() >= registry.MANUAL_INSTALL_TOOLS


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
