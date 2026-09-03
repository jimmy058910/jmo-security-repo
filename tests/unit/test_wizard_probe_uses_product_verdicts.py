#!/usr/bin/env python3
"""Guard: the wizard probe asks the product, it does not re-derive the answer.

Regression for #1138.

`scripts/dev/test_wizard_tools.py` is named in CLAUDE.md as the thing to run
before `jmo wizard`. It reached its verdicts through `ToolManager`'s *private*
helpers - `_find_binary`, `_get_tool_version`, `_verify_execution` - each of
which answers a narrower question than `check_tool()` does. So it disagreed
with `jmo tools check`, and in one case with itself. Measured on Windows,
balanced profile, before the fix:

    [MISS] zap: not installed          `tools check` read `zap OK 2.17.0`
    [OK]   zap: ready to execute       the SAME run
    cdxgen: version parse failed       `tools check` read 12.8.2
    [OK] Java 21.0.12 found
    2. Install Java 11+ for dependency-check      the SAME run

22 passed / 3 failed, exit 1. After: 25 passed / 0 failed, exit 0, with
`cdxgen: 12.8.2` and `zap: 2.17.0` matching `tools check`.

This is the "mirror of a mirror" shape from `.claude/rules/testing.rules.md`:
a second implementation of something the code already decides, drifting from it
silently. The fix is not to keep the two in step by hand - it is to have only
one of them.

**Why an AST guard rather than a behavioural one.** The script's output depends
on which tools are installed on the machine running it, so a test that executes
it would either need every tool (`requires_tools`, absent on the PR shards) or
would assert nothing. What is checkable everywhere is the property that made it
wrong: reaching past the public verdict.
"""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PROBE = REPO_ROOT / "scripts" / "dev" / "test_wizard_tools.py"

#: ToolManager helpers that answer a narrower question than `check_tool()`.
#: `_verify_execution` says "would this run if installed" and says nothing about
#: whether it *is*; `_find_binary` and `_get_tool_version` each resolve through
#: one path where `check_tool` tries several.
NARROWER_THAN_CHECK_TOOL = {
    "_find_binary",
    "_get_tool_version",
    "_verify_execution",
}

#: Probing the host for a *dependency* is not the same question and stays.
#: `_get_java_version` / `_get_node_version` are about the machine, not about a
#: tool's status, and `check_tool` has no field that answers them.
ALLOWED_PRIVATE = {"_get_java_version", "_get_node_version"}


def _private_tool_manager_calls() -> list[tuple[int, str]]:
    """(line, attribute) for every `self.tm._<name>(...)` call in the probe."""
    tree = ast.parse(PROBE.read_text(encoding="utf-8"))
    calls: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not isinstance(func, ast.Attribute) or not func.attr.startswith("_"):
            continue
        # self.tm.<something>
        owner = func.value
        if (
            isinstance(owner, ast.Attribute)
            and owner.attr == "tm"
            and isinstance(owner.value, ast.Name)
            and owner.value.id == "self"
        ):
            calls.append((node.lineno, func.attr))
    return calls


def test_the_probe_exists_where_claude_md_says_it_does():
    """Meta-guard: every assertion below is vacuous if the file moved."""
    assert PROBE.is_file(), f"{PROBE} is missing; CLAUDE.md points readers at it"


def test_the_probe_asks_check_tool_for_its_verdicts():
    """It has to actually use the public API, or the guard below is vacuous."""
    source = PROBE.read_text(encoding="utf-8")

    assert "self.tm.check_tool(" in source, (
        "the probe no longer asks ToolManager.check_tool() for tool status, so "
        "it is free to disagree with `jmo tools check` again"
    )


def test_the_probe_does_not_re_derive_tool_status():
    """The guard itself."""
    offenders = [
        f"line {line}: self.tm.{attr}()"
        for line, attr in _private_tool_manager_calls()
        if attr in NARROWER_THAN_CHECK_TOOL
    ]

    assert not offenders, (
        "scripts/dev/test_wizard_tools.py reaches past ToolManager.check_tool() "
        "for a tool's status. Those helpers answer narrower questions, which is "
        "how the probe came to print `[MISS] zap: not installed` and "
        "`[OK] zap: ready to execute` in one run (#1138):\n  " + "\n  ".join(offenders)
    )


def test_host_dependency_probes_are_still_allowed():
    """Negative control, in the over-correction direction.

    "Use check_tool for everything" would be wrong: whether the *machine* has
    Java or Node is a different question, and `check_tool` has no field for it.
    If this fails, the denylist above has been widened into a ban on asking.
    """
    assert not (NARROWER_THAN_CHECK_TOOL & ALLOWED_PRIVATE)

    attrs = {attr for _, attr in _private_tool_manager_calls()}

    assert attrs & ALLOWED_PRIVATE, (
        "the probe no longer checks for Java/Node at all - it should still "
        "report a missing host dependency, just not re-derive tool status"
    )
