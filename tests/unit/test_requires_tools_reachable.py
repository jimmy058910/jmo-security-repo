#!/usr/bin/env python3
"""Guard: a `requires_tools` test must be selected by some CI invocation.

Regression for #1028.

Every pytest invocation in `ci.yml` and `scheduled.yml` is path-scoped. A
`requires_tools` test in a directory none of those paths names is selected by
nothing -- and unlike a skip, a **deselect is not countable**. It does not
appear in any summary, so the test simply stops existing without anything
saying so.

Measured at Phase 6 closeout: `tests/security/` is named by no workflow at all
(`git grep tests/security -- .github/` exits 1). Marking
`test_trufflehog_scan_no_verified_secrets` as `requires_tools` -- semantically
correct, it does require the tool -- moved it from *visibly skipped* in the main
shards to *invisibly deselected everywhere*. That marker was reverted, so today
nothing is unreachable; what remains is a directory where the next person to add
the marker gets silence.

## What this asserts

For each test FILE carrying `requires_tools`, at least one workflow pytest
invocation both

  1. names a path that covers the file, and
  2. has a marker expression that can select a `requires_tools` test.

File granularity is deliberate: the defect is a *path scope* gap, and a
per-test check would collect the whole suite to answer a question about
directories.

## What it cannot assert

Whether the job actually runs (`if:` conditions, path filters, cron gating) or
whether the tools are installed on that runner. Those are real limits and
saying so is more useful than implying otherwise -- `tests/security`'s test
never executed on CI even before the marker, because bare `trufflehog` is not
on the runners' PATH. The point here is selection, which is the half that fails
silently.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
TESTS = REPO_ROOT / "tests"
WORKFLOWS = REPO_ROOT / ".github" / "workflows"

MARKER = "requires_tools"


# ---------------------------------------------------------------------------
# Which test files carry the marker
# ---------------------------------------------------------------------------


def _files_with_marker() -> set[Path]:
    """Test files using `@pytest.mark.requires_tools` or a `pytestmark` for it.

    An AST scan rather than a pytest collection: the question is which FILES
    carry the marker, and collecting ~9800 tests to answer it would make this
    guard slower than the suite it protects.
    """
    found: set[Path] = set()
    for path in TESTS.rglob("test_*.py"):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except SyntaxError:  # pragma: no cover - a broken test file fails elsewhere
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Attribute) and node.attr == MARKER:
                found.add(path)
                break
    return found


# ---------------------------------------------------------------------------
# Which paths the workflows select, and under what marker expression
# ---------------------------------------------------------------------------

_PYTEST_PATH = re.compile(r"(?<![\w/.-])tests/[\w/.-]*")
_MARKER_EXPR = re.compile(r"-m\s+[\"']([^\"']+)[\"']")


def _run_blocks() -> list[str]:
    """Every `run:` script in both workflows, shell continuations folded."""
    blocks: list[str] = []
    for wf in ("ci.yml", "scheduled.yml"):
        doc = yaml.safe_load((WORKFLOWS / wf).read_text(encoding="utf-8"))
        for job in (doc.get("jobs") or {}).values():
            for step in job.get("steps") or []:
                script = step.get("run")
                if isinstance(script, str) and "pytest" in script:
                    blocks.append(script.replace("\\\n", " "))
    return blocks


def _invocations() -> list[tuple[set[str], str | None]]:
    """(paths, marker expression) for each pytest command found."""
    out: list[tuple[set[str], str | None]] = []
    for block in _run_blocks():
        for line in block.split("pytest ")[1:]:
            # Stop at the next shell command boundary so a later `&&` or a
            # following step's paths are not folded into this invocation.
            segment = re.split(r"&&|\|\||;|\n\s*\w+=", line)[0]
            paths = set(_PYTEST_PATH.findall(segment))
            expr = _MARKER_EXPR.search(segment)
            out.append((paths, expr.group(1) if expr else None))
    return out


def _expression_can_select_requires_tools(expr: str | None) -> bool:
    """COULD this `-m` expression select some `requires_tools` test?

    Satisfiability with `requires_tools` pinned true, not evaluation with every
    other marker false. The difference is load-bearing: `-m "integration and not
    slow"` cannot select a test marked *only* `requires_tools`, but the
    integration suite is full of tests marked both, and calling that invocation
    "no coverage" reported eleven files as unreachable that CI does in fact run.

    The other marker names are few, so every assignment is tried rather than
    reasoned about.
    """
    if expr is None:
        return True
    names = sorted(
        n
        for n in set(re.findall(r"[A-Za-z_]\w*", expr))
        if n not in {"not", "and", "or", MARKER}
    )
    for bits in range(1 << len(names)):
        env = {n: bool(bits >> i & 1) for i, n in enumerate(names)}
        env[MARKER] = True
        try:
            if eval(expr, {"__builtins__": {}}, env):
                return True
        except Exception:  # pragma: no cover - a malformed expression is a real bug
            pytest.fail(f"could not evaluate workflow marker expression {expr!r}")
    return False


def _covers(scope: str, file: Path) -> bool:
    """Does a pytest path argument select this file?"""
    rel = file.relative_to(REPO_ROOT).as_posix()
    scope = scope.rstrip("/")
    return rel == scope or rel.startswith(scope + "/")


# ---------------------------------------------------------------------------
# The guard
# ---------------------------------------------------------------------------


def _selecting_scopes() -> set[str]:
    scopes: set[str] = set()
    for paths, expr in _invocations():
        if _expression_can_select_requires_tools(expr):
            scopes |= paths
    return scopes


def test_the_extractors_found_something() -> None:
    """Meta-guard, and the reason this file is not vacuous.

    Every assertion below is satisfied by an extractor that finds no marked
    files, or by one that finds no workflow invocations -- in opposite
    directions, so one meta-guard cannot cover both.
    """
    marked = _files_with_marker()
    assert len(marked) >= 15, f"only {len(marked)} files carry {MARKER}"

    invocations = _invocations()
    assert len(invocations) >= 8, f"only {len(invocations)} pytest invocations parsed"

    scopes = _selecting_scopes()
    assert scopes, "no workflow invocation can select a requires_tools test"
    assert "tests/" in scopes or any(s.startswith("tests/") for s in scopes)


def test_every_marked_file_is_selected_by_some_invocation() -> None:
    """The defect itself: a marked file no path scope reaches."""
    scopes = _selecting_scopes()
    unreachable = sorted(
        str(f.relative_to(REPO_ROOT).as_posix())
        for f in _files_with_marker()
        if not any(_covers(scope, f) for scope in scopes)
    )
    assert not unreachable, (
        f"{len(unreachable)} file(s) carry `{MARKER}` and are selected by no CI "
        f"pytest invocation, so those tests are DESELECTED everywhere -- which, "
        f"unlike a skip, appears in no summary:\n  " + "\n  ".join(unreachable)
    )


def test_a_marker_expression_that_excludes_the_marker_does_not_count() -> None:
    """The discriminator the whole guard rests on.

    The main shards run `-m "not smoke and not requires_tools and not docker"`
    over all of `tests/`, so treating any `tests/`-scoped invocation as coverage
    would make this guard pass for every directory in the repository -- the
    exact false negative it exists to prevent.
    """
    assert not _expression_can_select_requires_tools(
        "not smoke and not requires_tools and not docker"
    )
    assert not _expression_can_select_requires_tools("not requires_tools and not smoke")
    assert _expression_can_select_requires_tools("requires_tools")
    assert _expression_can_select_requires_tools("not docker")
    assert _expression_can_select_requires_tools(None)


def test_tests_security_is_still_the_uncovered_directory() -> None:
    """Pins the measurement, so a workflow change that fixes it is visible.

    `tests/security/` is named by no workflow (`git grep tests/security --
    .github/` exits 1). It carries no `requires_tools` marker today -- the one
    that was added there was reverted for exactly this reason -- so the guard
    above is green. This records WHY it is green, so that if someone adds the
    directory to a requires_tools invocation, this fails and gets deleted on
    purpose rather than the fact quietly ceasing to be true.
    """
    scopes = _selecting_scopes()
    security = TESTS / "security"
    covered = [s for s in scopes if _covers(s, security / "test_secrets_management.py")]
    assert not covered, (
        f"tests/security/ is now selected by {covered}; #1028's trap is gone. "
        "Delete this test and say so."
    )
